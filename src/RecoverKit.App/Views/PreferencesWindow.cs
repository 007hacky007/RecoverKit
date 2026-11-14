using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.LogicalTree;
using Avalonia.Media;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Diagnostics;

namespace RecoverKit.App.Views;

/// <summary>Preferences: Performance, GPU Configuration, Files and Paths, Key search, Other. Closes with true on OK.</summary>
public sealed class PreferencesWindow : Window
{
    private readonly Settings _s;
    private readonly DeviceStrategy _loadedStrategy;
    private bool _threadsEdited;
    private bool _strategyEdited;
    private readonly CheckBox _automaticCalibration = Check("Measure the fastest method automatically");
    private readonly TextBlock _profileStatus = L.Text("", dim: true, wrap: true);
    private readonly HashcatTool? _hashcat;
    private List<BackendDevice> _devices;
    public bool HashcatChanged { get; private set; }

    private static readonly string[] Strategies =
    [
        "Keep one CPU thread free for each GPU (recommended)",
        "Avoid the CPU whenever a GPU can run (fast GPUs)",
        "Use all CPU threads next to the GPUs (slow GPUs)",
        "CPU only, no GPUs (for testing)",
    ];
    private static readonly string[] Priorities = ["Idle (recommended)", "Below normal", "Normal", "High (not recommended)"];

    private readonly ComboBox _strategy = new() { ItemsSource = Strategies, HorizontalAlignment = HorizontalAlignment.Stretch };
    private readonly ComboBox _priority = new() { ItemsSource = Priorities, MinWidth = 240 };
    private readonly NumericUpDown _maxThreads = L.Number(1, Math.Max(1, Environment.ProcessorCount), Environment.ProcessorCount);
    private readonly CheckBox _optimized = Check("Use optimized kernels for brute-force (faster, limits password length to 27)");
    private readonly CheckBox _native = Check("Use the built-in CPU engine (ZIP, Office 97-2003, PDF, RAR 3.x/5, TrueCrypt Whirlpool)");
    private readonly CheckBox _hybrid = Check("Run it next to the GPUs: share masks and supported file dictionaries between CPU and GPUs");
    private readonly CheckBox _hashcatCpu = Check("For other formats, also give hashcat the CPU next to the GPUs (OpenCL CPU runtime)");
    private readonly TextBox _extra = new();
    private readonly StackPanel _gpuList = new() { Spacing = 2 };
    private readonly List<(CheckBox Box, BackendDevice Device)> _gpuChecks = new();
    private readonly Slider _workload = new() { Minimum = 1, Maximum = 4, TickFrequency = 1, IsSnapToTickEnabled = true, TickPlacement = Avalonia.Controls.TickPlacement.BottomRight };
    private readonly TextBlock _backendLabel = L.Text("", dim: true);
    private static readonly (string Text, int Percent)[] Duties =
    [
        ("All the time (no limit)", 100),
        ("75% of the time", 75),
        ("Half of the time", 50),
        ("25% of the time", 25),
    ];
    private readonly ComboBox _duty = new() { ItemsSource = Duties.Select(d => d.Text).ToArray(), MinWidth = 220 };
    private readonly CheckBox _tempGuard = Check("Pause when the GPU gets too hot");
    private readonly NumericUpDown _tempLimit = L.Number(ThermalGuard.MinLimit, ThermalGuard.MaxLimit, 85, 110);
    private readonly NumericUpDown _tempHysteresis = L.Number(ThermalGuard.MinHysteresis, ThermalGuard.MaxHysteresis, 10, 110);
    private readonly TextBlock _tempNow = L.Text("", dim: true, wrap: true);
    private readonly TextBlock _tempResume = L.Text("", dim: true);
    private Control? _tempRows;
    private readonly CheckBox _powerLimit = Check("Limit GPU power (needs administrator rights)");
    private readonly StackPanel _powerRows = new() { Spacing = 6 };
    private readonly List<(NumericUpDown Box, int Index)> _powerBoxes = new();
    private Control? _powerGroup;
    private readonly CheckBox _screensaver = Check("Keep the display and system awake while an attack runs");
    private readonly CheckBox _useScenario = Check("Use external scenario file");
    private readonly TextBox _scenarioFile = new();
    private readonly TextBox _hashcatPath = new();
    private readonly TextBox _dataPath = new();
    private readonly TextBox _defaultDict = new();
    private readonly TextBox _onSuccess = new();
    private readonly TextBox _onFail = new();
    private readonly TextBox _rainbowPath = new();
    private readonly CheckBox _autoDecrypt = Check("Decrypt the document after a successful attack and save it with the suffix");
    private readonly TextBox _decryptSuffix = new() { Margin = new Thickness(28, 0, 0, 0), MaxWidth = 240, HorizontalAlignment = HorizontalAlignment.Left };
    private readonly CheckBox _noCache = Check("Don't use password cache");
    private readonly CheckBox _noKeyCache = Check("Don't use key cache");
    private readonly CheckBox _tryStay = Check("Try the fast ZIP key search first (WinZip-style archives with 5+ encrypted files)");
    private readonly CheckBox _reduce = Check("Reduce informational output (hide hashcat messages)");
    private readonly CheckBox _autoUpdate = Check("Check for updates when RecoverKit starts (at most once an hour)");
    private readonly CheckBox _logHashes = Check("Include extracted hashes (only needed to debug file parsing)");
    private readonly Button _apply;

    private static CheckBox Check(string text) => new() { Content = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap } };

    public PreferencesWindow(Settings s, HashcatTool? hashcat, List<BackendDevice> devices, int tab)
    {
        _s = s;
        _loadedStrategy = s.Strategy;
        _hashcat = hashcat;
        _devices = devices;
        Title = Platform.IsMac ? "Settings" : "Preferences";
        Icon = Icons.AppIcon();
        Width = 680;
        Height = 560;
        MinWidth = 560;
        MinHeight = 440;
        CanMinimize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var tabs = new TabControl { Margin = new Thickness(12, 8, 12, 0) };
        tabs.Items.Add(Tab("Performance", PerformanceTab()));
        tabs.Items.Add(Tab("GPU", GpuTab()));
        if (_powerGroup is not null) _powerGroup.IsVisible = false;   // until nvidia-smi reports an adjustable limit
        tabs.Items.Add(Tab("Files and Paths", PathsTab()));
        tabs.Items.Add(Tab("Key search", KeySearchTab()));
        tabs.Items.Add(Tab("Other", OtherTab()));
        tabs.SelectedIndex = Math.Clamp(tab, 0, tabs.ItemCount - 1);

        var ok = L.Button("OK", () => { Apply(); Close(true); }, 90, isDefault: true);
        var cancel = L.Button("Cancel", () => Close(false), 90, isCancel: true);
        _apply = L.Button("Apply", () => { Apply(); s.Save(); _apply!.IsEnabled = false; }, 90);
        _apply.IsEnabled = false;
        var footer = L.Footer(Platform.IsMac ? [_apply, cancel, ok] : [ok, cancel, _apply]);
        var root = new DockPanel();
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(tabs);
        Content = root;
        LoadValues();
        _maxThreads.ValueChanged += (_, _) => _threadsEdited = true;
        _strategy.SelectionChanged += (_, _) => _strategyEdited = true;
        // Apply stays disabled until something changes.
        TrackChanges(tabs, () => _apply.IsEnabled = true);
    }

    private static TabItem Tab(string name, Control content) => new()
    {
        Header = name, FontSize = 14,
        Content = new ScrollViewer { Content = new Border { Padding = new Thickness(4, 12, 8, 12), Child = content }, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled },
    };

    private void TrackChanges(Control root, Action changed)
    {
        foreach (var c in root.GetSelfAndLogicalDescendants())
        {
            switch (c)
            {
                case CheckBox cb: cb.IsCheckedChanged += (_, _) => changed(); break;
                case ComboBox co: co.SelectionChanged += (_, _) => changed(); break;
                case NumericUpDown nu: nu.ValueChanged += (_, _) => changed(); break;
                case Slider sl: sl.ValueChanged += (_, _) => changed(); break;
                case TextBox tx: tx.TextChanged += (_, _) => changed(); break;
            }
        }
        _gpuChanged = changed;
    }

    private Action? _gpuChanged;

    private Control PathRow(TextBox box, Func<Task<string?>> pick)
    {
        var g = L.Grid("*,Auto");
        g.Put(box, 0, 0);
        g.Put(L.Button("...", async () => { if (await pick() is { } p) box.Text = p; }, 40), 0, 1);
        return g;
    }

    private Task<string?> PickFile(string filter) => Pick.Open(this, filter);
    private Task<string?> PickFolder() => Pick.FolderPath(this);

    // ------------------------------------------------------------------ tabs

    private Control PerformanceTab()
    {
        var grid = L.Grid("Auto,*,Auto", rowSpacing: 10, columnSpacing: 12);
        grid.Put(L.Text("Application priority"), 0, 0);
        grid.Put(_priority, 0, 1, 2);
        grid.Put(L.Text("Maximum number of CPU threads"), 1, 0);
        grid.Put(_maxThreads, 1, 1);
        grid.Put(L.Button("Detect", () => _maxThreads.Value = _maxThreads.Maximum, 84), 1, 2);

        var hc = L.Grid("Auto,*", rowSpacing: 10, columnSpacing: 12);
        hc.Put(_optimized, 0, 0, 2);
        hc.Put(_native, 1, 0, 2);
        _hybrid.Margin = new Thickness(28, 0, 0, 0);
        hc.Put(_hybrid, 2, 0, 2);
        var cpuNote = L.Text(HashcatCpuNote(), dim: true, wrap: true);
        cpuNote.FontSize = 12;
        hc.Put(L.Column(4, _hashcatCpu, cpuNote), 3, 0, 2);
        hc.Put(L.Text("Extra hashcat arguments"), 4, 0);
        hc.Put(_extra, 4, 1);
        _native.IsCheckedChanged += (_, _) => _hybrid.IsEnabled = _native.IsChecked == true;

        return L.Column(16,
            L.Group("CPU/GPU performance strategy", StrategyBox()),
            L.Group("", grid),
            L.Group("Recovery engines", hc),
            L.Group("Performance profile", ProfileBox()));
    }

    private Control ProfileBox()
    {
        RefreshProfile();
        var reset = L.Button("Reset", () => { PerformanceProfiles.Reset(); RefreshProfile(); }, 90);
        var run = L.Button("Run detailed test", async () =>
        {
            await new DetailedBenchmarkWindow(_hashcat, _s, _devices).ShowDialog(this);
            RefreshProfile();
        }, 150);
        return L.Column(8, _profileStatus, _automaticCalibration,
            L.Text("A short measurement on the first longer attack chooses a correct method for this PC. Very short attacks start immediately. Your engine, device, thread and power choices take priority.", dim: true, wrap: true),
            L.Row(reset, run));
    }

    private void RefreshProfile()
    {
        var profile = PerformanceProfiles.Load();
        _profileStatus.Text = profile.MeasuredAt is { } at
            ? $"Performance profile: measured on {at.LocalDateTime:yyyy-MM-dd} ({profile.Source}), {profile.Decisions.Select(d => d.Mode).Distinct().Count()} formats"
            : "Performance profile: no measurements yet";
    }

    /// <summary>What adding the CPU to hashcat can be expected to bring, or why it is unavailable here.</summary>
    private string HashcatCpuNote()
    {
        bool cpuDevice = _devices.Any(d => !d.IsSkippedAlias && d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase));
        if (!cpuDevice)
            return "hashcat sees no processor device on this computer" + (Platform.IsMac ? " (Apple silicon has none)" : " (install the CPU runtime from Tools)") + ", so this has no effect.";
        return "Usually adds a few percent at most: hashcat's CPU kernels are far slower than a GPU and need the cores that feed the GPUs. " +
               "Check with Tools > Benchmark before leaving it on. The \"Use all CPU threads\" strategy does the same for every format.";
    }

    /// <summary>The strategy list, with a note where hashcat has no CPU device (Apple silicon).</summary>
    private Control StrategyBox()
    {
        var note = L.Text(Platform.IsMac
            ? "On this computer hashcat sees no processor device: \"CPU only\" runs the built-in CPU engine, which covers ZIP, Office 97-2003, PDF and RAR 3.x."
            : "hashcat sees no processor device yet: \"CPU only\" runs the built-in CPU engine for ZIP, Office 97-2003, PDF and RAR 3.x. " +
              "Other formats need a CPU runtime: Tools > Download CPU runtime.", dim: true, wrap: true);
        note.FontSize = 12;
        void Sync() => note.IsVisible = _strategy.SelectedIndex == (int)DeviceStrategy.CpuOnly
            && HashcatRunner.NoCpuDevice(new Settings { Strategy = DeviceStrategy.CpuOnly }, _devices);
        _strategy.SelectionChanged += (_, _) => Sync();
        Opened += (_, _) => Sync();
        return L.Column(6, _strategy, note);
    }

    private Control GpuTab()
    {
        var header = L.Grid("2*,*,*,*", columnSpacing: 8);
        string[] cols = ["GPU name", "Compute units", "Frequency", "Memory"];
        for (int i = 0; i < cols.Length; i++) header.Put(L.Text(cols[i], dim: true, bold: true), 0, i);
        var list = L.Column(6, header, new Border { Height = 1, Background = Palette.LineBrush }, _gpuList);

        var labels = L.Grid("*,*");
        labels.Put(L.Text("Lag free display", dim: true), 0, 0);
        var perf = labels.Put(L.Text("Performance", dim: true), 0, 1);
        perf.HorizontalAlignment = HorizontalAlignment.Right;

        var detectRow = L.Grid("*,Auto");
        detectRow.Put(_backendLabel, 0, 0);
        detectRow.Put(L.Button("Detect", async () =>
        {
            if (_hashcat is null) return;
            Cursor = new Avalonia.Input.Cursor(Avalonia.Input.StandardCursorType.Wait);
            try { _devices = await _hashcat.DevicesAsync(); FillDevices(); await RefreshTemperatureAsync(); }
            finally { Cursor = Avalonia.Input.Cursor.Default; }
        }, 84), 0, 1);

        return L.Column(16,
            L.Group("Devices", list),
            L.Group("GPU load", LoadBox(labels)),
            L.Group("GPU temperature", TemperatureBox()),
            _powerGroup = L.Group("GPU power limit (NVIDIA)", PowerBox()),
            detectRow,
            _screensaver);
    }

    /// <summary>Workload profile (hashcat -w) and the share of time the GPU works.</summary>
    private Control LoadBox(Control labels)
    {
        var duty = L.Grid("Auto,Auto", columnSpacing: 12);
        duty.Put(L.Text("Let the GPU work"), 0, 0);
        duty.Put(_duty, 0, 1);
        var note = L.Text("Workload sets how big each piece of GPU work is: lower keeps the desktop responsive " +
                          "(hashcat 8 ignores it and always uses the former level 3). " +
                          "Working only part of the time pauses hashcat in cycles of a minute, so the GPU idles in between: " +
                          "average power, heat and fan noise drop, and the attack takes correspondingly longer. " +
                          "On NVIDIA GPUs a real power limit can also be set (needs administrator rights).", dim: true, wrap: true);
        note.FontSize = 12;
        return L.Column(6, L.Text("Workload"), L.Column(2, labels, _workload), duty, note);
    }

    private Control TemperatureBox()
    {
        var g = L.Grid("Auto,Auto,*", rowSpacing: 8, columnSpacing: 10);
        g.Put(L.Text("Pause at"), 0, 0);
        g.Put(_tempLimit, 0, 1);
        g.Put(L.Text("°C", dim: true), 0, 2);
        g.Put(L.Text("Resume when it cools by"), 1, 0);
        g.Put(_tempHysteresis, 1, 1);
        g.Put(_tempResume, 1, 2);
        _tempRows = g;
        void Sync()
        {
            g.IsEnabled = _tempGuard.IsChecked == true && _tempGuard.IsEnabled;
            _tempResume.Text = $"°C (resumes at {_tempLimit.IntValue() - _tempHysteresis.IntValue()} °C)";
        }
        _tempGuard.IsCheckedChanged += (_, _) => Sync();
        _tempLimit.ValueChanged += (_, _) => Sync();
        _tempHysteresis.ValueChanged += (_, _) => Sync();
        Opened += (_, _) => { Sync(); _ = RefreshTemperatureAsync(); };
        var note = L.Text("hashcat is suspended while the GPU cools and continues exactly where it stopped. " +
                          "As a safety net hashcat also aborts on its own 10 °C above the limit.", dim: true, wrap: true);
        note.FontSize = 12;
        return L.Column(8, _tempGuard, g, _tempNow, note);
    }

    /// <summary>NVIDIA power limit: shown only when nvidia-smi reports an adjustable limit.</summary>
    private Control PowerBox()
    {
        var note = L.Text((OperatingSystem.IsWindows() ? "Windows asks" : "Your system asks") +
                          " for administrator rights at the start of each attack, because only an administrator may change a GPU's " +
                          "power limit. A small helper sets the limit and restores the previous one when the attack ends; " +
                          "RecoverKit itself keeps running without administrator rights.", dim: true, wrap: true);
        note.FontSize = 12;
        _powerLimit.IsCheckedChanged += (_, _) => _powerRows.IsEnabled = _powerLimit.IsChecked == true;
        Opened += async (_, _) => await LoadPowerLimitsAsync();
        return L.Column(8, _powerLimit, _powerRows, note);
    }

    private async Task LoadPowerLimitsAsync()
    {
        var gpus = await PowerLimiter.QueryAsync();
        if (_powerGroup is not null) _powerGroup.IsVisible = gpus.Count > 0;
        _powerRows.Children.Clear();
        _powerBoxes.Clear();
        foreach (var g in gpus)
        {
            int value = _s.GpuPowerWatts.TryGetValue(g.Index, out var w) && g.Allows(w) ? w : (int)Math.Round(Math.Clamp(g.DefaultWatts, g.MinAllowed, g.MaxAllowed));
            var box = L.Number(g.MinAllowed, g.MaxAllowed, value, 110);
            box.ValueChanged += (_, _) => _gpuChanged?.Invoke();
            var row = L.Grid("Auto,Auto,*", columnSpacing: 10);
            row.Put(L.Text($"GPU {g.Index}: {g.Name}"), 0, 0);
            row.Put(box, 0, 1);
            row.Put(L.Text($"W (allowed {g.MinAllowed}-{g.MaxAllowed} W, default {PowerLimitRequest.Watts(g.DefaultWatts)}, now {PowerLimitRequest.Watts(g.CurrentWatts)})", dim: true, wrap: true), 0, 2);
            _powerRows.Children.Add(row);
            _powerBoxes.Add((box, g.Index));
        }
        _powerRows.IsEnabled = _powerLimit.IsChecked == true;
    }

    /// <summary>Shows the current temperature, or why the guard is unavailable.</summary>
    private async Task RefreshTemperatureAsync()
    {
        bool hasGpu = _devices.Any(d => !d.IsSkippedAlias && d.Type.Contains("GPU", StringComparison.OrdinalIgnoreCase));
        var (temp, source) = await Task.Run(() =>
        {
            var src = GpuTemperature.External;
            int t = src?.ReadHottest() ?? -1;
            return t >= 0 ? (t, src!.Name) : (GpuTemperature.LastReported, "hashcat");
        });
        bool unsupported = !hasGpu || (temp < 0 && GpuTemperature.HashcatReportsNone);
        _tempNow.Text = !hasGpu ? "No GPU detected: the temperature guard only applies to GPUs."
            : temp >= 0 ? $"Current temperature: {temp} °C (from {source})."
            : unsupported ? "Temperature not reported by this GPU / driver, so the guard is unavailable."
            : "Temperature not reported yet: hashcat shows it once an attack runs on the GPU.";
        _tempGuard.IsEnabled = !unsupported;
        if (_tempRows is not null) _tempRows.IsEnabled = !unsupported && _tempGuard.IsChecked == true;
    }

    private Control HashcatRow()
    {
        var g = L.Grid("*,Auto,Auto");
        g.Put(_hashcatPath, 0, 0);
        g.Put(L.Button("...", async () =>
        {
            if (await PickFile(OperatingSystem.IsWindows() ? "hashcat|hashcat.exe|All files|*.*" : "All files|*.*") is { } p) _hashcatPath.Text = p;
        }, 40), 0, 1);
        g.Put(L.Button(Platform.IsMac ? "Install" : "Download", async () =>
        {
            if (await HashcatDownloadWindow.RunAsync(this) is { } exe)
            {
                _hashcatPath.Text = exe;
                HashcatChanged = true;
            }
        }, 94), 0, 2);
        return g;
    }

    private Control PathsTab()
    {
        var exec = L.Grid("Auto,*", rowSpacing: 8, columnSpacing: 10);
        exec.Put(L.Text("On success"), 0, 0);
        exec.Put(PathRow(_onSuccess, () => PickFile("All files|*.*")), 0, 1);
        exec.Put(L.Text("On fail"), 1, 0);
        exec.Put(PathRow(_onFail, () => PickFile("All files|*.*")), 1, 1);
        return L.Column(14,
            L.Group(OperatingSystem.IsWindows() ? "hashcat executable (hashcat.exe)" : "hashcat executable", HashcatRow()),
            L.Group("Default dictionary (used by scenarios as *default)", PathRow(_defaultDict, () => PickFile("Dictionary files (*.dic; *.txt)|*.dic;*.txt|All files|*.*"))),
            L.Group("Folder for dictionaries and rule files", PathRow(_dataPath, PickFolder)),
            L.Group("Run these programs when recovery ends", exec),
            L.Group("", L.Column(8, _useScenario, PathRow(_scenarioFile, () => PickFile("Scenario files (*.txt)|*.txt|All files|*.*")))));
    }

    private Control KeySearchTab() => L.Column(14,
        L.Group("", L.Column(8, _autoDecrypt, _decryptSuffix)),
        L.Group("Default path for rainbow tables", PathRow(_rainbowPath, PickFolder)),
        L.Text("Key search is available in the wizard for 40-bit RC4 documents. Rainbow tables are not supported by the hashcat engine; the path is kept for compatibility.", dim: true, wrap: true));

    private Control OtherTab()
    {
        var clearPw = L.Button("Clear", async () =>
        {
            if (!await Msg.Ask(this, "Delete all cached recovered passwords?", Title)) return;
            try
            {
                File.Delete(_s.PotfilePath);
                foreach (var file in Directory.EnumerateFiles(_s.VolumePasswordCacheDir, "*.potfile")) File.Delete(file);
                await Msg.Info(this, "Done!", Title);
            }
            catch (IOException ex) { await Msg.Warn(this, ex.Message, Title); }
        });
        Button clearKey = null!;
        clearKey = L.Button("Clear", async () =>
        {
            try { File.Delete(_s.KeyCachePath); clearKey.IsEnabled = false; await Msg.Info(this, "Done!", Title); }
            catch (IOException ex) { await Msg.Warn(this, ex.Message, Title); }
        });
        clearKey.IsEnabled = File.Exists(_s.KeyCachePath);
        var clearSessions = L.Button("Clear saved sessions", async () =>
        {
            foreach (var f in Directory.EnumerateFiles(_s.SessionsDir)) try { File.Delete(f); } catch (IOException) { }
            await Msg.Info(this, "Done!", Title);
        }, 160);
        clearSessions.HorizontalAlignment = HorizontalAlignment.Left;
        var openLog = L.Button(Platform.IsMac ? "Show in Finder" : "Open folder", () =>
        {
            Directory.CreateDirectory(DebugLog.Directory);
            Platform.Shell(DebugLog.Directory);
        }, 120);

        Control Line(Control left, Control right)
        {
            var g = L.Grid("*,Auto", columnSpacing: 12);
            g.Put(left, 0, 0);
            g.Put(right, 0, 1);
            return g;
        }
        return L.Column(14,
            L.Group("Password cache", Line(_noCache, clearPw)),
            L.Group("Key cache", L.Column(4, Line(_noKeyCache, clearKey),
                L.Text("Keys recovered by key search (40-bit RC4: MS Office 97-2003, PDF 1.1-1.3).", dim: true, wrap: true))),
            L.Group("Fast ZIP key search", L.Column(4, _tryStay,
                L.Text("Stay's attack on weak WinZip-style encryption headers recovers the cipher keys in minutes, without a password, and writes a decrypted copy.", dim: true, wrap: true))),
            L.Group("", _reduce),
            L.Group("Updates", L.Column(4, _autoUpdate,
                L.Text("Asks GitHub which version is the latest. Your files and passwords are never sent.", dim: true, wrap: true))),
            L.Group("Interrupted attacks", clearSessions),
            L.Group("Debug log", Line(_logHashes, openLog)));
    }

    // ------------------------------------------------------------------ load / apply

    private void LoadValues()
    {
        _strategy.SelectedIndex = (int)_s.Strategy;
        _automaticCalibration.IsChecked = _s.AutomaticPerformanceCalibration;
        _priority.SelectedIndex = (int)_s.Priority;
        // 0 means "one per logical processor"; show the number it resolves to.
        _maxThreads.Value = _s.MaxCpuThreads <= 0 ? _maxThreads.Maximum : Math.Clamp(_s.MaxCpuThreads, 1, (int)_maxThreads.Maximum);
        _optimized.IsChecked = _s.OptimizedKernels;
        _native.IsChecked = _s.UseNativeCpuEngine;
        _hybrid.IsChecked = _s.HybridCpuGpu;
        _hybrid.IsEnabled = _s.UseNativeCpuEngine;
        _hashcatCpu.IsChecked = _s.HashcatCpuWithGpu;
        _extra.Text = _s.ExtraArguments;
        _workload.Value = Math.Clamp(_s.Workload, 1, 4);
        int duty = Array.FindIndex(Duties, d => d.Percent >= _s.GpuDutyPercent && d.Percent - 25 < _s.GpuDutyPercent);
        _duty.SelectedIndex = duty < 0 ? 0 : duty;
        _tempGuard.IsChecked = _s.GpuTempGuard;
        _powerLimit.IsChecked = _s.GpuPowerLimit;
        _tempLimit.Value = Math.Clamp(_s.GpuTempLimit, ThermalGuard.MinLimit, ThermalGuard.MaxLimit);
        _tempHysteresis.Value = Math.Clamp(_s.GpuTempHysteresis, ThermalGuard.MinHysteresis, ThermalGuard.MaxHysteresis);
        _screensaver.IsChecked = _s.PreventScreensaver;
        _useScenario.IsChecked = _s.UseExternalScenarioFile;
        _scenarioFile.Text = _s.ExternalScenarioFile ?? "";
        _hashcatPath.Text = _s.HashcatPath ?? _hashcat?.Exe ?? "";
        _dataPath.Text = _s.DataPath ?? "";
        _defaultDict.Text = _s.DefaultDictionary ?? "";
        _onSuccess.Text = _s.ExecuteOnSuccess ?? "";
        _onFail.Text = _s.ExecuteOnFail ?? "";
        _rainbowPath.Text = _s.RainbowTablesPath ?? "";
        _autoDecrypt.IsChecked = _s.AutoDecrypt;
        _decryptSuffix.Text = string.IsNullOrEmpty(_s.DecryptSuffix) ? "_decrypted" : _s.DecryptSuffix;
        _noCache.IsChecked = _s.DontUsePasswordCache;
        _noKeyCache.IsChecked = _s.DontUseKeyCache;
        _tryStay.IsChecked = _s.TryStayZipAttack;
        _reduce.IsChecked = _s.ReduceOutput;
        _logHashes.IsChecked = _s.DebugLogIncludeHashes;
        _autoUpdate.IsChecked = _s.CheckForUpdatesAtStart;
        FillDevices();
    }

    private void FillDevices()
    {
        // GPUs only: the processor is configured on the Performance tab
        // (strategy, thread count), and the workload slider only governs GPU kernels.
        _gpuList.Children.Clear();
        _gpuChecks.Clear();
        var gpus = _devices.Where(d => !d.IsSkippedAlias && d.Type.Contains("GPU", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var d in gpus)
        {
            var row = L.Grid("2*,*,*,*", columnSpacing: 8);
            var cb = new CheckBox { Content = new TextBlock { Text = d.Name + (d.IsIntegratedGpu ? " (integrated)" : ""), TextTrimming = TextTrimming.CharacterEllipsis }, IsChecked = !HashcatRunner.IsDisabled(_s, d) };
            cb.IsCheckedChanged += (_, _) => _gpuChanged?.Invoke();
            row.Put(cb, 0, 0);
            row.Put(L.Text(d.Processors > 0 ? d.Processors.ToString() : "n/a"), 0, 1);
            row.Put(L.Text(d.ClockMhz > 0 ? $"{d.ClockMhz} MHz" : "n/a"), 0, 2);
            row.Put(L.Text(d.MemoryMb > 0 ? $"{d.MemoryMb} MB" : "n/a"), 0, 3);
            _gpuList.Children.Add(row);
            _gpuChecks.Add((cb, d));
        }
        if (gpus.Count == 0) _gpuList.Children.Add(L.Text("No compatible GPU devices detected.", dim: true));
        _workload.IsEnabled = _duty.IsEnabled = gpus.Count > 0;
        _backendLabel.Text = gpus.Count == 0 ? ""
            : string.Join(", ", gpus.Select(d => d.Backend + (d.BackendVersion.Length > 0 ? " " + d.BackendVersion : "")).Distinct());
    }

    private void Apply()
    {
        _s.Strategy = (DeviceStrategy)Math.Max(0, _strategy.SelectedIndex);
        if (_strategyEdited || _s.Strategy != _loadedStrategy) _s.PerformanceStrategyExplicit = true;
        if (_threadsEdited) _s.PerformanceThreadsExplicit = true;
        _s.AutomaticPerformanceCalibration = _automaticCalibration.IsChecked == true;
        _s.Priority = (ProcessPriority)Math.Max(0, _priority.SelectedIndex);
        _s.MaxCpuThreads = _maxThreads.Value >= _maxThreads.Maximum ? 0 : _maxThreads.IntValue();
        _s.OptimizedKernels = _optimized.IsChecked == true;
        _s.UseNativeCpuEngine = _native.IsChecked == true;
        _s.HybridCpuGpu = _hybrid.IsChecked == true;
        _s.HashcatCpuWithGpu = _hashcatCpu.IsChecked == true;
        _s.ExtraArguments = (_extra.Text ?? "").Trim();
        _s.Workload = (int)Math.Round(_workload.Value);
        _s.GpuDutyPercent = Duties[Math.Max(0, _duty.SelectedIndex)].Percent;
        _s.GpuTempGuard = _tempGuard.IsChecked == true;
        if (_powerBoxes.Count > 0)
        {
            _s.GpuPowerLimit = _powerLimit.IsChecked == true;
            foreach (var (box, index) in _powerBoxes) _s.GpuPowerWatts[index] = box.IntValue();
        }
        _s.GpuTempLimit = _tempLimit.IntValue();
        _s.GpuTempHysteresis = _tempHysteresis.IntValue();
        _s.PreventScreensaver = _screensaver.IsChecked == true;
        var off = _gpuChecks.Where(g => g.Box.IsChecked != true).Select(g => g.Device).ToList();
        _s.DisabledDevices = off.Select(d => d.Id).ToList();
        _s.DisabledDeviceKeys = off.Select(d => d.Key).ToList();
        _s.UseExternalScenarioFile = _useScenario.IsChecked == true;
        _s.ExternalScenarioFile = Null(_scenarioFile.Text);
        var hp = Null(_hashcatPath.Text);
        if (hp != _s.HashcatPath && hp != _hashcat?.Exe) HashcatChanged = true;
        _s.HashcatPath = hp;
        _s.DataPath = Null(_dataPath.Text);
        _s.DefaultDictionary = Null(_defaultDict.Text);
        _s.ExecuteOnSuccess = Null(_onSuccess.Text);
        _s.ExecuteOnFail = Null(_onFail.Text);
        _s.RainbowTablesPath = Null(_rainbowPath.Text);
        _s.AutoDecrypt = _autoDecrypt.IsChecked == true;
        _s.DecryptSuffix = string.IsNullOrWhiteSpace(_decryptSuffix.Text) ? "_decrypted" : _decryptSuffix.Text.Trim();
        _s.DontUsePasswordCache = _noCache.IsChecked == true;
        _s.DontUseKeyCache = _noKeyCache.IsChecked == true;
        _s.TryStayZipAttack = _tryStay.IsChecked == true;
        _s.ReduceOutput = _reduce.IsChecked == true;
        _s.DebugLogIncludeHashes = _logHashes.IsChecked == true;
        _s.CheckForUpdatesAtStart = _autoUpdate.IsChecked == true;
        DebugLog.IncludeHashes = _s.DebugLogIncludeHashes;
    }

    private static string? Null(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
