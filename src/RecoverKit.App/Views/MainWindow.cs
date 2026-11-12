using System.Numerics;
using System.Text.RegularExpressions;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Rectangle = Avalonia.Controls.Shapes.Rectangle;
using Avalonia.Platform.Storage;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Views;

/// <summary>
/// Main window: menu, toolbar, information pane, status pane and status bar, following the classic
/// single-document password-recovery layout. On macOS the menu lives in the system menu bar.
/// </summary>
public sealed partial class MainWindow : Window
{
    public const string AppName = "RecoverKit";
    public static readonly string AppVersion = typeof(MainWindow).Assembly.GetName().Version?.ToString(3) ?? "1.0";

    private readonly Settings _settings = Settings.Load();
    private HashcatTool? _hashcat;
    private List<BackendDevice> _devices = new();
    private string _hashcatVersion = "";
    private string _deviceStatus = "";   // right status pane text between attacks

    private readonly SelectableTextBlock _info = new() { TextWrapping = TextWrapping.Wrap, LineHeight = 19, Margin = new Thickness(12, 10, 12, 10) };
    private readonly ScrollViewer _infoScroll;
    private readonly TextBlock _curPassword = Value(), _estTime = Value(), _curSpeed = Value(), _avgSpeed = Value();
    private readonly ProgressBar _progress = new() { Minimum = 0, Maximum = 1000, Height = 6, MinHeight = 6, Margin = new Thickness(0, 6, 0, 0) };
    private readonly TextBlock _statusLeft = new() { VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis };
    private readonly TextBlock _statusRight = new() { VerticalAlignment = VerticalAlignment.Center };
    private Button _tbStart = null!, _tbStop = null!;
    private NativeMenuItem _miStart = null!, _miStop = null!;
    private readonly List<NativeMenuItem> _idleOnly = new();   // File and Options items, disabled during an attack

    private Detection? _current;
    private CancellationTokenSource? _cts;
    private DateTime _stepStarted;
    private BigInteger _stepKeyspace;
    private bool _busyDialog;      // a modal flow (wizard, preferences, ...) is open
    private bool _closeConfirmed;
    private bool _opened;
    private string? _pendingOpen;

    public MainWindow() : this(null) { }

    public MainWindow(string? fileToOpen)
    {
        _pendingOpen = fileToOpen;
        Title = AppName;
        Icon = Icons.AppIcon();
        MinWidth = 560;
        MinHeight = 420;
        Width = 680;
        Height = 520;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        if (_settings.WindowBounds is { Length: 4 } wb && wb[2] >= MinWidth && wb[3] >= MinHeight)
        {
            WindowStartupLocation = WindowStartupLocation.Manual;
            Position = new PixelPoint(wb[0], wb[1]);
            Width = wb[2];
            Height = wb[3];
        }

        var menu = BuildMenu();
        NativeMenu.SetMenu(this, menu);
        _infoScroll = new ScrollViewer { Content = _info, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled };

        var root = new DockPanel();
        var menuBar = new NativeMenuBar();   // renders the menu inside the window except on macOS
        DockPanel.SetDock(menuBar, Dock.Top);
        root.Children.Add(menuBar);
        var toolbar = BuildToolbar();
        DockPanel.SetDock(toolbar, Dock.Top);
        root.Children.Add(toolbar);
        var statusBar = BuildStatusBar();
        DockPanel.SetDock(statusBar, Dock.Bottom);
        root.Children.Add(statusBar);
        var statusPane = BuildStatusPane();
        DockPanel.SetDock(statusPane, Dock.Bottom);
        root.Children.Add(statusPane);
        root.Children.Add(new Border
        {
            Child = _infoScroll, Background = Palette.PaneBrush, BorderBrush = Palette.LineBrush,
            BorderThickness = new Thickness(0, 1, 0, 1),
        });
        Content = root;

        DragDrop.SetAllowDrop(this, true);
        AddHandler(DragDrop.DragOverEvent, (object? _, DragEventArgs e) =>
            e.DragEffects = e.DataTransfer.TryGetFiles() is { Length: > 0 } ? DragDropEffects.Copy : DragDropEffects.None);
        AddHandler(DragDrop.DropEvent, async (object? _, DragEventArgs e) =>
        {
            var files = e.DataTransfer.TryGetFiles()?.Select(f => f.TryGetLocalPath()).OfType<string>().ToArray() ?? [];
            if (files.Length == 0) return;
            if (files.Length > 1) { await Warn("Cannot process multiple files at once, please drop only one at a time."); return; }
            await OpenFileAsync(files[0]);
        });

        Opened += async (_, _) =>
        {
            if (WindowStartupLocation == WindowStartupLocation.Manual && Screens.ScreenFromPoint(Position) is null)
                Position = new PixelPoint(100, 100);   // the saved position is on a monitor that is gone
            _opened = true;
            await InitHashcatAsync();
            if (_pendingOpen is { } f) { _pendingOpen = null; await OpenFileAsync(f); }
        };
        Closing += OnClosing;
        SetRunning(false);
        ShowStartPage();
    }

    private static TextBlock Value() => new() { FontWeight = FontWeight.SemiBold, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis };

    /// <summary>A file opened from Finder (or the Dock) while the app runs.</summary>
    public void OpenFromShell(string path)
    {
        if (!_opened) { _pendingOpen = path; return; }
        Activate();
        _ = OpenFileAsync(path);
    }

    // ------------------------------------------------------------------ layout

    private NativeMenuItem Item(string header, Action a, KeyGesture? gesture = null, bool idleOnly = false)
    {
        var i = new NativeMenuItem(header) { Gesture = gesture };
        i.Click += (_, _) => a();
        if (idleOnly) _idleOnly.Add(i);
        if (gesture is not null && !Platform.IsMac)
            KeyBindings.Add(new KeyBinding { Gesture = gesture, Command = new Relay(() => { if (i.IsEnabled) a(); }) });
        return i;
    }

    private static NativeMenuItem Sub(string header, params NativeMenuItemBase[] items)
    {
        var m = new NativeMenu();
        foreach (var i in items) m.Items.Add(i);
        return new NativeMenuItem(header) { Menu = m };
    }

    private NativeMenu BuildMenu()
    {
        bool mac = Platform.IsMac;
        var file = new List<NativeMenuItemBase>
        {
            Item(mac ? "Open..." : "_Open...", OpenDialog, new KeyGesture(Key.O, Platform.Cmd), idleOnly: true),
            Item(mac ? "Open As..." : "Open _As...", OpenAsDialog, idleOnly: true),
            new NativeMenuItemSeparator(),
            Item(mac ? "WPA-PMK Generator..." : "_WPA-PMK Generator", () => _ = RunGeneratorAsync(WizardMode.PmkGenerator), idleOnly: true),
            Item(mac ? "Dictionary Generator..." : "_Dictionary Generator", () => _ = RunGeneratorAsync(WizardMode.DictionaryGenerator), idleOnly: true),
        };
        if (!mac) file.AddRange([new NativeMenuItemSeparator(), Item("E_xit", Close)]);   // macOS: Quit is in the app menu

        _miStart = Item(mac ? "Start" : "_Start", StartWizard, mac ? new KeyGesture(Key.R, KeyModifiers.Meta) : new KeyGesture(Key.F5));
        _miStop = Item(mac ? "Stop" : "S_top", StopAttack, mac ? new KeyGesture(Key.OemPeriod, KeyModifiers.Meta) : new KeyGesture(Key.F5, KeyModifiers.Shift));

        var options = new List<NativeMenuItemBase>();
        if (!mac) options.Add(Item("_Preferences", () => ShowPreferences(0), idleOnly: true));   // macOS: Settings in the app menu
        options.Add(Item(mac ? "GPU Configuration..." : "_GPU Configuration", () => ShowPreferences(1), new KeyGesture(Key.G, Platform.Cmd), idleOnly: true));

        var tools = new List<NativeMenuItemBase>
        {
            Item(mac ? "Rules Editor" : "_Rules editor", () => _ = ShowRulesEditorAsync()),
            new NativeMenuItemSeparator(),
            Item(mac ? "Benchmark" : "_Benchmark", () => _ = ShowBenchmarkAsync()),
            new NativeMenuItemSeparator(),
            Item(mac ? "Install hashcat..." : "_Download hashcat ...", () => _ = DownloadHashcatAsync()),
        };
        if (CpuRuntime.IsSupportedPlatform) tools.Add(Item("Download _CPU runtime (OpenCL) ...", () => _ = DownloadCpuRuntimeAsync()));

        var help = new List<NativeMenuItemBase>
        {
            Item(mac ? "RecoverKit Help" : "_Help contents", () => _ = ShowHelpAsync(), mac ? new KeyGesture(Key.OemQuestion, KeyModifiers.Meta | KeyModifiers.Shift) : new KeyGesture(Key.F1)),
            Item(mac ? "hashcat Website" : "hashcat _website", () => Platform.Shell("https://hashcat.net/hashcat/")),
            Item(mac ? "Show Debug Log" : "Open _debug log folder", OpenLogFolder),
        };
        if (!mac)   // macOS: both are in the app menu
            help.AddRange([new NativeMenuItemSeparator(), Item("Check for _updates", () => _ = CheckForUpdatesAsync()), Item($"_About {AppName}", ShowAbout)]);

        var menu = new NativeMenu();
        menu.Items.Add(Sub(mac ? "File" : "_File", file.ToArray()));
        menu.Items.Add(Sub(mac ? "Recovery" : "_Recovery", _miStart, _miStop));
        menu.Items.Add(Sub(mac ? "Options" : "_Options", options.ToArray()));
        menu.Items.Add(Sub(mac ? "Tools" : "_Tools", tools.ToArray()));
        menu.Items.Add(Sub(mac ? "Help" : "_Help", help.ToArray()));
        return menu;
    }

    private Control BuildToolbar()
    {
        const double sz = 26;
        Button B(Control icon, string tip, Action a)
        {
            var b = new Button { Content = icon, Padding = new Thickness(5), Background = Brushes.Transparent, BorderThickness = new Thickness(0) };
            b.Classes.Add("tool");
            ToolTip.SetTip(b, tip);
            AutomationProperties(b, tip);
            b.Click += (_, _) => a();
            return b;
        }
        Control Sep() => new Rectangle { Width = 1, Height = 26, Fill = Palette.LineBrush, Margin = new Thickness(6, 0) };
        _tbStart = B(Icons.Start(sz), "Start", StartWizard);
        _tbStop = B(Icons.Stop(sz), "Stop", StopAttack);
        _tbStart.PropertyChanged += (_, e) => { if (e.Property == IsEnabledProperty) _tbStart.Content = Icons.Start(sz, _tbStart.IsEnabled); };
        _tbStop.PropertyChanged += (_, e) => { if (e.Property == IsEnabledProperty) _tbStop.Content = Icons.Stop(sz, _tbStop.IsEnabled); };
        var bar = new StackPanel
        {
            Orientation = Orientation.Horizontal, Spacing = 2, Margin = new Thickness(6, 4),
            Children =
            {
                B(Icons.Open(sz), $"Open file ({Platform.Shortcut("O")})", OpenDialog), Sep(),
                _tbStart, _tbStop, Sep(),
                B(Icons.Gear(sz), Platform.IsMac ? "Settings" : "Preferences", () => ShowPreferences(0)),
                B(Icons.Help(sz), "Help", () => _ = ShowHelpAsync()),
            },
        };
        return bar;
    }

    private static void AutomationProperties(Control c, string name) => Avalonia.Automation.AutomationProperties.SetName(c, name);

    private Control BuildStatusPane()
    {
        var t = L.Grid("Auto,*,Auto,*", rowSpacing: 3, columnSpacing: 8);
        t.Margin = new Thickness(12, 8, 12, 8);
        t.Put(L.Text("Current password:", dim: true), 0, 0); t.Put(_curPassword, 0, 1);
        t.Put(L.Text("Estimated time:", dim: true), 0, 2); t.Put(_estTime, 0, 3);
        t.Put(L.Text("Current speed:", dim: true), 1, 0); t.Put(_curSpeed, 1, 1);
        t.Put(L.Text("Average speed:", dim: true), 1, 2); t.Put(_avgSpeed, 1, 3);
        t.Put(_progress, 2, 0, 4);
        return t;
    }

    private Control BuildStatusBar()
    {
        var g = L.Grid("*,Auto", columnSpacing: 10);
        g.Put(_statusLeft, 0, 0);
        g.Put(new Border { BorderBrush = Palette.LineBrush, BorderThickness = new Thickness(1, 0, 0, 0), Padding = new Thickness(10, 0, 0, 0), Child = _statusRight }, 0, 1);
        _statusLeft.FontSize = _statusRight.FontSize = 12;
        _statusLeft.Foreground = _statusRight.Foreground = Palette.DimBrush;
        return new Border
        {
            Child = g, Padding = new Thickness(12, 5), Background = Palette.BandBrush,
            BorderBrush = Palette.LineBrush, BorderThickness = new Thickness(0, 1, 0, 0),
        };
    }

    // ------------------------------------------------------------------ info pane

    private readonly System.Text.StringBuilder _uiLine = new();
    private const int MaxInlines = 6000;

    [GeneratedRegex(@"https://[^\s""'<>)\]]+")]
    private static partial Regex UrlRegex();

    private void Write(string text, IBrush? color = null, bool bold = false, double size = 0, bool log = true)
    {
        if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(() => Write(text, color, bold, size, log)); return; }
        // Mirror what the user sees into the debug log, one complete line at a time.
        _uiLine.Append(log ? text : $"(redacted, {text.Length} chars)");
        var buffered = _uiLine.ToString();
        int nl = buffered.LastIndexOf('\n');
        if (nl >= 0)
        {
            foreach (var l in buffered[..nl].Replace("\r", "").Split('\n')) DebugLog.Ui(l);
            _uiLine.Clear().Append(buffered[(nl + 1)..]);
        }

        var inlines = _info.Inlines!;
        var lines = text.Replace("\r\n", "\n").Split('\n');
        for (int i = 0; i < lines.Length; i++)
        {
            if (i > 0) inlines.Add(new LineBreak());
            if (lines[i].Length == 0) continue;
            // The pane also shows text taken from the opened file, so only web links to known sites are clickable.
            int at = 0;
            foreach (Match m in UrlRegex().Matches(lines[i]))
            {
                if (!IsTrustedLink(m.Value)) continue;
                if (m.Index > at) inlines.Add(Styled(new Run(lines[i][at..m.Index]), color, bold, size));
                inlines.Add(LinkInline(m.Value, () => Platform.Shell(m.Value)));
                at = m.Index + m.Length;
            }
            if (at < lines[i].Length) inlines.Add(Styled(new Run(lines[i][at..]), color, bold, size));
        }
        while (inlines.Count > MaxInlines) inlines.RemoveAt(0);
        Dispatcher.UIThread.Post(() => _infoScroll.ScrollToEnd(), DispatcherPriority.Background);
    }

    private static Run Styled(Run r, IBrush? color, bool bold, double size)
    {
        if (color is not null) r.Foreground = color;
        if (bold) r.FontWeight = FontWeight.SemiBold;
        if (size > 0) r.FontSize = size;
        return r;
    }

    private static InlineUIContainer LinkInline(string text, Action click)
    {
        var t = new TextBlock { Text = text, Foreground = Palette.LinkBrush, TextDecorations = TextDecorations.Underline, Cursor = new Cursor(StandardCursorType.Hand) };
        t.PointerReleased += (_, e) => { if (e.InitialPressMouseButton == MouseButton.Left) click(); };
        return new InlineUIContainer(t) { BaselineAlignment = BaselineAlignment.TextBottom };
    }

    /// <summary>Appends a clickable link with friendly text.</summary>
    private void WriteLink(string text, Action click)
    {
        _info.Inlines!.Add(LinkInline(text, click));
        _info.Inlines.Add(new LineBreak());
        DebugLog.Ui($"[link] {text}");
    }

    private void Line(string text = "", IBrush? color = null, bool bold = false) => Write(text + "\n", color, bold);

    private void ClearInfo() => _info.Inlines!.Clear();

    private void Log(LogKind kind, string text)
    {
        if (!Dispatcher.UIThread.CheckAccess()) { Dispatcher.UIThread.Post(() => Log(kind, text)); return; }
        switch (kind)
        {
            case LogKind.Step: Line(text, Palette.StepBrush, true); break;
            case LogKind.Warning: Line(text, Palette.WarningBrush); break;
            case LogKind.Error: Line(text, Palette.ErrorBrush, true); break;
            case LogKind.Success: Line(text, Palette.SuccessBrush, true); break;
            default: Line(text, Palette.DimBrush); break;
        }
    }

    private void ShowStartPage()
    {
        ClearInfo();
        Write(AppName, bold: true);
        Line($" {AppVersion} {Platform.Arch} recovers passwords for:");
        Line();
        foreach (var s in new[]
                 {
                     "MS Office 97-2021 documents (Word, Excel, PowerPoint);",
                     "OpenOffice / LibreOffice / OpenDocument files;",
                     "ZIP/WinZip archives and RAR 3.x-5.x archives;",
                     "Adobe PDF 1.2-1.7 documents;",
                     "Apple iOS / iTunes backups (open the backup's Manifest.plist);",
                     "BlackBerry .ipd backups (detection only; no hashcat kernel);",
                     "TrueCrypt and VeraCrypt volumes (File > Open As);",
                     "WPA/WPA2 handshakes (.22000, .hccapx, .hccap);",
                     "any other hash supported by hashcat (File > Open As).",
                 })
            Line("  • " + s);
        Line();
        Line("Main features are:");
        foreach (var s in new[]
                 {
                     Platform.IsMac
                         ? "GPU acceleration on Apple silicon (Metal and OpenCL), and a CPU engine tuned for its NEON and crypto instructions"
                         : "GPU acceleration on a wide range of GPUs: NVIDIA (CUDA/OpenCL), AMD (HIP/OpenCL) and Intel Arc (OpenCL)",
                     "Several types of attacks: brute-force, brute-force with extended mask, and dictionary based ones",
                     "Automated password recovery with predefined and user-defined scenarios",
                     "User-defined sets of mutation rules for dictionary attacks and multi-word combinations",
                     "Supports Unicode, UTF-8 and ANSI dictionaries",
                     "Interrupted attacks can be continued later; recovered passwords are cached",
                     "After a successful attack the document can be decrypted automatically (MS Office)",
                 })
            Line("  • " + s);
        Line();
        Line($"Open a protected file with File > Open ({Platform.Shortcut("O")}) or drag and drop it here.", Palette.DimBrush);
    }

    // ------------------------------------------------------------------ hashcat

    private async Task InitHashcatAsync()
    {
        await PrepareBundledHashcatAsync();
        _hashcat = HashcatTool.Locate(_settings.HashcatPath);
        SetRunning(_cts is not null);
        if (_hashcat is null)
        {
            _statusLeft.Text = "hashcat not found";
            Line();
            Line("hashcat was not found.", Palette.ErrorBrush, true);
            Line((Platform.IsMac ? "Use Tools > Install hashcat" : "Use Tools > Download hashcat") + " to set it up automatically, or set its location in " +
                 (Platform.IsMac ? "RecoverKit > Settings > Files and Paths." : "Options > Preferences > Files and Paths."), Palette.DimBrush);
            Dispatcher.UIThread.Post(() => _ = OfferHashcatDownloadAsync());
            return;
        }
        _hashcat.MaxCpuThreads = _settings.MaxCpuThreads;
        DebugLog.Info($"hashcat: {_hashcat.Exe}");
        DebugLog.LogSettings(_settings);
        try
        {
            _hashcatVersion = await _hashcat.VersionAsync();
            _statusLeft.Text = $"© {DateTime.Now.Year} {AppName} contributors  |  hashcat {_hashcatVersion}";
            _statusRight.Text = "Detecting GPUs...";
            _devices = await _hashcat.DevicesAsync();
            var usable = _devices.Where(d => !d.IsSkippedAlias).ToList();
            var gpus = usable.Where(d => d.Type.Contains("GPU", StringComparison.OrdinalIgnoreCase)).ToList();
            bool cpu = usable.Any(d => d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase));
            _statusRight.Text = _deviceStatus = gpus.Count switch
            {
                1 => gpus[0].Name + (gpus[0].Backend.Length > 0 ? $" ({gpus[0].Backend})" : ""),
                > 1 => $"{gpus.Count} GPU devices",
                _ => cpu ? "No GPU detected, using CPU" : "No GPU detected",
            };
            Line();
            if (gpus.Count == 0 && cpu)
                Line("No compatible GPU devices detected. Passwords are recovered on the processor " +
                     $"({(_settings.MaxCpuThreads > 0 ? _settings.MaxCpuThreads : Environment.ProcessorCount)} threads).", Palette.DimBrush);
            else if (gpus.Count == 0) NoDevicesNotice();
            foreach (var d in usable)
                Line($"Device #{d.Id}: {d.Name} ({d.Backend}{(d.Processors > 0 ? $", {d.Processors} compute units" : "")}{(d.MemoryMb > 0 ? $", {d.MemoryMb} MB" : "")})"
                     + (_settings.DisabledDevices.Contains(d.Id) ? " - disabled" : ""), Palette.DimBrush);
        }
        catch (Exception ex) when (ex is TimeoutException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            _statusRight.Text = "hashcat error";
            Line("Cannot run hashcat: " + ex.Message, Palette.ErrorBrush);
        }
    }

    /// <summary>
    /// macOS: hashcat ships inside the app bundle and is copied to the user's engines folder
    /// (it writes kernel caches next to itself, and the signed bundle must stay unmodified).
    /// </summary>
    private async Task PrepareBundledHashcatAsync()
    {
        if (HashcatInstaller.BundledDirectory is null || !new HashcatInstaller().BundleNeedsInstall()) return;
        _statusLeft.Text = $"Preparing hashcat {HashcatInstaller.Version}...";
        var progress = new Progress<InstallProgress>(p =>
        {
            if (p.BytesTotal > 0) _statusLeft.Text = $"Preparing hashcat {HashcatInstaller.Version}... {p.Fraction:P0}";
        });
        bool ok = await Task.Run(() => HashcatInstaller.TryInstallBundled(progress));
        DebugLog.Info(ok ? "Bundled hashcat copied to the engines folder" : "Bundled hashcat could not be copied");
    }

    private void AutoDecrypt(Detection det, string password)
    {
        var t = det.Target!;
        if (!OfficeDecryptor.CanDecrypt(t.FormatId))
        {
            Line($"Automatic decryption is available for MS Office 2007-2021 documents; {t.FormatName} is not supported.", Palette.DimBrush);
            return;
        }
        try
        {
            var dir = Path.GetDirectoryName(det.FilePath) ?? ".";
            var name = Path.GetFileNameWithoutExtension(det.FilePath);
            var ext = Path.GetExtension(det.FilePath);
            var outPath = Path.Combine(dir, name + _settings.DecryptSuffix + ext);
            OfficeDecryptor.DecryptToFile(det.FilePath, password, outPath);
            Log(LogKind.Success, $"Document decrypted and saved to: {outPath}");
        }
        catch (Exception ex) when (ex is UnsupportedFormatException or IOException or FormatException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            Log(LogKind.Warning, "Automatic decryption failed: " + ex.Message);
        }
    }

    private async Task<bool> RequireHashcatAsync()
    {
        if (_hashcat is not null) return true;
        if (await Msg.Ask(this, Platform.IsMac ? "hashcat was not found. Install it now?" : "hashcat was not found. Download it now?"))
            await DownloadHashcatAsync();
        return _hashcat is not null;
    }

    private bool _offeredDownload;

    /// <summary>On first start without hashcat, offer a one-click download.</summary>
    private async Task OfferHashcatDownloadAsync()
    {
        if (_offeredDownload || _hashcat is not null || _busyDialog) return;
        _offeredDownload = true;
        if (await Msg.Ask(this, $"hashcat (the GPU engine) was not found.\n\n{(Platform.IsMac ? "Install" : "Download")} hashcat {HashcatInstaller.Version} now?"))
            await DownloadHashcatAsync();
    }

    private async Task DownloadHashcatAsync()
    {
        if (_busyDialog) return;
        _busyDialog = true;
        string? exe;
        try { exe = await HashcatDownloadWindow.RunAsync(this); }
        finally { _busyDialog = false; }
        if (exe is null) return;
        _settings.HashcatPath = exe;
        _settings.Save();
        // Redraw the start page so the stale "hashcat was not found" notice disappears.
        if (_current is null) ShowStartPage();
        await InitHashcatAsync();
    }

    /// <summary>hashcat found no OpenCL/CUDA/HIP/Metal device at all (typically: no GPU driver installed).</summary>
    private void NoDevicesNotice()
    {
        if (CpuRuntime.BlockedByElevation)
        {
            Line("No compatible devices detected. RecoverKit is running as administrator, and Windows does not let an " +
                 "administrator process load the per-user CPU runtime. Start RecoverKit normally to recover passwords on the processor.",
                 Palette.WarningBrush);
            return;
        }
        if (!CpuRuntime.IsSupportedPlatform)
        {
            Line("No compatible devices detected. The built-in CPU engine still works for the formats it supports.", Palette.WarningBrush);
            return;
        }
        Line("No compatible GPU devices detected. Install the NVIDIA, AMD or Intel graphics driver, or use the processor: " +
             "Tools > Download CPU runtime (OpenCL).", Palette.WarningBrush);
        Dispatcher.UIThread.Post(() => _ = OfferCpuRuntimeAsync(force: false));
    }

    private bool _offeredCpuRuntime;

    private async Task OfferCpuRuntimeAsync(bool force)
    {
        if (!CpuRuntime.IsSupportedPlatform || CpuRuntime.Locate() is not null || (_offeredCpuRuntime && !force) || _busyDialog) return;
        _offeredCpuRuntime = true;
        if (await Msg.Ask(this, "No GPU driver was found, so hashcat has no device to run on.\n\n" +
                                "Download Intel's CPU runtime to recover passwords on the processor?"))
            await DownloadCpuRuntimeAsync();
    }

    private async Task DownloadCpuRuntimeAsync()
    {
        if (_cts is not null || _busyDialog) return;
        if (!CpuRuntime.IsSupportedPlatform)
        {
            await Warn("The CPU runtime download is for Windows. On Linux install PoCL; macOS needs no extra runtime.");
            return;
        }
        _busyDialog = true;
        bool ok;
        try { ok = await CpuRuntimeDownloadWindow.RunAsync(this); }
        finally { _busyDialog = false; }
        if (!ok) return;
        if (_current is null) ShowStartPage();
        await InitHashcatAsync();
    }

    // ------------------------------------------------------------------ tools

    private async Task ShowRulesEditorAsync()
    {
        if (!await RequireHashcatAsync()) return;
        new RulesEditorWindow(_hashcat!, _settings).Show(this);
    }

    private async Task ShowBenchmarkAsync()
    {
        if (_busyDialog || _cts is not null || !await RequireHashcatAsync()) return;
        _busyDialog = true;
        try { await new BenchmarkWindow(_hashcat!, _settings, _devices).ShowDialog(this); }
        finally { _busyDialog = false; }
    }

    // ------------------------------------------------------------------ generators

    /// <summary>File &gt; Dictionary Generator / WPA-PMK Generator: write an attack's candidates (or their PMKs) to a file.</summary>
    private async Task RunGeneratorAsync(WizardMode mode)
    {
        if (_cts is not null || _busyDialog || !await RequireHashcatAsync()) return;
        bool pmk = mode == WizardMode.PmkGenerator;
        var target = new HashTarget
        {
            FormatId = pmk ? "WPAH" : "NONE",
            FormatName = pmk ? "WPA-PMK Generator" : "Dictionary Generator",
            Protection = "",
            Modes = [0],
            HashLines = "",
            MaxPasswordLength = pmk ? 63 : 256,
        };
        var ctx = new PlannerContext { DataPath = _settings.DataPath, HashcatDir = _hashcat!.Directory, DefaultDictionary = _settings.DefaultDictionary };
        var w = new WizardWindow(target, "", LoadScenarios(), _settings, ctx, _hashcat, mode);
        _busyDialog = true;
        bool ok;
        try { ok = await w.ShowDialog<bool>(this) && w.Steps.Count > 0; }
        finally { _busyDialog = false; }
        if (!ok) return;

        var prepared = new List<PreparedAttack>();
        BigInteger total = 0;
        foreach (var spec in w.Steps)
        {
            try { var pa = AttackPlanner.Prepare(spec, target, ctx); prepared.Add(pa); total += pa.Keyspace; }
            catch (AttackPlanException ex) { Log(LogKind.Warning, $"{spec.Describe()}: skipped, {ex.Message}"); }
        }
        if (prepared.Count == 0) return;
        double gb = (double)total * (pmk ? 75 : 10) / 1e9;
        if (total > 500_000_000 && !await Msg.Ask(this,
                $"This writes about {total:N0} {(pmk ? "PMKs" : "words")} (roughly {gb:N1} GB{(pmk ? ", PMK computation is slow" : "")}).\n\nContinue?",
                icon: MsgIcon.Warning)) return;

        _cts = new CancellationTokenSource();
        SetRunning(true);
        ResetStatus();
        Line();
        Line(pmk ? $"WPA-PMK Generator: SSID \"{w.Ssid}\", {prepared.Count} step(s) -> {w.ResultFile}"
                 : $"Dictionary Generator: {prepared.Count} step(s), {w.OutputEncoding} -> {w.ResultFile}", bold: true);
        DebugLog.Info($"Generator {mode}: {prepared.Count} step(s), keyspace {total}, file {w.ResultFile}");
        var started = DateTime.Now;
        var progress = new Progress<long>(n =>
        {
            double secs = Math.Max(0.5, (DateTime.Now - started).TotalSeconds);
            _curPassword.Text = $"{Fmt.Count(n)} of {Fmt.Count(total)}";
            _avgSpeed.Text = Fmt.Speed(n / secs);
            _progress.Value = total > 0 ? Math.Clamp((double)n / (double)total * 1000, 0, 1000) : 0;
        });
        try
        {
            int threads = _settings.MaxCpuThreads > 0 ? _settings.MaxCpuThreads : Environment.ProcessorCount;
            var token = _cts.Token;
            long n = pmk
                ? await Task.Run(() => CandidateExport.WritePmkTableAsync(prepared, _hashcat!, w.ResultFile, w.Ssid, threads, progress, token))
                : await Task.Run(() => CandidateExport.WriteDictionaryAsync(prepared, _hashcat!, w.ResultFile, CandidateExport.EncodingFor(w.OutputEncoding), progress, token));
            Log(LogKind.Success, pmk ? $"PMK table saved: {w.ResultFile} ({n:N0} PMKs). Use it as the dictionary for WPA handshakes of \"{w.Ssid}\"."
                                     : $"Dictionary saved: {w.ResultFile} ({n:N0} words).");
        }
        catch (OperationCanceledException) { Log(LogKind.Warning, "Generation stopped by user; the file contains the candidates written so far."); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            Log(LogKind.Error, "Generation failed: " + ex.Message);
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            SetRunning(false);
        }
    }

    // ------------------------------------------------------------------ open

    private async void OpenDialog()
    {
        if (_cts is not null || _busyDialog) return;
        var path = await Pick.Open(this, string.Join('|', FormatDetector.OpenFilter), _settings.LastOpenedDirectory);
        if (path is not null) await OpenFileAsync(path);
    }

    private async void OpenAsDialog()
    {
        if (_cts is not null || _busyDialog) return;
        _busyDialog = true;
        Detection? det;
        try { det = await OpenAsWindow.RunAsync(this, _settings); }
        finally { _busyDialog = false; }
        if (det is not null) await ShowDetectionAsync(det);
    }

    private async Task OpenFileAsync(string path)
    {
        if (_cts is not null) { await Warn("Stop the current attack first."); return; }
        if (_busyDialog) return;
        _settings.LastOpenedDirectory = Path.GetDirectoryName(path);
        Cursor = new Cursor(StandardCursorType.Wait);
        Detection det;
        try { det = await Task.Run(() => FormatDetector.Detect(path)); }
        finally { Cursor = Cursor.Default; }
        await ShowDetectionAsync(det);
    }

    private async Task ShowDetectionAsync(Detection det)
    {
        _current = det;
        DebugLog.Info($"Detected {det.FilePath}: type={det.TypeName}, format={det.Target?.FormatId}, modes={string.Join(",", det.Target?.Modes ?? [])}, " +
                      $"protection={det.Target?.Protection}, message={det.Message}");
        foreach (var kv in det.Info) DebugLog.Info($"  {kv.Key}: {kv.Value}");
        DebugLog.IncludeHashes = _settings.DebugLogIncludeHashes;
        DebugLog.RegisterHashes(det.Target?.HashLines);
        if (det.Target?.HashLines is { Length: > 0 } hl)
            // Only the full hash is masked by the log, so a truncated one must never be written unless asked for.
            DebugLog.Info(_settings.DebugLogIncludeHashes
                ? "  extracted hash: " + (hl.Length > 4000 ? hl[..4000] + $"... ({hl.Length} chars)" : hl)
                : $"  extracted hash: <{hl.Length} chars>  (enable \"Include extracted hashes\" in Preferences > Other to log it)");
        Title = $"{AppName} - {Path.GetFileName(det.FilePath)}";
        ClearInfo();
        ResetStatus();
        void Row(string k, string v) { Write(k + "  ", Palette.DimBrush); Line(v, bold: true); }
        Row("File:", det.FilePath);
        Row("Type:", det.TypeName);
        if (det.Target is { } t)
        {
            Row("Protection:", t.Protection);
            Row("Recovery speed:", Fmt.SpeedClass(t.Speed));
            Row("hashcat mode:", string.Join(", ", t.Modes));
            if (t.MaxPasswordLength is int ml) Row("Maximum supported password length:", ml.ToString());
        }
        foreach (var kv in det.Info) Row(kv.Key + ":", kv.Value);
        Line();
        if (det.Target is null)
        {
            Line(det.Message ?? "Nothing to attack.", Palette.WarningBrush, true);
            SetRunning(false);
            return;
        }
        Line("File is password protected to open.", bold: true);
        if (det.Target.Notes is { } notes) Line(notes, Palette.DimBrush);
        SetRunning(false);

        if (!await RequireHashcatAsync()) return;
        var saved = SessionState.Load(_settings, det.Target);
        if (saved is not null)
        {
            var r = await Msg.Show(this,
                $"Attack was interrupted ({saved.SavedUtc.ToLocalTime():g}, step {saved.StepIndex + 1} of {saved.Steps.Count}).\n\nContinue the interrupted attack?\n(No starts a new attack.)",
                AppName, MsgButtons.YesNoCancel, MsgIcon.Question);
            if (r == MsgResult.Yes) { await RunAsync(saved.Steps, saved); return; }
            if (r != MsgResult.No) return;
            SessionState.Delete(_settings, saved.Key);
        }
        StartWizard();
    }

    // ------------------------------------------------------------------ attack

    private async void StartWizard()
    {
        if (_cts is not null || _busyDialog || _current?.Target is null) return;
        if (!await RequireHashcatAsync()) return;
        var scenarios = LoadScenarios();
        var w = new WizardWindow(_current.Target, _current.FilePath, scenarios, _settings, new PlannerContext
        {
            DataPath = _settings.DataPath, HashcatDir = _hashcat!.Directory, DefaultDictionary = _settings.DefaultDictionary,
        }, _hashcat);
        _busyDialog = true;
        bool ok;
        try { ok = await w.ShowDialog<bool>(this) && w.Steps.Count > 0; }
        finally { _busyDialog = false; }
        DebugLog.Info(ok ? $"Wizard finished with {w.Steps.Count} step(s): " + string.Join(" | ", w.Steps.Select(s => s.Describe())) : "Wizard cancelled");
        if (ok) await RunAsync(w.Steps, null);
    }

    private List<Scenario> LoadScenarios()
    {
        if (_settings.UseExternalScenarioFile && File.Exists(_settings.ExternalScenarioFile))
        {
            try
            {
                var list = ScenarioParser.LoadFile(_settings.ExternalScenarioFile!, out var errors);
                foreach (var e in errors) Log(LogKind.Warning, e);
                if (list.Count > 0) return list;
            }
            catch (IOException ex) { Log(LogKind.Warning, ex.Message); }
            Log(LogKind.Warning, "Warning! Cannot load external scenario file, using built-in scenarios.");
        }
        return ScenarioParser.LoadDefault();
    }

    private async Task RunAsync(IReadOnlyList<AttackSpec> steps, SessionState? resume)
    {
        var det = _current!;
        var target = det.Target!;
        _cts = new CancellationTokenSource();
        SetRunning(true);
        ResetStatus();
        Line();
        Line(resume is null ? "Attack started." : "Continuing interrupted attack.", bold: true);
        if (_settings.PreventScreensaver) Platform.KeepAwake(true);

        var session = new RecoverySession(_hashcat!, _settings) { Devices = _devices };
        session.Log += (k, m) => Log(k, m);
        session.StepStarted += (i, n, desc, ks) => Dispatcher.UIThread.Post(() =>
        {
            _stepStarted = DateTime.Now;
            _stepKeyspace = ks;
            _progress.Value = 0;
            _curPassword.Text = "starting...";
        });
        session.Status += s => Dispatcher.UIThread.Post(() => UpdateStatus(s));

        SessionResult result;
        var token = _cts.Token;
        try
        {
            result = await Task.Run(() => session.RunAsync(target, det.FilePath, steps, resume, token));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            result = new SessionResult { Outcome = SessionOutcome.Error, Error = ex.Message };
        }
        finally
        {
            Platform.KeepAwake(false);
            Title = $"{AppName} - {Path.GetFileName(det.FilePath)}";
            _statusRight.Text = _deviceStatus;
            _cts.Dispose();
            _cts = null;
            SetRunning(false);
            _settings.Save();
        }
        if (_closeConfirmed) return;   // the window is closing; nothing more to show

        switch (result.Outcome)
        {
            case SessionOutcome.Found:
            case SessionOutcome.FoundInCache:
                _progress.Value = _progress.Maximum;
                if (_curPassword.Text == "starting...") _curPassword.Text = "";
                Line();
                Log(LogKind.Success, result.Outcome == SessionOutcome.FoundInCache ? "Previously recovered password(s):" : "Password found:");
                foreach (var p in result.Passwords) Write((p.Length == 0 ? "(empty)" : p) + "\n", Palette.SuccessBrush, true, 18, log: false);
                DebugLog.Info($"Outcome {result.Outcome}: {result.Passwords.Count} password(s), lengths " + string.Join(",", result.Passwords.Select(x => x.Length)));
                if (result.Passwords.Count > 0)
                {
                    if (await CopyAsync(result.Passwords[0])) Line("Password copied to the clipboard.", Palette.DimBrush);
                    await PasswordFoundWindow.RunAsync(this, result.Passwords);
                }
                if (result.Key is { } k1)
                {
                    Write("Encryption key: ", Palette.DimBrush);
                    Write(k1, Palette.DimBrush, log: false);
                    Line(" (found by key search; the password above derives the same key, so it opens the document).", Palette.DimBrush);
                }
                if (result.Outcome == SessionOutcome.FoundInCache) WriteLink("Clear password cache", ClearPasswordCacheForCurrent);
                if (_settings.AutoDecrypt && result.Outcome == SessionOutcome.Found && result.Passwords.Count > 0)
                    AutoDecrypt(det, result.Passwords[0]);
                Execute(_settings.ExecuteOnSuccess);
                break;
            case SessionOutcome.KeyRecovered:
                Line();
                Write("Encryption key recovered: ", Palette.SuccessBrush, true);
                Write((result.Key ?? "") + "\n", Palette.SuccessBrush, true, log: false);
                Line("No password of up to 8 printable characters derives this key. The key is kept in the key cache; " +
                     "a longer equivalent password can be searched by running the key search again with a GPU.", Palette.DimBrush);
                Execute(_settings.ExecuteOnSuccess);
                break;
            case SessionOutcome.NotFound:
                ResetStatus();
                Line();
                Log(LogKind.Warning, "The whole range of passwords defined by the attack settings was checked, but the password was not found. " +
                                     "Extend the range by changing the attack settings.");
                Execute(_settings.ExecuteOnFail);
                break;
            case SessionOutcome.Stopped:
                ResetStatus();
                Line();
                Log(LogKind.Warning, "Attack was interrupted by user. Open the same file again to continue it.");
                break;
            default:
                ResetStatus();
                Line();
                Log(LogKind.Error, "Attack was interrupted because of an error: " + result.Error);
                Execute(_settings.ExecuteOnFail);
                if (result.Error?.Contains("No OpenCL, HIP or CUDA compatible platform", StringComparison.OrdinalIgnoreCase) == true)
                    Dispatcher.UIThread.Post(() => _ = OfferCpuRuntimeAsync(force: true));
                break;
        }
    }

    private async Task<bool> CopyAsync(string text)
    {
        try
        {
            if (Clipboard is null) return false;
            await Clipboard.SetTextAsync(text);
            return true;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.ExternalException)
        {
            DebugLog.Warn("Clipboard: " + ex.Message);
            return false;
        }
    }

    private void StopAttack()
    {
        if (_cts is null) return;
        Line("Please wait while stopping attack...", Palette.DimBrush);
        _cts.Cancel();
    }

    private void UpdateStatus(HashcatStatus s)
    {
        double speed = s.TotalSpeed;
        _curSpeed.Text = Fmt.Speed(speed);
        double elapsed = s.TimeStart > 0 ? DateTimeOffset.UtcNow.ToUnixTimeSeconds() - s.TimeStart : (DateTime.Now - _stepStarted).TotalSeconds;
        _avgSpeed.Text = elapsed > 1 ? Fmt.Speed((s.ProgressDone - s.ResumedFrom) / elapsed) : Fmt.Speed(speed);
        long remaining = Math.Max(0, s.ProgressTotal - s.ProgressDone);
        _estTime.Text = s.Status == 3 && speed > 0 ? Fmt.Duration(remaining / speed) : s.StatusText;
        _curPassword.Text = s.MaskLength is int ml && ml > 0
            ? $"{ml} symbol(s), {Fmt.Count(s.ProgressDone)} of {Fmt.Count(s.ProgressTotal)}"
            : $"{Fmt.Count(s.ProgressDone)} of {Fmt.Count(s.ProgressTotal)} ({s.Fraction:P1})";
        _progress.Value = Math.Clamp(s.Fraction * 1000, 0, 1000);
        if (_current is not null) Title = $"{(int)(s.Fraction * 100)}% - {AppName} - {Path.GetFileName(_current.FilePath)}";
        var temps = s.Devices.Where(d => d.Temperature > 0).Select(d => $"{d.Temperature}°C").ToList();
        _statusRight.Text = $"{s.StatusText}{(temps.Count > 0 ? "  " + string.Join(" ", temps) : "")}";
    }

    private void ResetStatus()
    {
        foreach (var l in new[] { _curPassword, _estTime, _curSpeed, _avgSpeed }) l.Text = "";
        _progress.Value = 0;
    }

    private void SetRunning(bool running)
    {
        bool canStart = !running && _current?.Target is not null && _hashcat is not null;
        _tbStart.IsEnabled = _miStart.IsEnabled = canStart;
        _tbStop.IsEnabled = _miStop.IsEnabled = running;
        foreach (var m in _idleOnly) m.IsEnabled = !running;
    }

    private void Execute(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try { Platform.Shell(path); }
        catch (System.ComponentModel.Win32Exception ex) { Log(LogKind.Warning, $"Cannot execute {path}: {ex.Message}"); }
    }

    // ------------------------------------------------------------------ dialogs

    internal async void ShowPreferences(int tab)
    {
        if (_cts is not null || _busyDialog) return;
        _busyDialog = true;
        var f = new PreferencesWindow(_settings, _hashcat, _devices, tab);
        bool ok;
        try { ok = await f.ShowDialog<bool>(this); }
        finally { _busyDialog = false; }
        if (!ok) return;
        _settings.Save();
        DebugLog.Info("Preferences changed");
        DebugLog.LogSettings(_settings);
        if (_hashcat is not null) _hashcat.MaxCpuThreads = _settings.MaxCpuThreads;
        if (f.HashcatChanged) await InitHashcatAsync();
    }

    private async Task ShowHelpAsync()
    {
        var readme = Path.Combine(AppContext.BaseDirectory, "README.html");
        if (File.Exists(readme)) { Platform.Shell(readme); return; }
        await Msg.Show(this,
            $"1. Open a protected file (File > Open, {Platform.Shortcut("O")}, or drag & drop).\n" +
            "2. Choose an attack in the Password Recovery Wizard: a scenario, brute-force, brute-force with extended mask, or dictionary.\n" +
            "3. Watch progress in the status pane; Stop interrupts and the attack can be continued later.\n\n" +
            "TrueCrypt/VeraCrypt volumes and raw hashes: File > Open As.\n" +
            $"GPU selection and workload: Options > GPU Configuration ({Platform.Shortcut("G")}).\n\n" +
            "More: https://github.com/007hacky007/RecoverKit",
            "Help", MsgButtons.Ok, MsgIcon.Info);
    }

    private static readonly string[] TrustedHosts = ["github.com", "hashcat.net", "www.intel.com", "intel.com", "files.pythonhosted.org", "www.7-zip.org"];

    internal static bool IsTrustedLink(string link) =>
        Uri.TryCreate(link.Trim(), UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps
        && TrustedHosts.Contains(u.Host, StringComparer.OrdinalIgnoreCase);

    /// <summary>Removes this file's entries from the password cache (hashcat potfile).</summary>
    private async void ClearPasswordCacheForCurrent()
    {
        if (_current?.Target is not { } t || !File.Exists(_settings.PotfilePath)) return;
        var hashes = t.HashLines.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(h => h.Trim() + ":").ToList();
        try
        {
            var lines = File.ReadAllLines(_settings.PotfilePath);
            var keep = lines.Where(l => !hashes.Any(h => l.StartsWith(h, StringComparison.OrdinalIgnoreCase))).ToArray();
            File.WriteAllLines(_settings.PotfilePath, keep);
            DebugLog.Info($"Password cache: removed {lines.Length - keep.Length} entr(ies) for {t.FormatId}");
            Line($"Password cache cleared for this file ({lines.Length - keep.Length} entr{(lines.Length - keep.Length == 1 ? "y" : "ies")}).", Palette.DimBrush);
        }
        catch (IOException ex) { await Warn("Cannot clear the password cache: " + ex.Message); }
    }

    /// <summary>Help &gt; Check for updates: asks the project's GitHub releases (only when clicked).</summary>
    internal async Task CheckForUpdatesAsync()
    {
        const string api = "https://api.github.com/repos/007hacky007/RecoverKit/releases/latest";
        const string title = "Check for updates";
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("RecoverKit/1.0");
            http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            using var resp = await http.GetAsync(api);
            DebugLog.Info($"Update check: HTTP {(int)resp.StatusCode}");
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                await Msg.Info(this, $"No RecoverKit releases are published yet. You are using version {AppVersion}.", title);
                return;
            }
            resp.EnsureSuccessStatusCode();
            using var doc = System.Text.Json.JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            string tag = doc.RootElement.GetProperty("tag_name").GetString() ?? "";
            string url = doc.RootElement.TryGetProperty("html_url", out var u) ? u.GetString() ?? "" : "";
            bool newer = Version.TryParse(tag.TrimStart('v', 'V'), out var latest) && Version.TryParse(AppVersion, out var mine) && latest > mine;
            if (!newer)
                await Msg.Info(this, $"You are using the latest version ({AppVersion}).", title);
            else if (await Msg.Ask(this, $"RecoverKit {tag} is available (you have {AppVersion}).\n\nOpen the download page?", title)
                     && url.StartsWith("https://github.com/", StringComparison.Ordinal))
                Platform.Shell(url);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException or KeyNotFoundException)
        {
            DebugLog.Warn("Update check failed: " + ex.Message);
            await Msg.Warn(this, "Could not check for updates: " + ex.Message, title);
        }
    }

    private static void OpenLogFolder()
    {
        Directory.CreateDirectory(DebugLog.Directory);
        if (DebugLog.CurrentFile is { } f && File.Exists(f)) Platform.Reveal(f);
        else Platform.Shell(DebugLog.Directory);
    }

    internal void ShowAbout() => _ = Msg.Show(this,
        $"{AppName} {AppVersion} {Platform.Arch}\n\nGPU accelerated password recovery front-end.\n" +
        $"Password verification engine: hashcat {(_hashcatVersion.Length > 0 ? _hashcatVersion : "(not found)")} (MIT license, https://hashcat.net)\n\n" +
        "Use only on files you own or are authorized to recover.",
        $"About {AppName}", MsgButtons.Ok, MsgIcon.Info);

    private Task<MsgResult> Warn(string text) => Msg.Warn(this, text);

    private async void OnClosing(object? sender, WindowClosingEventArgs e)
    {
        if (_cts is not null && !_closeConfirmed)
        {
            e.Cancel = true;
            if (!await Msg.Ask(this, "An attack is running. Stop it and exit?\n(It can be continued later.)")) return;
            _closeConfirmed = true;
            _cts?.Cancel();
            for (int i = 0; i < 100 && _cts is not null; i++) await Task.Delay(100);
            Close();
            return;
        }
        if (WindowState == WindowState.Normal) _settings.WindowBounds = [Position.X, Position.Y, (int)Width, (int)Height];
        _settings.Save();
    }

    /// <summary>A tiny ICommand for key bindings.</summary>
    private sealed class Relay(Action run) : System.Windows.Input.ICommand
    {
        public event EventHandler? CanExecuteChanged { add { } remove { } }
        public bool CanExecute(object? parameter) => true;
        public void Execute(object? parameter) => run();
    }
}
