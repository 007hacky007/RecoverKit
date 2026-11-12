using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Forms;

/// <summary>
/// Main window: menu (1), toolbar (2), information pane (3), status pane (4) and status bar,
/// following the classic single-document password-recovery layout.
/// </summary>
public sealed class MainForm : Form
{
    public const string AppName = "RecoverKit";
    public static readonly string AppVersion = typeof(MainForm).Assembly.GetName().Version?.ToString(3) ?? "1.0";

    private readonly Settings _settings = Settings.Load();
    private HashcatTool? _hashcat;
    private List<BackendDevice> _devices = new();
    private string _hashcatVersion = "";
    private string _deviceStatus = "";   // right status pane text between attacks

    private readonly RichTextBox _info = new() { ReadOnly = true, BorderStyle = BorderStyle.None, BackColor = SystemColors.Window, DetectUrls = true, Dock = DockStyle.Fill, Font = new Font("Segoe UI", 9.5f) };
    private readonly Label _curPassword = Value(), _estTime = Value(), _curSpeed = Value(), _avgSpeed = Value();
    private readonly ProgressBar _progress = new() { Dock = DockStyle.Fill, Height = 16, Maximum = 1000 };
    private readonly ToolStripStatusLabel _statusLeft = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly ToolStripStatusLabel _statusRight = new() { BorderSides = ToolStripStatusLabelBorderSides.Left, AutoSize = true };
    private ToolStripButton _tbStart = null!, _tbStop = null!;
    private ToolStripMenuItem _miStart = null!, _miStop = null!;

    private Detection? _current;
    private CancellationTokenSource? _cts;
    private DateTime _stepStarted;
    private BigInteger _stepKeyspace;

    public MainForm(string? fileToOpen)
    {
        Text = AppName;
        Icon = Icons.AppIcon();
        Font = new Font("Segoe UI", 9f);
        AllowDrop = true;
        MinimumSize = new Size(560, 420);
        Size = new Size(640, 480);
        StartPosition = FormStartPosition.CenterScreen;
        if (_settings.WindowBounds is { Length: 4 } wb)
        {
            StartPosition = FormStartPosition.Manual;
            Bounds = new Rectangle(wb[0], wb[1], wb[2], wb[3]);
        }

        BuildMenu();
        var toolbar = BuildToolbar();
        var infoHost = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8, 6, 4, 4), BackColor = SystemColors.Window, BorderStyle = BorderStyle.Fixed3D };
        infoHost.Controls.Add(_info);
        var statusPane = BuildStatusPane();
        var statusStrip = new StatusStrip { SizingGrip = true };
        statusStrip.Items.AddRange([_statusLeft, _statusRight]);

        Controls.Add(infoHost);
        Controls.Add(statusPane);
        Controls.Add(toolbar);
        Controls.Add(MainMenuStrip!);
        Controls.Add(statusStrip);

        _info.LinkClicked += (_, e) =>
        {
            if (e.LinkText is not { } l) return;
            if (l.Contains(ClearCacheLink, StringComparison.Ordinal)) ClearPasswordCacheForCurrent();
            else Shell(l);
        };
        DragEnter += (_, e) => e.Effect = e.Data?.GetDataPresent(DataFormats.FileDrop) == true ? DragDropEffects.Copy : DragDropEffects.None;
        DragDrop += (_, e) =>
        {
            if (e.Data?.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
            {
                if (files.Length > 1) { Warn("Cannot process multiple files at once, please drop only one at a time."); return; }
                _ = OpenFileAsync(files[0]);
            }
        };
        Shown += async (_, _) =>
        {
            await InitHashcatAsync();
            if (fileToOpen is not null) await OpenFileAsync(fileToOpen);
        };
        FormClosing += OnClosing;
        SetRunning(false);
        ShowStartPage();
    }

    private static Label Value() => new() { AutoSize = true, Font = new Font("Segoe UI", 9f, FontStyle.Bold), Anchor = AnchorStyles.Left };

    // ------------------------------------------------------------------ layout

    private void BuildMenu()
    {
        var ms = new MenuStrip();
        var file = new ToolStripMenuItem("&File");
        file.DropDownItems.Add(new ToolStripMenuItem("&Open ...", null, (_, _) => OpenDialog(), Keys.Control | Keys.O));
        file.DropDownItems.Add(new ToolStripMenuItem("Open &As ...", null, (_, _) => OpenAsDialog()));
        file.DropDownItems.Add(new ToolStripMenuItem("&WPA-PMK Generator", null, async (_, _) => await RunGeneratorAsync(WizardMode.PmkGenerator)));
        file.DropDownItems.Add(new ToolStripMenuItem("&Dictionary Generator", null, async (_, _) => await RunGeneratorAsync(WizardMode.DictionaryGenerator)));
        file.DropDownItems.Add(new ToolStripSeparator());
        file.DropDownItems.Add(new ToolStripMenuItem("E&xit", null, (_, _) => Close()));

        var rec = new ToolStripMenuItem("&Recovery");
        _miStart = new ToolStripMenuItem("&Start", null, (_, _) => StartWizard(), Keys.F5);
        _miStop = new ToolStripMenuItem("S&top", null, (_, _) => StopAttack(), Keys.Shift | Keys.F5);
        rec.DropDownItems.AddRange([_miStart, _miStop]);

        var opt = new ToolStripMenuItem("&Options");
        opt.DropDownItems.Add(new ToolStripMenuItem("&Preferences", null, (_, _) => ShowPreferences(0)));
        opt.DropDownItems.Add(new ToolStripMenuItem("&GPU Configuration", null, (_, _) => ShowPreferences(1), Keys.Control | Keys.G));

        var tools = new ToolStripMenuItem("&Tools");
        tools.DropDownItems.Add(new ToolStripMenuItem("&Rules editor", null, (_, _) => { if (RequireHashcat()) new RulesEditorForm(_hashcat!, _settings).Show(this); }));
        tools.DropDownItems.Add(new ToolStripSeparator());
        tools.DropDownItems.Add(new ToolStripMenuItem("&Benchmark", null, (_, _) => { if (RequireHashcat()) using (var f = new BenchmarkForm(_hashcat!, _settings, _devices)) f.ShowDialog(this); }));
        tools.DropDownItems.Add(new ToolStripSeparator());
        tools.DropDownItems.Add(new ToolStripMenuItem("&Download hashcat ...", null, (_, _) => DownloadHashcat()));
        tools.DropDownItems.Add(new ToolStripMenuItem("Download &CPU runtime (OpenCL) ...", null, (_, _) => DownloadCpuRuntime()));

        var help = new ToolStripMenuItem("&Help");
        help.DropDownItems.Add(new ToolStripMenuItem("&Help contents", null, (_, _) => ShowHelp(), Keys.F1));
        help.DropDownItems.Add(new ToolStripMenuItem("hashcat &website", null, (_, _) => Shell("https://hashcat.net/hashcat/")));
        help.DropDownItems.Add(new ToolStripMenuItem("Open &debug log folder", null, (_, _) => OpenLogFolder()));
        help.DropDownItems.Add(new ToolStripSeparator());
        help.DropDownItems.Add(new ToolStripMenuItem("Check for &updates", null, async (_, _) => await CheckForUpdatesAsync()));
        help.DropDownItems.Add(new ToolStripMenuItem($"&About {AppName}", null, (_, _) => ShowAbout()));

        ms.Items.AddRange([file, rec, opt, tools, help]);
        MainMenuStrip = ms;
    }

    private ToolStrip BuildToolbar()
    {
        int sz = LogicalToDeviceUnits(32);
        var ts = new ToolStrip { ImageScalingSize = new Size(sz, sz), GripStyle = ToolStripGripStyle.Hidden, Padding = new Padding(6, 2, 0, 2) };
        ToolStripButton B(Image img, string tip, Action a) { var b = new ToolStripButton(img) { ToolTipText = tip, AccessibleName = tip, DisplayStyle = ToolStripItemDisplayStyle.Image, Margin = new Padding(2) }; b.Click += (_, _) => a(); return b; }
        _tbStart = B(Icons.Start(sz), "Start", StartWizard);
        _tbStop = B(Icons.Stop(sz), "Stop", StopAttack);
        ts.Items.AddRange([
            B(Icons.Open(sz), "Open file ...", OpenDialog),
            new ToolStripSeparator(),
            _tbStart, _tbStop,
            new ToolStripSeparator(),
            B(Icons.Gear(sz), "Preferences", () => ShowPreferences(0)),
            B(Icons.Help(sz), "Help contents", ShowHelp),
        ]);
        return ts;
    }

    private Control BuildStatusPane()
    {
        var t = new TableLayoutPanel { Dock = DockStyle.Bottom, ColumnCount = 4, RowCount = 3, AutoSize = true, Padding = new Padding(6, 4, 6, 4) };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        Label L(string s) => new() { Text = s, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 2, 6, 2) };
        t.Controls.Add(L("Current password:"), 0, 0); t.Controls.Add(_curPassword, 1, 0);
        t.Controls.Add(L("Estimated time:"), 2, 0); t.Controls.Add(_estTime, 3, 0);
        t.Controls.Add(L("Current speed:"), 0, 1); t.Controls.Add(_curSpeed, 1, 1);
        t.Controls.Add(L("Average speed:"), 2, 1); t.Controls.Add(_avgSpeed, 3, 1);
        t.Controls.Add(_progress, 0, 2);
        t.SetColumnSpan(_progress, 4);
        return t;
    }

    // ------------------------------------------------------------------ info pane

    private readonly System.Text.StringBuilder _uiLine = new();

    private void Write(string text, Color? color = null, bool bold = false, float size = 0, bool log = true)
    {
        if (InvokeRequired) { BeginInvoke(() => Write(text, color, bold, size, log)); return; }
        // Mirror what the user sees into the debug log, one complete line at a time.
        _uiLine.Append(log ? text : $"(redacted, {text.Length} chars)");
        var buffered = _uiLine.ToString();
        int nl = buffered.LastIndexOf('\n');
        if (nl >= 0)
        {
            foreach (var l in buffered[..nl].Replace("\r", "").Split('\n')) DebugLog.Ui(l);
            _uiLine.Clear().Append(buffered[(nl + 1)..]);
        }
        _info.SelectionStart = _info.TextLength;
        _info.SelectionLength = 0;
        _info.SelectionColor = color ?? SystemColors.WindowText;
        _info.SelectionFont = new Font(_info.Font.FontFamily, size > 0 ? size : _info.Font.Size, bold ? FontStyle.Bold : FontStyle.Regular);
        _info.AppendText(text);
        _info.SelectionStart = _info.TextLength;
        _info.ScrollToCaret();
    }

    private void Line(string text = "", Color? color = null, bool bold = false) => Write(text + Environment.NewLine, color, bold);

    private void Log(LogKind kind, string text)
    {
        switch (kind)
        {
            case LogKind.Step: Line(text, Color.FromArgb(0, 70, 170), true); break;
            case LogKind.Warning: Line(text, Color.FromArgb(190, 100, 0)); break;
            case LogKind.Error: Line(text, Color.FromArgb(200, 0, 0), true); break;
            case LogKind.Success: Line(text, Color.FromArgb(0, 130, 0), true); break;
            default: Line(text, Color.DimGray); break;
        }
    }

    private void ShowStartPage()
    {
        _info.Clear();
        Write(AppName, bold: true);
        Line($" {AppVersion} x64 recovers passwords for:");
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
                     "GPU acceleration on a wide range of GPUs: NVIDIA (CUDA/OpenCL), AMD (HIP/OpenCL) and Intel Arc (OpenCL)",
                     "Several types of attacks: brute-force, brute-force with extended mask, and dictionary based ones",
                     "Automated password recovery with predefined and user-defined scenarios",
                     "User-defined sets of mutation rules for dictionary attacks and multi-word combinations",
                     "Supports Unicode, UTF-8 and ANSI dictionaries",
                     "Interrupted attacks can be continued later; recovered passwords are cached",
                     "After a successful attack the document can be decrypted automatically (MS Office)",
                 })
            Line("  • " + s);
        Line();
        Line("Open a protected file with File > Open (Ctrl+O) or drag and drop it here.", Color.DimGray);
    }

    // ------------------------------------------------------------------ hashcat

    private async Task InitHashcatAsync()
    {
        _hashcat = HashcatTool.Locate(_settings.HashcatPath);
        if (_hashcat is null)
        {
            _statusLeft.Text = "hashcat not found";
            Line();
            Line("hashcat was not found.", Color.FromArgb(200, 0, 0), true);
            Line("Use Tools > Download hashcat to fetch it automatically, or set its location in " +
                 "Options > Preferences > Files and Paths.", Color.DimGray);
            BeginInvoke(() => OfferHashcatDownload());
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
            _statusRight.Text = _deviceStatus = gpus.Count > 0 ? $"{gpus.Count} GPU device(s)" : cpu ? "No GPU detected, using CPU" : "No GPU detected";
            Line();
            if (gpus.Count == 0 && cpu)
                Line("No compatible GPU devices detected. Passwords are recovered on the processor " +
                     $"({(_settings.MaxCpuThreads > 0 ? _settings.MaxCpuThreads : Environment.ProcessorCount)} threads).", Color.DimGray);
            else if (gpus.Count == 0) NoDevicesNotice();
            foreach (var d in usable)
                Line($"Device #{d.Id}: {d.Name} ({d.Backend}{(d.Processors > 0 ? $", {d.Processors} compute units" : "")}{(d.MemoryMb > 0 ? $", {d.MemoryMb} MB" : "")})"
                     + (_settings.DisabledDevices.Contains(d.Id) ? " - disabled" : ""), Color.DimGray);
        }
        catch (Exception ex) when (ex is TimeoutException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            _statusRight.Text = "hashcat error";
            Line("Cannot run hashcat: " + ex.Message, Color.FromArgb(200, 0, 0));
        }
    }

    private void AutoDecrypt(Detection det, string password)
    {
        var t = det.Target!;
        if (!OfficeDecryptor.CanDecrypt(t.FormatId))
        {
            Line($"Automatic decryption is available for MS Office 2007-2021 documents; {t.FormatName} is not supported.", Color.DimGray);
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
        catch (Exception ex) when (ex is UnsupportedFormatException or IOException or FormatException or System.Security.Cryptography.CryptographicException)
        {
            Log(LogKind.Warning, "Automatic decryption failed: " + ex.Message);
        }
    }

    private bool RequireHashcat()
    {
        if (_hashcat is not null) return true;
        if (MessageBox.Show(this, "hashcat was not found. Download it now?", AppName,
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            DownloadHashcat();
        return _hashcat is not null;
    }

    private bool _offeredDownload;

    /// <summary>On first start without hashcat, offer a one-click download.</summary>
    private void OfferHashcatDownload()
    {
        if (_offeredDownload || _hashcat is not null) return;
        _offeredDownload = true;
        if (MessageBox.Show(this, $"hashcat (the GPU engine) was not found.\r\n\r\nDownload hashcat {HashcatInstaller.Version} now?",
                AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            DownloadHashcat();
    }

    private void DownloadHashcat()
    {
        using var f = new HashcatDownloadForm();
        if (f.ShowDialog(this) == DialogResult.OK && f.InstalledExe is { } exe)
        {
            _settings.HashcatPath = exe;
            _settings.Save();
            // Redraw the start page so the stale "hashcat was not found" notice disappears.
            if (_current is null) ShowStartPage();
            _ = InitHashcatAsync();
        }
    }

    /// <summary>hashcat found no OpenCL/CUDA/HIP device at all (typically: no GPU driver installed).</summary>
    private void NoDevicesNotice()
    {
        if (CpuRuntime.BlockedByElevation)
        {
            Line("No compatible devices detected. RecoverKit is running as administrator, and Windows does not let an " +
                 "administrator process load the per-user CPU runtime. Start RecoverKit normally to recover passwords on the processor.",
                 Color.FromArgb(190, 100, 0));
            return;
        }
        Line("No compatible GPU devices detected. Install the NVIDIA, AMD or Intel graphics driver, or use the processor: " +
             "Tools > Download CPU runtime (OpenCL).", Color.FromArgb(190, 100, 0));
        BeginInvoke(() => OfferCpuRuntime(force: false));
    }

    private bool _offeredCpuRuntime;

    private void OfferCpuRuntime(bool force)
    {
        if (!CpuRuntime.IsSupportedPlatform || CpuRuntime.Locate() is not null || (_offeredCpuRuntime && !force)) return;
        _offeredCpuRuntime = true;
        if (MessageBox.Show(this, "No GPU driver was found, so hashcat has no device to run on.\r\n\r\n" +
                                  "Download Intel's CPU runtime to recover passwords on the processor?",
                AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
            DownloadCpuRuntime();
    }

    private void DownloadCpuRuntime()
    {
        if (_cts is not null) return;
        if (!CpuRuntime.IsSupportedPlatform)
        {
            Warn("The CPU runtime download is for Windows. On Linux install PoCL; macOS already provides an OpenCL CPU device.");
            return;
        }
        using var f = new CpuRuntimeDownloadForm();
        if (f.ShowDialog(this) != DialogResult.OK) return;
        if (_current is null) ShowStartPage();
        _ = InitHashcatAsync();
    }

    // ------------------------------------------------------------------ generators

    /// <summary>File &gt; Dictionary Generator / WPA-PMK Generator: write an attack's candidates (or their PMKs) to a file.</summary>
    private async Task RunGeneratorAsync(WizardMode mode)
    {
        if (_cts is not null || !RequireHashcat()) return;
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
        using var w = new WizardForm(target, "", LoadScenarios(), _settings, ctx, _hashcat, mode);
        if (w.ShowDialog(this) != DialogResult.OK || w.Steps.Count == 0) return;

        var prepared = new List<PreparedAttack>();
        System.Numerics.BigInteger total = 0;
        foreach (var spec in w.Steps)
        {
            try { var pa = AttackPlanner.Prepare(spec, target, ctx); prepared.Add(pa); total += pa.Keyspace; }
            catch (AttackPlanException ex) { Log(LogKind.Warning, $"{spec.Describe()}: skipped, {ex.Message}"); }
        }
        if (prepared.Count == 0) return;
        double gb = (double)total * (pmk ? 75 : 10) / 1e9;
        if (total > 500_000_000 && MessageBox.Show(this,
                $"This writes about {total:N0} {(pmk ? "PMKs" : "words")} (roughly {gb:N1} GB{(pmk ? ", PMK computation is slow" : "")}).\r\n\r\nContinue?",
                AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes) return;

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
            _progress.Value = total > 0 ? (int)Math.Clamp((double)n / (double)total * 1000, 0, 1000) : 0;
        });
        try
        {
            int threads = _settings.MaxCpuThreads > 0 ? _settings.MaxCpuThreads : Environment.ProcessorCount;
            long n = pmk
                ? await Task.Run(() => CandidateExport.WritePmkTableAsync(prepared, _hashcat!, w.ResultFile, w.Ssid, threads, progress, _cts.Token))
                : await Task.Run(() => CandidateExport.WriteDictionaryAsync(prepared, _hashcat!, w.ResultFile, CandidateExport.EncodingFor(w.OutputEncoding), progress, _cts.Token));
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

    private void OpenDialog()
    {
        if (_cts is not null) return;
        using var d = new OpenFileDialog { Filter = string.Join('|', FormatDetector.OpenFilter), InitialDirectory = _settings.LastOpenedDirectory ?? "" };
        if (d.ShowDialog(this) == DialogResult.OK) _ = OpenFileAsync(d.FileName);
    }

    private void OpenAsDialog()
    {
        if (_cts is not null) return;
        using var f = new OpenAsForm(_settings);
        if (f.ShowDialog(this) == DialogResult.OK && f.Result is { } det) _ = ShowDetectionAsync(det);
    }

    private async Task OpenFileAsync(string path)
    {
        if (_cts is not null) { Warn("Stop the current attack first."); return; }
        _settings.LastOpenedDirectory = Path.GetDirectoryName(path);
        UseWaitCursor = true;
        try
        {
            var det = await Task.Run(() => FormatDetector.Detect(path));
            await ShowDetectionAsync(det);
        }
        finally { UseWaitCursor = false; }
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
            DebugLog.Info("  extracted hash: " + (hl.Length > 4000 ? hl[..4000] + $"... ({hl.Length} chars)" : hl) +
                          (_settings.DebugLogIncludeHashes ? "" : "  (enable \"Include extracted hashes\" in Preferences > Other to log it)"));
        Text = $"{AppName} - {Path.GetFileName(det.FilePath)}";
        _info.Clear();
        ResetStatus();
        void Row(string k, string v) { Write(k.PadRight(0) + "  ", Color.DimGray); Line(v, bold: true); }
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
            Line(det.Message ?? "Nothing to attack.", Color.FromArgb(190, 100, 0), true);
            SetRunning(false);
            return;
        }
        Line("File is password protected to open.", bold: true);
        if (det.Target.Notes is { } notes) Line(notes, Color.DimGray);
        SetRunning(false);

        if (!RequireHashcat()) return;
        var saved = SessionState.Load(_settings, det.Target);
        if (saved is not null)
        {
            var r = MessageBox.Show(this,
                $"Attack was interrupted ({saved.SavedUtc.ToLocalTime():g}, step {saved.StepIndex + 1} of {saved.Steps.Count}).\r\n\r\nContinue the interrupted attack?\r\n(No starts a new attack.)",
                AppName, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (r == DialogResult.Yes) { await RunAsync(saved.Steps, saved); return; }
            if (r == DialogResult.Cancel) return;
            SessionState.Delete(_settings, saved.Key);
        }
        StartWizard();
    }

    // ------------------------------------------------------------------ attack

    private void StartWizard()
    {
        if (_cts is not null || _current?.Target is null) return;
        if (!RequireHashcat()) return;
        var scenarios = LoadScenarios();
        using var w = new WizardForm(_current.Target, _current.FilePath, scenarios, _settings, new PlannerContext
        {
            DataPath = _settings.DataPath, HashcatDir = _hashcat!.Directory, DefaultDictionary = _settings.DefaultDictionary,
        }, _hashcat);
        var ok = w.ShowDialog(this) == DialogResult.OK && w.Steps.Count > 0;
        DebugLog.Info(ok ? $"Wizard finished with {w.Steps.Count} step(s): " + string.Join(" | ", w.Steps.Select(s => s.Describe())) : "Wizard cancelled");
        if (ok) _ = RunAsync(w.Steps, null);
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
        if (_settings.PreventScreensaver) KeepAwake(true);

        var session = new RecoverySession(_hashcat!, _settings) { Devices = _devices };
        session.Log += (k, m) => Log(k, m);
        session.StepStarted += (i, n, desc, ks) => BeginInvoke(() =>
        {
            _stepStarted = DateTime.Now;
            _stepKeyspace = ks;
            _progress.Value = 0;
            _curPassword.Text = "starting...";
        });
        session.Status += s => BeginInvoke(() => UpdateStatus(s));

        SessionResult result;
        try
        {
            result = await Task.Run(() => session.RunAsync(target, det.FilePath, steps, resume, _cts.Token));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            result = new SessionResult { Outcome = SessionOutcome.Error, Error = ex.Message };
        }
        finally
        {
            KeepAwake(false);
            Text = $"{AppName} - {Path.GetFileName(det.FilePath)}";
            _statusRight.Text = _deviceStatus;
            _cts.Dispose();
            _cts = null;
            SetRunning(false);
            _settings.Save();
        }

        switch (result.Outcome)
        {
            case SessionOutcome.Found:
            case SessionOutcome.FoundInCache:
                _progress.Value = _progress.Maximum;
                if (_curPassword.Text == "starting...") _curPassword.Text = "";
                Line();
                Log(LogKind.Success, result.Outcome == SessionOutcome.FoundInCache ? "Previously recovered password(s):" : "Password found:");
                foreach (var p in result.Passwords) Write(p.Length == 0 ? "(empty)" : p, Color.FromArgb(0, 110, 0), true, 14f, log: false);
                DebugLog.Info($"Outcome {result.Outcome}: {result.Passwords.Count} password(s), lengths " + string.Join(",", result.Passwords.Select(x => x.Length)));
                Line();
                if (result.Passwords.Count > 0)
                {
                    try { Clipboard.SetText(result.Passwords[0]); Line("Password copied to the clipboard.", Color.DimGray); }
                    catch (ExternalException) { }
                    using var dlg = new PasswordFoundForm(result.Passwords);
                    dlg.ShowDialog(this);
                }
                if (result.Key is { } k1) Line($"Encryption key: {k1} (found by key search; the password above derives the same key, so it opens the document).", Color.DimGray);
                if (result.Outcome == SessionOutcome.FoundInCache) WriteLink("Clear password cache", ClearCacheLink);
                if (_settings.AutoDecrypt && result.Outcome == SessionOutcome.Found && result.Passwords.Count > 0)
                    AutoDecrypt(det, result.Passwords[0]);
                Execute(_settings.ExecuteOnSuccess);
                break;
            case SessionOutcome.KeyRecovered:
                Line();
                Log(LogKind.Success, $"Encryption key recovered: {result.Key}");
                Line("No password of up to 8 printable characters derives this key. The key is kept in the key cache; " +
                     "a longer equivalent password can be searched by running the key search again with a GPU.", Color.DimGray);
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
                    BeginInvoke(() => OfferCpuRuntime(force: true));
                break;
        }
    }

    private void StopAttack()
    {
        if (_cts is null) return;
        Line("Please wait while stopping attack...", Color.DimGray);
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
        _progress.Value = Math.Clamp((int)(s.Fraction * 1000), 0, 1000);
        if (_current is not null) Text = $"{(int)(s.Fraction * 100)}% - {AppName} - {Path.GetFileName(_current.FilePath)}";
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
        _tbStart.Enabled = _miStart.Enabled = canStart;
        _tbStop.Enabled = _miStop.Enabled = running;
        if (MainMenuStrip is not null)
            foreach (ToolStripMenuItem m in MainMenuStrip.Items)
                if (m.Text is "&File" or "&Options") m.Enabled = !running;
    }

    private void Execute(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try { Shell(path); }
        catch (System.ComponentModel.Win32Exception ex) { Log(LogKind.Warning, $"Cannot execute {path}: {ex.Message}"); }
    }

    // ------------------------------------------------------------------ dialogs

    private void ShowPreferences(int tab)
    {
        if (_cts is not null) return;
        using var f = new PreferencesForm(_settings, _hashcat, _devices, tab);
        if (f.ShowDialog(this) != DialogResult.OK) return;
        _settings.Save();
        DebugLog.Info("Preferences changed");
        DebugLog.LogSettings(_settings);
        if (_hashcat is not null) _hashcat.MaxCpuThreads = _settings.MaxCpuThreads;
        if (f.HashcatChanged) _ = InitHashcatAsync();
    }

    private void ShowHelp()
    {
        var readme = Path.Combine(AppContext.BaseDirectory, "README.html");
        if (File.Exists(readme)) Shell(readme);
        else MessageBox.Show(this,
            "1. Open a protected file (File > Open, Ctrl+O, or drag & drop).\r\n" +
            "2. Choose an attack in the Password Recovery Wizard: a scenario, brute-force, brute-force with extended mask, or dictionary.\r\n" +
            "3. Watch progress in the status pane; Stop interrupts and the attack can be continued later.\r\n\r\n" +
            "TrueCrypt/VeraCrypt volumes and raw hashes: File > Open As.\r\n" +
            "GPU selection and workload: Options > GPU Configuration (Ctrl+G).",
            "Help", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private const string ClearCacheLink = "recoverkit:clear-password-cache";

    /// <summary>Appends a clickable link with friendly text (RTF hyperlink field).</summary>
    private void WriteLink(string text, string target)
    {
        _info.SelectionStart = _info.TextLength;
        _info.SelectedRtf = @"{\rtf1{\field{\*\fldinst{HYPERLINK """ + target + @"""}}{\fldrslt{" + text + @"}}}\par}";
        DebugLog.Ui($"[link] {text}");
    }

    /// <summary>Removes this file's entries from the password cache (hashcat potfile).</summary>
    private void ClearPasswordCacheForCurrent()
    {
        if (_current?.Target is not { } t || !File.Exists(_settings.PotfilePath)) return;
        var hashes = t.HashLines.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(h => h.Trim() + ":").ToList();
        try
        {
            var lines = File.ReadAllLines(_settings.PotfilePath);
            var keep = lines.Where(l => !hashes.Any(h => l.StartsWith(h, StringComparison.OrdinalIgnoreCase))).ToArray();
            File.WriteAllLines(_settings.PotfilePath, keep);
            DebugLog.Info($"Password cache: removed {lines.Length - keep.Length} entr(ies) for {t.FormatId}");
            Line($"Password cache cleared for this file ({lines.Length - keep.Length} entr{(lines.Length - keep.Length == 1 ? "y" : "ies")}).", Color.DimGray);
        }
        catch (IOException ex) { Warn("Cannot clear the password cache: " + ex.Message); }
    }

    /// <summary>Help &gt; Check for updates: asks the project's GitHub releases (only when clicked).</summary>
    private async Task CheckForUpdatesAsync()
    {
        const string api = "https://api.github.com/repos/007hacky007/RecoverKit/releases/latest";
        try
        {
            using var http = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            http.DefaultRequestHeaders.UserAgent.ParseAdd("RecoverKit/1.0");
            http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            using var resp = await http.GetAsync(api);
            DebugLog.Info($"Update check: HTTP {(int)resp.StatusCode}");
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                MessageBox.Show(this, $"No RecoverKit releases are published yet. You are using version {AppVersion}.", "Check for updates",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            resp.EnsureSuccessStatusCode();
            using var doc = System.Text.Json.JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            string tag = doc.RootElement.GetProperty("tag_name").GetString() ?? "";
            string url = doc.RootElement.TryGetProperty("html_url", out var u) ? u.GetString() ?? "" : "";
            bool newer = Version.TryParse(tag.TrimStart('v', 'V'), out var latest) && Version.TryParse(AppVersion, out var mine) && latest > mine;
            if (!newer)
                MessageBox.Show(this, $"You are using the latest version ({AppVersion}).", "Check for updates", MessageBoxButtons.OK, MessageBoxIcon.Information);
            else if (MessageBox.Show(this, $"RecoverKit {tag} is available (you have {AppVersion}).\r\n\r\nOpen the download page?", "Check for updates",
                         MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes && url.StartsWith("https://github.com/", StringComparison.Ordinal))
                Shell(url);
        }
        catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or TaskCanceledException or System.Text.Json.JsonException or KeyNotFoundException)
        {
            DebugLog.Warn("Update check failed: " + ex.Message);
            MessageBox.Show(this, "Could not check for updates: " + ex.Message, "Check for updates", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void OpenLogFolder()
    {
        System.IO.Directory.CreateDirectory(DebugLog.Directory);
        if (DebugLog.CurrentFile is { } f && File.Exists(f))
            Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { "/select," + f } })?.Dispose();
        else Shell(DebugLog.Directory);
    }

    private void ShowAbout() => MessageBox.Show(this,
        $"{AppName} {AppVersion} x64\r\n\r\nGPU accelerated password recovery front-end.\r\n" +
        $"Password verification engine: hashcat {(_hashcatVersion.Length > 0 ? _hashcatVersion : "(not found)")} (MIT license, https://hashcat.net)\r\n\r\n" +
        "Use only on files you own or are authorized to recover.",
        $"About {AppName}", MessageBoxButtons.OK, MessageBoxIcon.Information);

    private void Warn(string text) => MessageBox.Show(this, text, AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);

    private static void Shell(string target) => Process.Start(new ProcessStartInfo(target) { UseShellExecute = true })?.Dispose();

    private void OnClosing(object? sender, FormClosingEventArgs e)
    {
        if (_cts is not null)
        {
            if (MessageBox.Show(this, "An attack is running. Stop it and exit?\r\n(It can be continued later.)", AppName,
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) { e.Cancel = true; return; }
            _cts.Cancel();
            for (int i = 0; i < 100 && _cts is not null; i++) { Application.DoEvents(); Thread.Sleep(100); }
        }
        if (WindowState == FormWindowState.Normal) _settings.WindowBounds = [Bounds.X, Bounds.Y, Bounds.Width, Bounds.Height];
        _settings.Save();
    }

    // ------------------------------------------------------------------ power

    [DllImport("kernel32.dll")] private static extern uint SetThreadExecutionState(uint esFlags);

    private static void KeepAwake(bool on)
    {
        const uint Continuous = 0x80000000, System = 0x00000001, Display = 0x00000002;
        try { SetThreadExecutionState(on ? Continuous | System | Display : Continuous); }
        catch (EntryPointNotFoundException) { }
        catch (DllNotFoundException) { }
    }
}
