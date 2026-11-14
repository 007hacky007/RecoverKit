using System.Numerics;
using System.Text.RegularExpressions;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Documents;
using Rectangle = Avalonia.Controls.Shapes.Rectangle;
using Ellipse = Avalonia.Controls.Shapes.Ellipse;
using Avalonia.Platform.Storage;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Dependencies;
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

    private readonly SelectableTextBlock _info = new() { TextWrapping = TextWrapping.Wrap, LineHeight = 19, Margin = new Thickness(16, 10, 16, 10) };
    private readonly ScrollViewer _infoScroll;
    // Status band: four labelled values and the progress bar.
    private readonly TextBlock _curPassword = Value(mono: true), _estTime = Value(), _curSpeed = Value(), _tested = Value();
    private readonly ProgressStrip _progress = new() { Margin = new Thickness(0, 10, 0, 0) };
    private Border _band = null!;
    private readonly TextBlock _statusLeft = new() { VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis };
    private readonly TextBlock _statusRight = new() { VerticalAlignment = VerticalAlignment.Center };
    private Button _tbStart = null!, _tbStop = null!;
    // Device pill on the right of the toolbar.
    private readonly Ellipse _pillDot = new() { Width = 7, Height = 7, VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _pillText = new() { FontSize = 11, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis };
    private Border _pill = null!;
    private PillState _pillState = PillState.Busy;
    private int _gpuTemp = -1;
    // Empty state: the drop zone. Loaded: the file card above the log.
    private DropFrame _dropZone = null!;
    private Border _dropLayer = null!;
    // The dependencies page, a layer above the drop zone and the file pane.
    private Border _depsLayer = null!;
    private DependenciesPage? _depsPage;
    private Task<DependenciesOutcome>? _depsRun;
    private bool _depsQueued;   // the start check posted the page, which is not shown yet
    private IReadOnlyList<DependencyItem> _depsItems = [];   // rows of the latest scan
    private readonly TextBlock _dropTitle = new() { FontSize = 15, FontWeight = FontWeight.SemiBold, HorizontalAlignment = HorizontalAlignment.Center, TextAlignment = TextAlignment.Center, TextWrapping = TextWrapping.Wrap };
    private Control _dropHint = null!, _dropChips = null!;
    private readonly StackPanel _dropNotices = new() { Spacing = 4, MaxWidth = 460, HorizontalAlignment = HorizontalAlignment.Center };
    private bool _dragging;
    private bool _generatorView;   // no file open, but a generator's log is shown
    private DockPanel _filePane = null!;
    private readonly FileCard _fileCard = new();
    private NativeMenuItem _miStart = null!, _miStop = null!;
    private readonly List<NativeMenuItem> _idleOnly = new();   // File and Options items, disabled during an attack

    private Detection? _current;
    private CancellationTokenSource? _cts;
    private DateTime _stepStarted;
    private BigInteger _stepKeyspace;
    private Button _tbUpdate = null!;
    private ReleaseInfo? _availableUpdate;   // a newer release found by a check; shows the toolbar's Update button
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
        MinHeight = 460;
        Width = 700;
        Height = 600;
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
            Child = BuildPane(), Background = Palette.PaneBrush, BorderBrush = Palette.LineBrush,
            BorderThickness = new Thickness(0, 1, 0, 1),
        });
        Content = root;

        DragDrop.SetAllowDrop(this, true);
        AddHandler(DragDrop.DragOverEvent, (object? _, DragEventArgs e) =>
        {
            var files = e.DataTransfer.TryGetFiles();
            e.DragEffects = files is { Length: > 0 } ? DragDropEffects.Copy : DragDropEffects.None;
            SetDragging(files is { Length: > 0 } && _cts is null && !_busyDialog, files);
        });
        AddHandler(DragDrop.DragLeaveEvent, (object? _, DragEventArgs _) => SetDragging(false, null));
        AddHandler(DragDrop.DropEvent, async (object? _, DragEventArgs e) =>
        {
            SetDragging(false, null);
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
            _ = AutoCheckForUpdatesAsync();
            await InitHashcatAsync();
#if DEBUG
            if (Environment.GetEnvironmentVariable("RECOVERKIT_DETAILED_TEST") is { Length: > 0 } reportDirectory)
            {
                var diagnostics = new DetailedBenchmarkWindow(_hashcat, _settings, _devices);
                diagnostics.Show(this);
                await diagnostics.DebugRunAsync(reportDirectory, Environment.GetEnvironmentVariable("RECOVERKIT_DETAILED_SECTIONS"));
                Environment.Exit(0);
            }
#endif
            if (!DepsShown && _pendingOpen is { } f) { _pendingOpen = null; await OpenFileAsync(f); }
        };
        Closing += OnClosing;
        SetRunning(false);
        ShowStartPage();
    }

    private static TextBlock Value(bool mono = false)
    {
        var t = new TextBlock
        {
            FontSize = mono ? 14 : 15, FontWeight = mono ? FontWeight.Normal : FontWeight.SemiBold, VerticalAlignment = VerticalAlignment.Center,
            TextTrimming = TextTrimming.CharacterEllipsis, Text = "-", FontFeatures = Ui.Styles.TabularDigits,
        };
        if (mono) t.FontFamily = Ui.Styles.Mono;
        return t;
    }

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
            Item(mac ? "Dependencies..." : "_Dependencies...", () => _ = ShowDependenciesAsync(DepsTrigger.User), idleOnly: true),
        };

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
        Button B(LineIcon icon, string label, string tip, Action a)
        {
            icon.HorizontalAlignment = HorizontalAlignment.Center;
            var b = new Button
            {
                Content = L.Column(2, icon, new TextBlock { Text = label, FontSize = 11, HorizontalAlignment = HorizontalAlignment.Center }),
                Padding = new Thickness(10, 5, 10, 4), MinWidth = 52, HorizontalContentAlignment = HorizontalAlignment.Center,
            };
            b.Classes.Add("tool");
            ToolTip.SetTip(b, tip);
            AutomationProperties(b, label);
            b.Click += (_, _) => a();
            return b;
        }
        Control Sep() => new Rectangle { Width = 1, Height = 30, Fill = Palette.LineBrush, Margin = new Thickness(6, 0), VerticalAlignment = VerticalAlignment.Center };
        _tbStart = B(Icons.Start(), "Start", $"Start ({(Platform.IsMac ? "Cmd+R" : "F5")})", StartWizard);
        _tbStop = B(Icons.Stop(), "Stop", $"Stop ({(Platform.IsMac ? "Cmd+." : "Shift+F5")})", StopAttack);
        var left = new StackPanel
        {
            Orientation = Orientation.Horizontal, Spacing = 2,
            Children =
            {
                B(Icons.Open(), "Open", $"Open file ({Platform.Shortcut("O")})", OpenDialog), Sep(),
                _tbStart, _tbStop, Sep(),
                B(Icons.Bench(), "Benchmark", "Measure the recovery speed of each format on this computer", () => _ = ShowBenchmarkAsync()),
                B(Icons.Gear(), "Settings", Platform.IsMac ? "Settings (Cmd+,)" : "Preferences", () => ShowPreferences(0)),
                B(Icons.Help(), "Help", "Help", () => _ = ShowHelpAsync()),
                (_tbUpdate = B(Icons.Download(), "Update", "Install the new version", () => _ = InstallUpdateAsync())),
            },
        };
        _tbUpdate.Classes.Add("accent");
        _tbUpdate.Margin = new Thickness(8, 0, 0, 0);
        _tbUpdate.IsVisible = false;
        _pill = new Border
        {
            CornerRadius = new CornerRadius(999), Padding = new Thickness(9, 4), Background = Palette.ChipBrush,
            BorderBrush = Palette.LineBrush, BorderThickness = new Thickness(1), VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(12, 0, 2, 0),
            Child = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 7, Children = { _pillDot, _pillText } },
        };
        _pillText.Foreground = Palette.DimBrush;
        SetPill(PillState.Busy, "Starting...");
        var bar = new DockPanel { Margin = new Thickness(10, 6) };
        DockPanel.SetDock(left, Dock.Left);
        bar.Children.Add(left);
        _pill.HorizontalAlignment = HorizontalAlignment.Right;
        bar.Children.Add(_pill);
        return bar;
    }

    private enum PillState { Busy, Ready, Cpu, Problem, Hot }

    private string _pillBase = "";

    /// <summary>Device pill: a coloured dot and a short engine status (plus the hottest GPU while an attack runs).</summary>
    private void SetPill(PillState state, string? text = null)
    {
        _pillState = state;
        if (text is not null) _pillBase = text;
        _pillDot.Fill = state switch
        {
            PillState.Ready => Palette.GoodBrush,
            PillState.Cpu => Palette.AccentBrush,
            PillState.Problem => Palette.ErrorBrush,
            PillState.Hot => Palette.WarnBrush,
            _ => Palette.DimBrush,
        };
        _pillText.Text = _gpuTemp >= 0 && state != PillState.Hot ? $"{_pillBase}  ·  GPU {_gpuTemp} °C" : _pillBase;
    }

    private static void AutomationProperties(Control c, string name) => Avalonia.Automation.AutomationProperties.SetName(c, name);

    private Control BuildStatusPane()
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("*,*,*,*"), ColumnSpacing = 12 };
        void Stat(string label, TextBlock value, int col)
        {
            var l = new TextBlock { Text = label.ToUpperInvariant(), FontSize = 10.5, LetterSpacing = 0.7, Foreground = Palette.DimBrush };
            var p = L.Column(1, l, value);
            Grid.SetColumn(p, col);
            g.Children.Add(p);
        }
        Stat("Trying", _curPassword, 0);
        Stat("Speed", _curSpeed, 1);
        Stat("Time left", _estTime, 2);
        Stat("Tested", _tested, 3);
        _band = new Border
        {
            Padding = new Thickness(16, 12), Background = Palette.StatusBandBrush,
            Child = L.Column(0, g, _progress),
        };
        return _band;
    }

    /// <summary>The pane between toolbar and status band: drop zone when empty, file card and log when a file is open.</summary>
    private Control BuildPane()
    {
        // ---- drop zone
        var hint = new TextBlock { Foreground = Palette.DimBrush, FontSize = 12.5, TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center };
        hint.Inlines!.Add(new Run("or choose Open ("));
        hint.Inlines.Add(new InlineUIContainer(new Border
        {
            BorderBrush = Palette.LineBrush, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(4), Padding = new Thickness(5, 0),
            Child = new TextBlock { Text = Platform.Shortcut("O").Replace('+', ' '), FontFamily = Ui.Styles.Mono, FontSize = 11 },
        }) { BaselineAlignment = BaselineAlignment.Center });
        hint.Inlines.Add(new Run("). RecoverKit detects the format and picks the right attack."));
        _dropHint = hint;
        var chips = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Center, MaxWidth = 470, ItemSpacing = 6, LineSpacing = 6, ItemsAlignment = WrapPanelItemsAlignment.Center };
        foreach (var c in new[] { "Word, Excel, PowerPoint", "Access 97-2003", "Excel sheet protection", "PDF", "ZIP", "RAR 3 / 5", "7-Zip", "KeePass", "OpenDocument", "VeraCrypt", "TrueCrypt", "Wi-Fi handshake", "iTunes backup", "Android backup", "Crypto wallets" })
            chips.Children.Add(new Border
            {
                Background = Palette.ChipBrush, CornerRadius = new CornerRadius(6), Padding = new Thickness(8, 3),
                Child = new TextBlock { Text = c, FontSize = 11, Foreground = Palette.DimBrush },
            });
        _dropChips = chips;
        var lockIcon = Icons.Lock();
        lockIcon.Brush = Palette.StepBrush;
        lockIcon.HorizontalAlignment = HorizontalAlignment.Center;
        _dropTitle.Text = "Drop a protected file here";
        var dropContent = L.Column(12, lockIcon, _dropTitle, hint, chips, _dropNotices);
        dropContent.HorizontalAlignment = HorizontalAlignment.Center;
        dropContent.VerticalAlignment = VerticalAlignment.Center;
        dropContent.Margin = new Thickness(16);
        _dropZone = new DropFrame
        {
            Margin = new Thickness(18),
            Child = new ScrollViewer { Content = dropContent, VerticalAlignment = VerticalAlignment.Center, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled },
        };

        // ---- file pane
        _filePane = new DockPanel { IsVisible = false };
        DockPanel.SetDock(_fileCard, Dock.Top);
        _filePane.Children.Add(_fileCard);
        _filePane.Children.Add(_infoScroll);

        BuildLive();

        _dropLayer = new Border { Background = Palette.PaneBrush, Child = _dropZone };
        _depsLayer = new Border { Background = Palette.PaneBrush, IsVisible = false };
        return new Grid { Children = { _filePane, _dropLayer, _depsLayer } };
    }

    /// <summary>Shows the drop zone (empty state) or the file pane; while files are dragged over the window the zone lights up on top.</summary>
    private void UpdatePane()
    {
        bool empty = _current is null && !_generatorView;
        _filePane.IsVisible = !empty;
        _fileCard.IsVisible = _current is not null;
        _dropLayer.IsVisible = empty || _dragging;
        _dropZone.Active = _dragging;
        _dropHint.IsVisible = _dropChips.IsVisible = !_dragging;
        _dropNotices.IsVisible = !_dragging && _dropNotices.Children.Count > 0;
        if (!_dragging) _dropTitle.Text = "Drop a protected file here";
    }

    private void SetDragging(bool on, IStorageItem[]? files)
    {
        if (on) _dropTitle.Text = files is { Length: > 1 } ? "Drop one file at a time" : $"Release to open {files?[0].Name}";
        if (_dragging == on) return;
        _dragging = on;
        UpdatePane();
    }

    /// <summary>A notice on the empty screen (hashcat missing, no GPU, ...); also written to the log.</summary>
    private void Notice(string text, IBrush color)
    {
        Line(text, color);
        _dropNotices.Children.Add(new TextBlock { Text = text, Foreground = color, FontSize = 12, TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center });
        UpdatePane();
    }

    private Control BuildStatusBar()
    {
        var g = L.Grid("*,Auto", columnSpacing: 10);
        g.Put(_statusLeft, 0, 0);
        g.Put(_statusRight, 0, 1);
        _statusLeft.FontSize = _statusRight.FontSize = 11;
        _statusLeft.Foreground = _statusRight.Foreground = Palette.DimBrush;
        _statusRight.Text = IdleStatusRight;
        return new Border
        {
            Child = g, Padding = new Thickness(16, 5), Background = Palette.StatusBandBrush,
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
        if (_liveActive && !_logVisible)
        {
            // Errors open the details; warnings are counted on the "Show details" toggle.
            if (kind == LogKind.Error) SetDetails(true);
            else if (kind == LogKind.Warning) { _warnCount++; SetDetails(false); }
        }
        switch (kind)
        {
            case LogKind.Step: Line(text, Palette.StepBrush, true); break;
            case LogKind.Warning: Line(text, Palette.WarningBrush); break;
            case LogKind.Error: Line(text, Palette.ErrorBrush, true); break;
            case LogKind.Success: Line(text, Palette.SuccessBrush, true); break;
            default: Line(text, Palette.DimBrush); break;
        }
    }

    private static string IdleStatusRight => $"{AppName} {AppVersion}";

    /// <summary>The empty state: no file, the drop zone with format chips.</summary>
    private void ShowStartPage()
    {
        ClearInfo();
        _dropNotices.Children.Clear();
        _generatorView = false;
        UpdatePane();
    }

    /// <summary>Formats and features, shown in About (the start page used to list them).</summary>
    internal static string FeatureList() => string.Join("\n", new[]
    {
        "Recovers passwords for:",
        "  • MS Office 97-2021 documents (Word, Excel, PowerPoint), plus Excel and Word editing restrictions",
        "  • Access 97-2003 .mdb / .mde database passwords (instant recovery)",
        "  • Word 6/95 and Excel 5/95 XOR passwords (when recoverable)",
        "  • OpenOffice / LibreOffice / OpenDocument files",
        "  • ZIP/WinZip, RAR 3.x-5.x and 7-Zip archives",
        "  • KeePass 1 KDB and KDBX 2/3/4 databases (optional keyfile)",
        "  • Adobe PDF 1.2-1.7 documents",
        "  • Apple iOS / iTunes backups (open the backup's Manifest.plist)",
        "  • Android adb / Helium .ab backups (versions 1-5)",
        "  • BlackBerry .ipd backups (detection only; no hashcat kernel)",
        "  • TrueCrypt and VeraCrypt volumes (File > Open As)",
        "  • WPA/WPA2 handshakes (.22000, .hccapx, .hccap)",
        "  • Ethereum v3, Electrum, MetaMask and Blockchain.com wallets",
        "  • any other hash supported by hashcat (File > Open As)",
        "",
        "Main features:",
        "  • " + (Platform.IsMac
            ? "GPU acceleration on Apple silicon (Metal and OpenCL), and a CPU engine tuned for its NEON and crypto instructions"
            : "GPU acceleration on NVIDIA (CUDA/OpenCL), AMD (HIP/OpenCL) and Intel Arc (OpenCL) GPUs"),
        "  • Brute-force, brute-force with extended mask, and dictionary attacks",
        "  • Automated recovery with predefined and user-defined scenarios",
        "  • User-defined mutation rules for dictionaries and multi-word combinations",
        "  • Unicode, UTF-8 and ANSI dictionaries",
        "  • Interrupted attacks can be continued later; recovered passwords are cached",
        "  • After a successful attack the document can be decrypted (MS Office)",
        "  • Remove Word editing / write restrictions and OpenDocument text section protection instantly",
    });

    // ------------------------------------------------------------------ hashcat

    private const string AttentionNotice = "Some components need attention: Tools > Dependencies.";

    private async Task InitHashcatAsync(bool showPage = true)
    {
        string? bundleError = await PrepareBundledHashcatAsync();
        SetPill(PillState.Busy, "Detecting GPUs...");
        var scan = await Task.Run(() => DependencyScan.RunAsync(_settings, bundleError));
        _depsItems = scan.Items;
        _hashcat = scan.Tool;
        _hashcatVersion = scan.HashcatVersion;
        _devices = scan.Devices;
        SetRunning(_cts is not null);
        if (_hashcat is null)
        {
            _statusLeft.Text = "hashcat not found";
            SetPill(PillState.Problem, "hashcat not found");
            Line();
            Line("hashcat was not found.", Palette.ErrorBrush, true);
        }
        else
        {
            _hashcat.MaxCpuThreads = _settings.MaxCpuThreads;
            DebugLog.Info($"hashcat: {_hashcat.Exe}");
            DebugLog.LogSettings(_settings);
            if (scan.Facts.HashcatError is { Length: > 0 } error)
            {
                SetPill(PillState.Problem, "hashcat error");
                Notice(error, Palette.ErrorBrush);
            }
            else ShowDevices();
        }
        if (scan.Items.Any(i => i.Light != Light.Green))
            Notice(AttentionNotice, scan.Items.Any(i => i.Light == Light.Red) ? Palette.ErrorBrush : Palette.WarningBrush);
        if (showPage && DependencyCheck.ShouldShowAtStart(scan.Items, _settings.SkippedDependencies))
        {
            _depsQueued = true;
            Dispatcher.UIThread.Post(() => _ = ShowDependenciesAsync(DepsTrigger.Startup, scan.Items));
        }
    }

    /// <summary>The pill, status bar and log lines for the devices hashcat reported.</summary>
    private void ShowDevices()
    {
        _statusLeft.Text = $"hashcat {_hashcatVersion}  ·  © {DateTime.Now.Year} {AppName} contributors";
        var usable = _devices.Where(d => !d.IsSkippedAlias).ToList();
        var gpus = usable.Where(d => d.Type.Contains("GPU", StringComparison.OrdinalIgnoreCase)).ToList();
        bool cpu = usable.Any(d => d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase));
        int threads = _settings.MaxCpuThreads > 0 ? _settings.MaxCpuThreads : Environment.ProcessorCount;
        _deviceStatus = gpus.Count switch
        {
            1 => gpus[0].Name + (gpus[0].Backend.Length > 0 ? $" ({gpus[0].Backend})" : ""),
            > 1 => $"{gpus.Count} GPU devices",
            _ => cpu ? $"No GPU, using the CPU ({threads} threads)" : "No GPU detected",
        };
        SetPill(gpus.Count > 0 ? PillState.Ready : cpu ? PillState.Cpu : PillState.Problem,
                gpus.Count > 0 ? "GPU ready: " + _deviceStatus : _deviceStatus);
        var deviceLines = usable.Select(d =>
            $"Device #{d.Id}: {d.Name} ({d.Backend}{(d.Processors > 0 ? $", {d.Processors} compute units" : "")}{(d.MemoryMb > 0 ? $", {d.MemoryMb} MB" : "")})"
            + (d.IsIntegratedGpu ? ", integrated" : "") + (HashcatRunner.IsDisabled(_settings, d) ? ", disabled" : "")).ToList();
        ToolTip.SetTip(_pill, deviceLines.Count > 0 ? string.Join("\n", deviceLines) : null);
        Line();
        if (gpus.Count == 0 && cpu)
            Line($"No compatible GPU devices detected. Passwords are recovered on the processor ({threads} threads).", Palette.DimBrush);
        else if (gpus.Count == 0) NoDevicesNotice();
        foreach (var d in deviceLines) Line(d, Palette.DimBrush);
    }

    /// <summary>
    /// hashcat ships with the app and is copied to the user's engines folder (it writes kernel caches
    /// next to itself, and the signed bundle must stay unmodified). Returns why the copy failed, or null.
    /// </summary>
    private async Task<string?> PrepareBundledHashcatAsync()
    {
        if (HashcatInstaller.BundledDirectory is null || !new HashcatInstaller().BundleNeedsInstall()) return null;
        _statusLeft.Text = $"Preparing hashcat {HashcatInstaller.Version}...";
        var progress = new Progress<InstallProgress>(p =>
        {
            if (p.BytesTotal > 0) _statusLeft.Text = $"Preparing hashcat {HashcatInstaller.Version}... {p.Fraction:P0}";
        });
        string? error = await Task.Run(() => HashcatInstaller.TryInstallBundledError(progress));
        DebugLog.Info(error is null ? "Bundled hashcat copied to the engines folder" : "Bundled hashcat could not be copied: " + error);
        return error;
    }

    private void AutoDecrypt(Detection det, string password)
    {
        var t = det.Target!;
        if (!OfficeDecryptor.CanDecrypt(t.FormatId))
        {
            Line($"Automatic decryption is available for MS Office 2007-2021 documents; {t.FormatName} is not supported.", Palette.DimBrush);
            return;
        }
        var dir = Path.GetDirectoryName(det.FilePath) ?? ".";
        var name = Path.GetFileNameWithoutExtension(det.FilePath);
        var ext = Path.GetExtension(det.FilePath);
        DecryptTo(det, password, Path.Combine(dir, name + _settings.DecryptSuffix + ext), automatic: true);
    }

    /// <summary>Writes a decrypted copy of an MS Office document; the result goes to the log.</summary>
    private bool DecryptTo(Detection det, string password, string outPath, bool automatic = false)
    {
        try
        {
            OfficeDecryptor.DecryptToFile(det.FilePath, password, outPath);
            Log(LogKind.Success, $"Document decrypted and saved to: {outPath}");
            return true;
        }
        catch (Exception ex) when (ex is UnsupportedFormatException or IOException or FormatException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            Log(LogKind.Warning, (automatic ? "Automatic decryption failed: " : "Decryption failed: ") + ex.Message);
            return false;
        }
    }

    private async Task<bool> RequireHashcatAsync()
        => _hashcat is not null || await ShowDependenciesAsync(DepsTrigger.NeedHashcat);

    /// <summary>hashcat found no OpenCL/CUDA/HIP/Metal device at all (typically: no GPU driver installed).</summary>
    private void NoDevicesNotice()
    {
        if (CpuRuntime.BlockedByElevation)
        {
            Notice("No compatible devices detected. RecoverKit is running as administrator, and Windows does not let an " +
                   "administrator process load the per-user CPU runtime. Start RecoverKit normally to recover passwords on the processor.",
                   Palette.WarningBrush);
            return;
        }
        if (!CpuRuntime.IsSupportedPlatform)
        {
            Notice("No compatible devices detected. The built-in CPU engine still works for the formats it supports.", Palette.WarningBrush);
            return;
        }
        Notice("No compatible GPU devices detected. Install the NVIDIA, AMD or Intel graphics driver, or use the processor: " +
               "Tools > Dependencies.", Palette.WarningBrush);
    }

    // ------------------------------------------------------------------ dependencies

    /// <summary>Why the dependencies page is shown.</summary>
    private enum DepsTrigger { Startup, User, NeedHashcat, NeedCpu }

    private bool DepsShown => _depsPage is not null || _depsQueued || _depsRun is { IsCompleted: false };

    /// <summary>
    /// Shows the dependencies page over the pane and waits until it closes. True when the hashcat row
    /// (<see cref="DepsTrigger.NeedHashcat"/>) or the CPU runtime row (<see cref="DepsTrigger.NeedCpu"/>)
    /// is green afterwards, otherwise when everything was installed. A call while the page is open waits for it.
    /// </summary>
    private async Task<bool> ShowDependenciesAsync(DepsTrigger trigger, IReadOnlyList<DependencyItem>? items = null)
    {
        if (trigger == DepsTrigger.Startup) _depsQueued = false;
        if (_depsRun is not { IsCompleted: false })
        {
            if (trigger == DepsTrigger.User && _cts is not null) return false;
            _depsRun = RunDependenciesPageAsync(trigger, items);
        }
        var outcome = await _depsRun;
        return trigger switch
        {
            DepsTrigger.NeedHashcat => _hashcat is not null && RowGreen(DependencyId.Hashcat),
            DepsTrigger.NeedCpu => RowGreen(DependencyId.CpuRuntime),
            _ => outcome == DependenciesOutcome.Installed,
        };
    }

    private bool RowGreen(DependencyId id) => _depsItems.Any(i => i.Id == id && i.Light == Light.Green);

    private Task<DependencyScan> ScanAsync() => Task.Run(() => DependencyScan.RunAsync(_settings));

    private async Task<DependenciesOutcome> RunDependenciesPageAsync(DepsTrigger trigger, IReadOnlyList<DependencyItem>? items)
    {
        var pillState = _pillState;
        var pillText = _pillBase;
        bool rescanned = false;
        if (items is null) _depsItems = items = (await ScanAsync()).Items;
        var page = new DependenciesPage(items, _settings.SkippedDependencies, async () =>
        {
            rescanned = true;
            return _depsItems = (await ScanAsync()).Items;
        }, new DependencyInstaller(_settings));
        _depsPage = page;
        _depsLayer.Child = page;
        _depsLayer.IsVisible = true;
        SetPill(PillState.Problem, "Setup needed");

        var (outcome, newlySkipped) = await page.Completion;
        DebugLog.Info($"Dependencies page closed: {outcome}");
        _depsLayer.IsVisible = false;
        _depsLayer.Child = null;
        _depsPage = null;

        if (trigger == DepsTrigger.Startup && newlySkipped.Count > 0)
        {
            _settings.SkippedDependencies = [.. _settings.SkippedDependencies.Concat(newlySkipped).Distinct()];
            try { _settings.Save(); } catch (IOException ex) { DebugLog.Warn("Settings not saved: " + ex.Message); }
        }
        // Installed, or "Check again" may have found a change made outside RecoverKit: pick up the new state.
        if (outcome == DependenciesOutcome.Installed || rescanned)
        {
            // Redraw the start page so stale notices disappear.
            if (_current is null) ShowStartPage();
            await InitHashcatAsync(showPage: false);
        }
        else SetPill(pillState, pillText);
        if (_pendingOpen is { } f)
        {
            _pendingOpen = null;
            Dispatcher.UIThread.Post(() => _ = OpenFileAsync(f));
        }
        return outcome;
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
        var w = new WizardWindow(target, "", LoadScenarios(), _settings, ctx, _hashcat, mode, _devices);
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
        HideLive();
        _generatorView = true;
        UpdatePane();
        Line();
        Line(pmk ? $"WPA-PMK Generator: SSID \"{w.Ssid}\", {prepared.Count} step(s) -> {w.ResultFile}"
                 : $"Dictionary Generator: {prepared.Count} step(s), {w.OutputEncoding} -> {w.ResultFile}", bold: true);
        DebugLog.Info($"Generator {mode}: {prepared.Count} step(s), keyspace {total}, file {w.ResultFile}");
        var started = DateTime.Now;
        var progress = new Progress<long>(n =>
        {
            double secs = Math.Max(0.5, (DateTime.Now - started).TotalSeconds);
            _curPassword.Text = pmk ? "PMKs" : "words";
            _tested.Text = $"{Fmt.Count(n)} of {Fmt.Count(total)}";
            _curSpeed.Text = Fmt.Speed(n / secs);
            _estTime.Text = n > 0 ? Fmt.Duration((double)(total - n) / (n / secs)) : "-";
            _progress.Value = total > 0 ? Math.Clamp((double)n / (double)total, 0, 1) : 0;
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
        if (_depsPage is { } page)
        {
            // An install is never cancelled by opening a file: the file waits until the page closes.
            if (page.Installing) { _pendingOpen = path; return; }
            page.Skip();
        }
        if (_cts is not null) { await Warn("Stop the current attack first."); return; }
        if (_busyDialog) return;
        _settings.LastOpenedDirectory = Path.GetDirectoryName(path);
        Cursor = new Cursor(StandardCursorType.Wait);
        Detection det;
        try { det = await Task.Run(() => FormatDetector.Detect(path)); }
        finally { Cursor = Cursor.Default; }
        // A tiny KDB can be attackable only after its keyfile has been selected.
        if (det.TypeName.StartsWith("KeePass", StringComparison.Ordinal))
        {
            _busyDialog = true;
            try
            {
                var answer = await Msg.Show(this, "Does this KeePass database also require a keyfile?\n\nChoose No for password-only recovery.",
                    "KeePass keyfile", MsgButtons.YesNoCancel, MsgIcon.Question);
                if (answer == MsgResult.Cancel) return;
                if (answer == MsgResult.Yes)
                {
                    var keyfile = await Pick.Open(this, "All files|*.*", _settings.LastOpenedDirectory);
                    if (keyfile is null) return;
                    det = await Task.Run(() => FormatDetector.Detect(path, keyfile));
                }
            }
            finally { _busyDialog = false; }
        }
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
        if (!ShowDetectionInfo(det)) return;

        if (!await RequireHashcatAsync()) return;
        var saved = SessionState.Load(_settings, det.Target!);
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

    /// <summary>Shows a detection result: file card and the details in the log. False when there is nothing to attack.</summary>
    private bool ShowDetectionInfo(Detection det)
    {
        _current = det;
        Title = $"{AppName} - {Path.GetFileName(det.FilePath)}";
        ClearInfo();
        ResetStatus();
        HideLive();
        _fileCard.Show(det);
        UpdatePane();
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
        if (InstantUnlock.All(det.Unlocks) is { } all) ShowUnlock(det, all);
        foreach (var u in det.Unlocks) ShowUnlock(det, u);
        if (det.Target is null)
        {
            if (det.Unlocks.Count == 0) Line(det.Message ?? "Nothing to attack.", Palette.WarningBrush, true);
            else if (det.Message is { } m) Line(m, Palette.DimBrush);
            SetRunning(false);
            return false;
        }
        Line("File is password protected to open.", bold: true);
        if (det.Target.Notes is { } notes) Line(notes, Palette.DimBrush);
        SetRunning(false);
        return true;
    }

#if DEBUG
    /// <summary>Snapshot mode: show a detection without asking anything or starting the wizard.</summary>
    internal void DebugShowDetection(Detection det) => ShowDetectionInfo(det);

    internal IReadOnlyList<BackendDevice> DebugDevices => _devices;

    /// <summary>Snapshot mode: the drop zone as it looks while a file is dragged over the window.</summary>
    internal void DebugDrag(bool on, string name)
    {
        _dragging = on;
        UpdatePane();
        if (on) _dropTitle.Text = $"Release to open {name}";
    }

    internal static HashcatStatus DebugStatus(double fraction, double speed, int temp = 71) => new()
    {
        Status = 3, GuessBase = "kaja?1?1?1?1", MaskLength = 8, ProgressDone = (long)(1_679_616 * fraction), ProgressTotal = 1_679_616,
        TimeStart = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 40,
        Devices = [new DeviceSpeed { Id = 1, Name = "Apple M1 Pro", Type = "GPU", Speed = speed, Temperature = temp }],
    };

    /// <summary>Snapshot mode: a real attack on a test file, saving the window while it runs and when it ends.</summary>
    internal async Task DebugRealRunAsync(string file, IReadOnlyList<AttackSpec> steps, Func<string, Task> save)
    {
        var det = await Task.Run(() => FormatDetector.Detect(file));
        if (!ShowDetectionInfo(det) || _hashcat is null) { await save("real-failed"); return; }
        var run = RunAsync(steps, null, "Debug run");
        for (int i = 0; i < 12 && !run.IsCompleted; i++) { await Task.Delay(1000); if (i == 3) await save("real-running"); }
        // Close the found dialog when it comes up.
        for (int i = 0; i < 30 && !run.IsCompleted; i++)
        {
            await Task.Delay(500);
            var dialog = OwnedWindows.OfType<PasswordFoundWindow>().FirstOrDefault();
            if (dialog is null) continue;
            await Snapshots.Save(dialog, Path.Combine(Snapshots.Dir!, "real-dialog.png"));
            dialog.Close();
        }
        await run;
        await save("real-done");
        SetDetails(true);
        await save("real-details");
    }

    /// <summary>Snapshot mode: walks the main window through its states with made-up status data.</summary>
    internal async Task DebugStatesAsync(Func<string, Task> save)
    {
        List<AttackSpec> steps =
        [
            new() { Kind = AttackKind.Dictionary, Rules = RulesPreset.AsIs },
            new() { Kind = AttackKind.BruteForce, Smalls = true, Digits = true, Mask = "kaja????" },
            new() { Kind = AttackKind.Mask, HashcatMask = "?u?l?l?l?d?d" },
            new() { Kind = AttackKind.Dictionary, Rules = RulesPreset.TwoWords },
        ];
        SetRunning(true);
        BeginLive(steps, "Scenario: Fast formats");
        Log(LogKind.Step, "Step 1/4: Dictionary: english.dic, rules: Check words «as is» - 14 344 391 candidates");
        Log(LogKind.Info, "Step 1 finished, password not found (14 344 391 candidates tested).");
        Log(LogKind.Step, "Step 2/4: Brute-force: smalls + digits, mask \"kaja????\" - 1 679 616 candidates");
        OnStepStarted(1, 4, steps[1].Describe());
        var rnd = new Random(7);
        var t0 = DateTime.UtcNow.AddSeconds(-60);
        for (int i = 0; i <= 60; i++) _spark.Add(41_000 + Math.Sin(i / 5.0) * 900 + rnd.NextDouble() * 700 - (i is > 38 and < 44 ? 9_000 : 0), t0.AddSeconds(i));
        _latest = DebugStatus(0.42, 41_800);
        OnUiTick();
        _progress.Snap(0.42);
        _ring.Snap(0.42);
        await save("running");
        OnThermal(new ThermalEvent(ThermalState.Paused, 87, 85, 75));
        await save("paused");
        OnThermal(new ThermalEvent(ThermalState.Normal, 74, 85, 75));
        SetRunning(false);
        _gpuTemp = -1;
        SetPill(_pillState);
        FinishLive(new SessionResult { Outcome = SessionOutcome.Found, Passwords = ["kaja2019"] });
        ShowFound(["kaja2019"]);
        await save("found");
    }
#endif

    // ------------------------------------------------------------------ attack

    private async void StartWizard()
    {
        if (_cts is not null || _busyDialog || _current?.Target is null) return;
        if (!await RequireHashcatAsync()) return;
        var scenarios = LoadScenarios();
        var w = new WizardWindow(_current.Target, _current.FilePath, scenarios, _settings, new PlannerContext
        {
            DataPath = _settings.DataPath, HashcatDir = _hashcat!.Directory, DefaultDictionary = _settings.DefaultDictionary,
        }, _hashcat, devices: _devices);
        _busyDialog = true;
        bool ok;
        try { ok = await w.ShowDialog<bool>(this) && w.Steps.Count > 0; }
        finally { _busyDialog = false; }
        DebugLog.Info(ok ? $"Wizard finished with {w.Steps.Count} step(s): " + string.Join(" | ", w.Steps.Select(s => s.Describe())) : "Wizard cancelled");
        if (ok) await RunAsync(w.Steps, null, w.ScenarioName is { } sn ? "Scenario: " + sn : null);
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

    private async Task RunAsync(IReadOnlyList<AttackSpec> steps, SessionState? resume, string? badge = null)
    {
        var det = _current!;
        var target = det.Target!;
        _cts = new CancellationTokenSource();
        SetRunning(true);
        ResetStatus();
        BeginLive(steps, resume is not null ? "Resumed" : badge ?? (steps.Count == 1 ? ChipLabel(steps[0]) : $"{steps.Count} steps"));
        Line();
        Line(resume is null ? "Attack started." : "Continuing interrupted attack.", bold: true);
        if (_settings.PreventScreensaver) Platform.KeepAwake(true);

        var session = new RecoverySession(_hashcat!, _settings) { Devices = _devices };
        session.ConfirmElevation = r => Dispatcher.UIThread.InvokeAsync(() => PowerLimitWindow.AskAsync(this, r));
        session.Log += (k, m) => Log(k, m);
        session.StepStarted += (i, n, desc, ks) => Dispatcher.UIThread.Post(() =>
        {
            _stepStarted = DateTime.Now;
            _stepKeyspace = ks;
            _progress.Snap(0);
            _curPassword.Text = "starting...";
            OnStepStarted(i, n, desc);
        });
        // The UI timer picks up the newest status (at most 8 times a second).
        session.Status += s => _latest = s;
        session.Thermal += e => Dispatcher.UIThread.Post(() => OnThermal(e));

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
            _statusRight.Text = IdleStatusRight;
            _gpuTemp = -1;
            SetPill(_pillState);
            _cts.Dispose();
            _cts = null;
            SetRunning(false);
            _settings.Save();
        }
        if (_closeConfirmed) return;   // the window is closing; nothing more to show
        FinishLive(result);

        switch (result.Outcome)
        {
            case SessionOutcome.Found:
            case SessionOutcome.FoundInCache:
                ShowFound(result.Passwords);
                Line();
                Log(LogKind.Success, result.Outcome == SessionOutcome.FoundInCache ? "Previously recovered password(s):" : "Password found:");
                foreach (var p in result.Passwords) Write((p.Length == 0 ? "(empty)" : p) + "\n", Palette.SuccessBrush, true, 18, log: false);
                DebugLog.Info($"Outcome {result.Outcome}: {result.Passwords.Count} password(s), lengths " + string.Join(",", result.Passwords.Select(x => x.Length)));
                if (result.Passwords.Count > 0)
                {
                    if (result.Passwords[0].Length > 0 && await CopyAsync(result.Passwords[0])) Line("Password copied to the clipboard.", Palette.DimBrush);
                    string pw0 = result.Passwords[0];
                    Func<Window, Task>? decrypt = OfficeDecryptor.CanDecrypt(target.FormatId) && pw0.Length > 0
                        ? owner => DecryptWithDialogAsync(det, pw0, owner) : null;
                    await PasswordFoundWindow.RunAsync(this, result.Passwords, Path.GetFileName(det.FilePath),
                        result.Outcome == SessionOutcome.Found ? DateTime.Now - _attackStarted : null, decrypt);
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
                if (result.DecryptedCopy is { } decrypted)
                {
                    Write("Archive decrypted to: ", Palette.DimBrush);
                    WriteLink(decrypted, () => Platform.Reveal(decrypted));
                    Line("The fast key search recovered the ZipCrypto cipher keys and wrote a password-free copy of the archive; " +
                         "the password itself was not found.", Palette.DimBrush);
                }
                else
                {
                    Line("No password of up to 8 printable characters derives this key. The key is kept in the key cache; " +
                         "a longer equivalent password can be searched by running the key search again with a GPU.", Palette.DimBrush);
                }
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
                // The CPU runtime row exists only where RecoverKit can install it (Windows).
                if (CpuRuntime.IsSupportedPlatform
                    && (result.Error?.StartsWith(HashcatRunner.NoCpuDeviceMessage, StringComparison.Ordinal) == true
                        || result.Error?.Contains("No OpenCL, HIP or CUDA compatible platform", StringComparison.OrdinalIgnoreCase) == true))
                    Dispatcher.UIThread.Post(() => _ = ShowDependenciesAsync(DepsTrigger.NeedCpu));
                break;
        }
    }

    /// <summary>Shows a weak protection that can be undone right away: its password and a save link.</summary>
    private void ShowUnlock(Detection det, InstantUnlock u)
    {
        Line(u.Title, Palette.SuccessBrush, true);
        Line(u.Description, Palette.DimBrush);
        if (u.Password is { } pw)
        {
            Write("Password: ", Palette.DimBrush);
            Write((pw.Length == 0 ? "(empty password)" : pw) + "\n", Palette.SuccessBrush, true, log: false);
            DebugLog.Info($"Instant unlock: password of {pw.Length} character(s) shown");
            if (pw.Length > 0) WriteLink("Copy password", () => _ = CopyAsync(pw));
        }
        if (u.SaveLabel is { } label && u.SaveCopyAsync is not null) WriteLink(label, () => _ = SaveUnlockAsync(det, u));
        Line();
    }

    private async Task SaveUnlockAsync(Detection det, InstantUnlock u)
    {
        var ext = Path.GetExtension(det.FilePath);
        var filter = ext.Length > 1 ? $"Same type (*{ext})|*{ext}|All files|*.*" : "All files|*.*";
        var outPath = await Pick.Save(this, filter, Path.GetFileName(u.SuggestedPath(det.FilePath)), Path.GetDirectoryName(det.FilePath),
            ext.Length > 1 ? ext.TrimStart('.') : null);
        if (outPath is null) return;
        try
        {
            await u.SaveAsync(det.FilePath, outPath);
            DebugLog.Info($"Instant unlock saved: {u.Title}");
            Write("Saved: ", Palette.DimBrush);
            WriteLink(outPath, () => Platform.Reveal(outPath));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or InvalidDataException
                                       or UnsupportedFormatException or InvalidOperationException)
        {
            DebugLog.Error("Instant unlock", ex);
            await Msg.Error(this, ex.Message, u.Title);
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
        double elapsed = s.TimeStart > 0 ? DateTimeOffset.UtcNow.ToUnixTimeSeconds() - s.TimeStart : (DateTime.Now - _stepStarted).TotalSeconds;
        _curSpeed.Text = Fmt.Speed(speed);
        ToolTip.SetTip(_curSpeed, "Average: " + (elapsed > 1 ? Fmt.Speed((s.ProgressDone - s.ResumedFrom) / elapsed) : Fmt.Speed(speed)));
        long remaining = Math.Max(0, s.ProgressTotal - s.ProgressDone);
        _estTime.Text = s.Status == 3 && speed > 0 ? Fmt.Duration(remaining / speed) : s.StatusText;
        _curPassword.Text = TryingText(s);
        _tested.Text = Fmt.Count(s.ProgressDone);
        ToolTip.SetTip(_tested, $"{Fmt.Count(s.ProgressDone)} of {Fmt.Count(s.ProgressTotal)} ({s.Fraction:P1}) in this step");
        _progress.Value = Math.Clamp(s.Fraction, 0, 1);
        if (_current is not null) Title = $"{(int)(s.Fraction * 100)}% - {AppName} - {Path.GetFileName(_current.FilePath)}";
        _statusRight.Text = s.StatusText;
        _gpuTemp = HottestGpu(s);
        if (_thermal is { State: ThermalState.Paused } th)
        {
            _estTime.Text = "Paused";
            _statusRight.Text = "Paused (GPU cooling)";
            if (_gpuTemp >= 0) ShowCooling(_gpuTemp, th.ResumeBelow);
        }
        else SetPill(_pillState);
    }

    /// <summary>The hottest GPU in degrees Celsius, or -1 when hashcat reports no temperature.</summary>
    internal static int HottestGpu(HashcatStatus s)
    {
        var temps = s.Devices.Where(d => d.Temperature >= 0 && !d.Type.Contains("CPU", StringComparison.OrdinalIgnoreCase)).Select(d => d.Temperature).ToList();
        return temps.Count > 0 ? temps.Max() : -1;
    }

    /// <summary>
    /// What hashcat is working on: the mask or the wordlist (and rules), as its status reports it. hashcat
    /// does not report single candidates in its JSON status, so this never shows invented passwords.
    /// </summary>
    internal static string TryingText(HashcatStatus s)
    {
        static string Short(string v) => v.Contains('/') || v.Contains('\\') ? Path.GetFileName(v) : v;
        var b = Short(s.GuessBase);
        if (s.GuessMod is { Length: > 0 } m) b = b.Length > 0 ? $"{b} + {Short(m)}" : Short(m);
        if (s.MaskLength is int ml && ml > 0) b = b.Length > 0 ? $"{b} ({ml})" : $"{ml} characters";
        return b.Length > 0 ? b : s.StatusText;
    }

    private void ResetStatus()
    {
        foreach (var l in new[] { _curPassword, _estTime, _curSpeed, _tested }) { l.Text = "-"; ToolTip.SetTip(l, null); }
        _progress.Snap(0);
        _progress.Fill = Palette.AccentBrush;
        _progress.Sheen = false;
        _band.Background = Palette.StatusBandBrush;
    }

    /// <summary>Status band after a find: full green bar and a green tint.</summary>
    private void ShowFound(IReadOnlyList<string> passwords)
    {
        _progress.Sheen = false;
        _progress.Fill = Palette.GoodBrush;
        _progress.Value = 1;
        _band.Background = TintedBand(Palette.GoodSoftBrush);
        _estTime.Text = "Done";
        _curPassword.Text = passwords.Count > 0 && passwords[0].Length > 0 ? passwords[0] : "-";
        _fileCard.SetBadge("Password found", FileCard.BadgeKind.Good);
    }

    private static IBrush TintedBand(IBrush tint)
    {
        var a = (Palette.StatusBandBrush as ISolidColorBrush)!.Color;
        var b = (tint as ISolidColorBrush)!.Color;
        double t = b.A / 255.0;
        byte Mix(byte x, byte y) => (byte)Math.Round(x + (y - x) * t);
        return new SolidColorBrush(Color.FromRgb(Mix(a.R, b.R), Mix(a.G, b.G), Mix(a.B, b.B)));
    }

    private void SetRunning(bool running)
    {
        bool canStart = !running && _current?.Target is not null && _hashcat is not null;
        _tbStart.IsEnabled = _miStart.IsEnabled = canStart;
        _tbStop.IsEnabled = _miStop.IsEnabled = running;
        _tbStart.Classes.Set("accent", canStart);
        foreach (var m in _idleOnly) m.IsEnabled = !running;
        _progress.Sheen = running;
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
        bool cpuOnlyBefore = _settings.Strategy == DeviceStrategy.CpuOnly, cpuWithGpuBefore = _settings.HashcatCpuWithGpu;
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
        bool cpuTurnedOn = (!cpuOnlyBefore && _settings.Strategy == DeviceStrategy.CpuOnly) || (!cpuWithGpuBefore && _settings.HashcatCpuWithGpu);
        if (OperatingSystem.IsWindows() && cpuTurnedOn && CpuRuntime.Locate() is null)
            await ShowDependenciesAsync(DepsTrigger.NeedCpu);
    }

    private async Task ShowHelpAsync()
    {
        var readme = Path.Combine(AppContext.BaseDirectory, "README.html");
        if (File.Exists(readme)) { Platform.Shell(readme); return; }
        await Msg.Show(this,
            $"1. Open a protected file (File > Open, {Platform.Shortcut("O")}, or drag & drop).\n" +
            "2. Choose an attack in the Password Recovery Wizard: a scenario, brute-force, brute-force with extended mask, or dictionary.\n" +
            "3. Watch progress in the status pane; Stop interrupts and the attack can be continued later.\n\n" +
            "If the developers ask for a detailed performance report: Tools > Benchmark > Detailed performance test, then Save report and send the file.\n\n" +
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
        if (_current?.Target is not { } t) return;
        string potfile = SessionState.PasswordCacheFor(_settings, t);
        if (!File.Exists(potfile)) return;
        var hashes = t.HashLines.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(h => h.Trim() + ":").ToList();
        try
        {
            var lines = File.ReadAllLines(potfile);
            var keep = lines.Where(l => !hashes.Any(h => l.StartsWith(h, StringComparison.OrdinalIgnoreCase))).ToArray();
            File.WriteAllLines(potfile, keep);
            DebugLog.Info($"Password cache: removed {lines.Length - keep.Length} entr(ies) for {t.FormatId}");
            Line($"Password cache cleared for this file ({lines.Length - keep.Length} entr{(lines.Length - keep.Length == 1 ? "y" : "ies")}).", Palette.DimBrush);
        }
        catch (IOException ex) { await Warn("Cannot clear the password cache: " + ex.Message); }
    }

    /// <summary>
    /// At start, unless turned off in Preferences, asks GitHub for a newer release at most once an hour
    /// (<see cref="AppUpdater.AutomaticCheckDue"/>). Failures only go to the debug log; a newer release
    /// shows the toolbar's Update button and a line in the log.
    /// </summary>
    private async Task AutoCheckForUpdatesAsync()
    {
        if (!_settings.CheckForUpdatesAtStart || !AppUpdater.AutomaticCheckDue(_settings.LastUpdateCheckUtc, DateTime.UtcNow)) return;
        _settings.LastUpdateCheckUtc = DateTime.UtcNow;
        try { _settings.Save(); } catch (IOException ex) { DebugLog.Warn("Settings not saved: " + ex.Message); }
        ReleaseInfo? release;
        try { release = await AppUpdater.FetchLatestAsync(); }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException or KeyNotFoundException)
        {
            DebugLog.Warn("Automatic update check failed: " + ex.Message);
            return;
        }
        if (release is null || !AppUpdater.IsNewer(release, AppVersion)) return;
        DebugLog.Info($"Update available: {release.Tag}");
        ShowUpdateAvailable(release);
        Line($"{AppName} {release.Tag} is available (you have {AppVersion}). Click Update in the toolbar to install it.", Palette.AccentBrush);
    }

    private void ShowUpdateAvailable(ReleaseInfo release)
    {
        _availableUpdate = release;
        _tbUpdate.IsVisible = true;
        ToolTip.SetTip(_tbUpdate, $"Install {AppName} {release.Tag} (you have {AppVersion})");
    }

    /// <summary>
    /// Help &gt; Check for updates: asks the project's GitHub releases. A newer release is downloaded,
    /// verified and installed from here (<see cref="InstallUpdateAsync"/>).
    /// </summary>
    internal async Task CheckForUpdatesAsync()
    {
        const string title = "Check for updates";
        ReleaseInfo? release;
        try { release = await AppUpdater.FetchLatestAsync(); }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException or KeyNotFoundException)
        {
            DebugLog.Warn("Update check failed: " + ex.Message);
            await Msg.Warn(this, "Could not check for updates: " + ex.Message, title);
            return;
        }
        if (release is null)
        {
            await Msg.Info(this, $"No RecoverKit releases are published yet. You are using version {AppVersion}.", title);
            return;
        }
        if (!AppUpdater.IsNewer(release, AppVersion))
        {
            await Msg.Info(this, $"You are using the latest version ({AppVersion}).", title);
            return;
        }
        ShowUpdateAvailable(release);
        await InstallUpdateAsync(start: false);
    }

    /// <summary>
    /// Downloads, verifies and installs <see cref="_availableUpdate"/> (<see cref="AppUpdater"/>), then
    /// closes so the update script can replace this copy. With <paramref name="start"/> (the toolbar
    /// button) the download begins without a second click. When this installation cannot be updated
    /// in place, or an attack runs, the download page is offered instead.
    /// </summary>
    private async Task InstallUpdateAsync(bool start = true)
    {
        const string title = "Update";
        if (_availableUpdate is not { } release || _busyDialog) return;
        var kind = AppUpdater.DetectInstallKind();
        var asset = AppUpdater.ChooseAsset(release, kind);
        bool busy = _cts is not null;
        if (asset is null || busy)
        {
            string hint = asset is not null && busy ? "Stop the running attack to install it from here, or open the download page now." : "Open the download page?";
            if (await Msg.Ask(this, $"RecoverKit {release.Tag} is available (you have {AppVersion}).\n\n{hint}", title)
                && release.PageUrl.StartsWith("https://github.com/", StringComparison.Ordinal))
                Platform.Shell(release.PageUrl);
            return;
        }
        _busyDialog = true;
        PreparedUpdate? update;
        try { update = await UpdateWindow.RunAsync(this, release, kind, asset, start); }
        finally { _busyDialog = false; }
        if (update is null) return;
        try { AppUpdater.Apply(update); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            DebugLog.Error("Update could not be started", ex);
            await Msg.Error(this, "The update could not be started: " + ex.Message, title);
            return;
        }
        Close();   // the update script waits for this process to end, installs, and starts RecoverKit again
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
        FeatureList() + "\n\n" +
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
