using System.Numerics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Views;

public enum WizardMode { Recover, DictionaryGenerator, PmkGenerator }

/// <summary>
/// Password Recovery Wizard: choose a scenario or configure one attack. The same wizard drives the
/// Dictionary Generator and WPA-PMK Generator, which only replace the first page.
/// Closes with true when <see cref="Steps"/> holds the attack(s) to run.
/// </summary>
public sealed class WizardWindow : Window
{
    private enum Choice { Scenario, Brute, Mask, Dict, Key }

    public WizardMode Mode { get; }
    public string ResultFile { get; private set; } = "";
    public string OutputEncoding { get; private set; } = "UTF8";
    public string Ssid { get; private set; } = "default";
    public List<AttackSpec> Steps { get; } = new();

    /// <summary>RAR3 block validation choice (cosmetic; the hashcat 12500 kernel validates all blocks).</summary>
    public bool Rar3ValidateAllBlocks { get; private set; } = true;

    // Remember the last configuration during the application's lifetime.
    private static AttackSpec _lastBrute = new() { Kind = AttackKind.BruteForce, Smalls = true, Digits = true, MinLength = 1, MaxLength = 6 };
    private static AttackSpec _lastMask = new() { Kind = AttackKind.Mask, HashcatMask = "?u?l?l?l?l?d?d", MinLength = 7, MaxLength = 7 };
    private static AttackSpec _lastDict = new() { Kind = AttackKind.Dictionary };

    private readonly HashTarget _target;
    private readonly string _filePath;
    private readonly Settings _settings;
    private readonly PlannerContext _ctx;
    private readonly List<Scenario> _scenarios;
    private readonly HashcatTool? _tool;

    private readonly TextBlock _title = new() { FontSize = 18, VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap };
    private readonly Button _back = new() { Content = "←", Width = 34, Height = 30, Padding = new Thickness(0), HorizontalContentAlignment = HorizontalAlignment.Center };
    private readonly Button _next = new() { Content = "Next", MinWidth = 90, HorizontalContentAlignment = HorizontalAlignment.Center, Classes = { "accent" } };
    private readonly Button _cancel = new() { Content = "Cancel", MinWidth = 90, IsCancel = true, HorizontalContentAlignment = HorizontalAlignment.Center };
    private readonly ContentControl _host = new();

    private readonly Stack<Func<Control>> _history = new();
    private Func<Control>? _currentFactory;
    private Func<Task<bool>>? _commit;           // last page: validate and fill Steps
    private Func<Task<bool>>? _firstPageCheck;   // generator first pages
    private bool _atFirstPage;
    private Choice _choice = Choice.Scenario;
    private Scenario? _scenario;

    public WizardWindow(HashTarget target, string filePath, List<Scenario> scenarios, Settings settings, PlannerContext ctx, HashcatTool? tool = null,
        WizardMode mode = WizardMode.Recover)
    {
        Mode = mode;
        _target = target;
        _filePath = filePath;
        _scenarios = scenarios;
        _settings = settings;
        _ctx = ctx;
        _tool = tool;

        Title = mode switch { WizardMode.DictionaryGenerator => "Dictionary Generator", WizardMode.PmkGenerator => "WPA-PMK Generator", _ => "Password Recovery Wizard" };
        Icon = Icons.AppIcon();
        Width = 560;
        Height = 560;
        CanResize = false;
        CanMinimize = false;
        CanMaximize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        _title.Foreground = Palette.TitleBrush;

        _back.Click += (_, _) => GoBack();
        _next.Click += async (_, _) => await NextAsync();
        _cancel.Click += (_, _) => Close(false);
        ToolTip.SetTip(_back, "Back");

        var header = new DockPanel { Margin = new Thickness(18, 14, 24, 10) };
        DockPanel.SetDock(_back, Dock.Left);
        _back.Margin = new Thickness(0, 0, 12, 0);
        header.Children.Add(_back);
        header.Children.Add(_title);

        Control[] buttons = Platform.IsMac ? [_cancel, _next] : [_next, _cancel];
        var footer = L.Footer(buttons);
        var root = new DockPanel();
        DockPanel.SetDock(footer, Dock.Bottom);
        DockPanel.SetDock(header, Dock.Top);
        root.Children.Add(footer);
        root.Children.Add(header);
        _host.Margin = new Thickness(28, 4, 28, 12);
        root.Children.Add(new ScrollViewer { Content = _host, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled });
        Content = root;

        _scenario = scenarios.FirstOrDefault(s => s.DefaultFor.Contains(target.FormatId)) ?? scenarios.FirstOrDefault();

        // Enter advances (this replaces IsDefault on Next, so it cannot fire twice). Radio buttons and check
        // boxes derive from Button and would swallow Enter, so they are caught on the way down; fields that
        // leave Enter unhandled are caught on the way up. A focused push button keeps Enter for itself.
        AddHandler(KeyDownEvent, async (object? _, Avalonia.Input.KeyEventArgs e) =>
        {
            if (!IsPlainEnter(e) || FocusManager?.GetFocusedElement() is not Avalonia.Controls.Primitives.ToggleButton) return;
            e.Handled = true;
            await NextAsync();
        }, Avalonia.Interactivity.RoutingStrategies.Tunnel);
        AddHandler(KeyDownEvent, async (object? _, Avalonia.Input.KeyEventArgs e) =>
        {
            if (e.Handled || !IsPlainEnter(e)) return;
            if (FocusManager?.GetFocusedElement() is Button or TextBox { AcceptsReturn: true } or ComboBox { IsDropDownOpen: true } or ComboBoxItem) return;
            e.Handled = true;
            await NextAsync();
        }, Avalonia.Interactivity.RoutingStrategies.Bubble);

        Show(mode switch
        {
            WizardMode.DictionaryGenerator => DictionaryGeneratorPage,
            WizardMode.PmkGenerator => PmkGeneratorPage,
            _ => FileInfoPage,
        });
    }

    // ------------------------------------------------------------------ navigation

    private void Show(Func<Control> factory, bool push = false)
    {
        if (push && _currentFactory is not null) _history.Push(_currentFactory);
        _currentFactory = factory;
        _commit = null;
        _atFirstPage = false;
        _host.Content = factory();
        _back.IsVisible = _history.Count > 0;
        _next.Focus();
    }

#if DEBUG
    /// <summary>Snapshot mode: page names and a way to show each one.</summary>
    internal static readonly string[] DebugPageNames = ["file", "attack", "brute", "mask", "dict"];
    internal void DebugShow(int i) => Show(i switch { 0 => FileInfoPage, 1 => AttackTypePage, 2 => BrutePage, 3 => MaskPage, _ => DictPage }, i > 0);
#endif

    private static bool IsPlainEnter(Avalonia.Input.KeyEventArgs e) => e.Key == Avalonia.Input.Key.Enter && e.KeyModifiers == Avalonia.Input.KeyModifiers.None;

    private void GoBack()
    {
        if (_history.Count > 0) Show(_history.Pop());
    }

    private void SetNext(string text) => _next.Content = text;

    private async Task NextAsync()
    {
        if (_commit is not null)
        {
            if (await _commit()) Close(true);
            return;
        }
        if (_atFirstPage)
        {
            if (_firstPageCheck is not null && !await _firstPageCheck()) return;
            Show(AttackTypePage, true);
            return;
        }
        switch (_choice)
        {
            case Choice.Scenario when _scenario is not null:
                Steps.Clear();
                Steps.AddRange(_scenario.Steps.Select(x => x.Clone()));
                Close(true);
                break;
            case Choice.Brute: Show(BrutePage, true); break;
            case Choice.Mask: Show(MaskPage, true); break;
            case Choice.Dict: Show(DictPage, true); break;
            case Choice.Key:
                Steps.Clear();
                Steps.Add(new AttackSpec { Kind = AttackKind.KeySearch });
                Close(true);
                break;
        }
    }

    private Grid Page(string title)
    {
        _title.Text = title;
        return L.Grid("Auto,*,Auto,*", rowSpacing: 8, columnSpacing: 10);
    }

    private static TextBlock Lb(string s) => L.Text(s);

    private Task Warn(string text, string? title = null) => Msg.Warn(this, text, title ?? Title);

    // ------------------------------------------------------------------ file info page

    private Control FileInfoPage()
    {
        _atFirstPage = true;
        SetNext("Next");
        _title.Text = "File is password protected";
        var g = L.Grid("Auto,*", rowSpacing: 6, columnSpacing: 10);
        int row = 0;
        TextBlock Info(string k, string v)
        {
            g.Put(L.Text(k, dim: true), row, 0);
            var value = g.Put(new TextBlock { Text = v, FontWeight = FontWeight.SemiBold, TextWrapping = TextWrapping.Wrap }, row, 1);
            row++;
            return value;
        }
        Info("File:", _filePath);
        Info("Type:", _target.FormatName);
        Info("Protection:", _target.Protection);
        Info("Recovery speed:", Fmt.SpeedClass(_target.Speed));
        if (_target.MaxPasswordLength is int ml) Info("Maximum password length:", ml.ToString());
        else if (_tool is not null && _target.Modes.Count > 0)
        {
            var label = L.Text("Maximum password length:", dim: true);
            g.Put(label, row, 0);
            var value = g.Put(new TextBlock { Text = "...", FontWeight = FontWeight.SemiBold }, row, 1);
            row++;
            _ = FillMaxLengthAsync(label, value, _target.Modes[0]);
        }
        var panel = L.Column(16, g);
        if (FormatSpecificGroup() is { } grp) panel.Children.Add(grp);
        return panel;
    }

    private async Task FillMaxLengthAsync(TextBlock label, TextBlock value, int mode)
    {
        var info = await _tool!.ModeInfoAsync(mode);
        if (info is { PasswordLenMax: > 0 }) value.Text = info.PasswordLenMax.ToString();
        else label.IsVisible = value.IsVisible = false;
    }

    private Control DictionaryGeneratorPage()
    {
        _atFirstPage = true;
        SetNext("Next");
        var t = Page("Dictionary Generator settings");
        var file = new TextBox { Text = ResultFile };
        var browse = L.Button("...", async () =>
        {
            if (await Pick.Save(this, "Dictionary files (*.txt;*.dic)|*.txt;*.dic|All files|*.*", "dictionary.txt", defaultExt: "txt") is { } p) file.Text = p;
        }, 40);
        var enc = new ComboBox { ItemsSource = CandidateExport.Encodings, SelectedItem = OutputEncoding, HorizontalAlignment = HorizontalAlignment.Stretch };
        t.Put(Lb("Result file:"), 0, 0); t.Put(file, 0, 1, 2); t.Put(browse, 0, 3);
        t.Put(Lb("Encoding:"), 1, 0); t.Put(enc, 1, 1, 2);
        _firstPageCheck = async () =>
        {
            if (string.IsNullOrWhiteSpace(file.Text)) { await Warn("Choose the result file."); return false; }
            ResultFile = file.Text.Trim();
            OutputEncoding = enc.SelectedItem as string ?? "UTF8";
            return true;
        };
        return t;
    }

    private Control PmkGeneratorPage()
    {
        _atFirstPage = true;
        SetNext("Next");
        var t = Page("WPA-PMK Generator settings");
        var ssid = new TextBox { Text = Ssid };
        if (ResultFile.Length == 0)
            ResultFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "default.pmk");
        var file = new TextBox { Text = ResultFile };
        var browse = L.Button("...", async () =>
        {
            if (await Pick.Save(this, "PMK tables (*.pmk)|*.pmk|All files|*.*", Path.GetFileName(file.Text), defaultExt: "pmk") is { } p) file.Text = p;
        }, 40);
        t.Put(Lb("SSID:"), 0, 0); t.Put(ssid, 0, 1, 2);
        t.Put(Lb("Result file:"), 1, 0); t.Put(file, 1, 1, 2); t.Put(browse, 1, 3);
        _firstPageCheck = async () =>
        {
            var s = ssid.Text ?? "";
            if (s.Length == 0 || System.Text.Encoding.UTF8.GetByteCount(s) > 32) { await Warn("The SSID must be 1-32 bytes long."); return false; }
            if (string.IsNullOrWhiteSpace(file.Text)) { await Warn("Choose the result file."); return false; }
            Ssid = s;
            ResultFile = file.Text.Trim();
            return true;
        };
        return t;
    }

    /// <summary>Optional per-format options shown on the file-info page (RAR3, ...).</summary>
    private Control? FormatSpecificGroup()
    {
        if (_target.FormatId != "RAR3") return null;
        var rbInvalid = new RadioButton { GroupName = "rar3", Content = "Treat PPM blocks as invalid", IsChecked = !Rar3ValidateAllBlocks };
        var rbAll = new RadioButton { GroupName = "rar3", Content = "Validate all blocks (use this if unsure)", IsChecked = Rar3ValidateAllBlocks };
        rbAll.IsCheckedChanged += (_, _) => Rar3ValidateAllBlocks = rbAll.IsChecked == true;
        TextBlock Hint(string s) { var h = L.Text(s, dim: true, wrap: true); h.Margin = new Thickness(28, 0, 0, 4); h.FontSize = 12; return h; }
        return L.Group("RAR3 specifics", L.Column(2,
            rbInvalid, Hint("Low CPU and RAM usage. Passwords for archives with text compression (PPMd method) WILL NOT BE FOUND."),
            rbAll, Hint("High CPU and RAM usage. Recommended only if the PPMd compression method is present.")));
    }

    // ------------------------------------------------------------------ attack type page

    private Control AttackTypePage()
    {
        _title.Text = "Select attack type";
        RadioButton R(string text, Choice c)
        {
            var rb = new RadioButton { GroupName = "attack", Content = text, IsChecked = _choice == c };
            rb.IsCheckedChanged += (_, _) => { if (rb.IsChecked == true) { _choice = c; UpdateAttackTypeButtons(); } };
            return rb;
        }
        var scenario = new ComboBox { ItemsSource = _scenarios, SelectedItem = _scenario, HorizontalAlignment = HorizontalAlignment.Stretch, IsEnabled = _choice == Choice.Scenario };
        scenario.SelectionChanged += (_, _) => _scenario = scenario.SelectedItem as Scenario;
        var rbScenario = R("Use attack scenario:", Choice.Scenario);
        rbScenario.IsCheckedChanged += (_, _) => scenario.IsEnabled = rbScenario.IsChecked == true;

        var scenarioRow = L.Grid("Auto,*", columnSpacing: 10);
        scenarioRow.Put(rbScenario, 0, 0);
        scenarioRow.Put(scenario, 0, 1);
        var p = L.Column(10, scenarioRow, R("Brute-force", Choice.Brute), R("Brute-force with extended mask", Choice.Mask), R("Dictionary based", Choice.Dict));
        // 40-bit RC4 formats: search the whole key space instead of passwords (always succeeds).
        if (Mode == WizardMode.Recover && KeySearch.Supports(_target)) p.Children.Add(R("Key search", Choice.Key));
        else if (_choice == Choice.Key) _choice = Choice.Scenario;
        UpdateAttackTypeButtons();
        return p;
    }

    /// <summary>A scenario starts directly (Finish); a single attack type opens its settings page (Next).</summary>
    private void UpdateAttackTypeButtons()
    {
        if (!_atFirstPage && _commit is null) SetNext(_choice is Choice.Scenario or Choice.Key ? "Finish" : "Next");
    }

    // ------------------------------------------------------------------ estimates

    private sealed record Estimate(TextBlock Count, TextBlock Time, TextBox Speed);

    private Estimate EstimateRow(Grid t, int row)
    {
        var count = new TextBlock { VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap };
        var time = new TextBlock { VerticalAlignment = VerticalAlignment.Center };
        var speed = new TextBox { Text = _settings.SpeedFor(_target.Modes[0]).ToString("F0"), TextAlignment = TextAlignment.Right, MinWidth = 80 };
        t.Put(Lb("Passwords to process:"), row, 0);
        t.Put(count, row, 1, 3);
        t.Put(Lb("Estimated time:"), row + 1, 0);
        t.Put(time, row + 1, 1);
        var at = L.Text("@ speed:");
        at.HorizontalAlignment = HorizontalAlignment.Right;
        t.Put(at, row + 1, 2);
        t.Put(speed, row + 1, 3);
        return new Estimate(count, time, speed);
    }

    private static void ShowEstimate(Estimate e, BigInteger ks, string? error)
    {
        if (error is not null) { e.Count.Text = error; e.Time.Text = ""; return; }
        e.Count.Text = Fmt.Count(ks);
        double.TryParse(e.Speed.Text, out var sp);
        e.Time.Text = Fmt.Duration(ks, sp);
    }

    // ------------------------------------------------------------------ brute-force

    private Control BrutePage()
    {
        SetNext("Finish");
        var a = _lastBrute.Clone();
        var t = Page("Brute-force settings");
        var caps = new CheckBox { Content = "All latin capitals", IsChecked = a.Caps };
        var smalls = new CheckBox { Content = "All latin smalls", IsChecked = a.Smalls };
        var digits = new CheckBox { Content = "All digits", IsChecked = a.Digits };
        var specials = new CheckBox { Content = "All specials", IsChecked = a.Specials };
        var user = new CheckBox { Content = "User defined", IsChecked = a.UseUserCharset };
        var userText = new TextBox { Text = a.UserCharset, IsEnabled = a.UseUserCharset };
        var alphabet = new ComboBox { ItemsSource = Charsets.National.Keys.ToList(), SelectedItem = a.Alphabet, HorizontalAlignment = HorizontalAlignment.Stretch };
        var min = L.Number(1, 64, a.MinLength);
        var max = L.Number(1, 64, a.MaxLength);
        var mask = new TextBox { Text = a.Mask };
        var maskSym = new TextBox { MaxLength = 1, Text = a.MaskSymbol.ToString(), TextAlignment = TextAlignment.Center, Width = 44, HorizontalAlignment = HorizontalAlignment.Left };
        ToolTip.SetTip(mask, "Optional. Known characters plus the mask symbol for unknown positions, e.g. password????");

        t.Put(caps, 0, 0, 2); t.Put(alphabet, 0, 2, 2);
        t.Put(smalls, 1, 0, 2);
        t.Put(digits, 2, 0, 2);
        t.Put(specials, 3, 0, 2);
        t.Put(user, 4, 0, 2);
        t.Put(userText, 5, 0, 4);
        t.Put(Lb("Minimum length"), 6, 0); t.Put(min, 6, 1);
        t.Put(Lb("Maximum length"), 6, 2); t.Put(max, 6, 3);
        t.Put(Lb("Mask"), 7, 0); t.Put(mask, 7, 1);
        t.Put(Lb("Mask symbol"), 7, 2); t.Put(maskSym, 7, 3);
        var est = EstimateRow(t, 8);

        AttackSpec Read() => new()
        {
            Kind = AttackKind.BruteForce, Caps = caps.IsChecked == true, Smalls = smalls.IsChecked == true, Digits = digits.IsChecked == true,
            Specials = specials.IsChecked == true, UseUserCharset = user.IsChecked == true, UserCharset = userText.Text ?? "",
            Alphabet = alphabet.SelectedItem as string ?? Charsets.LatinOnly, MinLength = min.IntValue(), MaxLength = max.IntValue(),
            Mask = mask.Text ?? "", MaskSymbol = maskSym.Text is { Length: > 0 } ms ? ms[0] : '?',
        };
        void Update()
        {
            userText.IsEnabled = user.IsChecked == true;
            if (min.Value > max.Value) max.Value = min.Value;
            var r = Read();
            ShowEstimate(est, Charsets.BruteKeyspace(r), Charsets.Build(r).Length == 0 ? "select a character set" : null);
            min.IsEnabled = max.IsEnabled = r.Mask.Length == 0;
        }
        foreach (var cb in new[] { caps, smalls, digits, specials, user }) cb.IsCheckedChanged += (_, _) => Update();
        foreach (var tb in new[] { userText, mask, maskSym, est.Speed }) tb.TextChanged += (_, _) => Update();
        alphabet.SelectionChanged += (_, _) => Update();
        min.ValueChanged += (_, _) => Update();
        max.ValueChanged += (_, _) => Update();
        Update();
        _commit = async () =>
        {
            var r = Read();
            if (!await ValidateAsync(r)) return false;
            _lastBrute = r;
            Steps.Clear();
            Steps.Add(r);
            return true;
        };
        return t;
    }

    // ------------------------------------------------------------------ extended mask

    private Control MaskPage()
    {
        SetNext("Finish");
        var a = _lastMask.Clone();
        var t = Page("Brute-force with mask settings");
        var g = L.Grid("Auto,*,Auto,*", rowSpacing: 6, columnSpacing: 8);
        var sets = new TextBox[8];
        for (int i = 0; i < 8; i++)
        {
            sets[i] = new TextBox { Text = a.CustomCharsets[i] ?? "" };
            g.Put(L.Text($"?{i + 1}"), i % 4, i < 4 ? 0 : 2);
            g.Put(sets[i], i % 4, i < 4 ? 1 : 3);
        }
        t.Put(L.Group("Custom charsets", g), 0, 0, 4);
        var min = L.Number(1, 64, a.MinLength);
        var max = L.Number(1, 64, a.MaxLength);
        var mask = new TextBox { Text = a.HashcatMask, FontFamily = new FontFamily("Menlo, Consolas, monospace") };
        t.Put(Lb("Minimum length"), 1, 0); t.Put(min, 1, 1);
        t.Put(Lb("Maximum length"), 1, 2); t.Put(max, 1, 3);
        t.Put(Lb("Mask"), 2, 0); t.Put(mask, 2, 1, 3);
        var legend = L.Text("?l smalls  ?u capitals  ?d digits  ?s specials  ?a all  ?b any byte  ?1-?8 custom  ?? literal ?", dim: true, wrap: true);
        legend.FontSize = 12;
        t.Put(legend, 3, 0, 4);
        var est = EstimateRow(t, 4);

        AttackSpec Read()
        {
            var r = new AttackSpec { Kind = AttackKind.Mask, HashcatMask = mask.Text ?? "", MinLength = min.IntValue(), MaxLength = max.IntValue() };
            for (int i = 0; i < 8; i++) r.CustomCharsets[i] = sets[i].Text ?? "";
            int len = Charsets.MaskPositions(r.HashcatMask, r.CustomCharsets).Count;
            r.MaxLength = Math.Min(r.MaxLength, Math.Max(1, len));
            r.Increment = r.MinLength < len;
            return r;
        }
        void Update()
        {
            int len = Charsets.MaskPositions(mask.Text ?? "", sets.Select(s => s.Text ?? "").ToArray()).Count;
            if (len > 0 && max.Value > len) max.Value = len;
            var r = Read();
            ShowEstimate(est, Charsets.MaskKeyspace(r.HashcatMask, r.CustomCharsets, r.Increment, r.MinLength, r.MaxLength), len == 0 ? "enter a mask" : null);
        }
        foreach (var s in sets) s.TextChanged += (_, _) => Update();
        mask.TextChanged += (_, _) => Update();
        min.ValueChanged += (_, _) => Update();
        max.ValueChanged += (_, _) => Update();
        est.Speed.TextChanged += (_, _) => Update();
        Update();
        _commit = async () =>
        {
            var r = Read();
            if (!await ValidateAsync(r)) return false;
            _lastMask = r;
            Steps.Clear();
            Steps.Add(r);
            return true;
        };
        return t;
    }

    // ------------------------------------------------------------------ dictionary

    private Control DictPage()
    {
        SetNext("Finish");
        var a = _lastDict.Clone();
        if (string.IsNullOrEmpty(a.Dictionaries[0]) && !string.IsNullOrEmpty(_settings.DefaultDictionary)) a.Dictionaries[0] = _settings.DefaultDictionary;
        var t = Page("Dictionary settings");
        var ruleNames = AttackSpec.PresetOrder.Select(AttackSpec.RulesName).Append("Custom rules file...").ToList();
        var rules = new ComboBox
        {
            ItemsSource = ruleNames, HorizontalAlignment = HorizontalAlignment.Stretch,
            SelectedIndex = a.Rules == RulesPreset.CustomFile ? ruleNames.Count - 1 : Array.IndexOf(AttackSpec.PresetOrder, a.Rules),
        };
        string? customRules = a.RulesFile;
        CancellationTokenSource? countCts = null;

        var items = BuiltinDictionaries.Names.ToList();
        if (_settings.DataPath is { } dp && Directory.Exists(dp))
            items.AddRange(Directory.EnumerateFiles(dp).Where(f => f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".dic", StringComparison.OrdinalIgnoreCase)).Take(200));
        var dicts = new ComboBox[4];
        var btns = new Button[4];
        string[] labels = ["Primary dictionary", "Dictionary #2", "Dictionary #3", "Dictionary #4"];
        var rulesBtn = new Button { Content = "...", MinWidth = 40, HorizontalContentAlignment = HorizontalAlignment.Center };
        t.Put(Lb("Rules set"), 0, 0); t.Put(rules, 0, 1, 2); t.Put(rulesBtn, 0, 3);
        for (int i = 0; i < 4; i++)
        {
            dicts[i] = new ComboBox
            {
                IsEditable = true, ItemsSource = items, HorizontalAlignment = HorizontalAlignment.Stretch,
                Text = BuiltinDictionaries.IsBuiltin(a.Dictionaries[i]) ? BuiltinDictionaries.DisplayName(a.Dictionaries[i]!) : a.Dictionaries[i] ?? "",
            };
            int k = i;
            btns[i] = L.Button("...", async () =>
            {
                if (await Pick.Open(this, "Dictionary files (*.dic; *.txt)|*.dic;*.txt|All files|*.*", _settings.LastDictionaryDirectory ?? _settings.DataPath) is { } p)
                {
                    dicts[k].Text = p;
                    _settings.LastDictionaryDirectory = Path.GetDirectoryName(p);
                }
            }, 40);
            t.Put(Lb(labels[i]), 1 + i, 0); t.Put(dicts[i], 1 + i, 1, 2); t.Put(btns[i], 1 + i, 3);
        }
        var skipMin = L.Number(0, 256, a.SkipShorterThan, 100);
        var skipMax = L.Number(0, 256, a.SkipLongerThan, 100);
        var skipRow = new WrapPanel { ItemSpacing = 8, LineSpacing = 6 };
        foreach (var c in new Control[] { Lb("Skip passwords shorter than"), skipMin, Lb("and longer than"), skipMax, Lb("symbols") }) skipRow.Children.Add(c);
        t.Put(skipRow, 5, 0, 4);
        var note = L.Text("0 = no limit. Rules files come from hashcat's rules folder or the data folder.", dim: true, wrap: true);
        note.FontSize = 12;
        t.Put(note, 6, 0, 4);
        var est = EstimateRow(t, 7);

        static string? DictValue(ComboBox cb)
        {
            var v = (cb.Text ?? "").Trim();
            if (v.Length == 0) return null;
            return BuiltinDictionaries.Names.Contains(v) ? BuiltinDictionaries.Reference(v) : v;
        }
        RulesPreset Preset() => rules.SelectedIndex >= 0 && rules.SelectedIndex < AttackSpec.PresetOrder.Length ? AttackSpec.PresetOrder[rules.SelectedIndex] : RulesPreset.CustomFile;
        static int Need(RulesPreset p) => p switch { RulesPreset.TwoWords or RulesPreset.TwoWordsAdvanced => 2, RulesPreset.ThreeWords => 3, _ => 1 };

        AttackSpec Read()
        {
            var r = new AttackSpec { Kind = AttackKind.Dictionary, Rules = Preset(), RulesFile = customRules, SkipShorterThan = skipMin.IntValue(), SkipLongerThan = skipMax.IntValue() };
            int need = Need(r.Rules);
            for (int i = 0; i < 4; i++) r.Dictionaries[i] = i < need ? DictValue(dicts[i]) : null;
            return r;
        }

        async void Update()
        {
            var r = Read();
            int need = Need(r.Rules);
            for (int i = 1; i < 4; i++) dicts[i].IsEnabled = btns[i].IsEnabled = i < need;
            countCts?.Cancel();
            var cts = countCts = new CancellationTokenSource();
            est.Count.Text = "counting...";
            try
            {
                var p = await Task.Run(() => AttackPlanner.Prepare(r, _target, _ctx, path => Wordlists.CountLines(path, cts.Token)), cts.Token);
                if (!cts.IsCancellationRequested) ShowEstimate(est, p.Keyspace, null);
            }
            catch (AttackPlanException ex) { if (!cts.IsCancellationRequested) ShowEstimate(est, 0, ex.Message); }
            catch (OperationCanceledException) { }
            catch (IOException ex) { if (!cts.IsCancellationRequested) ShowEstimate(est, 0, ex.Message); }
        }
        async Task PickRules()
        {
            var dir = _ctx.HashcatDir is { } hd ? Path.Combine(hd, "rules") : null;
            if (await Pick.Open(this, "Rules files (*.rule; *.txt)|*.rule;*.txt|All files|*.*", dir) is { } p)
            {
                customRules = p;
                rules.SelectedIndex = ruleNames.Count - 1;
                Update();
            }
        }
        rulesBtn.Click += async (_, _) => await PickRules();
        rules.SelectionChanged += async (_, _) =>
        {
            if (Preset() == RulesPreset.CustomFile && string.IsNullOrEmpty(customRules)) await PickRules();
            Update();
        };
        foreach (var d in dicts) { d.PropertyChanged += (_, e) => { if (e.Property == ComboBox.TextProperty) Update(); }; }
        skipMin.ValueChanged += (_, _) => Update();
        skipMax.ValueChanged += (_, _) => Update();
        est.Speed.TextChanged += (_, _) => Update();
        Update();
        _commit = async () =>
        {
            countCts?.Cancel();
            var r = Read();
            if (!await ValidateAsync(r)) return false;
            _lastDict = r;
            Steps.Clear();
            Steps.Add(r);
            return true;
        };
        return t;
    }

    private async Task<bool> ValidateAsync(AttackSpec a)
    {
        try
        {
            if (a.Kind == AttackKind.Dictionary)
            {
                // Planning a dictionary attack counts lines; avoid it here, only check inputs.
                foreach (var d in a.Dictionaries.Where(d => d is not null))
                    if (!File.Exists(AttackPlanner.ResolveDictionary(d, _ctx))) throw new AttackPlanException($"Dictionary not found: {d}");
                if (a.Dictionaries[0] is null) throw new AttackPlanException("Select a primary dictionary.");
                if (a.Rules is RulesPreset.Simple or RulesPreset.Advanced or RulesPreset.Complex or RulesPreset.CustomFile) AttackPlanner.ResolveRules(a, _ctx);
            }
            else AttackPlanner.Prepare(a, _target, _ctx);
            return true;
        }
        catch (AttackPlanException ex)
        {
            await Warn(ex.Message, "Sorry, these settings are incorrect.");
            return false;
        }
    }
}
