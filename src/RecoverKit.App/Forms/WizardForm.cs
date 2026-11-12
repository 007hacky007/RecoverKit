using System.Numerics;
using System.Runtime.InteropServices;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Forms;

public enum WizardMode { Recover, DictionaryGenerator, PmkGenerator }

/// <summary>
/// Password Recovery Wizard: choose a scenario or configure one attack. The same wizard drives the
/// Dictionary Generator and WPA-PMK Generator, which only replace the first page.
/// </summary>
public sealed class WizardForm : Form
{
    public WizardMode Mode { get; }
    public string ResultFile { get; private set; } = "";
    public string OutputEncoding { get; private set; } = "UTF8";
    public string Ssid { get; private set; } = "default";
    private Func<bool>? _firstPageCheck;

    public List<AttackSpec> Steps { get; } = new();

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
    private bool _atFileInfo;

    /// <summary>RAR3 block validation choice (cosmetic; the hashcat 12500 kernel validates all blocks).</summary>
    public bool Rar3ValidateAllBlocks { get; private set; } = true;

    private readonly Panel _host = new() { Dock = DockStyle.Fill, Padding = new Padding(28, 8, 28, 8) };
    private readonly Label _title = new() { AutoSize = true, Font = new Font("Segoe UI", 12.5f), ForeColor = Color.FromArgb(0, 51, 153), Margin = new Padding(0, 0, 0, 12) };
    private readonly Button _back = new() { Text = "←", FlatStyle = FlatStyle.Flat, Width = 30, Height = 28, Font = new Font("Segoe UI", 11f) };
    private readonly Button _next = new() { Text = "&Next", Width = 80 };
    private readonly Button _cancel = new() { Text = "Cancel", Width = 80, DialogResult = DialogResult.Cancel };

    private Control? _page;
    private readonly Stack<Func<Control>> _history = new();
    private Func<Control>? _currentFactory;
    private Func<bool>? _commit;

    // page 1
    private readonly RadioButton _rbScenario = new() { Text = "Use attack scenario:", AutoSize = true };
    private readonly RadioButton _rbBrute = new() { Text = "Brute-force", AutoSize = true };
    private readonly RadioButton _rbMask = new() { Text = "Brute-force with extended mask", AutoSize = true };
    private readonly RadioButton _rbDict = new() { Text = "Dictionary based", AutoSize = true };
    private readonly RadioButton _rbKey = new() { Text = "Key search", AutoSize = true };
    private readonly ComboBox _cbScenario = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 230 };

    public WizardForm(HashTarget target, string filePath, List<Scenario> scenarios, Settings settings, PlannerContext ctx, HashcatTool? tool = null,
        WizardMode mode = WizardMode.Recover)
    {
        Mode = mode;
        _target = target;
        _filePath = filePath;
        _scenarios = scenarios;
        _settings = settings;
        _ctx = ctx;
        _tool = tool;

        // Aero-style wizard: the window is titled (taskbar, Alt+Tab, accessibility) but the
        // caption is not painted, because the header row already shows it next to the back arrow.
        Text = "Password Recovery Wizard";
        Font = new Font("Segoe UI", 9f);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(470, 440);
        CancelButton = _cancel;
        AcceptButton = _next;

        var header = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 44, Padding = new Padding(6, 8, 0, 0), WrapContents = false };
        _back.FlatAppearance.BorderSize = 0;
        _back.Click += (_, _) => GoBack();
        header.Controls.Add(_back);
        header.Controls.Add(new Label { Text = "Password Recovery Wizard", AutoSize = true, Margin = new Padding(14, 7, 0, 0) });

        var footer = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 46, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(0, 8, 12, 0), BackColor = SystemColors.Control };
        footer.Controls.Add(_cancel);
        footer.Controls.Add(_next);
        _next.Click += (_, _) => Next();

        var body = new Panel { Dock = DockStyle.Fill, BackColor = SystemColors.Window };
        body.Controls.Add(_host);
        Controls.Add(body);
        Controls.Add(header);
        Controls.Add(footer);
        BackColor = SystemColors.Window;

        foreach (var s in scenarios) _cbScenario.Items.Add(s);
        var def = scenarios.FirstOrDefault(s => s.DefaultFor.Contains(target.FormatId)) ?? scenarios.FirstOrDefault();
        if (def is not null) _cbScenario.SelectedItem = def;
        // The scenario radio shares a row with its dropdown, i.e. a different parent panel, which would
        // make WinForms treat it as a separate group. Keep the four choices mutually exclusive by hand.
        RadioButton[] choices = [_rbScenario, _rbBrute, _rbMask, _rbDict, _rbKey];
        foreach (var rb in choices)
            rb.CheckedChanged += (_, _) =>
            {
                if (rb.Checked) foreach (var other in choices) if (other != rb) other.Checked = false;
                UpdateAttackTypeButtons();
            };
        _rbScenario.Checked = true;

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
        _atFileInfo = false;
        _host.Controls.Clear();
        // Old pages are not disposed: shared controls (title, page-1 radios) get re-parented onto the new page.
        _page = factory();
        _host.Controls.Add(_page);
        _back.Enabled = _history.Count > 0;
        // Enter must advance (the default button), not hit whichever button had focus.
        ActiveControl = _next;
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        if (!OperatingSystem.IsWindows()) return;
        var opts = new WtaOptions { Flags = 0x1 | 0x2, Mask = 0x1 | 0x2 };   // WTNCA_NODRAWCAPTION | WTNCA_NODRAWICON
        try { SetWindowThemeAttribute(Handle, 1 /* WTA_NONCLIENT */, ref opts, (uint)Marshal.SizeOf<WtaOptions>()); }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { }
    }

    [StructLayout(LayoutKind.Sequential)] private struct WtaOptions { public uint Flags; public uint Mask; }
    [DllImport("uxtheme.dll")] private static extern int SetWindowThemeAttribute(IntPtr hwnd, int attr, ref WtaOptions opts, uint size);

    private void GoBack()
    {
        if (_history.Count > 0) Show(_history.Pop());
    }

    private void Next()
    {
        if (_commit is not null)
        {
            if (_commit()) { DialogResult = DialogResult.OK; Close(); }
            return;
        }
        if (_atFileInfo)
        {
            if (_firstPageCheck is not null && !_firstPageCheck()) return;
            Show(AttackTypePage, true);
            return;
        }
        if (_rbScenario.Checked && _cbScenario.SelectedItem is Scenario sc)
        {
            Steps.Clear();
            Steps.AddRange(sc.Steps.Select(x => x.Clone()));
            DialogResult = DialogResult.OK;
            Close();
        }
        else if (_rbBrute.Checked) Show(BrutePage, true);
        else if (_rbMask.Checked) Show(MaskPage, true);
        else if (_rbDict.Checked) Show(DictPage, true);
        else if (_rbKey.Checked)
        {
            Steps.Clear();
            Steps.Add(new AttackSpec { Kind = AttackKind.KeySearch });
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    private TableLayoutPanel Page(string title, int rows)
    {
        _title.Text = title;
        var t = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = rows + 1, AutoSize = false };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 38));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 22));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 22));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 18));
        t.Controls.Add(_title, 0, 0);
        t.SetColumnSpan(_title, 4);
        return t;
    }

    private static Label L(string s) => new() { Text = s, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 4, 3) };

    // ------------------------------------------------------------------ file info page

    private Control FileInfoPage()
    {
        _atFileInfo = true;
        _next.Text = "&Next";
        _title.Text = "File is password protected";
        var f = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true };
        f.Controls.Add(_title);

        Label Info(string k, string v)
        {
            var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0, 1, 0, 1) };
            row.Controls.Add(new Label { Text = k, AutoSize = true, Margin = new Padding(0, 3, 6, 0), ForeColor = Color.DimGray });
            var value = new Label { Text = v, AutoSize = true, Margin = new Padding(0, 3, 0, 0), Font = new Font(Font, FontStyle.Bold) };
            row.Controls.Add(value);
            f.Controls.Add(row);
            return value;
        }
        Info("File:", _filePath);
        Info("Type:", _target.FormatName);
        Info("Protection:", _target.Protection);
        Info("Recovery speed:", Fmt.SpeedClass(_target.Speed));
        if (_target.MaxPasswordLength is int ml) Info("Maximum supported password length:", ml.ToString());
        else if (_tool is not null && _target.Modes.Count > 0)
        {
            // The engine's limit for this hash mode.
            var value = Info("Maximum supported password length:", "...");
            _ = FillMaxLengthAsync(value, _target.Modes[0]);
        }
        if (FormatSpecificGroup() is { } grp) { grp.Margin = new Padding(0, 14, 0, 0); f.Controls.Add(grp); }
        return f;
    }

    private async Task FillMaxLengthAsync(Label value, int mode)
    {
        var info = await _tool!.ModeInfoAsync(mode);
        if (value.IsDisposed) return;
        if (info is { PasswordLenMax: > 0 }) value.Text = info.PasswordLenMax.ToString();
        else value.Parent?.Hide();
    }

    private Control DictionaryGeneratorPage()
    {
        _atFileInfo = true;
        _next.Text = "&Next";
        var t = Page("Dictionary Generator Settings", 3);   // an empty last row absorbs the remaining height
        var file = new TextBox { Dock = DockStyle.Fill, Text = ResultFile };
        var browse = new Button { Text = "...", Width = 32, Anchor = AnchorStyles.Left };
        browse.Click += (_, _) =>
        {
            using var d = new SaveFileDialog { Filter = "Dictionary files (*.txt;*.dic)|*.txt;*.dic|All files|*.*", FileName = "dictionary.txt" };
            if (d.ShowDialog(this) == DialogResult.OK) file.Text = d.FileName;
        };
        var enc = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 200 };
        enc.Items.AddRange(CandidateExport.Encodings);
        enc.SelectedItem = OutputEncoding;
        t.Controls.Add(L("Result file:"), 0, 1); t.Controls.Add(file, 1, 1); t.SetColumnSpan(file, 2); t.Controls.Add(browse, 3, 1);
        t.Controls.Add(L("Encoding"), 0, 2); t.Controls.Add(enc, 1, 2); t.SetColumnSpan(enc, 2);
        _firstPageCheck = () =>
        {
            if (string.IsNullOrWhiteSpace(file.Text)) { MessageBox.Show(this, "Choose the result file.", Text); return false; }
            ResultFile = file.Text.Trim();
            OutputEncoding = (string?)enc.SelectedItem ?? "UTF8";
            return true;
        };
        return t;
    }

    private Control PmkGeneratorPage()
    {
        _atFileInfo = true;
        _next.Text = "&Next";
        var t = Page("WPA-PMK Generator settings", 3);   // an empty last row absorbs the remaining height
        var ssid = new TextBox { Width = 200, Text = Ssid };
        if (ResultFile.Length == 0)
            ResultFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "default.pmk");
        var file = new TextBox { Dock = DockStyle.Fill, Text = ResultFile };
        var browse = new Button { Text = "...", Width = 32, Anchor = AnchorStyles.Left };
        browse.Click += (_, _) =>
        {
            using var d = new SaveFileDialog { Filter = "PMK tables (*.pmk)|*.pmk|All files|*.*", FileName = Path.GetFileName(file.Text) };
            if (d.ShowDialog(this) == DialogResult.OK) file.Text = d.FileName;
        };
        t.Controls.Add(L("SSID:"), 0, 1); t.Controls.Add(ssid, 1, 1); t.SetColumnSpan(ssid, 2);
        t.Controls.Add(L("Result file:"), 0, 2); t.Controls.Add(file, 1, 2); t.SetColumnSpan(file, 2); t.Controls.Add(browse, 3, 2);
        _firstPageCheck = () =>
        {
            var s = ssid.Text;
            if (s.Length == 0 || System.Text.Encoding.UTF8.GetByteCount(s) > 32) { MessageBox.Show(this, "The SSID must be 1-32 bytes long.", Text); return false; }
            if (string.IsNullOrWhiteSpace(file.Text)) { MessageBox.Show(this, "Choose the result file.", Text); return false; }
            Ssid = s;
            ResultFile = file.Text.Trim();
            return true;
        };
        return t;
    }

    /// <summary>Optional per-format options panel shown on the file-info page (RAR3, VeraCrypt, ...).</summary>
    private GroupBox? FormatSpecificGroup()
    {
        if (_target.FormatId == "RAR3")
        {
            var g = new GroupBox { Text = "RAR3 specifics", AutoSize = true, Width = 400, Padding = new Padding(8, 4, 8, 8) };
            var layout = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Dock = DockStyle.Fill };
            var rbInvalid = new RadioButton { AutoSize = true, Text = "Treat PPM blocks as invalid", MaximumSize = new Size(380, 0) };
            var hint1 = new Label { AutoSize = true, ForeColor = Color.DimGray, MaximumSize = new Size(360, 0), Margin = new Padding(20, 0, 0, 6), Text = "Low CPU and RAM usage. Passwords for archives with text compression (PPMd method) WILL NOT BE FOUND." };
            var rbAll = new RadioButton { AutoSize = true, Checked = true, Text = "Validate all blocks (use this if unsure)", MaximumSize = new Size(380, 0) };
            var hint2 = new Label { AutoSize = true, ForeColor = Color.DimGray, MaximumSize = new Size(360, 0), Margin = new Padding(20, 0, 0, 0), Text = "High CPU and RAM usage. Recommended only if the PPMd compression method is present." };
            rbAll.CheckedChanged += (_, _) => Rar3ValidateAllBlocks = rbAll.Checked;
            layout.Controls.AddRange([rbInvalid, hint1, rbAll, hint2]);
            g.Controls.Add(layout);
            return g;
        }
        return null;
    }

    // ------------------------------------------------------------------ attack type page

    private Control AttackTypePage()
    {
        _next.Text = "&Next";
        _title.Text = "Select attack type";
        var f = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        f.Controls.Add(_title);
        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        row.Controls.Add(_rbScenario);
        _cbScenario.Margin = new Padding(6, 0, 0, 0);
        row.Controls.Add(_cbScenario);
        f.Controls.Add(row);
        f.Controls.Add(_rbBrute);
        f.Controls.Add(_rbMask);
        f.Controls.Add(_rbDict);
        // 40-bit RC4 formats: search the whole key space instead of passwords (always succeeds).
        if (Mode == WizardMode.Recover && KeySearch.Supports(_target)) f.Controls.Add(_rbKey);
        UpdateAttackTypeButtons();
        return f;
    }

    /// <summary>A scenario starts directly (Finish); a single attack type opens its settings page (Next).</summary>
    private void UpdateAttackTypeButtons()
    {
        _cbScenario.Enabled = _rbScenario.Checked;
        if (!_atFileInfo && _commit is null) _next.Text = _rbScenario.Checked || _rbKey.Checked ? "&Finish" : "&Next";
    }

    // ------------------------------------------------------------------ estimates

    private (Label count, Label time, TextBox speed) EstimateRow(TableLayoutPanel t, int row)
    {
        var count = new Label { AutoSize = true, Anchor = AnchorStyles.Left };
        var time = new Label { AutoSize = true, Anchor = AnchorStyles.Left };
        var speed = new TextBox { Width = 70, Text = _settings.SpeedFor(_target.Modes[0]).ToString("F0"), TextAlign = HorizontalAlignment.Right, Anchor = AnchorStyles.Right };
        t.Controls.Add(L("Passwords to process:"), 0, row);
        t.Controls.Add(count, 1, row);
        t.SetColumnSpan(count, 3);
        t.Controls.Add(L("Estimated time:"), 0, row + 1);
        t.Controls.Add(time, 1, row + 1);
        t.Controls.Add(new Label { Text = "@ speed:", AutoSize = true, Anchor = AnchorStyles.Right, Margin = new Padding(0, 6, 0, 0) }, 2, row + 1);
        t.Controls.Add(speed, 3, row + 1);
        return (count, time, speed);
    }

    private static void ShowEstimate((Label count, Label time, TextBox speed) e, BigInteger ks, string? error)
    {
        if (error is not null) { e.count.Text = error; e.time.Text = ""; return; }
        e.count.Text = Fmt.Count(ks);
        double.TryParse(e.speed.Text, out var sp);
        e.time.Text = Fmt.Duration(ks, sp);
    }

    // ------------------------------------------------------------------ brute-force

    private Control BrutePage()
    {
        _next.Text = "&Finish";
        var a = _lastBrute.Clone();
        var t = Page("Brute-force settings", 12);
        var caps = new CheckBox { Text = "All latin capitals", AutoSize = true, Checked = a.Caps };
        var smalls = new CheckBox { Text = "All latin smalls", AutoSize = true, Checked = a.Smalls };
        var digits = new CheckBox { Text = "All digits", AutoSize = true, Checked = a.Digits };
        var specials = new CheckBox { Text = "All specials", AutoSize = true, Checked = a.Specials };
        var user = new CheckBox { Text = "User defined", AutoSize = true, Checked = a.UseUserCharset };
        var userText = new TextBox { Dock = DockStyle.Fill, Text = a.UserCharset, Enabled = a.UseUserCharset };
        var alphabet = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
        alphabet.Items.AddRange(Charsets.National.Keys.Cast<object>().ToArray());
        alphabet.SelectedItem = a.Alphabet;
        var min = new NumericUpDown { Minimum = 1, Maximum = 64, Value = Math.Clamp(a.MinLength, 1, 64), Width = 50, Anchor = AnchorStyles.Right };
        var max = new NumericUpDown { Minimum = 1, Maximum = 64, Value = Math.Clamp(a.MaxLength, 1, 64), Width = 50, Anchor = AnchorStyles.Right };
        var mask = new TextBox { Dock = DockStyle.Fill, Text = a.Mask };
        var maskSym = new TextBox { Width = 40, MaxLength = 1, Text = a.MaskSymbol.ToString(), TextAlign = HorizontalAlignment.Center, Anchor = AnchorStyles.Right };

        t.Controls.Add(caps, 0, 1); t.Controls.Add(alphabet, 2, 1); t.SetColumnSpan(alphabet, 2);
        t.Controls.Add(smalls, 0, 2);
        t.Controls.Add(digits, 0, 3);
        t.Controls.Add(specials, 0, 4);
        t.Controls.Add(user, 0, 5);
        t.Controls.Add(userText, 0, 6); t.SetColumnSpan(userText, 4);
        t.Controls.Add(L("Minimum length"), 0, 7); t.Controls.Add(min, 1, 7);
        t.Controls.Add(L("Maximum length"), 2, 7); t.Controls.Add(max, 3, 7);
        t.Controls.Add(L("Mask"), 0, 8); t.Controls.Add(mask, 1, 8); t.SetColumnSpan(mask, 1);
        t.Controls.Add(L("Mask symbol"), 2, 8); t.Controls.Add(maskSym, 3, 8);
        var est = EstimateRow(t, 10);
        new ToolTip().SetToolTip(mask, "Optional. Known characters plus the mask symbol for unknown positions, e.g. password????");

        AttackSpec Read() => new()
        {
            Kind = AttackKind.BruteForce, Caps = caps.Checked, Smalls = smalls.Checked, Digits = digits.Checked, Specials = specials.Checked,
            UseUserCharset = user.Checked, UserCharset = userText.Text, Alphabet = alphabet.SelectedItem as string ?? Charsets.LatinOnly,
            MinLength = (int)min.Value, MaxLength = (int)max.Value, Mask = mask.Text, MaskSymbol = maskSym.Text.Length > 0 ? maskSym.Text[0] : '?',
        };
        void Update()
        {
            userText.Enabled = user.Checked;
            if (min.Value > max.Value) max.Value = min.Value;
            var r = Read();
            ShowEstimate(est, Charsets.BruteKeyspace(r), Charsets.Build(r).Length == 0 ? "select a character set" : null);
            if (r.Mask.Length > 0) { min.Enabled = max.Enabled = false; } else { min.Enabled = max.Enabled = true; }
        }
        foreach (var c in new Control[] { caps, smalls, digits, specials, user, userText, alphabet, min, max, mask, maskSym, est.speed })
        {
            if (c is CheckBox cb) cb.CheckedChanged += (_, _) => Update();
            else if (c is ComboBox co) co.SelectedIndexChanged += (_, _) => Update();
            else if (c is NumericUpDown n) n.ValueChanged += (_, _) => Update();
            else c.TextChanged += (_, _) => Update();
        }
        Update();
        _commit = () =>
        {
            var r = Read();
            if (!Validate(r)) return false;
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
        _next.Text = "&Finish";
        var a = _lastMask.Clone();
        var t = Page("Brute-force with mask settings", 10);
        var group = new GroupBox { Text = "Custom charsets", Dock = DockStyle.Fill, Height = 150 };
        var g = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 4 };
        g.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 28)); g.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        g.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 28)); g.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        var sets = new TextBox[8];
        for (int i = 0; i < 8; i++)
        {
            sets[i] = new TextBox { Dock = DockStyle.Fill, Text = a.CustomCharsets[i] ?? "" };
            g.Controls.Add(new Label { Text = $"?{i + 1}", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 0, 0) }, i < 4 ? 0 : 2, i % 4);
            g.Controls.Add(sets[i], i < 4 ? 1 : 3, i % 4);
        }
        group.Controls.Add(g);
        t.Controls.Add(group, 0, 1); t.SetColumnSpan(group, 4); t.SetRowSpan(group, 4);
        var min = new NumericUpDown { Minimum = 1, Maximum = 64, Value = Math.Clamp(a.MinLength, 1, 64), Width = 50, Anchor = AnchorStyles.Right };
        var max = new NumericUpDown { Minimum = 1, Maximum = 64, Value = Math.Clamp(a.MaxLength, 1, 64), Width = 50, Anchor = AnchorStyles.Right };
        var mask = new TextBox { Dock = DockStyle.Fill, Text = a.HashcatMask };
        t.Controls.Add(L("Minimum length"), 0, 5); t.Controls.Add(min, 1, 5);
        t.Controls.Add(L("Maximum length"), 2, 5); t.Controls.Add(max, 3, 5);
        t.Controls.Add(L("Mask"), 0, 6); t.Controls.Add(mask, 1, 6); t.SetColumnSpan(mask, 3);
        var legend = new Label { AutoSize = true, ForeColor = Color.DimGray, MaximumSize = new Size(410, 0), Text = "?l smalls  ?u capitals  ?d digits  ?s specials  ?a all  ?b any byte  ?1-?8 custom  ?? literal ?" };
        t.Controls.Add(legend, 0, 7); t.SetColumnSpan(legend, 4);
        var est = EstimateRow(t, 8);

        AttackSpec Read()
        {
            var r = new AttackSpec { Kind = AttackKind.Mask, HashcatMask = mask.Text, MinLength = (int)min.Value, MaxLength = (int)max.Value };
            for (int i = 0; i < 8; i++) r.CustomCharsets[i] = sets[i].Text;
            int len = Charsets.MaskPositions(r.HashcatMask, r.CustomCharsets).Count;
            r.MaxLength = Math.Min(r.MaxLength, Math.Max(1, len));
            r.Increment = r.MinLength < len;
            return r;
        }
        void Update()
        {
            int len = Charsets.MaskPositions(mask.Text, sets.Select(s => s.Text).ToArray()).Count;
            if (len > 0 && max.Value != len && max.Value > len) max.Value = len;
            var r = Read();
            ShowEstimate(est, Charsets.MaskKeyspace(r.HashcatMask, r.CustomCharsets, r.Increment, r.MinLength, r.MaxLength), len == 0 ? "enter a mask" : null);
        }
        foreach (var s in sets) s.TextChanged += (_, _) => Update();
        mask.TextChanged += (_, _) => Update();
        min.ValueChanged += (_, _) => Update();
        max.ValueChanged += (_, _) => Update();
        est.speed.TextChanged += (_, _) => Update();
        Update();
        _commit = () =>
        {
            var r = Read();
            if (!Validate(r)) return false;
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
        _next.Text = "&Finish";
        var a = _lastDict.Clone();
        if (string.IsNullOrEmpty(a.Dictionaries[0]) && !string.IsNullOrEmpty(_settings.DefaultDictionary)) a.Dictionaries[0] = _settings.DefaultDictionary;
        var t = Page("Dictionary settings", 12);
        var rules = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
        foreach (var p in AttackSpec.PresetOrder) rules.Items.Add(AttackSpec.RulesName(p));
        rules.Items.Add("Custom rules file...");
        rules.SelectedIndex = a.Rules == RulesPreset.CustomFile ? rules.Items.Count - 1 : Array.IndexOf(AttackSpec.PresetOrder, a.Rules);
        string? customRules = a.RulesFile;
        CancellationTokenSource? countCts = null;
        var rulesBtn = new Button { Text = "...", Width = 32, Anchor = AnchorStyles.Left };

        var dicts = new ComboBox[4];
        var btns = new Button[4];
        string[] labels = ["Primary dictionary", "Dictionary #2", "Dictionary #3", "Dictionary #4"];
        t.Controls.Add(L("Rules set"), 0, 1); t.Controls.Add(rules, 1, 1); t.SetColumnSpan(rules, 2); t.Controls.Add(rulesBtn, 3, 1);
        for (int i = 0; i < 4; i++)
        {
            dicts[i] = new ComboBox { Dock = DockStyle.Fill };
            foreach (var n in BuiltinDictionaries.Names) dicts[i].Items.Add(n);
            if (_settings.DataPath is { } dp && Directory.Exists(dp))
                foreach (var f in Directory.EnumerateFiles(dp).Where(f => f.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".dic", StringComparison.OrdinalIgnoreCase)).Take(200))
                    dicts[i].Items.Add(f);
            dicts[i].Text = BuiltinDictionaries.IsBuiltin(a.Dictionaries[i]) ? BuiltinDictionaries.DisplayName(a.Dictionaries[i]!) : a.Dictionaries[i] ?? "";
            btns[i] = new Button { Text = "...", Width = 32, Anchor = AnchorStyles.Left };
            int k = i;
            btns[i].Click += (_, _) =>
            {
                using var d = new OpenFileDialog { Filter = "Dictionary files (*.dic; *.txt)|*.dic;*.txt|All files|*.*", InitialDirectory = _settings.LastDictionaryDirectory ?? _settings.DataPath ?? "" };
                if (d.ShowDialog(this) == DialogResult.OK) { dicts[k].Text = d.FileName; _settings.LastDictionaryDirectory = Path.GetDirectoryName(d.FileName); }
            };
            t.Controls.Add(L(labels[i]), 0, 2 + i); t.Controls.Add(dicts[i], 1, 2 + i); t.SetColumnSpan(dicts[i], 2); t.Controls.Add(btns[i], 3, 2 + i);
        }
        var skipMin = new NumericUpDown { Minimum = 0, Maximum = 256, Value = a.SkipShorterThan, Width = 50 };
        var skipMax = new NumericUpDown { Minimum = 0, Maximum = 256, Value = a.SkipLongerThan, Width = 50 };
        var skipRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        skipRow.Controls.AddRange([L("Skip passwords less than"), skipMin, L("and greater than"), skipMax, L("symbols")]);
        t.Controls.Add(skipRow, 0, 7); t.SetColumnSpan(skipRow, 4);
        var note = new Label { AutoSize = true, ForeColor = Color.DimGray, MaximumSize = new Size(410, 0), Text = "0 = no limit. Rules files come from hashcat's rules folder or the data folder." };
        t.Controls.Add(note, 0, 8); t.SetColumnSpan(note, 4);
        var est = EstimateRow(t, 10);

        static string? DictValue(ComboBox cb)
        {
            var t = cb.Text.Trim();
            if (t.Length == 0) return null;
            return BuiltinDictionaries.Names.Contains(t) ? BuiltinDictionaries.Reference(t) : t;
        }
        RulesPreset Preset() => rules.SelectedIndex >= 0 && rules.SelectedIndex < AttackSpec.PresetOrder.Length ? AttackSpec.PresetOrder[rules.SelectedIndex] : RulesPreset.CustomFile;
        rulesBtn.Click += (_, _) =>
        {
            using var d = new OpenFileDialog { Filter = "Rules files (*.rule; *.txt)|*.rule;*.txt|All files|*.*", InitialDirectory = _ctx.HashcatDir is { } hd ? Path.Combine(hd, "rules") : "" };
            if (d.ShowDialog(this) == DialogResult.OK) { customRules = d.FileName; rules.SelectedIndex = rules.Items.Count - 1; Update(); }
        };

        AttackSpec Read()
        {
            var r = new AttackSpec { Kind = AttackKind.Dictionary, Rules = Preset(), RulesFile = customRules, SkipShorterThan = (int)skipMin.Value, SkipLongerThan = (int)skipMax.Value };
            int need = r.Rules switch { RulesPreset.TwoWords or RulesPreset.TwoWordsAdvanced => 2, RulesPreset.ThreeWords => 3, _ => 1 };
            for (int i = 0; i < 4; i++) r.Dictionaries[i] = i < need ? DictValue(dicts[i]) : null;
            return r;
        }

        async void Update()
        {
            var r = Read();
            int need = r.Rules switch { RulesPreset.TwoWords or RulesPreset.TwoWordsAdvanced => 2, RulesPreset.ThreeWords => 3, _ => 1 };
            for (int i = 1; i < 4; i++) dicts[i].Enabled = btns[i].Enabled = i < need;
            countCts?.Cancel();
            var cts = countCts = new CancellationTokenSource();
            est.count.Text = "counting...";
            try
            {
                var p = await Task.Run(() => AttackPlanner.Prepare(r, _target, _ctx, path => Wordlists.CountLines(path, cts.Token)), cts.Token);
                if (!cts.IsCancellationRequested) ShowEstimate(est, p.Keyspace, null);
            }
            catch (AttackPlanException ex) { if (!cts.IsCancellationRequested) ShowEstimate(est, 0, ex.Message); }
            catch (OperationCanceledException) { }
            catch (IOException ex) { if (!cts.IsCancellationRequested) ShowEstimate(est, 0, ex.Message); }
        }
        rules.SelectedIndexChanged += (_, _) =>
        {
            if (Preset() == RulesPreset.CustomFile && string.IsNullOrEmpty(customRules)) rulesBtn.PerformClick();
            Update();
        };
        foreach (var d in dicts) { d.TextChanged += (_, _) => Update(); d.SelectedIndexChanged += (_, _) => Update(); }
        skipMin.ValueChanged += (_, _) => Update();
        skipMax.ValueChanged += (_, _) => Update();
        est.speed.TextChanged += (_, _) => Update();
        Update();
        _commit = () =>
        {
            countCts?.Cancel();
            var r = Read();
            if (!Validate(r)) return false;
            _lastDict = r;
            Steps.Clear();
            Steps.Add(r);
            return true;
        };
        return t;
    }

    private bool Validate(AttackSpec a)
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
            MessageBox.Show(this, ex.Message, "Sorry, these settings are incorrect.", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return false;
        }
    }
}
