using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Forms;

/// <summary>
/// Rules editor: edit a hashcat rule file and see the mutated test words immediately.
/// Previews are produced by hashcat --stdout, so they match the cracking engine exactly.
/// </summary>
public sealed class RulesEditorForm : Form
{
    private readonly HashcatTool _hashcat;
    private readonly Settings _settings;
    private readonly TextBox _editor = new() { Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 10f), AcceptsTab = true };
    private readonly TextBox _result = new() { Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill, Font = new Font("Consolas", 10f), ReadOnly = true, BackColor = Color.FromArgb(240, 240, 240) };
    private readonly TextBox[] _words = new TextBox[4];
    private readonly Label _state = new() { AutoSize = true, Dock = DockStyle.Fill };
    private readonly System.Windows.Forms.Timer _debounce = new() { Interval = 450 };
    private CancellationTokenSource? _cts;
    private string? _path;
    private bool _dirty;

    private const string Template =
        "# hashcat rule file - one rule per line, functions are applied left to right\n" +
        "# lines starting with # are comments\n" +
        ":\n" +
        "c\n" +
        "u\n" +
        "$1\n" +
        "$1 $2 $3\n" +
        "c $!\n" +
        "sa@ so0 se3\n" +
        "r\n" +
        "d\n";

    public RulesEditorForm(HashcatTool hashcat, Settings settings)
    {
        _hashcat = hashcat;
        _settings = settings;
        Text = "Rules editor";
        Font = new Font("Segoe UI", 9f);
        StartPosition = FormStartPosition.CenterParent;
        Size = new Size(640, 600);
        MinimumSize = new Size(520, 420);
        ShowInTaskbar = false;

        var top = new TableLayoutPanel { Dock = DockStyle.Top, Height = 130, ColumnCount = 4, RowCount = 4, Padding = new Padding(8, 8, 8, 0) };
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
        top.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        Button B(string t, Action a) { var b = new Button { Text = t, Width = 100 }; b.Click += (_, _) => a(); return b; }
        top.Controls.Add(B("New", New), 0, 0);
        top.Controls.Add(B("Show legend", ShowLegend), 1, 0);
        top.Controls.Add(B("Open ...", Open), 0, 1);
        top.Controls.Add(B("Save", () => Save(false)), 0, 2);
        top.Controls.Add(B("Save as ...", () => Save(true)), 0, 3);
        string[] defaults = ["GooD", "PassWorD", "aNd", "StroNg!"];
        for (int i = 0; i < 4; i++)
        {
            _words[i] = new TextBox { Dock = DockStyle.Fill, Text = defaults[i] };
            _words[i].TextChanged += (_, _) => Kick();
            top.Controls.Add(new Label { Text = $"Test word #{i + 1}", AutoSize = true, Anchor = AnchorStyles.Right, Margin = new Padding(0, 6, 6, 0) }, 2, i);
            top.Controls.Add(_words[i], 3, i);
        }

        var split = new SplitContainer { Dock = DockStyle.Fill, SplitterDistance = 300, Panel1MinSize = 150, Panel2MinSize = 150 };
        split.Panel1.Padding = new Padding(8, 8, 4, 0);
        split.Panel2.Padding = new Padding(4, 8, 8, 0);
        split.Panel1.Controls.Add(_editor);
        split.Panel2.Controls.Add(_result);

        var bottom = new TableLayoutPanel { Dock = DockStyle.Bottom, Height = 40, ColumnCount = 2, Padding = new Padding(8, 4, 8, 4) };
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        bottom.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 100));
        var close = new Button { Text = "Close", Width = 90 };
        close.Click += (_, _) => Close();
        bottom.Controls.Add(_state, 0, 0);
        bottom.Controls.Add(close, 1, 0);

        Controls.Add(split);
        Controls.Add(top);
        Controls.Add(bottom);

        _editor.Text = Template.Replace("\n", Environment.NewLine);
        _editor.TextChanged += (_, _) => { _dirty = true; Kick(); };
        _debounce.Tick += async (_, _) => { _debounce.Stop(); await PreviewAsync(); };
        FormClosing += (_, e) =>
        {
            if (_dirty && MessageBox.Show(this, "Discard unsaved changes?", Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                e.Cancel = true;
        };
        _dirty = false;
        Shown += async (_, _) => await PreviewAsync();
    }

    private void Kick()
    {
        _debounce.Stop();
        _debounce.Start();
    }

    private async Task PreviewAsync()
    {
        _cts?.Cancel();
        var cts = _cts = new CancellationTokenSource();
        var words = _words.Select(w => w.Text).Where(w => w.Length > 0).ToList();
        var rules = _editor.Text;
        int ruleCount = rules.Replace("\r", "").Split('\n').Count(l => l.Trim().Length > 0 && !l.StartsWith('#'));
        try
        {
            var outp = await _hashcat.ApplyRulesAsync(words, rules, cts.Token);
            if (cts.IsCancellationRequested) return;
            _result.Text = string.Join(Environment.NewLine, outp);
            int expected = ruleCount * words.Count;
            _state.Text = outp.Count == expected || ruleCount == 0
                ? $"{ruleCount} rule(s), {outp.Count} candidate(s)"
                : $"{ruleCount} rule(s), {outp.Count} candidate(s) - some rules are invalid or rejected words and were skipped by hashcat";
            _state.ForeColor = outp.Count == expected ? SystemColors.ControlText : Color.FromArgb(190, 100, 0);
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or OperationCanceledException or System.ComponentModel.Win32Exception)
        {
            if (!cts.IsCancellationRequested) { _state.Text = ex.Message; _state.ForeColor = Color.Red; }
        }
    }

    private void New()
    {
        _editor.Text = Template.Replace("\n", Environment.NewLine);
        _path = null;
        _dirty = false;
    }

    private void Open()
    {
        using var d = new OpenFileDialog { Filter = "Rules files (*.rule; *.txt)|*.rule;*.txt|All files|*.*", InitialDirectory = _settings.DataPath ?? Path.Combine(_hashcat.Directory, "rules") };
        if (d.ShowDialog(this) != DialogResult.OK) return;
        var info = new FileInfo(d.FileName);
        if (info.Length > 2_000_000 && MessageBox.Show(this, "This rules file is large; previews will be slow. Open anyway?", Text, MessageBoxButtons.YesNo) != DialogResult.Yes) return;
        _editor.Text = File.ReadAllText(d.FileName).Replace("\r\n", "\n").Replace("\n", Environment.NewLine);
        _path = d.FileName;
        _dirty = false;
    }

    private void Save(bool asNew)
    {
        if (asNew || _path is null)
        {
            using var d = new SaveFileDialog { Filter = "Rules files (*.rule)|*.rule|All files|*.*", DefaultExt = "rule", InitialDirectory = _settings.DataPath ?? "" };
            if (d.ShowDialog(this) != DialogResult.OK) return;
            _path = d.FileName;
        }
        try
        {
            File.WriteAllText(_path, _editor.Text.Replace("\r\n", "\n"), new UTF8Encoding(false));
            _dirty = false;
            _state.Text = "Rules file has been successfully saved.";
        }
        catch (IOException ex) { MessageBox.Show(this, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private void ShowLegend()
    {
        var f = new Form { Text = "Legend", Size = new Size(560, 600), StartPosition = FormStartPosition.CenterParent, ShowInTaskbar = false, Font = Font };
        f.Controls.Add(new TextBox { Multiline = true, ReadOnly = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 9.5f), Text = Legend.Replace("\n", Environment.NewLine) });
        f.Show(this);
    }

    private const string Legend =
        "hashcat rule functions (N = position 0-9 then A-Z, X/Y = characters)\n\n" +
        "Example word: PassWorD\n\n" +
        ":      do nothing                    PassWorD\n" +
        "l      lowercase all                 password\n" +
        "u      uppercase all                 PASSWORD\n" +
        "c      capitalize first, lower rest  Password\n" +
        "C      lower first, upper rest       pASSWORD\n" +
        "t      toggle case of all            pASSwORd\n" +
        "TN     toggle case at position N     T0 -> passWorD\n" +
        "r      reverse                       DroWssaP\n" +
        "d      duplicate word                PassWorDPassWorD\n" +
        "pN     append word N times           p2 -> PassWorDPassWorDPassWorD\n" +
        "f      append reversed word          PassWorDDroWssaP\n" +
        "{      rotate left                   assWorDP\n" +
        "}      rotate right                  DPassWor\n" +
        "$X     append character              $1 -> PassWorD1\n" +
        "^X     prepend character             ^1 -> 1PassWorD\n" +
        "[      delete first character        assWorD\n" +
        "]      delete last character         PassWor\n" +
        "DN     delete character at N         D3 -> PasWorD\n" +
        "xNM    keep M characters from N      x04 -> Pass\n" +
        "ONM    delete M characters from N    O12 -> PsWorD\n" +
        "iNX    insert X at position N        i4! -> Pass!WorD\n" +
        "oNX    overwrite position N with X   o3$ -> Pas$WorD\n" +
        "'N     truncate at N                 '6 -> PassWo\n" +
        "sXY    replace all X with Y          ss$ -> Pa$$WorD\n" +
        "@X     purge all X                   @s -> PaWorD\n" +
        "zN     duplicate first char N times  z2 -> PPPassWorD\n" +
        "ZN     duplicate last char N times   Z2 -> PassWorDDD\n" +
        "q      duplicate every character     PPaassssWWoorrDD\n" +
        "k / K  swap first two / last two     aPssWorD / PassWoDr\n" +
        "*NM    swap characters at N and M    *04 -> WassPorD\n" +
        "E      title case (after spaces)     \n" +
        "eX     title case after separator X  \n\n" +
        "Several functions on one line are applied in order, e.g.  c $2 $0 $2 $5\n" +
        "Lines starting with # are comments. Invalid rules are skipped by hashcat.\n" +
        "Multi-word combinations are chosen in the wizard (Two/Three words rule sets).";
}
