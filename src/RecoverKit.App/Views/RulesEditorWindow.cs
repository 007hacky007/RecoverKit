using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Views;

/// <summary>
/// Rules editor: edit a hashcat rule file and see the mutated test words immediately.
/// Previews are produced by hashcat --stdout, so they match the cracking engine exactly.
/// </summary>
public sealed class RulesEditorWindow : Window
{
    private static readonly FontFamily Mono = new("Menlo, Consolas, monospace");

    private readonly HashcatTool _hashcat;
    private readonly Settings _settings;
    private readonly TextBox _editor = new() { AcceptsReturn = true, AcceptsTab = true, TextWrapping = TextWrapping.NoWrap, FontFamily = Mono, FontSize = 13 };
    private readonly TextBox _result = new() { AcceptsReturn = true, IsReadOnly = true, TextWrapping = TextWrapping.NoWrap, FontFamily = Mono, FontSize = 13 };
    private readonly TextBox[] _words = new TextBox[4];
    private readonly TextBlock _state = L.Text("", wrap: true);
    private readonly DispatcherTimer _debounce = new() { Interval = TimeSpan.FromMilliseconds(450) };
    private CancellationTokenSource? _cts;
    private string? _path;
    private bool _dirty;
    private bool _closeConfirmed;

    private const string RulesTemplate =
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

    public RulesEditorWindow(HashcatTool hashcat, Settings settings)
    {
        _hashcat = hashcat;
        _settings = settings;
        Title = "Rules Editor";
        Icon = Icons.AppIcon();
        Width = 720;
        Height = 640;
        MinWidth = 560;
        MinHeight = 440;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var top = L.Grid("Auto,Auto,Auto,*", rowSpacing: 6, columnSpacing: 10);
        top.Put(L.Button("New", New, 110), 0, 0);
        top.Put(L.Button("Show legend", ShowLegend, 110), 0, 1);
        top.Put(L.Button("Open...", () => _ = OpenAsync(), 110), 1, 0);
        top.Put(L.Button("Save", () => _ = SaveAsync(false), 110), 2, 0);
        top.Put(L.Button("Save as...", () => _ = SaveAsync(true), 110), 3, 0);
        string[] defaults = ["GooD", "PassWorD", "aNd", "StroNg!"];
        for (int i = 0; i < 4; i++)
        {
            _words[i] = new TextBox { Text = defaults[i] };
            _words[i].TextChanged += (_, _) => Kick();
            var lbl = L.Text($"Test word #{i + 1}");
            lbl.HorizontalAlignment = HorizontalAlignment.Right;
            top.Put(lbl, i, 2);
            top.Put(_words[i], i, 3);
        }
        top.Margin = new Thickness(12, 12, 12, 8);

        var split = new Grid { ColumnDefinitions = new ColumnDefinitions("*,6,*"), Margin = new Thickness(12, 0, 12, 0) };
        Grid.SetColumn(_editor, 0);
        var splitter = new GridSplitter { ResizeDirection = GridResizeDirection.Columns, Background = Brushes.Transparent };
        Grid.SetColumn(splitter, 1);
        Grid.SetColumn(_result, 2);
        split.Children.Add(_editor);
        split.Children.Add(splitter);
        split.Children.Add(_result);

        var bottom = L.Grid("*,Auto", columnSpacing: 10);
        bottom.Put(_state, 0, 0);
        bottom.Put(L.Button("Close", Close, 90, isCancel: true), 0, 1);
        var footer = new Border { Padding = new Thickness(12, 10), Child = bottom };

        var root = new DockPanel();
        DockPanel.SetDock(top, Dock.Top);
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(top);
        root.Children.Add(footer);
        root.Children.Add(split);
        Content = root;

        _editor.Text = RulesTemplate;
        _editor.TextChanged += (_, _) => { _dirty = true; Kick(); };
        _debounce.Tick += async (_, _) => { _debounce.Stop(); await PreviewAsync(); };
        Closing += async (_, e) =>
        {
            if (!_dirty || _closeConfirmed) return;
            e.Cancel = true;
            if (await Msg.Ask(this, "Discard unsaved changes?", Title)) { _closeConfirmed = true; Close(); }
        };
        _dirty = false;
        Opened += async (_, _) => { _dirty = false; await PreviewAsync(); };
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
        var words = _words.Select(w => w.Text ?? "").Where(w => w.Length > 0).ToList();
        var rules = _editor.Text ?? "";
        int ruleCount = rules.Replace("\r", "").Split('\n').Count(l => l.Trim().Length > 0 && !l.StartsWith('#'));
        try
        {
            var outp = await _hashcat.ApplyRulesAsync(words, rules, cts.Token);
            if (cts.IsCancellationRequested) return;
            _result.Text = string.Join("\n", outp);
            int expected = ruleCount * words.Count;
            _state.Text = outp.Count == expected || ruleCount == 0
                ? $"{ruleCount} rule(s), {outp.Count} candidate(s)"
                : $"{ruleCount} rule(s), {outp.Count} candidate(s) - some rules are invalid or rejected words and were skipped by hashcat";
            _state.Foreground = outp.Count == expected ? Palette.DimBrush : Palette.WarningBrush;
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or OperationCanceledException or System.ComponentModel.Win32Exception)
        {
            if (!cts.IsCancellationRequested) { _state.Text = ex.Message; _state.Foreground = Palette.ErrorBrush; }
        }
    }

    private void New()
    {
        _editor.Text = RulesTemplate;
        _path = null;
        _dirty = false;
    }

    private async Task OpenAsync()
    {
        var p = await Pick.Open(this, "Rules files (*.rule; *.txt)|*.rule;*.txt|All files|*.*", _settings.DataPath ?? Path.Combine(_hashcat.Directory, "rules"));
        if (p is null) return;
        var info = new FileInfo(p);
        if (info.Length > 2_000_000 && !await Msg.Ask(this, "This rules file is large; previews will be slow. Open anyway?", Title)) return;
        try
        {
            _editor.Text = (await File.ReadAllTextAsync(p)).Replace("\r\n", "\n");
            _path = p;
            _dirty = false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { await Msg.Error(this, ex.Message, Title); }
    }

    private async Task SaveAsync(bool asNew)
    {
        if (asNew || _path is null)
        {
            var p = await Pick.Save(this, "Rules files (*.rule)|*.rule|All files|*.*", "rules.rule", _settings.DataPath, "rule");
            if (p is null) return;
            _path = p;
        }
        try
        {
            await File.WriteAllTextAsync(_path, (_editor.Text ?? "").Replace("\r\n", "\n"), new UTF8Encoding(false));
            _dirty = false;
            _state.Text = "Rules file has been successfully saved.";
            _state.Foreground = Palette.DimBrush;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { await Msg.Error(this, ex.Message, Title); }
    }

    private void ShowLegend()
    {
        var w = new Window
        {
            Title = "Rule legend", Width = 620, Height = 640, Icon = Icons.AppIcon(), WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = new TextBox { Text = Legend, IsReadOnly = true, AcceptsReturn = true, FontFamily = Mono, FontSize = 13, Margin = new Thickness(10), TextWrapping = TextWrapping.NoWrap },
        };
        w.Show(this);
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
