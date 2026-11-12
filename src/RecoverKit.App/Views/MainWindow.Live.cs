using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using Ellipse = Avalonia.Controls.Shapes.Ellipse;

namespace RecoverKit.App.Views;

/// <summary>
/// The live attack view: a progress ring for the current step, scenario step chips, what hashcat is
/// trying, a speed sparkline, the GPU temperature guard state and, at the end, the found password.
/// The text log stays available under "Show details".
/// </summary>
public sealed partial class MainWindow
{
    private readonly ProgressRing _ring = new() { Width = 128, Height = 128 };
    private readonly TextBlock _ringPct = new() { FontSize = 24, FontWeight = FontWeight.SemiBold, HorizontalAlignment = HorizontalAlignment.Center, FontFeatures = Ui.Styles.TabularDigits };
    private readonly TextBlock _ringSub = new() { FontSize = 11, HorizontalAlignment = HorizontalAlignment.Center, TextAlignment = TextAlignment.Center, MaxWidth = 104, TextWrapping = TextWrapping.Wrap, FontFeatures = Ui.Styles.TabularDigits };
    private readonly WrapPanel _chips = new() { ItemSpacing = 6, LineSpacing = 6 };
    private readonly Border _thermalBanner = new() { CornerRadius = new CornerRadius(8), Padding = new Thickness(12, 7), IsVisible = false, BorderThickness = new Thickness(1) };
    private readonly TextBlock _thermalText = new() { TextWrapping = TextWrapping.Wrap, FontWeight = FontWeight.SemiBold, FontSize = 12.5 };
    private readonly Border _ticker = new() { CornerRadius = new CornerRadius(8), Padding = new Thickness(12, 8), BorderThickness = new Thickness(1) };
    private readonly TextBlock _tickerText = new() { FontFamily = Ui.Styles.Mono, FontSize = 13, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center, Text = "-" };
    private readonly Sparkline _spark = new();
    private readonly TextBlock _sparkSpeed = new() { FontSize = 11, FontFeatures = Ui.Styles.TabularDigits };
    private Grid _live = null!;
    private Border _foundCard = null!;
    private readonly SelectableTextBlock _foundPw = new() { FontFamily = Ui.Styles.Mono, FontSize = 20, FontWeight = FontWeight.SemiBold, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
    private Button _foundCopy = null!, _foundDecrypt = null!;
    private Button _detailsToggle = null!;
    private readonly TextBlock _detailsText = new() { FontSize = 12 };

    private bool _liveActive, _logVisible = true;
    private int _warnCount;
    private List<AttackSpec> _liveSteps = new();
    private int _stepIndex = -1;
    private DateTime _attackStarted;
    private DispatcherTimer? _uiTimer;
    private volatile HashcatStatus? _latest;
    private HashcatStatus? _applied;
    private DateTime _lastSample;
    private ThermalEvent? _thermal;
    private (PillState State, string Text)? _pillBeforeHot;
    private IReadOnlyList<string> _foundPasswords = [];

    /// <summary>Live view, found card and the "Show details" toggle, placed above the log in the file pane.</summary>
    private void BuildLive()
    {
        var ringHost = new Grid { Width = 128, Height = 128, VerticalAlignment = VerticalAlignment.Center };
        ringHost.Children.Add(_ring);
        ringHost.Children.Add(new StackPanel { Spacing = 0, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Children = { _ringPct, _ringSub } });
        _ringSub.Foreground = Palette.DimBrush;

        _thermalBanner.Background = Palette.WarnSoftBrush;
        _thermalBanner.BorderBrush = Palette.WarnBorderBrush;
        _thermalText.Foreground = Palette.WarningBrush;
        _thermalBanner.Child = _thermalText;

        var tickerLabel = new TextBlock { Text = "TRYING", FontSize = 10.5, LetterSpacing = 0.7, Foreground = Palette.DimBrush, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) };
        var tickerRow = new DockPanel();
        DockPanel.SetDock(tickerLabel, Dock.Left);
        tickerRow.Children.Add(tickerLabel);
        tickerRow.Children.Add(_tickerText);
        _ticker.Child = tickerRow;
        _ticker.Background = Palette.InsetBrush;
        _ticker.BorderBrush = Palette.LineBrush;
        ToolTip.SetTip(_ticker, "The mask or wordlist hashcat is working on, as its status reports it");

        var sparkHead = new DockPanel { Margin = new Thickness(0, 0, 0, 4) };
        _sparkSpeed.Foreground = Palette.DimBrush;
        DockPanel.SetDock(_sparkSpeed, Dock.Right);
        sparkHead.Children.Add(_sparkSpeed);
        sparkHead.Children.Add(new TextBlock { Text = "Speed, last 60 s", FontSize = 11, Foreground = Palette.DimBrush });
        var right = new StackPanel { Spacing = 10, VerticalAlignment = VerticalAlignment.Center, Children = { _chips, _thermalBanner, _ticker, new StackPanel { Children = { sparkHead, _spark } } } };

        _live = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = 18, Margin = new Thickness(16, 14, 16, 10), IsVisible = false };
        _live.Children.Add(ringHost);
        Grid.SetColumn(right, 1);
        _live.Children.Add(right);

        // ---- found card
        var check = Icons.Check(22);
        check.Brush = Palette.GoodBrush;
        check.VerticalAlignment = VerticalAlignment.Center;
        check.Margin = new Thickness(0, 0, 12, 0);
        _foundCopy = L.Button("Copy", () => _ = CopyFoundAsync(), 70, isDefault: false);
        _foundCopy.Classes.Add("accent");
        _foundDecrypt = L.Button("Decrypt file...", () => _ = DecryptFoundAsync(), 100);
        var buttons = L.Row(_foundCopy, _foundDecrypt);
        buttons.VerticalAlignment = VerticalAlignment.Center;
        buttons.Margin = new Thickness(12, 0, 0, 0);
        var row = new DockPanel();
        DockPanel.SetDock(check, Dock.Left);
        DockPanel.SetDock(buttons, Dock.Right);
        row.Children.Add(check);
        row.Children.Add(buttons);
        row.Children.Add(_foundPw);
        _foundCard = new Border
        {
            Margin = new Thickness(16, 0, 16, 6), Padding = new Thickness(16, 10), CornerRadius = new CornerRadius(10),
            Background = Palette.GoodSoftBrush, BorderBrush = Palette.GoodBorderBrush, BorderThickness = new Thickness(1),
            Child = row, IsVisible = false,
        };

        // ---- details toggle
        _detailsToggle = new Button
        {
            Content = _detailsText, Padding = new Thickness(8, 4), Margin = new Thickness(8, 0, 0, 2), HorizontalAlignment = HorizontalAlignment.Left,
            IsVisible = false,
        };
        _detailsToggle.Classes.Add("tool");
        _detailsToggle.Click += (_, _) => SetDetails(!_logVisible);
        Avalonia.Automation.AutomationProperties.SetName(_detailsToggle, "Show details");

        // File pane order: file card, live view, found card, toggle, log.
        foreach (var c in new Control[] { _live, _foundCard, _detailsToggle })
        {
            DockPanel.SetDock(c, Dock.Top);
            _filePane.Children.Insert(_filePane.Children.IndexOf(_infoScroll), c);
        }
    }

    /// <summary>Shows or hides the text log under the live view.</summary>
    private void SetDetails(bool show)
    {
        _logVisible = show;
        if (show) _warnCount = 0;
        _infoScroll.IsVisible = show || !_liveActive;
        _detailsText.Text = show ? "▾  Hide details" : _warnCount > 0 ? $"▸  Show details ({_warnCount} warning{(_warnCount == 1 ? "" : "s")})" : "▸  Show details";
        _detailsText.Foreground = !show && _warnCount > 0 ? Palette.WarningBrush : Palette.DimBrush;
        if (show) Dispatcher.UIThread.Post(() => _infoScroll.ScrollToEnd(), DispatcherPriority.Background);
    }

    /// <summary>Back to the plain file view (a new file was opened).</summary>
    private void HideLive()
    {
        StopUiTimer();
        _liveActive = false;
        _live.IsVisible = _foundCard.IsVisible = _detailsToggle.IsVisible = false;
        _infoScroll.IsVisible = true;
        _logVisible = true;
    }

    /// <summary>An attack starts: live view on, log collapsed.</summary>
    private void BeginLive(IReadOnlyList<AttackSpec> steps, string? badge)
    {
        _liveActive = true;
        _liveSteps = steps.ToList();
        _stepIndex = -1;
        _warnCount = 0;
        _thermal = null;
        _latest = _applied = null;
        _foundPasswords = [];
        _attackStarted = DateTime.Now;
        _live.IsVisible = true;
        _foundCard.IsVisible = false;
        _ticker.IsVisible = true;
        _thermalBanner.IsVisible = false;
        _detailsToggle.IsVisible = true;
        _ring.Fill = Palette.AccentBrush;
        _ring.Snap(0);
        _ringPct.Text = "0%";
        _ringPct.FontSize = 24;
        _ringPct.Foreground = Palette.ForegroundBrush;
        _ringSub.Text = "starting...";
        _tickerText.Text = "starting...";
        _sparkSpeed.Text = "";
        _spark.Clear();
        _lastSample = DateTime.MinValue;
        BuildChips();
        SetDetails(false);
        if (badge is not null) _fileCard.SetBadge(badge, FileCard.BadgeKind.Accent);
        _uiTimer ??= new DispatcherTimer(TimeSpan.FromMilliseconds(125), DispatcherPriority.Background, (_, _) => OnUiTick());
        _uiTimer.Start();
    }

    private void StopUiTimer() => _uiTimer?.Stop();

    /// <summary>At most 8 updates a second, whatever rate the engine reports at; one speed sample a second.</summary>
    private void OnUiTick()
    {
        var s = _latest;
        if (s is not null && !ReferenceEquals(s, _applied))
        {
            _applied = s;
            UpdateStatus(s);
            UpdateLive(s);
        }
        if (_applied is { } a && DateTime.UtcNow - _lastSample >= TimeSpan.FromSeconds(1))
        {
            _lastSample = DateTime.UtcNow;
            _spark.Add(_thermal?.State == ThermalState.Paused ? 0 : a.TotalSpeed);
        }
    }

    private void OnStepStarted(int index, int count, string description)
    {
        _stepIndex = index;
        _ring.Snap(0);
        if (_thermal?.State != ThermalState.Paused)
        {
            _ringPct.Text = "0%";
            _ringSub.Text = count > 1 ? $"step {index + 1} of {count}" : "starting...";
        }
        ToolTip.SetTip(_ring, description);
        _tickerText.Text = "starting...";
        BuildChips();
    }

    private void UpdateLive(HashcatStatus s)
    {
        if (!_liveActive) return;
        _ring.Value = Math.Clamp(s.Fraction, 0, 1);
        double speed = s.TotalSpeed;
        _tickerText.Text = TryingText(s);
        _sparkSpeed.Text = Fmt.Speed(speed);
        if (_thermal?.State == ThermalState.Paused) return;
        _ringPct.Text = $"{Math.Floor(s.Fraction * 100):0}%";
        long remaining = Math.Max(0, s.ProgressTotal - s.ProgressDone);
        _ringSub.Text = s.Status == 3 && speed > 0 ? Fmt.Duration(remaining / speed) + " left" : s.StatusText;
    }

    /// <summary>Scenario steps: done (check), current (pulsing dot), still to come (dim). Long scenarios are folded.</summary>
    private void BuildChips()
    {
        _chips.Children.Clear();
        int n = _liveSteps.Count;
        _chips.IsVisible = n > 1;
        if (n <= 1) return;
        int cur = Math.Max(0, _stepIndex);
        int first = 0, last = n - 1;
        if (n > 6) { first = Math.Max(0, cur - 1); last = Math.Min(n - 1, first + 3); }
        if (first > 0) _chips.Children.Add(Chip($"{first} done", ChipState.Done, null));
        for (int i = first; i <= last; i++)
        {
            var state = _stepIndex < 0 ? (i == 0 ? ChipState.Now : ChipState.Next) : i < cur ? ChipState.Done : i == cur ? ChipState.Now : ChipState.Next;
            if (_finishedAll && i <= cur) state = ChipState.Done;
            _chips.Children.Add(Chip(ChipLabel(_liveSteps[i]), state, _liveSteps[i].Describe()));
        }
        if (last < n - 1) _chips.Children.Add(Chip($"+{n - 1 - last} more", ChipState.Next, null));
    }

    private bool _finishedAll;

    private enum ChipState { Done, Now, Next }

    private static Control Chip(string text, ChipState state, string? tip)
    {
        var label = new TextBlock { Text = text, FontSize = 11, MaxWidth = 190, TextTrimming = TextTrimming.CharacterEllipsis, VerticalAlignment = VerticalAlignment.Center };
        var content = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
        var b = new Border { CornerRadius = new CornerRadius(999), Padding = new Thickness(9, 4), BorderThickness = new Thickness(1), Child = content };
        switch (state)
        {
            case ChipState.Done:
                var check = Icons.Check(11);
                check.Brush = Palette.SuccessBrush;
                check.VerticalAlignment = VerticalAlignment.Center;
                content.Children.Add(check);
                label.Foreground = Palette.SuccessBrush;
                b.BorderBrush = Palette.GoodBorderBrush;
                break;
            case ChipState.Now:
                var dot = new Ellipse { Width = 6, Height = 6, Fill = Palette.AccentBrush, VerticalAlignment = VerticalAlignment.Center };
                dot.Classes.Add("pulse");
                content.Children.Add(dot);
                label.Foreground = Palette.ForegroundBrush;
                b.BorderBrush = Palette.AccentBrush;
                b.Background = Palette.AccentSoftBrush;
                break;
            default:
                label.Foreground = Palette.DimBrush;
                b.BorderBrush = Palette.LineBrush;
                break;
        }
        content.Children.Add(label);
        if (tip is not null) ToolTip.SetTip(b, tip);
        return b;
    }

    /// <summary>A short name for a scenario step.</summary>
    internal static string ChipLabel(AttackSpec a) => a.Kind switch
    {
        AttackKind.BruteForce => a.Mask.Length > 0 ? $"Brute-force {a.Mask}" : $"Brute-force, {a.MinLength}-{a.MaxLength} chars",
        AttackKind.Mask => "Mask " + a.HashcatMask,
        AttackKind.KeySearch => "Key search",
        _ => a.Rules switch
        {
            RulesPreset.AsIs => "Dictionary",
            RulesPreset.TwoWords or RulesPreset.TwoWordsAdvanced => "Two-word combos",
            RulesPreset.ThreeWords => "Three-word combos",
            RulesPreset.CustomFile => "Dictionary + rules",
            _ => "Dictionary + mutations",
        },
    };

    // ------------------------------------------------------------------ thermal guard

    /// <summary>The GPU temperature guard paused or resumed the attack.</summary>
    private void OnThermal(ThermalEvent e)
    {
        _thermal = e;
        bool paused = e.State == ThermalState.Paused;
        if (e.Temperature >= 0) _gpuTemp = e.Temperature;
        if (paused)
        {
            _pillBeforeHot ??= (_pillState, _pillBase);
            _ring.Fill = Palette.WarnBrush;
            _ringPct.Text = "Cooling";
            _ringPct.FontSize = 19;
            _ringPct.Foreground = Palette.WarningBrush;
            ShowCooling(e.Temperature, e.ResumeBelow);
            _thermalBanner.IsVisible = _liveActive;
            _progress.Fill = Palette.WarnBrush;
            _progress.Sheen = false;
            _band.Background = TintedBand(Palette.WarnSoftBrush);
            _estTime.Text = "Paused";
            _statusRight.Text = "Paused (GPU cooling)";
        }
        else
        {
            if (_pillBeforeHot is { } p) { _pillBeforeHot = null; SetPill(p.State, p.Text); }
            _ring.Fill = Palette.AccentBrush;
            _ringPct.FontSize = 24;
            _ringPct.Foreground = Palette.ForegroundBrush;
            _thermalBanner.IsVisible = false;
            _progress.Fill = Palette.AccentBrush;
            _progress.Sheen = _cts is not null;
            _band.Background = Palette.StatusBandBrush;
            if (_applied is { } s) { UpdateStatus(s); UpdateLive(s); }
        }
    }

    /// <summary>The temperature while paused, kept current from hashcat's status.</summary>
    private void ShowCooling(int temperature, int resumeBelow)
    {
        SetPill(PillState.Hot, temperature >= 0 ? $"Cooling: GPU {temperature} °C" : "Cooling down the GPU");
        _ringSub.Text = temperature >= 0 ? $"GPU {temperature} °C" : "GPU too hot";
        _thermalText.Text = temperature >= 0
            ? $"Paused: GPU at {temperature} °C, resumes below {resumeBelow} °C"
            : $"Paused: the GPU is too hot, resumes below {resumeBelow} °C";
    }

    // ------------------------------------------------------------------ end of an attack

    /// <summary>Final state of the live view after an attack.</summary>
    private void FinishLive(SessionResult result)
    {
        StopUiTimer();
        if (_latest is { } last && !ReferenceEquals(last, _applied)) { _applied = last; UpdateLive(last); }
        if (_thermal?.State == ThermalState.Paused) OnThermal(new ThermalEvent(ThermalState.Normal, -1, _thermal.Limit, _thermal.ResumeBelow));
        _ticker.IsVisible = false;
        _ringPct.FontSize = 20;
        string elapsed = Fmt.Duration((DateTime.Now - _attackStarted).TotalSeconds);
        switch (result.Outcome)
        {
            case SessionOutcome.Found:
            case SessionOutcome.FoundInCache:
                _finishedAll = false;
                if (_stepIndex >= 0) { _finishedAll = true; BuildChips(); _finishedAll = false; }
                _ring.Fill = Palette.GoodBrush;
                _ring.Value = 1;
                _ringPct.Text = "Found";
                _ringPct.Foreground = Palette.SuccessBrush;
                _ringSub.Text = result.Outcome == SessionOutcome.FoundInCache ? "in the password cache" : $"after {elapsed}";
                ShowFoundCard(result.Passwords);
                _fileCard.SetBadge("Password found", FileCard.BadgeKind.Good);
                break;
            case SessionOutcome.KeyRecovered:
                _ring.Fill = Palette.GoodBrush;
                _ring.Value = 1;
                _ringPct.Text = "Key found";
                _ringPct.Foreground = Palette.SuccessBrush;
                _ringSub.Text = $"after {elapsed}";
                _fileCard.SetBadge("Encryption key found", FileCard.BadgeKind.Good);
                SetDetails(true);
                break;
            case SessionOutcome.NotFound:
                _finishedAll = true; BuildChips(); _finishedAll = false;
                _ring.Value = 1;
                _ring.Fill = Palette.DimBrush;
                _ringPct.Text = "Done";
                _ringPct.Foreground = Palette.ForegroundBrush;
                _ringSub.Text = "not found";
                _fileCard.SetBadge("Not found", FileCard.BadgeKind.Warn);
                SetDetails(true);
                break;
            case SessionOutcome.Stopped:
                _ringPct.Text = "Stopped";
                _ringPct.Foreground = Palette.ForegroundBrush;
                _ringSub.Text = "can be continued";
                _fileCard.SetBadge("Stopped", FileCard.BadgeKind.Neutral);
                SetDetails(true);
                break;
            default:
                _ring.Fill = Palette.ErrorBrush;
                _ringPct.Text = "Error";
                _ringPct.Foreground = Palette.ErrorBrush;
                _ringSub.Text = "see details";
                _fileCard.SetBadge("Error", FileCard.BadgeKind.Bad);
                SetDetails(true);
                break;
        }
    }

    private void ShowFoundCard(IReadOnlyList<string> passwords)
    {
        _foundPasswords = passwords;
        if (passwords.Count == 0) { _foundCard.IsVisible = false; return; }
        var first = passwords[0];
        _foundPw.Text = (first.Length == 0 ? "(empty password)" : first) + (passwords.Count > 1 ? $"  (+{passwords.Count - 1} more)" : "");
        _foundPw.FontStyle = first.Length == 0 ? FontStyle.Italic : FontStyle.Normal;
        _foundCopy.IsEnabled = first.Length > 0;
        _foundCopy.Content = "Copy";
        _foundDecrypt.IsVisible = _current?.Target is { } t && OfficeDecryptor.CanDecrypt(t.FormatId);
        _foundCard.IsVisible = true;
        if (!Platform.ReduceMotion) _ = RiseAsync(_foundCard);
    }

    /// <summary>A short rise-and-fade for a card that just appeared.</summary>
    internal static async Task RiseAsync(Control c)
    {
        var shift = new TranslateTransform(0, 8);
        c.RenderTransform = shift;
        c.Opacity = 0;
        var t0 = DateTime.UtcNow;
        while (true)
        {
            double t = Math.Min(1, (DateTime.UtcNow - t0).TotalMilliseconds / 420);
            double e = 1 - Math.Pow(1 - t, 3);
            c.Opacity = e;
            shift.Y = 8 * (1 - e);
            if (t >= 1) break;
            await Task.Delay(16);
        }
        c.RenderTransform = null;
    }

    private async Task CopyFoundAsync()
    {
        if (_foundPasswords.Count == 0 || _foundPasswords[0].Length == 0) return;
        if (!await CopyAsync(_foundPasswords[0])) return;
        _foundCopy.Content = "Copied";
        await Task.Delay(1800);
        _foundCopy.Content = "Copy";
    }

    private async Task DecryptFoundAsync()
    {
        if (_current is not { } det || _foundPasswords.Count == 0) return;
        await DecryptWithDialogAsync(det, _foundPasswords[0], this);
    }

    /// <summary>"Decrypt file...": asks where to save a decrypted copy (MS Office 2007-2021), then writes it.</summary>
    internal async Task DecryptWithDialogAsync(Detection det, string password, Window owner)
    {
        var ext = Path.GetExtension(det.FilePath);
        var suggested = Path.GetFileNameWithoutExtension(det.FilePath) + _settings.DecryptSuffix + ext;
        var filter = $"Same type (*{ext})|*{ext}|All files|*.*";
        var outPath = await Pick.Save(owner, filter, suggested, Path.GetDirectoryName(det.FilePath), ext.TrimStart('.'));
        if (outPath is null) return;
        if (DecryptTo(det, password, outPath))
            await Msg.Info(owner, "The decrypted copy was saved to:\n" + outPath, "Decrypt file");
        else
            SetDetails(true);
    }
}
