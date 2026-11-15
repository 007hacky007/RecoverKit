using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Shapes;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using RecoverKit.App.Ui;
using RecoverKit.Core.Dependencies;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Views;

public enum DependenciesOutcome { Installed, Skipped }

/// <summary>
/// The "Getting RecoverKit ready" page: one row per dependency with a traffic light, the licenses to accept
/// and "Install all". Completes once everything needed is installed, or when the user skips.
/// </summary>
public sealed class DependenciesPage : UserControl
{
    private const string PendingReason = "Checked once hashcat is ready";

    private readonly Func<Task<IReadOnlyList<DependencyItem>>> _rescan;
    private readonly DependencyInstaller _installer;
    private readonly TaskCompletionSource<(DependenciesOutcome, IReadOnlyList<string>)> _done = new(TaskCreationOptions.RunContinuationsAsynchronously);

    // Row keys (SkipKey, or the id) of yellow rows the user unchecked; survives "Check again".
    private readonly HashSet<string> _unchecked;
    // Licenses (by URL or name) the user accepted; survives "Check again".
    private readonly HashSet<string> _accepted = [];

    private IReadOnlyList<DependencyItem> _items;
    private readonly List<CheckBox> _rowChecks = [];
    private readonly List<(DependencyItem Item, Control Line, CheckBox Accept)> _licenses = [];
    private readonly Dictionary<DependencyId, (Ellipse Light, TextBlock Reason)> _rowParts = [];

    private readonly StackPanel _rows = L.Column(0);
    private readonly StackPanel _licenseList = L.Column(6);
    private readonly TextBlock _total = L.Text("", dim: true);
    private readonly HyperlinkButton _checkAgain = new() { Content = "Check again", Padding = new Thickness(0), VerticalAlignment = VerticalAlignment.Center };
    private readonly Button _skip;
    private readonly Button _install;
    private readonly ProgressBar _bar = new() { Minimum = 0, Maximum = 1000, Height = 6, MinHeight = 6, IsVisible = false };
    private readonly TextBlock _status = L.Text("", dim: true, wrap: true);
    private readonly TextBlock _sub = L.Text("", dim: true, wrap: true);

    private readonly Dictionary<DependencyId, string> _lastMessage = [];

    private CancellationTokenSource? _cts;
    private bool _scanning;

    public DependenciesPage(IReadOnlyList<DependencyItem> items, IReadOnlyCollection<string> skipped,
        Func<Task<IReadOnlyList<DependencyItem>>> rescan, DependencyInstaller installer)
    {
        _items = items;
        _unchecked = [.. skipped];
        _rescan = rescan;
        _installer = installer;

        _skip = L.Button("Skip for now", () =>
        {
            if (!Installing) { Skip(); return; }
            _cts?.Cancel();
            Refresh();
        }, 110);
        _install = L.Button("Install all", () => _ = InstallAsync(), 110, isDefault: true);
        _checkAgain.Click += (_, _) => _ = CheckAgainAsync();
        _status.IsVisible = false;

        var heading = new TextBlock { Text = "Getting RecoverKit ready", FontSize = 17, FontWeight = FontWeight.SemiBold };
        _sub.FontSize = 12.5;

        var footer = new DockPanel { Margin = new Thickness(0, 6, 0, 0) };
        var buttons = L.Row(Platform.IsMac ? [_skip, _install] : [_install, _skip]);
        DockPanel.SetDock(buttons, Dock.Right);
        footer.Children.Add(buttons);
        var left = L.Row(_total, _checkAgain);
        left.Spacing = 14;
        left.VerticalAlignment = VerticalAlignment.Center;
        footer.Children.Add(left);

        var body = L.Column(10, heading, _sub, _rows, _licenseList, _bar, _status, footer);
        body.MaxWidth = 640;
        body.Margin = new Thickness(28, 24);
        body.HorizontalAlignment = HorizontalAlignment.Center;
        body.VerticalAlignment = VerticalAlignment.Center;

        Content = new Border
        {
            Background = Palette.PaneBrush,
            Child = new ScrollViewer
            {
                Content = body, VerticalAlignment = VerticalAlignment.Stretch,
                HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled,
            },
        };
        BuildRows();
    }

    /// <summary>Installed when everything needed is in place, Skipped on "Skip for now"; NewlySkipped holds the SkipKeys to remember.</summary>
    public Task<(DependenciesOutcome Outcome, IReadOnlyList<string> NewlySkipped)> Completion => _done.Task;

    public bool Installing { get; private set; }

    /// <summary>True once any component finished installing, also when the user cancelled or skipped afterwards.</summary>
    public bool AnythingInstalled { get; private set; }

    /// <summary>"Skip for now": remembers every installable yellow row as skipped. Ignored while installing.</summary>
    public void Skip()
    {
        if (Installing || _done.Task.IsCompleted) return;
        var keys = _items.Where(IsOptional).Select(i => i.SkipKey).OfType<string>().Distinct().ToList();
        _done.TrySetResult((DependenciesOutcome.Skipped, keys));
    }

    private static bool IsOptional(DependencyItem i) => !i.Pending && i.Light == Light.Yellow && i.Installable;
    private static bool HasCheckBox(DependencyItem i) => !i.Pending && i.Light != Light.Green && i.Installable;
    private static string RowKey(DependencyItem i) => i.SkipKey ?? i.Id.ToString();
    private static string LicenseKey(DependencyItem i) => i.LicenseUrl ?? i.LicenseName ?? "";
    private bool IsChecked(DependencyItem i) => HasCheckBox(i) && (i.Light == Light.Red || !_unchecked.Contains(RowKey(i)));

    // ---- rows

    private void BuildRows()
    {
        _rows.Children.Clear();
        _rowChecks.Clear();
        _rowParts.Clear();
        _licenses.Clear();
        _licenseList.Children.Clear();
        for (int n = 0; n < _items.Count; n++)
        {
            var item = _items[n];
            _rows.Children.Add(BuildRow(item, n > 0));
            if (HasCheckBox(item) && !string.IsNullOrEmpty(item.LicenseName)) AddLicense(item);
        }
        Refresh();
    }

    private Control BuildRow(DependencyItem item, bool divider)
    {
        var light = new Ellipse { Width = 12, Height = 12, VerticalAlignment = VerticalAlignment.Center };
        var ring = new Border
        {
            Width = 18, Height = 18, CornerRadius = new CornerRadius(9), BorderThickness = new Thickness(3),
            VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 1, 0, 0), Child = light,
        };
        var reason = L.Text("", dim: true, wrap: true);
        reason.FontSize = 12;
        Paint(item, light, ring, reason);
        _rowParts[item.Id] = (light, reason);

        var g = L.Grid("Auto,*,Auto,Auto", rowSpacing: 1, columnSpacing: 12);
        g.Put(ring, 0, 0, rowSpan: 2);
        g.Put(L.Text(item.Name, bold: true), 0, 1);
        g.Put(reason, 1, 1);
        if (HasCheckBox(item) && item.DownloadBytes > 0)
        {
            var size = L.Text(Fmt.Size(item.DownloadBytes), dim: true);
            size.HorizontalAlignment = HorizontalAlignment.Right;
            size.FontFeatures = Ui.Styles.TabularDigits;
            g.Put(size, 0, 2, rowSpan: 2);
        }
        if (HasCheckBox(item))
        {
            var check = new CheckBox { IsChecked = IsChecked(item), VerticalAlignment = VerticalAlignment.Center, MinWidth = 0, Padding = new Thickness(0) };
            check.Tag = item;
            check.IsCheckedChanged += (_, _) =>
            {
                if (item.Light == Light.Red) return;
                if (check.IsChecked == true) _unchecked.Remove(RowKey(item));
                else _unchecked.Add(RowKey(item));
                Refresh();
            };
            _rowChecks.Add(check);
            g.Put(check, 0, 3, rowSpan: 2);
        }
        return new Border
        {
            Padding = new Thickness(0, 10), Child = g,
            BorderBrush = Palette.LineBrush, BorderThickness = new Thickness(0, divider ? 1 : 0, 0, 0),
        };
    }

    private static void Paint(DependencyItem item, Ellipse light, Border ring, TextBlock reason)
    {
        (light.Fill, ring.BorderBrush) = item.Pending
            ? (Palette.DimBrush, Palette.TrackBrush)
            : item.Light switch
            {
                Light.Green => (Palette.GoodBrush, Palette.GoodSoftBrush),
                Light.Yellow => (Palette.WarnBrush, Palette.WarnSoftBrush),
                _ => (Palette.BadTextBrush, Palette.BadSoftBrush),
            };
        reason.Text = item.Pending ? PendingReason : item.Reason;
    }

    private void AddLicense(DependencyItem item)
    {
        var accept = new CheckBox { Content = "I accept the", IsChecked = _accepted.Contains(LicenseKey(item)), VerticalAlignment = VerticalAlignment.Center };
        accept.IsCheckedChanged += (_, _) =>
        {
            if (accept.IsChecked == true) _accepted.Add(LicenseKey(item));
            else _accepted.Remove(LicenseKey(item));
            Refresh();
        };
        Control name = Uri.TryCreate(item.LicenseUrl, UriKind.Absolute, out var uri)
            ? new HyperlinkButton { Content = item.LicenseName, NavigateUri = uri, Padding = new Thickness(0), VerticalAlignment = VerticalAlignment.Center }
            : L.Text(item.LicenseName!);
        var line = L.Row(accept, name);
        line.Spacing = 4;
        _licenses.Add((item, line, accept));
        _licenseList.Children.Add(line);
    }

    /// <summary>Updates the license lines, the total and the buttons after any change.</summary>
    private void Refresh()
    {
        bool busy = Installing || _scanning;
        var selected = _items.Where(IsChecked).ToList();
        foreach (var (item, line, accept) in _licenses)
        {
            line.IsVisible = IsChecked(item);
            accept.IsEnabled = !busy;
        }
        _licenseList.IsVisible = _licenses.Any(l => l.Line.IsVisible);
        foreach (var c in _rowChecks) c.IsEnabled = !busy && ((DependencyItem)c.Tag!).Light != Light.Red;

        long total = selected.Sum(i => i.DownloadBytes);
        _total.Text = total > 0 ? Fmt.Size(total) + " to download" : "";
        _total.IsVisible = total > 0;
        _checkAgain.IsEnabled = !busy;
        bool licensed = _licenses.Where(l => l.Line.IsVisible).All(l => l.Accept.IsChecked == true);
        _install.IsEnabled = !busy && selected.Count > 0 && licensed;
        _install.Content = selected.Count > 0 && selected.All(i => i.Action == DependencyAction.RepairHashcat) ? "Repair" : "Install all";
        // Nothing to install (opened from Tools with every row green or fixable only outside RecoverKit).
        bool nothingToDo = !_items.Any(HasCheckBox);
        _sub.Text = !nothingToDo
            ? "A few components are missing. Install them once and RecoverKit won't ask again."
            : _items.All(i => !i.Pending && i.Light == Light.Green)
                ? "Everything RecoverKit needs is in place."
                : "Nothing here can be installed by RecoverKit. Follow the notes below, then Check again.";
        _skip.Content = Installing ? "Cancel" : nothingToDo ? "Close" : "Skip for now";
        _skip.IsEnabled = Installing ? !_scanning && _cts is { IsCancellationRequested: false } : !_scanning;
    }

    private void ShowStatus(string text)
    {
        _status.Text = text;
        _status.IsVisible = text.Length > 0;
    }

    // ---- actions

    private async Task CheckAgainAsync()
    {
        if (Installing || _scanning || _done.Task.IsCompleted) return;
        _scanning = true;
        ShowStatus("Checking...");
        Refresh();
        try
        {
            _items = await _rescan();
            ShowStatus("");
        }
        catch (Exception ex)
        {
            RecoverKit.Core.DebugLog.Error("Dependency check failed", ex);
            ShowStatus("Could not check again: " + ex.Message);
        }
        finally
        {
            _scanning = false;
            BuildRows();
        }
    }

    private async Task InstallAsync()
    {
        if (Installing || _scanning || _done.Task.IsCompleted || !_install.IsEnabled) return;
        var selected = _items.Where(IsChecked).ToList();
        if (selected.Count == 0) return;
        var newlySkipped = _items.Where(i => IsOptional(i) && !IsChecked(i)).Select(i => i.SkipKey).OfType<string>().Distinct().ToList();

        Installing = true;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _lastMessage.Clear();
        _bar.Value = 0;
        _bar.IsVisible = true;
        ShowStatus("Starting...");
        Refresh();

        var progress = new UiProgress(this);
        try
        {
            IReadOnlyList<(DependencyItem Item, Exception? Error)> results;
            try
            {
                results = await Task.Run(() => _installer.InstallAllAsync(selected, progress, ct), CancellationToken.None);
            }
            catch (OperationCanceledException)
            {
                // Rows that finished before the cancel were already marked green by their "done" report.
                ShowStatus("Cancelled.");
                return;
            }
            progress.Stop();

            var failures = new Dictionary<DependencyId, string>();
            foreach (var (item, error) in results)
            {
                if (error is null)
                {
                    AnythingInstalled = true;
                    SetItem(item.Id, i => i with { Light = Light.Green, Reason = item.Action == DependencyAction.RepairHashcat ? "Repaired. hashcat starts again." : "Installed.", Pending = false });
                }
                else
                {
                    failures[item.Id] = error.Message;
                    SetItem(item.Id, i => i with { Reason = error.Message });
                }
            }
            BuildRows();
            foreach (var id in failures.Keys)
                if (_items.FirstOrDefault(i => i.Id == id) is { } failed) MarkRow(failed with { Light = Light.Red, Pending = false });

            ShowStatus(failures.Count > 0 ? "Some components could not be installed. Checking again..." : "Checking again...");
            _scanning = true;
            Refresh();
            IReadOnlyList<DependencyItem> fresh;
            try { fresh = await _rescan(); }
            catch (Exception ex)
            {
                RecoverKit.Core.DebugLog.Error("Dependency check failed", ex);
                ShowStatus("Could not check again: " + ex.Message);
                return;
            }

            bool needsMore = fresh.Any(i => !i.Pending && i.Light == Light.Red)
                             || fresh.Any(i => IsOptional(i) && !_unchecked.Contains(RowKey(i)));
            if (!needsMore)
            {
                _done.TrySetResult((DependenciesOutcome.Installed, newlySkipped));
                return;
            }

            // Stay open with the new rows; a failed row stays red with the error until Check again or the page closes.
            _items = [.. fresh.Select(i => failures.TryGetValue(i.Id, out var msg) && i.Light != Light.Green && !i.Pending ? i with { Light = Light.Red, Reason = msg } : i)];
            ShowStatus(failures.Count > 0 ? "Some components could not be installed." : "");
            BuildRows();
        }
        catch (Exception ex)
        {
            RecoverKit.Core.DebugLog.Error("Installing dependencies failed", ex);
            ShowStatus("Install failed: " + ex.Message);
        }
        finally
        {
            progress.Stop();
            Installing = false;
            _scanning = false;
            _bar.IsVisible = false;
            _cts.Dispose();
            _cts = null;
            Refresh();
        }
    }

    private void SetItem(DependencyId id, Func<DependencyItem, DependencyItem> change)
        => _items = [.. _items.Select(i => i.Id == id ? change(i) : i)];

    private void MarkRow(DependencyItem item)
    {
        if (!_rowParts.TryGetValue(item.Id, out var parts) || parts.Light.Parent is not Border ring) return;
        Paint(item, parts.Light, ring, parts.Reason);
    }

    /// <summary>The row turns green as soon as its component finishes and leaves the checked set and the total, also if the user cancels later.</summary>
    private void OnDone(DependencyItem item)
    {
        AnythingInstalled = true;
        if (_done.Task.IsCompleted || _items.FirstOrDefault(i => i.Id == item.Id) is not { } row || row.Light == Light.Green) return;
        SetItem(item.Id, i => i with { Light = Light.Green, Reason = item.Action == DependencyAction.RepairHashcat ? "Repaired. hashcat starts again." : "Installed.", Pending = false });
        BuildRows();
    }

    private void OnProgress(DependencyItem item, InstallProgress p)
    {
        if (!Installing) return;
        // Byte reports carry no message; keep the last one this component gave ("Downloading NVIDIA NVRTC 12.8.93 ...").
        string msg = p.Message.TrimEnd('.', ' ');
        if (msg.Length > 0) _lastMessage[item.Id] = msg;
        else if (!_lastMessage.TryGetValue(item.Id, out msg!)) msg = "Installing " + item.Name;
        if (p.BytesTotal > 0)
        {
            _bar.IsIndeterminate = false;
            _bar.Value = p.Fraction * 1000;
            ShowStatus($"{msg}... {p.Fraction * 100:0}%");
        }
        else
        {
            _bar.IsIndeterminate = true;
            ShowStatus(msg + "...");
        }
    }

    /// <summary>Forwards installer progress, reported from any thread, to the UI thread.</summary>
    private sealed class UiProgress(DependenciesPage page) : IProgress<(DependencyItem Item, InstallProgress Progress)>
    {
        private volatile bool _stopped;

        public void Stop()
        {
            _stopped = true;
            page._bar.IsIndeterminate = false;
        }

        public void Report((DependencyItem Item, InstallProgress Progress) value)
        {
            // A finished component is never dropped, even when it arrives after a cancel ended the install.
            bool done = value.Progress.Stage == "done";
            if (_stopped && !done) return;
            Dispatcher.UIThread.Post(() => { if (done) page.OnDone(value.Item); else if (!_stopped) page.OnProgress(value.Item, value.Progress); });
        }
    }
}
