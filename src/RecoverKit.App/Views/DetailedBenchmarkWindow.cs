using System.Diagnostics;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Hashcat;

namespace RecoverKit.App.Views;

/// <summary>Runs isolated diagnostics and keeps completed measurements when abandoned.</summary>
public sealed class DetailedBenchmarkWindow : Window
{
    private readonly HashcatTool? _hashcat;
    private readonly Settings _settings;
    private readonly IReadOnlyList<BackendDevice> _devices;
    private readonly List<(string Id, CheckBox Box)> _sections = [];
    private readonly TextBlock _estimate = L.Text("", dim: true, wrap: true);
    private readonly TextBlock _section = L.Text("Ready", bold: true);
    private readonly TextBlock _step = L.Text("", wrap: true);
    private readonly TextBlock _timing = L.Text("", dim: true);
    private readonly SelectableTextBlock _results = new() { TextWrapping = TextWrapping.Wrap };
    private readonly ProgressBar _bar = new() { IsIndeterminate = true, Height = 5, IsVisible = false };
    private readonly Control _selectionGroup;
    private readonly Button _start;
    private readonly Button _save;
    private readonly Button _copy;
    private readonly Button _abandon;
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly Stopwatch _elapsed = new();
    private CancellationTokenSource? _cts;
    private DiagnosticReport? _report;
    private TimeSpan _remaining;
    private TimeSpan _lastElapsed;
    private bool _running;

    public DetailedBenchmarkWindow(HashcatTool? hashcat, Settings settings, IReadOnlyList<BackendDevice> devices)
    {
        _hashcat = hashcat;
        _settings = settings;
        _devices = devices;
        Title = "Detailed performance test";
        Icon = Icons.AppIcon();
        Width = 780;
        Height = 650;
        MinWidth = 590;
        MinHeight = 420;
        CanMinimize = false;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var selection = L.Column(4);
        foreach (var section in DetailedBenchmarkRunner.Sections)
        {
            var box = new CheckBox
            {
                Content = new TextBlock { Text = $"{section.Title} - about {section.EstimatedMinutes:N0} min", TextWrapping = TextWrapping.Wrap },
                IsChecked = true,
            };
            _sections.Add((section.Id, box));
            box.IsCheckedChanged += (_, _) => UpdateEstimate();
            selection.Children.Add(box);
        }
        _start = L.Button("Start detailed test", () => _ = RunAsync(), 155, isDefault: true);
        _save = L.Button("Save report...", () => _ = SaveAsync(), 125);
        _copy = L.Button("Copy summary", () => _ = CopyAsync(), 120);
        _save.IsEnabled = _copy.IsEnabled = false;
        _abandon = L.Button("Close", () => { if (_running) Abandon(); else Close(); }, 95, isCancel: true);
        var footer = L.Footer(_copy, _save, _start, _abandon);
        _selectionGroup = L.Group("Sections", selection);
        var body = L.Column(12,
            L.Text("Detailed performance test", bold: true, size: 22),
            L.Text("Measures every engine and device in detail so the developers can tune RecoverKit for this PC.", wrap: true),
            _estimate,
            _selectionGroup,
            L.Text("Uses only synthetic targets. Your files, recovery sessions and settings are kept intact. You can abandon the test and save its partial results.", dim: true, wrap: true),
            _bar, _section, _step, _timing, _results);
        var root = new DockPanel();
        DockPanel.SetDock(footer, Dock.Bottom);
        root.Children.Add(footer);
        root.Children.Add(new ScrollViewer
        {
            Content = new Border { Padding = new Thickness(22, 18), Child = body },
            HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled,
        });
        Content = root;
        _timer.Tick += (_, _) => UpdateTiming();
        Closing += (_, e) =>
        {
            if (!_running) return;
            e.Cancel = true;
            Abandon();
        };
        Closed += (_, _) => { _timer.Stop(); _cts?.Dispose(); };
        UpdateEstimate();
    }

    private void UpdateEstimate()
    {
        double minutes = DetailedBenchmarkRunner.Sections.Where(s => _sections.Any(c => c.Id == s.Id && c.Box.IsChecked == true))
            .Sum(s => s.EstimatedMinutes);
        _estimate.Text = $"Takes about {minutes:N0} minutes for the selected sections. More devices and first-time GPU compilation can take longer.";
        if (_start is not null) _start.IsEnabled = _sections.Any(s => s.Box.IsChecked == true);
    }

    private void Abandon()
    {
        _cts?.Cancel();
        _abandon.IsEnabled = false;
        _step.Text = "Stopping safely and keeping completed measurements...";
    }

    private void UpdateTiming()
    {
        var remaining = _remaining - (_elapsed.Elapsed - _lastElapsed);
        if (remaining < TimeSpan.Zero) remaining = TimeSpan.Zero;
        _timing.Text = $"Elapsed {_elapsed.Elapsed:hh\\:mm\\:ss} - estimated remaining {remaining:hh\\:mm\\:ss}";
    }

    private async Task RunAsync()
    {
        if (_running) return;
        _running = true;
        _cts?.Dispose();
        _cts = new CancellationTokenSource();
        _start.IsEnabled = _save.IsEnabled = _copy.IsEnabled = false;
        _selectionGroup.IsVisible = _estimate.IsVisible = false;
        foreach (var (_, box) in _sections) box.IsEnabled = false;
        _abandon.Content = "Abandon";
        _bar.IsVisible = true;
        _elapsed.Restart();
        _timer.Start();
        _results.Text = "";
        var selected = _sections.Where(s => s.Box.IsChecked == true).Select(s => s.Id).ToArray();
        var progress = new Progress<DiagnosticProgress>(p =>
        {
            if (!_running) return;
            _section.Text = p.Section;
            _step.Text = p.Step;
            _remaining = p.EstimatedRemaining;
            _lastElapsed = _elapsed.Elapsed;
            UpdateTiming();
        });
        try
        {
            var runner = new DetailedBenchmarkRunner(_hashcat, _settings, _devices);
            _report = await Task.Run(() => runner.RunAsync(selected, progress, _cts.Token));
            _section.Text = _report.Cancelled ? "Test abandoned - partial report ready" : "Report ready";
            _step.Text = "Save the report and send the file to the developers.";
            var text = new StringBuilder(DiagnosticHtml.Summary(_report));
            foreach (var group in _report.Measurements.GroupBy(m => m.Section))
            {
                text.AppendLine().AppendLine().AppendLine(group.Key);
                foreach (var row in group)
                {
                    text.Append(row.Step).Append(": ");
                    if (row.Error is not null) text.Append(row.Error);
                    else if (row.Speed > 0) text.Append($"{row.Speed:N0} candidates/s");
                    else text.Append(row.Correct ? "PASS" : "not measured");
                    text.AppendLine();
                }
            }
            _results.Text = DiagnosticHtml.Scrub(text.ToString());
        }
        catch (Exception ex)
        {
            _section.Text = "The test could not finish";
            _step.Text = DiagnosticHtml.Scrub(ex.Message);
        }
        finally
        {
            _running = false;
            _elapsed.Stop();
            _timer.Stop();
            _bar.IsVisible = false;
            _timing.Text = $"Elapsed {_elapsed.Elapsed:hh\\:mm\\:ss}";
            _save.IsEnabled = _copy.IsEnabled = _report is not null;
            _abandon.IsEnabled = true;
            _abandon.Content = "Close";
        }
    }

#if DEBUG
    internal async Task DebugRunAsync(string directory, string? sections)
    {
        Directory.CreateDirectory(directory);
        if (!string.IsNullOrWhiteSpace(sections))
        {
            var chosen = sections.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            foreach (var (id, box) in _sections) box.IsChecked = chosen.Contains(id, StringComparer.OrdinalIgnoreCase);
        }
        await Snapshots.Save(this, Path.Combine(directory, "detailed-start.png"));
        var running = RunAsync();
        await Task.Delay(1800);
        await Snapshots.Save(this, Path.Combine(directory, "detailed-running.png"));
        await running;
        if (_report is not null)
            await File.WriteAllTextAsync(Path.Combine(directory, "detailed-gui.html"), DiagnosticHtml.Render(_report));
        await Snapshots.Save(this, Path.Combine(directory, "detailed-finished.png"));
    }
#endif

    private async Task SaveAsync()
    {
        if (_report is null) return;
        var path = await Pick.Save(this, "HTML files (*.html)|*.html", $"RecoverKit-performance-{DateTime.Now:yyyy-MM-dd}.html", defaultExt: "html");
        if (path is null) return;
        try { await File.WriteAllTextAsync(path, DiagnosticHtml.Render(_report), new UTF8Encoding(false)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { await Msg.Error(this, ex.Message, Title); }
    }

    private async Task CopyAsync()
    {
        if (_report is null || Clipboard is null) return;
        try { await Clipboard.SetTextAsync(DiagnosticHtml.Summary(_report)); }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException)
        { await Msg.Error(this, ex.Message, Title); }
    }
}
