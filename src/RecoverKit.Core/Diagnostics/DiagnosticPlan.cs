using System.Diagnostics;
using System.Text.Json.Serialization;

namespace RecoverKit.Core.Diagnostics;

public sealed class DiagnosticStep
{
    public required string Section { get; init; }
    public required string Label { get; init; }
    public double BudgetSeconds { get; init; }
    public double ElapsedSeconds { get; set; }
    public string State { get; set; } = "pending";
    [JsonIgnore] internal Func<CancellationToken, Task> Run { get; init; } = _ => Task.CompletedTask;
    [JsonIgnore] internal Func<bool>? Needed { get; init; }
}

/// <summary>Conditional slots are planned before measurements; skipped slots consume no time.</summary>
internal sealed class DiagnosticPlan
{
    public TimeSpan TotalBudget { get; init; } = Timeout.InfiniteTimeSpan;
    public Dictionary<string, double> SectionBudgets { get; init; } = new();
    private readonly Stopwatch _totalClock = new();
    public List<DiagnosticStep> Steps { get; } = [];
    private readonly object _gate = new();
    private DiagnosticStep? _active;
    private readonly Stopwatch _stepClock = new();

    public void Add(string section, string label, double seconds, Func<Task> run, Func<bool>? needed = null, bool conditional = false)
        => Steps.Add(new() { Section = section, Label = label, BudgetSeconds = seconds, Run = _ => run(), Needed = needed, State = conditional ? "conditional" : "pending" });

    public void AddBounded(string section, string label, double seconds, Func<CancellationToken, Task> run, Func<bool>? needed = null)
        => Steps.Add(new() { Section = section, Label = label, BudgetSeconds = seconds, Run = run, Needed = needed });

    private double Remaining(string section) => SectionBudgets.GetValueOrDefault(section, double.MaxValue)
        - Steps.Where(s => s.Section == section).Sum(s => s.ElapsedSeconds);

    public DiagnosticProgress Progress(TimeSpan elapsed)
    {
        lock (_gate)
        {
            double remaining = 0;
            foreach (var step in Steps.Where(s => s.State is "pending" or "running"))
            {
                var completed = Steps.Where(s => s.Section == step.Section && s.State == "done" && s.ElapsedSeconds > .1).ToList();
                double scale = completed.Count == 0 ? 1 : Math.Clamp(completed.Sum(s => s.ElapsedSeconds) / completed.Sum(s => s.BudgetSeconds), .5, 3);
                double estimate = step.BudgetSeconds * scale;
                remaining += step == _active ? Math.Max(1, estimate - _stepClock.Elapsed.TotalSeconds) : estimate;
            }
            if (SectionBudgets.Count > 0)
                remaining = Steps.Where(s => s.State is "pending" or "running").GroupBy(s => s.Section)
                    .Sum(g => Math.Max(0, Math.Min(Remaining(g.Key), g.Sum(s => s.BudgetSeconds) - (g.Contains(_active!) ? _stepClock.Elapsed.TotalSeconds : 0))));
            if (TotalBudget != Timeout.InfiniteTimeSpan) remaining = Math.Min(remaining, Math.Max(0, TotalBudget.TotalSeconds - elapsed.TotalSeconds));
            double fraction = elapsed.TotalSeconds + remaining > 0 ? elapsed.TotalSeconds / (elapsed.TotalSeconds + remaining) : 1;
            return new(_active?.Section ?? "", _active?.Label ?? "Preparing", elapsed, TimeSpan.FromSeconds(remaining), fraction);
        }
    }

    public async Task RunAsync(DiagnosticReport report, Action pulse, CancellationToken ct)
    {
        _totalClock.Restart();
        foreach (var step in Steps)
        {
            ct.ThrowIfCancellationRequested();
            lock (_gate)
            {
                if (step.Needed?.Invoke() == false) { step.State = "skipped"; continue; }
                double available = Math.Min(Remaining(step.Section), TotalBudget == Timeout.InfiniteTimeSpan ? double.MaxValue : (TotalBudget - _totalClock.Elapsed).TotalSeconds);
                if (available + .001 < step.BudgetSeconds) { NotMeasured(report, step); continue; }
                _active = step;
                step.State = "running";
                _stepClock.Restart();
            }
            pulse();
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            if (TotalBudget != Timeout.InfiniteTimeSpan) deadline.CancelAfter(TimeSpan.FromSeconds(step.BudgetSeconds));
            try { await step.Run(deadline.Token); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { NotMeasured(report, step); }
            catch (Exception ex) when (ex is not OperationCanceledException && !ct.IsCancellationRequested)
            {
                report.Measurements.Add(new() { Section = step.Section, Step = step.Label, Error = ex is InvalidOperationException ? DiagnosticHtml.Scrub(ex.Message) : $"Step failed ({ex.GetType().Name}); private output omitted." });
            }
            finally
            {
                lock (_gate)
                {
                    step.ElapsedSeconds = _stepClock.Elapsed.TotalSeconds;
                    if (step.State == "running") step.State = "done";
                    _active = null;
                }
                pulse();
            }
        }
    }

    private static void NotMeasured(DiagnosticReport report, DiagnosticStep step)
    {
        step.State = "not measured";
        report.Measurements.Add(new() { Section = step.Section, Step = step.Label,
            Error = "Not measured, run the thorough test. The startup or measurement did not fit its time budget." });
    }

    internal static bool Contender(double speed, IEnumerable<double> speeds) => speed > 0 && speed >= speeds.DefaultIfEmpty(0).Max() / 1.10;
}
