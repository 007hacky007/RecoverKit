namespace RecoverKit.Core.Diagnostics;

public sealed class DiagnosticMeasurement
{
    public string Section { get; set; } = "";
    public string Step { get; set; } = "";
    public int Mode { get; set; }
    public string Target { get; set; } = "";
    public int Length { get; set; }
    public string Engine { get; set; } = "";
    public string Variant { get; set; } = "";
    public int Threads { get; set; }
    public string DeviceKey { get; set; } = "";
    public string Backend { get; set; } = "";
    public bool Correct { get; set; }
    public double Speed { get; set; }
    public double ElapsedSeconds { get; set; }
    public int Repeat { get; set; }
    public string? Error { get; set; }
    public Dictionary<string, string> Details { get; set; } = new();
}

public sealed class DiagnosticReport
{
    public DateTimeOffset Started { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? Finished { get; set; }
    public bool Cancelled { get; set; }
    public string CpuPolicy { get; set; } = "";
    public string GpuPolicy { get; set; } = "";
    public List<DiagnosticStep> Plan { get; set; } = [];
    public List<DiagnosticMeasurement> Measurements { get; set; } = [];
    public List<string> Summary { get; set; } = [];
    public List<PerformanceDecision> Decisions { get; set; } = [];
    public Dictionary<string, string> System { get; set; } = new();
    public WideVectorPathsSummary WideVectorPaths => global::RecoverKit.Core.Diagnostics.WideVectorPaths.Build(this);
}

public sealed record DiagnosticProgress(string Section, string Step, TimeSpan Elapsed, TimeSpan EstimatedRemaining, double Fraction = 0);
public sealed record DiagnosticSection(string Id, string Title, double EstimatedMinutes);
