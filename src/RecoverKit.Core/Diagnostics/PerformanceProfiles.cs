using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

public sealed class PerformanceDecision
{
    public string Domain { get; set; } = "cpu";
    public int Mode { get; set; }
    public string Target { get; set; } = "";
    public int Length { get; set; }
    public string Engine { get; set; } = "";
    public string Variant { get; set; } = "";
    public int Threads { get; set; }
    public List<string> DeviceKeys { get; set; } = [];
    public bool? Optimized { get; set; }
    public double Speed { get; set; }
    public double Margin { get; set; }
    public string Reason { get; set; } = "";
}

public sealed class PerformanceProfile
{
    public int Schema { get; set; } = 1;
    public DateTimeOffset? MeasuredAt { get; set; }
    public string Source { get; set; } = "";
    public string CpuFingerprint { get; set; } = "";
    public string GpuFingerprint { get; set; } = "";
    public List<PerformanceDecision> Decisions { get; set; } = [];
    public Dictionary<int, List<string>> FailedCpuVariants { get; set; } = new();
}

/// <summary>Measured choices are separate from preferences and never rewrite them.</summary>
public static class PerformanceProfiles
{
    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };
    private static string FilePath => Path.Combine(Settings.AppDataDir,"performance-profile.json");
    private static string Digest(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    public static string CpuFingerprint => Digest($"{SystemFacts.CpuName()}|{NativeKernels.CpuFeatures()}|{Environment.ProcessorCount}|{typeof(Settings).Assembly.GetName().Version}|{NativeKernels.NativeApiVersion}");
    public static string GpuFingerprint(HashcatTool? tool,IReadOnlyList<BackendDevice> devices) => Digest(
        CpuSoftwareVersion + "|" + (tool is null ? "absent" : tool.FullVersion) + "|" +
        string.Join(";",devices.OrderBy(d=>d.Key).Select(d=>$"{d.Key}:{d.Name}:{d.Backend}:{d.BackendVersion}:{d.DriverVersion}")));
    private static string CpuSoftwareVersion => typeof(Settings).Assembly.GetName().Version?.ToString() ?? "unknown";

    public static PerformanceProfile Load() => Load(FilePath);

    internal static PerformanceProfile Load(string filePath)
    {
        lock(Gate)
        {
            try { return JsonSerializer.Deserialize<PerformanceProfile>(File.ReadAllText(filePath),Json) is {Schema:1} p ? p : new(); }
            catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or JsonException) { return new(); }
        }
    }

    public static void Save(PerformanceProfile profile) => Save(profile, FilePath);

    internal static void Save(PerformanceProfile profile, string filePath)
    {
        lock(Gate)
        {
            var temp=filePath+".tmp";
            File.WriteAllText(temp,JsonSerializer.Serialize(profile,Json));
            File.Move(temp,filePath,true);
        }
    }

    public static void Reset() { lock(Gate) { File.Delete(FilePath); } }

    public static void Invalidate(PerformanceProfile profile,string cpu,string gpu)
    {
        if(profile.CpuFingerprint!=cpu)
        {
            profile.Decisions.Clear();
            profile.FailedCpuVariants.Clear();
        }
        else if(profile.GpuFingerprint!=gpu) profile.Decisions.RemoveAll(d=>d.Domain!="cpu");
        profile.CpuFingerprint=cpu;
        profile.GpuFingerprint=gpu;
    }

    private static (string Engine, string Variant, int Threads, string Device, string Backend, string Optimized) Configuration(DiagnosticMeasurement row)
        => (row.Engine, row.Variant, row.Threads, row.DeviceKey, row.Backend, row.Details.GetValueOrDefault("Optimized", ""));

    /// <summary>Two independent repeats on identical targets; the worst winner must beat the best baseline.</summary>
    public static PerformanceDecision? Choose(IEnumerable<DiagnosticMeasurement> measurements, string defaultVariant)
    {
        var all = measurements.ToList();
        var valid = all.Where(m => m.Correct && m.Error is null && double.IsFinite(m.Speed) && m.Speed > 0 && m.Repeat > 0).ToList();
        if (valid.Count == 0) return null;
        var defaults = valid.Where(r => r.Variant == defaultVariant).ToList();
        var target = defaults.FirstOrDefault(r => bool.TryParse(r.Details.GetValueOrDefault("Default"), out bool marked) && marked)
            ?? defaults.FirstOrDefault();
        if (target is null) return null;
        var comparable = all.Where(r => r.Mode == target.Mode && r.Target == target.Target && r.Length == target.Length).ToList();
        var failedVariants = comparable.Where(r => !r.Correct).Select(r => (r.Engine, r.Variant, r.DeviceKey, r.Backend)).ToHashSet();
        var groups = valid.Where(r => r.Mode == target.Mode && r.Target == target.Target && r.Length == target.Length)
            .Where(r => !failedVariants.Contains((r.Engine, r.Variant, r.DeviceKey, r.Backend)))
            .GroupBy(Configuration)
            .Where(g => g.Select(r => r.Repeat).Distinct().Count() >= 2)
            .Select(g => new { Key = g.Key, Row = g.First(), Low = g.Min(r => r.Speed), High = g.Max(r => r.Speed), Mean = g.Average(r => r.Speed) })
            .OrderByDescending(g => g.Mean).ToList();
        var baseline = groups.FirstOrDefault(g => g.Key == Configuration(target));
        // Without a measured exact baseline an alternative has no demonstrated advantage.
        if (baseline is null) return null;
        var winner = groups.FirstOrDefault(g => g.Low >= baseline.High * 1.05) ?? baseline;
        var row = winner.Row;
        double margin = winner == baseline ? 0 : winner.Low / baseline.High - 1;
        return new PerformanceDecision
        {
            Mode = row.Mode, Target = row.Target, Length = row.Length, Engine = row.Engine, Variant = row.Variant, Threads = row.Threads,
            DeviceKeys = row.DeviceKey.Length == 0 ? [] : row.DeviceKey.Split(';', StringSplitOptions.RemoveEmptyEntries).ToList(),
            Speed = winner.Mean, Margin = margin,
            Optimized = row.Details.TryGetValue("Optimized", out var opt) && bool.TryParse(opt, out bool optimized) ? optimized : null,
            Reason = margin > 0 ? $"measured at least {1 + margin:F2}x faster across two repeats" : "current default retained; no repeatable gain of 5%",
        };
    }

    public static PerformanceDecision? Apply(PerformanceDecision? decision,Settings settings,IReadOnlyList<BackendDevice> devices)
    {
        if(decision is null || settings.PerformanceStrategyExplicit || settings.Strategy!=DeviceStrategy.GpuOnly || settings.MaxCpuThreads>0
            || !settings.UseNativeCpuEngine || !string.IsNullOrWhiteSpace(settings.ExtraArguments)) return null;
        if(decision.Engine=="hybrid" && !settings.HybridCpuGpu) return null;
        if(decision.DeviceKeys.Any(k=>!devices.Any(d=>d.Key==k && !HashcatRunner.IsDisabled(settings,d)))) return null;
        return decision;
    }

    public static bool ShouldCalibrate(Settings s,int mode,double candidates,double speed) => s.AutomaticPerformanceCalibration
        && NativeKernels.Supports(mode) && candidates>0 && speed>0 && candidates/speed>=12
        && s.Strategy==DeviceStrategy.GpuOnly && !s.PerformanceStrategyExplicit && s.MaxCpuThreads==0
        && s.UseNativeCpuEngine && string.IsNullOrWhiteSpace(s.ExtraArguments);

    public static bool IsCpuVariantFailed(PerformanceProfile profile, int mode, string variant)
        => profile.FailedCpuVariants.TryGetValue(mode, out var failed) && failed.Contains(variant);

    public static void Record(DiagnosticReport report, HashcatTool? tool, IReadOnlyList<BackendDevice> devices, string source)
        => Record(report, tool, devices, source, FilePath);

    internal static void Record(DiagnosticReport report, HashcatTool? tool, IReadOnlyList<BackendDevice> devices, string source, string profilePath)
    {
        var p=Load(profilePath);
        Invalidate(p,CpuFingerprint,GpuFingerprint(tool,devices));
        foreach (var failed in report.Measurements.Where(row => row.Section == "cpu" && row.Mode > 0 && !row.Correct && row.Variant.Length > 0))
        {
            if (!p.FailedCpuVariants.TryGetValue(failed.Mode, out var variants)) p.FailedCpuVariants[failed.Mode] = variants = [];
            if (!variants.Contains(failed.Variant)) variants.Add(failed.Variant);
        }
        p.Decisions.RemoveAll(decision => decision.Domain == "cpu" && IsCpuVariantFailed(p, decision.Mode, decision.Variant));
        foreach(var group in report.Measurements.Where(m=>m.Mode>0).GroupBy(m=>(m.Section,m.Mode,m.Target,m.Length)))
        {
            string domain=group.Key.Section switch {"cpu"=>"cpu","hybrid"=>"execution","gpu"=>"gpu","zip"=>"zip",_=>""};
            if(domain.Length==0) continue;
            // Current native default, default backend or finite GPU-only run are the measured baseline.
            string baseline=domain=="cpu" && group.Key.Mode is 17200 or 17210
                ? DefaultZipVariant() : group.First().Variant;
            var ordered = domain == "cpu"
                ? group.OrderByDescending(row => row.Threads == Environment.ProcessorCount).ToList()
                : group.ToList();
            var d=Choose(ordered,baseline);
            if(d is null) continue;
            d.Domain=domain;
            if (domain == "cpu" && IsCpuVariantFailed(p, d.Mode, d.Variant)) continue;
            p.Decisions.RemoveAll(old=>old.Mode==d.Mode && old.Domain==d.Domain && old.Target==d.Target && old.Length==d.Length);
            p.Decisions.Add(d);
            report.Summary.Add($"Mode {d.Mode}, {d.Target}, length {d.Length}: {d.Engine} {d.Variant}, {d.Threads} CPU workers; {d.Reason}.");
        }
        p.MeasuredAt=DateTimeOffset.UtcNow;
        p.Source=source;
        Save(p, profilePath);
    }

    public static string DefaultZipVariant() => NativeKernels.ZipCryptoPath switch
    {
        "native ARM CRC"=>"arm-crc","native NEON"=>"neon","native scalar"=>"scalar","native AVX2"=>"avx2","native AVX-512"=>"avx512",
        "managed scalar"=>"managed-scalar",_=>"managed",
    };

    public static PerformanceDecision? ForMode(PerformanceProfile profile,int mode,int length,string domain) =>
        profile.Decisions.Where(d=>d.Mode==mode && d.Domain==domain && (length==0 || d.Length==length))
            .OrderByDescending(d=>d.Margin).FirstOrDefault();
}
