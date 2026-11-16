using RecoverKit.Core.Native.Kernels;
using System.Globalization;

namespace RecoverKit.Core.Diagnostics;

public sealed record WideVectorPathsSummary(bool? Avx512Available, string? Note, IReadOnlyList<WideVectorKernel> Rows);
public sealed record WideVectorKernel(int Mode, string Kernel, string Target, int Length,
    WideVectorComparison SingleThread, WideVectorComparison AllThreads, string Correctness, string SelfTestState);
public sealed record WideVectorComparison(int? Threads, WideVectorPathResult Avx2, WideVectorPathResult Avx512, double? Ratio,
    WideVectorPathResult? Scalar = null);
public sealed record WideVectorPathResult(string Status, string? Reason, double? Median, double? Minimum,
    double? Maximum, int SampleCount, string SelfTestState);

public static class WideVectorPaths
{
    public static WideVectorPathsSummary Build(DiagnosticReport report)
    {
        bool? available = bool.TryParse(report.System.GetValueOrDefault("AVX-512 available"), out bool flag) ? flag : null;
        if (available == false)
            return new(false, "AVX-512 is unavailable on this system; wide vector path comparisons were not measured.", []);

        int? allThreads = PositiveInt(report.System.GetValueOrDefault("Logical threads"));
        if (allThreads is { } logical && PositiveInt(report.System.GetValueOrDefault("CPU thread budget")) is { } budget)
            allThreads = Math.Min(logical, budget);
        var rows = new List<WideVectorKernel>();
        foreach (var (mode, name) in new[] { (12500, "RAR3"), (13000, "RAR5"), (13600, "WinZip AES"), (22000, "WPA"), (17200, "ZIP deflated"), (17210, "ZIP stored"), (29331, "TrueCrypt Whirlpool"), (29321, "TrueCrypt SHA-512 512"), (29322, "TrueCrypt SHA-512 1024"), (29323, "TrueCrypt SHA-512 1536"), (29421, "VeraCrypt SHA-512 512"), (29422, "VeraCrypt SHA-512 1024"), (29423, "VeraCrypt SHA-512 1536") })
        {
            var measurements = report.Measurements.Where(r => r.Section == "cpu" && r.Mode == mode
                && (r.Variant is "avx2" or "avx512" || mode == 29331 && r.Variant == "scalar")
                && !(mode == 17210 && r.Target == "published ZIP stored 453-byte fixture")).ToArray();
            // Keep every cell on one workload, including when only one requested path was timed.
            var workload = measurements.Where(r => r.Threads > 0).GroupBy(r => (r.Target, r.Length))
                .OrderByDescending(g => g.Where(r => Failure(r) is null).Select(r => r.Variant).Distinct().Count())
                .ThenByDescending(g => g.Count(r => r.Variant == (mode == 29331 ? "scalar" : "avx2")))
                .Select(g => g.Key).FirstOrDefault();
            var single = Compare(measurements, 1, workload, mode);
            var all = allThreads == 1 ? single : Compare(measurements, allThreads, workload, mode);
            var paths = new[] { single.Scalar ?? single.Avx2, single.Avx512, all.Scalar ?? all.Avx2, all.Avx512 };
            string correctness = measurements.Any(r => Failure(r, requireRate: r.Threads > 0) is not null) ? "FAIL"
                : paths.All(p => p.Status == "PASS") ? "PASS"
                : paths.Any(p => p.Status == "PASS") ? "PASS (measured paths); incomplete" : "not measured";
            var wideRows = measurements.Where(r => r.Variant == "avx512").ToArray();
            string selfTest = mode is 17200 or 17210 ? "no native guard; diagnostic check only"
                : States(wideRows.Any(r => r.Threads > 0) ? wideRows.Where(r => r.Threads > 0) : wideRows);
            rows.Add(new(mode, name, workload.Target ?? "", workload.Length, single, all, correctness, selfTest));
        }
        return new(available, null, rows);
    }

    private static WideVectorComparison Compare(DiagnosticMeasurement[] rows, int? threads, (string Target, int Length) workload, int mode)
    {
        var avx2 = Path(rows, "avx2", threads, workload, mode);
        var scalar = mode == 29331 ? Path(rows, "scalar", threads, workload, mode) : null;
        var avx512 = Path(rows, "avx512", threads, workload, mode);
        double? ratio = (scalar ?? avx2).Median is { } baseline && avx512.Median is { } wide && double.IsFinite(wide / baseline)
            ? wide / baseline : null;
        return new(threads, avx2, avx512, ratio, scalar);
    }

    private static WideVectorPathResult Path(DiagnosticMeasurement[] rows, string variant, int? threads, (string Target, int Length) workload, int mode)
    {
        var requested = rows.Where(r => r.Variant == variant && r.Threads == threads).ToArray();
        string state = mode is 17200 or 17210 ? "no native guard; diagnostic check only" : States(requested);
        var failures = requested.Select(r => Failure(r)).Where(s => s is not null).Distinct().ToArray();
        if (failures.Length > 0) return new("FAIL", string.Join("; ", failures), null, null, null, 0, state);
        var values = requested.Where(r => r.Target == workload.Target && r.Length == workload.Length)
            .Select(r => r.Speed).Order().ToArray();
        if (values.Length == 0)
            return new("not measured", threads is null ? "Logical thread count was not reported."
                : requested.Length > 0 ? "No measurement with matching target and length." : null, null, null, null, 0, state);
        double median = values.Length % 2 == 1 ? values[values.Length / 2]
            : values[values.Length / 2 - 1] / 2 + values[values.Length / 2] / 2;
        return new("PASS", null, median, values[0], values[^1], values.Length, state);
    }

    private static string? Failure(DiagnosticMeasurement row, bool requireRate = true)
    {
        if (!string.IsNullOrWhiteSpace(row.Error)) return row.Error;
        if (!row.Correct) return "Diagnostic correctness check failed.";
        string? state = row.Details.GetValueOrDefault("self-test state");
        if (row.Variant == "avx512" && state is ("failed" or "switched off")) return "Native self-test state: " + state + ".";
        if (row.Variant == "avx512" && (row.Mode is 12500 or 13000 or 13600 or 22000 or 29331 || TrueCryptSha512Kernel.SupportsMode(row.Mode)) && state != "passed")
            return "Native wide self-test did not pass: " + (state ?? "not reported") + ".";
        string actual = row.Details.GetValueOrDefault("actual path") ?? "";
        string normalized = actual.Replace("-", "").Replace(" ", "").ToLowerInvariant();
        if (normalized.StartsWith("native", StringComparison.Ordinal)) normalized = normalized[6..];
        if (normalized != row.Variant)
            return $"Requested {row.Variant}, actual path {(actual.Length == 0 ? "not reported" : actual)}.";
        if (requireRate && (!double.IsFinite(row.Speed) || row.Speed <= 0)) return "No positive finite measured rate was reported.";
        return null;
    }

    private static string States(IEnumerable<DiagnosticMeasurement> rows)
    {
        string result = string.Join("; ", rows.Select(r => r.Details.GetValueOrDefault("self-test state"))
            .Where(s => !string.IsNullOrWhiteSpace(s)).Distinct());
        return result.Length > 0 ? result : "not reported";
    }

    private static int? PositiveInt(string? text) => int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out int value) && value > 0 ? value : null;
}
