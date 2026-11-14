using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

/// <summary>Isolated, paired CPU measurements independent of the recovery preference.</summary>
public sealed record WhirlpoolCpuPaths(IReadOnlyList<CpuDiagnosticWorker.WorkerResult> Previous,
    IReadOnlyList<CpuDiagnosticWorker.WorkerResult> Avx512, int Threads)
{
    public static async Task<WhirlpoolCpuPaths> MeasureAsync(int threads, ProcessPriority priority, CancellationToken ct)
    {
        threads = Math.Clamp(threads, 1, Environment.ProcessorCount);
        var previous = new List<CpuDiagnosticWorker.WorkerResult>();
        var wide = new List<CpuDiagnosticWorker.WorkerResult>();
        for (int repeat = 1; repeat <= 3; repeat++)
        {
            previous.Add(await CpuDiagnosticWorker.MeasureAsync(29331, "scalar", threads, priority, repeat, ct, 3));
            wide.Add(await CpuDiagnosticWorker.MeasureAsync(29331, "avx512", threads, priority, repeat, ct, 3));
            if (!previous[^1].Check.Passed || !wide[^1].Check.Passed) break;
        }
        return new(previous, wide, threads);
    }

    public string Summary
    {
        get
        {
            var previous = Valid(Previous, "scalar");
            var wide = Valid(Avx512, "avx512");
            string ratio = previous.Length > 0 && wide.Length > 0 ? $" ({Median(wide) / Median(previous):F2}x)" : "";
            return $"Whirlpool CPU paths: previous {Rate(Previous, previous, "scalar")}, AVX-512 {Rate(Avx512, wide, "avx512")}{ratio}; " +
                $"{Threads} threads, length 7, {Math.Min(Previous.Count, Avx512.Count)} pairs; AVX-512 off by default";
        }
    }

    private static double[] Valid(IReadOnlyList<CpuDiagnosticWorker.WorkerResult> samples, string variant)
        => samples.Count > 0 && samples.All(s => CpuDiagnosticWorker.EnforcePath(s, variant).Check.Passed
            && double.IsFinite(s.Speed) && s.Speed > 0) ? samples.Select(s => s.Speed).Order().ToArray() : [];

    private static string Rate(IReadOnlyList<CpuDiagnosticWorker.WorkerResult> samples, double[] rates, string variant)
    {
        if (rates.Length > 0) return $"{Median(rates):N0}/s [range {rates[0]:N0}-{rates[^1]:N0}/s]";
        var failed = samples.Select(s => CpuDiagnosticWorker.EnforcePath(s, variant)).FirstOrDefault(s => !s.Check.Passed);
        return failed is null ? "not measured" : failed.SelfTestState switch
        {
            "failed" => "self-test failed",
            "switched off" => "switched off",
            "not run" => "self-test not run",
            _ => DiagnosticHtml.Scrub(failed.Check.Error ?? failed.Error ?? "path check failed"),
        };
    }

    private static double Median(double[] sorted) => sorted.Length % 2 == 1 ? sorted[sorted.Length / 2]
        : sorted[sorted.Length / 2 - 1] / 2 + sorted[sorted.Length / 2] / 2;
}
