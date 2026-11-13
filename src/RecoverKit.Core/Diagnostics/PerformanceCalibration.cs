using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

public static class PerformanceCalibration
{
    private static readonly SemaphoreSlim Gate = new(1, 1);

    /// <summary>A bounded CPU calibration avoids GPU startup overwhelming a short first attack.</summary>
    public static async Task<PerformanceProfile> EnsureAsync(HashcatTool tool, Settings settings, IReadOnlyList<BackendDevice> devices,
        int mode, int length, double candidates, Action<string> status, CancellationToken ct)
    {
        await Gate.WaitAsync(ct);
        DiagnosticReport? report = null;
        try
        {
            var profile = PerformanceProfiles.Load();
            string cpuFingerprint = PerformanceProfiles.CpuFingerprint;
            string gpuFingerprint = PerformanceProfiles.GpuFingerprint(tool, devices);
            bool changed = profile.CpuFingerprint != cpuFingerprint || profile.GpuFingerprint != gpuFingerprint;
            PerformanceProfiles.Invalidate(profile, cpuFingerprint, gpuFingerprint);
            if (changed && profile.MeasuredAt is not null) PerformanceProfiles.Save(profile);
            if (PerformanceProfiles.Apply(PerformanceProfiles.ForMode(profile, mode, length, "cpu"), settings, devices) is not null || length is < 1 or > 10) return profile;
            if (!NativeKernels.BenchmarkHashes.TryGetValue(mode, out var hash) || NativeKernels.TryCreate(mode, hash) is not { } kernel) return profile;
            // With no cache, the format's own capacity hint avoids spending seconds on a tiny ZIP job.
            double estimate = settings.SpeedByMode.TryGetValue(mode, out double cached) && cached > 0
                ? cached : Math.Max(10_000, kernel.SpeedHint * Environment.ProcessorCount);
            if (!PerformanceProfiles.ShouldCalibrate(settings, mode, candidates, estimate)) return profile;
            status("Measuring the fastest method for this PC...");
            report = new DiagnosticReport { CpuPolicy = PerformanceProfiles.PolicyFingerprint(settings, "cpu"), GpuPolicy = PerformanceProfiles.PolicyFingerprint(settings, "gpu") };
            string baseline = mode is 17210 or 17200 ? PerformanceProfiles.DefaultZipVariant() : "default";
            var variants = new List<string> { baseline };
            if (mode is 17210 or 17200)
            {
                var alternative = CpuDiagnostics.Variants.LastOrDefault(v => v.Supported && v.Name != baseline && v.Selector > 0);
                if (alternative is not null) variants.Add(alternative.Name);
            }
            else
            {
                var alternative = KernelVariants.ForMode(mode).FirstOrDefault(v => v.Supported && v.Name != baseline);
                if (alternative is not null) variants.Add(alternative.Name);
            }
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
            budget.CancelAfter(TimeSpan.FromSeconds(6));
            foreach (string variant in variants)
            {
                if (budget.IsCancellationRequested) break;
                var check = await CpuDiagnosticWorker.CheckAsync(mode, variant, budget.Token);
                if (!check.Passed)
                {
                    report.Measurements.Add(new()
                    {
                        Section = "cpu",
                        Step = "automatic correctness FAIL",
                        Mode = mode,
                        Target = $"automatic synthetic mode {mode}",
                        Length = length,
                        Engine = "cpu",
                        Variant = variant,
                        Correct = false,
                        Error = check.Error
                    });
                    continue;
                }
                bool failed = false;
                foreach (int threads in new[] { Environment.ProcessorCount, SystemFacts.PhysicalCores() }.Distinct())
                    for (int repeat = 1; repeat <= 2; repeat++)
                    {
                        if (budget.IsCancellationRequested || failed) break;
                        var result = await CpuDiagnosticWorker.MeasureAutomaticAsync(mode, variant, threads, length, settings.Priority, budget.Token);
                        ct.ThrowIfCancellationRequested();
                        if (!result.Check.Passed)
                        {
                            failed = true;
                            report.Measurements.Add(new()
                            {
                                Section = "cpu",
                                Step = "automatic worker failed",
                                Mode = mode,
                                Target = $"automatic synthetic mode {mode}",
                                Length = length,
                                Engine = "cpu",
                                Variant = variant,
                                Correct = false,
                                Error = result.Error ?? result.Check.Error
                            });
                            break;
                        }
                        // Completed candidates divided by measured engine elapsed time; unfinished batches are excluded.
                        if (result.Check.Passed && result.Speed > 0)
                            report.Measurements.Add(new()
                            {
                                Section = "cpu",
                                Step = "bounded automatic CPU calibration",
                                Mode = mode,
                                Target = $"automatic synthetic mode {mode}",
                                Length = length,
                                Engine = "cpu",
                                Variant = variant,
                                Threads = threads,
                                Repeat = repeat,
                                Correct = true,
                                Speed = result.Speed,
                                ElapsedSeconds = result.ElapsedSeconds
                            });
                    }
            }
            PerformanceProfiles.Record(report, tool, devices, "automatic");
            return PerformanceProfiles.Load();
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            if (report?.Measurements.Count > 0) PerformanceProfiles.Record(report, tool, devices, "automatic");
            return PerformanceProfiles.Load();
        }
        finally { Gate.Release(); }
    }
}
