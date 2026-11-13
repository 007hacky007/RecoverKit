using System.Diagnostics;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

public static class PerformanceCalibration
{
    private static readonly SemaphoreSlim Gate = new(1,1);

    /// <summary>A bounded CPU calibration avoids GPU startup overwhelming a short first attack.</summary>
    public static async Task<PerformanceProfile> EnsureAsync(HashcatTool tool,Settings settings,IReadOnlyList<BackendDevice> devices,
        int mode,int length,double candidates,Action<string> status,CancellationToken ct)
    {
        await Gate.WaitAsync(ct);
        try
        {
            var profile=PerformanceProfiles.Load();
            PerformanceProfiles.Invalidate(profile,PerformanceProfiles.CpuFingerprint,PerformanceProfiles.GpuFingerprint(tool,devices));
            if (PerformanceProfiles.ForMode(profile, mode, length, "cpu") is not null || length is < 1 or > 10) return profile;
            if (!NativeKernels.BenchmarkHashes.TryGetValue(mode, out var hash) || NativeKernels.TryCreate(mode, hash) is not { } kernel) return profile;
            // With no cache, the format's own capacity hint avoids spending seconds on a tiny ZIP job.
            double estimate = settings.SpeedByMode.TryGetValue(mode, out double cached) && cached > 0
                ? cached : Math.Max(10_000, kernel.SpeedHint * Environment.ProcessorCount);
            if (!PerformanceProfiles.ShouldCalibrate(settings, mode, candidates, estimate)) return profile;
            status("Measuring the fastest method for this PC...");
            var report=new DiagnosticReport();
            string baseline=mode is 17210 or 17200 ? PerformanceProfiles.DefaultZipVariant() : "default";
            var variants=new List<string>{baseline};
            if(mode is 17210 or 17200)
            {
                var alternative=CpuDiagnostics.Variants.LastOrDefault(v=>v.Supported && v.Name!=baseline && v.Selector>0);
                if(alternative is not null) variants.Add(alternative.Name);
            }
            var space=MaskSpace.FromHashcatArgs(["-a","3","-1","?u?d?s",string.Concat(Enumerable.Repeat("?1",length))])!;
            using var budget=CancellationTokenSource.CreateLinkedTokenSource(ct);
            budget.CancelAfter(TimeSpan.FromSeconds(6));
            foreach(string variant in variants)
            {
                if(budget.IsCancellationRequested) break;
                var check=mode is 17210 or 17200 ? CpuDiagnostics.CheckZipVariant(variant) : CpuDiagnostics.CheckKernel(mode);
                if (!check.Passed)
                {
                    report.Measurements.Add(new() { Section = "cpu", Step = "automatic correctness FAIL", Mode = mode,
                        Target = $"automatic synthetic mode {mode}", Length = length, Engine = "cpu", Variant = variant, Correct = false, Error = check.Error });
                    continue;
                }
                using var path=mode is 17210 or 17200 ? CpuDiagnostics.UseZipVariant(variant) : null;
                foreach(int threads in new[]{Environment.ProcessorCount,SystemFacts.PhysicalCores()}.Distinct())
                for(int repeat=1;repeat<=2;repeat++)
                {
                    if(budget.IsCancellationRequested) break;
                    using var sample=CancellationTokenSource.CreateLinkedTokenSource(budget.Token);
                    sample.CancelAfter(TimeSpan.FromMilliseconds(650));
                    var timer=Stopwatch.StartNew();
                    var result=await Task.Run(()=>new NativeEngine(kernel,space){Threads=threads,Priority=ThreadPriority.Normal}.Run(null,sample.Token),CancellationToken.None);
                    ct.ThrowIfCancellationRequested();
                    // End-to-end rates include startup and incomplete batches are excluded.
                    if(timer.Elapsed.TotalSeconds>0 && result.Tested>0)
                        report.Measurements.Add(new(){Section="cpu",Step="bounded automatic CPU calibration",Mode=mode,
                            Target=$"automatic synthetic mode {mode}",Length=length,Engine="cpu",Variant=variant,Threads=threads,Repeat=repeat,
                            Correct=true,Speed=result.Tested/timer.Elapsed.TotalSeconds,ElapsedSeconds=timer.Elapsed.TotalSeconds});
                }
            }
            PerformanceProfiles.Record(report,tool,devices,"automatic");
            return PerformanceProfiles.Load();
        }
        finally { Gate.Release(); }
    }
}
