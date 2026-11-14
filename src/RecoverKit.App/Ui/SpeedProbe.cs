using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.App.Ui;

/// <summary>Measures the selected engines. Hybrid rates use the same synthetic target and seven-character mask.</summary>
internal static class SpeedProbe
{
    public static bool HasGpu(IReadOnlyList<BackendDevice> devices)
        => devices.Any(d => !d.IsSkippedAlias && d.IsGpu);

    private static Settings ExecutionSettings(Settings preferences, IReadOnlyList<BackendDevice> devices, int mode, HashcatTool? tool = null)
    {
        var profile = PerformanceProfiles.Load();
        PerformanceProfiles.Invalidate(profile, PerformanceProfiles.CpuFingerprint,
            PerformanceProfiles.GpuFingerprint(tool ?? HashcatTool.Locate(preferences.HashcatPath), devices));
        return ProfileSettings.ForAttack(preferences, profile, devices, mode, MatchedSpeedProbe.Length,
            NativeKernels.BenchmarkHashes.GetValueOrDefault(mode, ""));
    }

    public static bool UseNative(Settings s, IReadOnlyList<BackendDevice> devices, int mode)
        => NativeEligible(ExecutionSettings(s, devices, mode), devices, mode);

    private static bool NativeEligible(Settings s, IReadOnlyList<BackendDevice> devices, int mode) =>
        s.UseNativeCpuEngine && string.IsNullOrWhiteSpace(s.ExtraArguments) && NativeKernels.Supports(mode)
        && s.PerformanceChoice?.Engine is not ("gpu" or "hybrid")
        && (HashcatRunner.ActiveGpus(s, devices).Count == 0 || s.Strategy == DeviceStrategy.CpuOnly || s.PerformanceChoice?.Engine == "cpu")
        && NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]) is not null;

    public static bool UseHybrid(Settings s, IReadOnlyList<BackendDevice> devices, int mode)
        => HybridEligible(ExecutionSettings(s, devices, mode), devices, mode);

    private static bool HybridEligible(Settings s, IReadOnlyList<BackendDevice> devices, int mode) =>
        s.UseNativeCpuEngine && s.HybridCpuGpu && string.IsNullOrWhiteSpace(s.ExtraArguments) && NativeKernels.Supports(mode)
        && s.PerformanceChoice?.Engine is not ("cpu" or "gpu")
        && s.Strategy is DeviceStrategy.GpuOnly or DeviceStrategy.GpuAndCpu && HashcatRunner.ActiveGpus(s, devices).Count > 0
        && (s.PerformanceChoice?.Engine == "hybrid" || !HybridRunner.CpuAddsTooLittle(s, devices, mode))
        && NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]) is not null;

    public static async Task<(double Speed, bool Native)> MeasureAsync(HashcatTool hashcat, Settings preferences,
        IReadOnlyList<BackendDevice> devices, int mode, TimeSpan nativeDuration, CancellationToken ct,
        Action<string>? cpuPathMeasured = null)
    {
        var s = ExecutionSettings(preferences, devices, mode, hashcat);
        using var selection = ProfileSettings.CpuSelection(s, mode);
        if (NativeEligible(s, devices, mode))
        {
            int measured = s.PerformanceChoice?.Engine == "cpu" ? s.PerformanceChoice.Threads : s.CpuPerformanceChoice?.Threads ?? 0;
            int threads = s.MaxCpuThreads > 0 ? s.MaxCpuThreads : measured > 0 ? measured : Environment.ProcessorCount;
            NativeKernels.ResetCpuPath(mode);
            double speed = await Task.Run(() => NativeKernels.Benchmark(mode, threads, nativeDuration, ct, MatchedSpeedProbe.Length), ct);
            if (speed > 0) cpuPathMeasured?.Invoke(NativeKernels.CpuPath(mode, actualOnly: true));
            return (speed, true);
        }
        bool hybrid = HybridEligible(s, devices, mode);
        if (hybrid || (NativeKernels.Supports(mode) && HashcatRunner.ActiveGpus(s, devices).Count > 0
            && string.IsNullOrWhiteSpace(s.ExtraArguments)))
        {
            int threads = HybridRunner.CpuThreads(s, devices, hashcatRunning: true);
            if (hybrid) NativeKernels.ResetCpuPath(mode);
            var (cpu, gpu) = await MatchedSpeedProbe.MeasureAsync(hashcat, s, devices, mode, threads, nativeDuration, hybrid, ct);
            if (gpu <= 0 || hybrid && cpu <= 0) return (0, false);
            if (hybrid) cpuPathMeasured?.Invoke(NativeKernels.CpuPath(mode, actualOnly: true));
            preferences.GpuSpeedByMode[mode] = gpu;
            if (hybrid) preferences.CpuSpeedByMode[mode] = cpu;
            DebugLog.Info($"Matched speed probe, mode {mode}, synthetic native fixture, length {MatchedSpeedProbe.Length}: GPU {gpu:N0}/s, CPU {cpu:N0}/s ({threads} threads)");
            return (hybrid ? MatchedSpeedProbe.CombinedRate(cpu, gpu) : gpu, false);
        }

        // hashcat's standalone benchmark has no live guard. Keep configured limits intact by leaving this measurement out.
        if (HashcatRunner.GuardFor(s, devices) is { Active: true } || !await MatchedSpeedProbe.PowerLimitAllowsAsync(s)) return (0, false);
        var args = HashcatRunner.DeviceArguments(s, devices);
        args.AddRange(["-w", s.Workload.ToString()]);
        if (s.OptimizedKernels && s.GpuPerformanceChoice?.Optimized != false
            && (await hashcat.ModeInfoAsync(mode))?.HasOptimizedKernel == true) args.Add("-O");
        return (await hashcat.BenchmarkAsync(mode, args, ct), false);
    }
}
