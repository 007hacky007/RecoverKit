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
        return ProfileSettings.ForAttack(preferences, profile, devices, mode, MatchedSpeedProbe.LengthFor(mode),
            NativeKernels.BenchmarkHashes.GetValueOrDefault(mode, ""));
    }

    public static bool UseNative(Settings s, IReadOnlyList<BackendDevice> devices, int mode)
        => NativeEligible(ExecutionSettings(s, devices, mode), devices, mode);

    private static bool NativeEligible(Settings s, IReadOnlyList<BackendDevice> devices, int mode) =>
        s.UseNativeCpuEngine && string.IsNullOrWhiteSpace(s.ExtraArguments) && NativeKernels.Supports(mode)
        && s.PerformanceChoice?.Engine is not ("gpu" or "hybrid")
        && (mode is not (13600 or 22000) || s.PerformanceChoice?.Engine == "cpu")
        && (HashcatRunner.ActiveGpus(s, devices).Count == 0 || s.Strategy == DeviceStrategy.CpuOnly || s.PerformanceChoice?.Engine == "cpu")
        && NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]) is not null;

    public static bool UseHybrid(Settings s, IReadOnlyList<BackendDevice> devices, int mode)
        => HybridEligible(ExecutionSettings(s, devices, mode), devices, mode);

    internal static bool HybridEligible(Settings s, IReadOnlyList<BackendDevice> devices, int mode) =>
        s.UseNativeCpuEngine && s.HybridCpuGpu && string.IsNullOrWhiteSpace(s.ExtraArguments) && NativeKernels.Supports(mode)
        && s.PerformanceChoice?.Engine is not ("cpu" or "gpu")
        && (mode is not (13600 or 22000) || s.PerformanceChoice?.Engine == "hybrid" || s.PerformanceStrategyExplicit
            || HashcatRunner.ActiveGpus(s, devices).Any(d => !d.IsIntegratedGpu))
        && s.Strategy is DeviceStrategy.GpuOnly or DeviceStrategy.GpuAndCpu && HashcatRunner.ActiveGpus(s, devices).Count > 0
        && (s.PerformanceChoice?.Engine == "hybrid" || !HybridRunner.CpuAddsTooLittle(s, devices, mode))
        && NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]) is not null;

    /// <summary>What a measurement used: the password length, and for hybrid runs each side's rate.</summary>
    public sealed record Details(int Length, double Cpu, double Gpu)
    {
        public string Engine { get; init; } = "";
        public int CpuThreads { get; init; }
        public List<string> Execution { get; init; } = [];
        public string Arguments { get; init; } = "";
    }

    public static async Task<string?> MeasureWhirlpoolPathsAsync(HashcatTool hashcat, Settings preferences,
        IReadOnlyList<BackendDevice> devices, CancellationToken ct)
    {
        if (!NativeKernels.WhirlpoolAvx512Supported) return null;
        var s = ExecutionSettings(preferences, devices, 29331, hashcat);
        int measured = s.PerformanceChoice?.Engine == "cpu" ? s.PerformanceChoice.Threads : s.CpuPerformanceChoice?.Threads ?? 0;
        int threads = HybridEligible(s, devices, 29331) ? HybridRunner.CpuThreads(s, devices, hashcatRunning: true)
            : s.MaxCpuThreads > 0 ? s.MaxCpuThreads : measured > 0 ? measured : Environment.ProcessorCount;
        return (await WhirlpoolCpuPaths.MeasureAsync(threads, s.Priority, ct)).Summary;
    }

    public static async Task<(double Speed, bool Native)> MeasureAsync(HashcatTool hashcat, Settings preferences,
        IReadOnlyList<BackendDevice> devices, int mode, TimeSpan nativeDuration, CancellationToken ct,
        Action<string>? cpuPathMeasured = null, Action<Details>? measuredWith = null)
    {
        int length = MatchedSpeedProbe.LengthFor(mode);
        var s = ExecutionSettings(preferences, devices, mode, hashcat);
        using var invocation = new BenchmarkSetup.Invocation(hashcat);
        Details Describe(int candidateLength, double cpu, double gpu, bool native, bool hybrid, int threads) => new(candidateLength, cpu, gpu)
        {
            Engine = BenchmarkSetup.Engine(s, devices, native, hybrid, threads,
                native || hybrid ? NativeKernels.CpuPath(mode, actualOnly: true) : null, invocation.Arguments),
            CpuThreads = threads, Execution = BenchmarkSetup.ExecutionLines(s), Arguments = invocation.Safe,
        };
        using var selection = ProfileSettings.CpuSelection(s, mode);
        if (NativeEligible(s, devices, mode))
        {
            int measured = s.PerformanceChoice?.Engine == "cpu" ? s.PerformanceChoice.Threads : s.CpuPerformanceChoice?.Threads ?? 0;
            int threads = s.MaxCpuThreads > 0 ? s.MaxCpuThreads : measured > 0 ? measured : Environment.ProcessorCount;
            NativeKernels.ResetCpuPath(mode);
            double speed = await Task.Run(() => NativeKernels.Benchmark(mode, threads, nativeDuration, ct, length, NativeRunner.ThreadPriorityFor(s.Priority)), ct);
            if (speed > 0) cpuPathMeasured?.Invoke(NativeKernels.CpuPath(mode, actualOnly: true));
            measuredWith?.Invoke(Describe(length, 0, 0, true, false, threads));
            return (speed, true);
        }
        if (HashcatRunner.NvidiaBackendError(s, devices) is { } backendError)
        {
            measuredWith?.Invoke(Describe(length, 0, 0, false, false, 0) with { Engine = "not measured: " + backendError });
            return (0, false);
        }
        bool hybrid = HybridEligible(s, devices, mode);
        if (hybrid || (NativeKernels.Supports(mode) && HashcatRunner.ActiveGpus(s, devices).Count > 0
            && string.IsNullOrWhiteSpace(s.ExtraArguments)))
        {
            int threads = HybridRunner.CpuThreads(s, devices, hashcatRunning: true);
            if (hybrid) NativeKernels.ResetCpuPath(mode);
            var (cpu, gpu) = await MatchedSpeedProbe.MeasureAsync(hashcat, s, devices, mode, threads, nativeDuration, hybrid, ct);
            measuredWith?.Invoke(Describe(length, hybrid ? cpu : 0, gpu, false, hybrid, hybrid ? threads : 0));
            if (gpu <= 0 || hybrid && cpu <= 0) return (0, false);
            if (hybrid) cpuPathMeasured?.Invoke(NativeKernels.CpuPath(mode, actualOnly: true));
            preferences.GpuSpeedByMode[mode] = gpu;
            if (hybrid) preferences.CpuSpeedByMode[mode] = cpu;
            DebugLog.Info($"Matched speed probe, mode {mode}, synthetic native fixture, length {length}: GPU {gpu:N0}/s, CPU {cpu:N0}/s ({threads} threads)");
            return (hybrid ? MatchedSpeedProbe.CombinedRate(cpu, gpu) : gpu, false);
        }

        // hashcat's standalone benchmark has no live guard. Keep configured limits intact by leaving this measurement out.
        if (HashcatRunner.GuardFor(s, devices) is { Active: true } || !await MatchedSpeedProbe.PowerLimitAllowsAsync(s))
        {
            measuredWith?.Invoke(Describe(0, 0, 0, false, false, 0) with { Engine = "not measured: configured GPU guard, duty or power limit prevents a standalone benchmark" });
            return (0, false);
        }
        var args = HashcatRunner.MustAvoidAppleOpenCl(mode, OperatingSystem.IsMacOS())
            ? HashcatRunner.MetalOnlyArguments(s, devices) : HashcatRunner.DeviceArguments(s, devices);
        args.AddRange(["-w", s.Workload.ToString()]);
        args.AddRange(s.ExtraArguments.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Where(a => a is not ("-O" or "--optimized-kernel-enable")));
        double rate = await hashcat.BenchmarkAsync(mode, args, ct, s.OptimizedKernels && s.GpuPerformanceChoice?.Optimized != false, s.Priority);
        // hashcat's own benchmark mask decides the length (seven characters unless the mode sets another).
        measuredWith?.Invoke(Describe((await hashcat.ModeInfoAsync(mode))?.BenchmarkLength ?? 0, 0, 0, false, false, 0));
        return (rate, false);
    }
}
