using RecoverKit.Core;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.App.Ui;

/// <summary>
/// Measures the recovery speed of one hash mode with the same engine and device arguments a real
/// attack would use: the built-in CPU kernels when no GPU is used, hashcat's benchmark on the GPUs
/// plus the built-in kernels on the CPU at the same time for hybrid formats, otherwise hashcat's
/// benchmark. Shared by the Benchmark window and the wizard's "Measure speed".
/// </summary>
internal static class SpeedProbe
{
    public static bool HasGpu(IReadOnlyList<BackendDevice> devices)
        => devices.Any(d => !d.IsSkippedAlias && d.IsGpu);

    /// <summary>True when an attack on this mode would run on the built-in CPU engine.</summary>
    public static bool UseNative(Settings s, IReadOnlyList<BackendDevice> devices, int mode) =>
        s.UseNativeCpuEngine && string.IsNullOrWhiteSpace(s.ExtraArguments) && NativeKernels.Supports(mode)
        && (HashcatRunner.ActiveGpus(s, devices).Count == 0 || s.Strategy == DeviceStrategy.CpuOnly)
        && NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]) is not null;

    /// <summary>True when a brute-force attack on this mode would run hybrid (hashcat on the GPUs, built-in engine on the CPU).</summary>
    public static bool UseHybrid(Settings s, IReadOnlyList<BackendDevice> devices, int mode) =>
        s.UseNativeCpuEngine && s.HybridCpuGpu && string.IsNullOrWhiteSpace(s.ExtraArguments) && NativeKernels.Supports(mode)
        && s.Strategy is DeviceStrategy.GpuOnly or DeviceStrategy.GpuAndCpu && HashcatRunner.ActiveGpus(s, devices).Count > 0
        && NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]) is not null;

    /// <summary>Passwords per second for <paramref name="mode"/> (0 when the device cannot run it).</summary>
    public static async Task<(double Speed, bool Native)> MeasureAsync(HashcatTool hashcat, Settings s, IReadOnlyList<BackendDevice> devices, int mode,
        TimeSpan nativeDuration, CancellationToken ct)
    {
        if (UseNative(s, devices, mode))
        {
            int threads = s.MaxCpuThreads > 0 ? s.MaxCpuThreads : Environment.ProcessorCount;
            return (await Task.Run(() => NativeKernels.Benchmark(mode, threads, nativeDuration, ct), ct), true);
        }
        bool hybrid = UseHybrid(s, devices, mode);
        var args = HashcatRunner.DeviceArguments(s, devices, gpuOnly: hybrid);
        args.AddRange(["-w", s.Workload.ToString()]);
        if (!hybrid) return (await hashcat.BenchmarkAsync(mode, args, ct, s.OptimizedKernels), false);

        // Both at once, as in an attack: they share cores, memory and power. The CPU keeps measuring
        // while hashcat runs (its start-up takes a while), and its last full measurement counts.
        using var done = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var gpu = hashcat.BenchmarkAsync(mode, args, ct, s.OptimizedKernels);
        int cpuThreads = HybridRunner.CpuThreads(s, devices, hashcatRunning: true);
        var cpu = Task.Run(() =>
        {
            double last = 0;
            while (!done.IsCancellationRequested)
            {
                // A sample cut short by the end of hashcat's run still covers its final seconds;
                // one shorter than the warm-up returns 0 and keeps the previous sample.
                double v = NativeKernels.Benchmark(mode, cpuThreads, nativeDuration, done.Token);
                if (v > 0) last = v;
            }
            return last;
        }, CancellationToken.None);
        double gpuSpeed;
        try { gpuSpeed = await gpu; }
        finally { done.Cancel(); }
        double cpuSpeed = await cpu;
        ct.ThrowIfCancellationRequested();
        if (gpuSpeed > 0) s.GpuSpeedByMode[mode] = gpuSpeed;
        if (cpuSpeed > 0) s.CpuSpeedByMode[mode] = cpuSpeed;
        DebugLog.Info($"Hybrid speed probe, mode {mode}: hashcat {gpuSpeed:N0} + built-in {cpuSpeed:N0} ({cpuThreads} threads)");
        return (gpuSpeed + cpuSpeed, false);
    }
}
