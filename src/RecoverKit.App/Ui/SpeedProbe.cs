using RecoverKit.Core;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.App.Ui;

/// <summary>
/// Measures the recovery speed of one hash mode with the same engine and device arguments a real
/// attack would use: the built-in CPU kernels when no GPU is used, otherwise hashcat's benchmark.
/// Shared by the Benchmark window and the wizard's "Measure speed".
/// </summary>
internal static class SpeedProbe
{
    public static bool HasGpu(IReadOnlyList<BackendDevice> devices)
        => devices.Any(d => !d.IsSkippedAlias && d.Type.Contains("GPU", StringComparison.OrdinalIgnoreCase));

    /// <summary>True when an attack on this mode would run on the built-in CPU engine.</summary>
    public static bool UseNative(Settings s, IReadOnlyList<BackendDevice> devices, int mode) =>
        s.UseNativeCpuEngine && string.IsNullOrWhiteSpace(s.ExtraArguments) && NativeKernels.Supports(mode)
        && (!HasGpu(devices) || s.Strategy == DeviceStrategy.CpuOnly)
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
        var args = HashcatRunner.DeviceArguments(s, devices);
        args.AddRange(["-w", s.Workload.ToString()]);
        if (s.OptimizedKernels && (await hashcat.ModeInfoAsync(mode))?.HasOptimizedKernel == true) args.Add("-O");
        return (await hashcat.BenchmarkAsync(mode, args, ct), false);
    }
}
