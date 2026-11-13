using System.Text.Json;
using System.Collections.Concurrent;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

/// <summary>A simultaneous CPU/GPU probe with identical target, charset and candidate length.</summary>
public static class MatchedSpeedProbe
{
    public const int Length = 7;

    internal static string HashLine(int mode) => NativeKernels.BenchmarkHashes[mode];

    internal static RunRequest CreateRequest(int mode, Settings settings, IReadOnlyList<BackendDevice> devices,
        string directory, TimeSpan duration, bool optimized)
    {
        var copy = JsonSerializer.Deserialize<Settings>(JsonSerializer.Serialize(settings))!;
        copy.PerformanceChoice = settings.PerformanceChoice;
        copy.CpuPerformanceChoice = settings.CpuPerformanceChoice;
        copy.GpuPerformanceChoice = settings.GpuPerformanceChoice;
        copy.ZipGpuPerformanceChoice = settings.ZipGpuPerformanceChoice;
        copy.DontUsePasswordCache = true;
        copy.SessionsDir = directory;
        var attack = new PreparedAttack { Description = "Synthetic matched speed measurement" };
        attack.Args.AddRange(["-a", "3", "-1", "?u?d?s", string.Concat(Enumerable.Repeat("?1", Length)),
            "--runtime", Math.Max(3, (int)Math.Ceiling(duration.TotalSeconds)).ToString(), "--restore-disable", "--logfile-disable", "--keep-guessing"]);
        return new RunRequest
        {
            Mode = mode, HashFile = Path.Combine(directory, "synthetic.hash"), Attack = attack,
            SessionName = "probe-" + Guid.NewGuid().ToString("N"), SessionDir = directory,
            Settings = copy, GpuOnly = true, Guard = HashcatRunner.GuardFor(copy, devices), UseOptimizedKernel = optimized,
        };
    }

    public static double CombinedRate(double cpu, double gpu) => cpu > 0 && gpu > 0 ? cpu + gpu : 0;

    public static async Task<bool> PowerLimitAllowsAsync(Settings settings)
    {
        if (!settings.GpuPowerLimit || settings.GpuPowerWatts.Count == 0) return true;
        var power = await NvidiaPower.QueryAsync();
        return power.Count > 0 && settings.GpuPowerWatts.All(pair => power.Any(p => p.Index == pair.Key && p.CurrentWatts <= pair.Value + .5));
    }

    public static async Task<(double Cpu, double Gpu)> MeasureAsync(HashcatTool tool, Settings settings,
        IReadOnlyList<BackendDevice> devices, int mode, int threads, TimeSpan duration, bool hybrid, CancellationToken ct)
    {
        if (!await PowerLimitAllowsAsync(settings)) return (0, 0);
        var directory = Directory.CreateTempSubdirectory("rk-speed-probe-").FullName;
        using var done = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(duration + TimeSpan.FromMinutes(3));
        Task<double> cpu = Task.FromResult(0d);
        try
        {
            var request = CreateRequest(mode, settings, devices, directory, duration,
                settings.OptimizedKernels && (settings.PerformanceChoice?.Optimized ?? settings.GpuPerformanceChoice?.Optimized) != false
                && (await tool.ModeInfoAsync(mode))?.HasOptimizedKernel == true);
            DebugLog.RegisterHashes(HashLine(mode));
            await File.WriteAllTextAsync(request.HashFile, HashLine(mode) + "\n", ct);
            var speeds = new ConcurrentQueue<double>();
            var runner = new HashcatRunner(tool) { KnownDevices = devices };
            runner.StatusReceived += status =>
            {
                if (status.Status == 3 && status.TotalSpeed > 0) speeds.Enqueue(status.TotalSpeed);
            };
            if (hybrid)
                cpu = Task.Run(() =>
                {
                    double last = 0;
                    while (!done.IsCancellationRequested)
                    {
                        double speed = NativeKernels.Benchmark(mode, threads, duration, done.Token, Length);
                        if (speed > 0) last = speed;
                    }
                    return last;
                }, CancellationToken.None);
            RunResult result;
            try { result = await runner.RunAsync(request, timeout.Token); }
            finally { done.Cancel(); }
            double cpuSpeed = await cpu;
            ct.ThrowIfCancellationRequested();
            if (result.Outcome == RunOutcome.Error || speeds.Count == 0) return (0, 0);
            var tail = speeds.Count > 3 ? speeds.Skip(2).Order().ToArray() : speeds.Order().ToArray();
            return (cpuSpeed, tail[tail.Length / 2]);
        }
        finally
        {
            done.Cancel();
            await cpu;
            try { Directory.Delete(directory, true); } catch (IOException) { }
        }
    }
}
