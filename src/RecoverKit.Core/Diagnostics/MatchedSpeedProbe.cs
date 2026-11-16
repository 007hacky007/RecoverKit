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

    /// <summary>
    /// The password length a format is measured at. RAR 3 hashes the password again in every one of its
    /// 262,144 rounds, so its cost grows with the length (4096 x (2L + 11) SHA-1 blocks: 1.32x more at 7
    /// characters than at 4). It is measured at 4 characters, the length the commercial product's RAR 3
    /// figure matches (live attacks at fixed lengths, docs/benchmarks.md). Formats whose key derivation
    /// hashes the password once cost the same at any of these lengths and use <see cref="Length"/>,
    /// except WPA, whose minimum password length is eight bytes.
    /// </summary>
    public static int LengthFor(int mode) => mode == 12500 ? 4 : CpuDiagnostics.CandidateLength(mode);

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
        attack.Args.AddRange(["-a", "3", "-1", "?u?d?s", string.Concat(Enumerable.Repeat("?1", LengthFor(mode))),
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
        if (!await PowerLimitAllowsAsync(settings))
        {
            DebugLog.Warn($"Matched speed probe, mode {mode}: GPU blocked by power limit; CPU not started, rate 0/s.");
            return (0, 0);
        }
        var directory = Directory.CreateTempSubdirectory("rk-speed-probe-").FullName;
        try
        {
            var request = CreateRequest(mode, settings, devices, directory, duration,
                settings.OptimizedKernels && (settings.PerformanceChoice?.Optimized ?? settings.GpuPerformanceChoice?.Optimized) != false
                && (await tool.ModeInfoAsync(mode))?.HasOptimizedKernel == true);
            DebugLog.RegisterHashes(HashLine(mode));
            await File.WriteAllTextAsync(request.HashFile, HashLine(mode) + "\n", ct);
            var runner = new HashcatRunner(tool) { KnownDevices = devices };
            return await MeasureAsync(mode, duration, (received, token) =>
            {
                runner.StatusReceived += received;
                return runner.RunAsync(request, token);
            }, hybrid ? token => NativeKernels.Benchmark(mode, threads, duration, token, LengthFor(mode), NativeRunner.ThreadPriorityFor(settings.Priority)) : null, ct);
        }
        finally
        {
            try { Directory.Delete(directory, true); } catch (IOException) { }
        }
    }

    internal static async Task<(double Cpu, double Gpu)> MeasureAsync(int mode, TimeSpan duration,
        Func<Action<HashcatStatus>, CancellationToken, Task<RunResult>> runGpu,
        Func<CancellationToken, double>? measureCpu, CancellationToken ct)
    {
        using var done = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(duration + TimeSpan.FromMinutes(3));
        var speeds = new ConcurrentQueue<double>();
        int statusLines = 0;
        HashcatStatus? runtimeStatus = null;
        void Received(HashcatStatus status)
        {
            Interlocked.Increment(ref statusLines);
            if (status.Status == 3 && status.TotalSpeed > 0) speeds.Enqueue(status.TotalSpeed);
            if (status.Status == 11) Interlocked.Exchange(ref runtimeStatus, status);
        }
        Exception? cpuFailure = null;
        Task<double> cpu = measureCpu is null ? Task.FromResult(0d) : Task.Run(() =>
        {
            try
            {
                double last = 0;
                while (!done.IsCancellationRequested)
                {
                    double speed = measureCpu(done.Token);
                    // A window cut short when hashcat exits counts only when no full one completed.
                    if (speed > 0 && (!done.IsCancellationRequested || last == 0)) last = speed;
                }
                return last;
            }
            catch (Exception ex)
            {
                cpuFailure = ex;
                DebugLog.Error($"Matched speed probe, mode {mode}, CPU failed", ex);
                return 0;
            }
        }, CancellationToken.None);
        RunResult? result = null;
        Exception? gpuFailure = null;
        double cpuSpeed;
        try { result = await runGpu(Received, timeout.Token); }
        catch (Exception ex)
        {
            gpuFailure = ex;
            if (!ct.IsCancellationRequested) DebugLog.Error($"Matched speed probe, mode {mode}, GPU failed", ex);
        }
        finally
        {
            done.Cancel();
            cpuSpeed = await cpu;
        }
        ct.ThrowIfCancellationRequested();
        double gpuSpeed = 0;
        if (result is not null && result.Outcome != RunOutcome.Error && !timeout.IsCancellationRequested)
        {
            if (speeds.Count > 0)
            {
                var tail = speeds.Count > 3 ? speeds.Skip(2).Order().ToArray() : speeds.Order().ToArray();
                gpuSpeed = tail[tail.Length / 2];
            }
            // Use completed work from a normal runtime exit, keeping the event's guard-adjusted speed.
            else if (result is { Outcome: RunOutcome.Aborted, ExitCode: 4, LastStatus.Status: 11 }
                && runtimeStatus is { TotalSpeed: > 0 } final
                && final.ProgressDone > final.Rejected)
                gpuSpeed = final.TotalSpeed;
        }
        string summary = $"Matched speed probe, mode {mode}: GPU {(gpuSpeed > 0 ? "measured" : "failed")}, rate {gpuSpeed:F3}/s, " +
            $"hashcat outcome {result?.Outcome.ToString() ?? "exception"}, exit {result?.ExitCode.ToString() ?? "unavailable"}, " +
            $"error: {result?.Error ?? gpuFailure?.Message ?? "none"}, status lines {statusLines}, running speed samples {speeds.Count}, " +
            $"last status {result?.LastStatus?.Status.ToString() ?? "none"}, timeout {timeout.IsCancellationRequested}; " +
            $"CPU {(measureCpu is null ? "disabled" : cpuSpeed > 0 ? "measured" : "failed")}, rate {cpuSpeed:F3}/s, exception: {cpuFailure?.Message ?? "none"}.";
        if (gpuSpeed <= 0 || measureCpu is not null && cpuSpeed <= 0) DebugLog.Warn(summary);
        else DebugLog.Info(summary);
        return gpuSpeed > 0 ? (cpuSpeed, gpuSpeed) : (0, 0);
    }
}
