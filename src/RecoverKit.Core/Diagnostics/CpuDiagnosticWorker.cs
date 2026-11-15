using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Text.Json;
using RecoverKit.Core.Native;

namespace RecoverKit.Core.Diagnostics;

/// <summary>A native kernel fault ends one worker process while the main diagnostics keeps its results.</summary>
public static class CpuDiagnosticWorker
{
    public const string Command = "--rk-cpu-diagnostic-worker";
    public sealed record WorkerResult(CpuDiagnostics.CorrectnessResult Check, double Speed, double ElapsedSeconds, string ActualPath, string? Error = null, string SelfTestState = "not applicable");

    public static int Run(string[] args)
    {
        if (args.Length != 9 || args[0] != Command || !int.TryParse(args[1], out int mode)
            || !int.TryParse(args[3], out int threads) || !Enum.TryParse<ProcessPriority>(args[4], out var priority)
            || !int.TryParse(args[5], out int repeat) || !int.TryParse(args[6], out int length)
            || !int.TryParse(args[7], out int seconds) || threads < 1 || threads > Environment.ProcessorCount
            || repeat < 0 || length is < 1 or > 10 || seconds is < -1 or > 60) return 2;
        WorkerResult result;
        try
        {
            string variant = args[2];
            if (!NativeKernels.BenchmarkHashes.ContainsKey(mode) || !KernelVariants.Supported(mode, variant))
                result = new(new(false, 0, "Requested CPU variant is unsupported: CPU feature missing or native library unavailable."), 0, 0, NativeKernels.CpuPath(mode), "Requested CPU variant is unsupported: CPU feature missing or native library unavailable.", NativeKernels.WideSelfTestState(mode));
            else
            {
                if (NativeRunner.LowersProcessPriority)
                    try { Process.GetCurrentProcess().PriorityClass = NativeRunner.ProcessClassFor(priority); }
                    catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or PlatformNotSupportedException) { }
                if (Math.Abs(mode) == 29331) NativeKernels.ConfigureWhirlpool(Settings.Load());
                NativeKernels.ResetCpuPath(mode);
                using var selection = KernelVariants.Select(mode, variant);
                var selected = EnforcePath(new(new(true, 0), 0, 0, NativeKernels.CpuPath(mode), SelfTestState: NativeKernels.WideSelfTestState(mode)), variant);
                var check = !selected.Check.Passed ? selected.Check : Math.Abs(mode) is 17200 or 17210
                    ? CpuDiagnostics.CheckZipVariant(variant) : CpuDiagnostics.CheckKernel(mode, variant);
                string path = selected.Check.Passed ? NativeKernels.CpuPath(mode, actualOnly: true) : selected.ActualPath;
                string state = NativeKernels.WideSelfTestState(mode);
                check = EnforcePath(new(check, 0, 0, path, SelfTestState: state), variant).Check;
                if (!check.Passed) result = new(check with { Error = DiagnosticHtml.Scrub(check.Error ?? "Correctness check failed.") }, 0, 0, path, SelfTestState: state);
                else
                {
                    var timer = Stopwatch.StartNew();
                    double speed;
                    if (seconds is -1 or 1)
                    {
                        var kernel = NativeKernels.TryCreate(Math.Abs(mode), NativeKernels.BenchmarkHashes[mode])!;
                        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "?u?d?s", string.Concat(Enumerable.Repeat("?1", length))])!;
                        using var sample = new CancellationTokenSource(TimeSpan.FromMilliseconds(seconds == 1 ? 1500 : 650));
                        var engine = new NativeEngine(kernel, space) { Threads = threads, Priority = NativeRunner.ThreadPriorityFor(priority), ProgressInterval = TimeSpan.FromMilliseconds(100) };
                        long warmupDone = 0;
                        double warmupElapsed = 0;
                        if (seconds == 1) engine.Progress += p =>
                        {
                            if (warmupElapsed == 0 && timer.Elapsed.TotalSeconds >= .5)
                            { warmupDone = p.Done; warmupElapsed = timer.Elapsed.TotalSeconds; }
                        };
                        var measured = engine.Run(null, sample.Token);
                        double elapsed = timer.Elapsed.TotalSeconds - warmupElapsed;
                        speed = elapsed > 0 && (seconds != 1 || warmupElapsed > 0)
                            ? (measured.Tested - warmupDone) / elapsed : 0;
                    }
                    else speed = seconds == 0 ? 0 : NativeKernels.Benchmark(mode, threads, TimeSpan.FromSeconds(seconds), length: length,
                        priority: NativeRunner.ThreadPriorityFor(priority));
                    result = EnforcePath(new(check, speed, timer.Elapsed.TotalSeconds, NativeKernels.CpuPath(mode, actualOnly: true), SelfTestState: NativeKernels.WideSelfTestState(mode)), variant);
                }
            }
        }
        catch (Exception ex) { result = Failed($"CPU worker step failed ({ex.GetType().Name})."); }
        try { File.WriteAllText(args[8], JsonSerializer.Serialize(result)); return 0; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return 3; }
    }

    internal static WorkerResult EnforcePath(WorkerResult result, string variant)
    {
        if (variant is not ("scalar" or "avx2" or "avx512" or "neon" or "arm-sha1")) return result;
        string actual = result.ActualPath.Replace("native ", "", StringComparison.OrdinalIgnoreCase).Replace("-", "").Replace(" ", "").ToLowerInvariant();
        if (actual == variant.Replace("-", "") && (variant != "avx512" || result.SelfTestState is not ("not run" or "failed" or "switched off"))) return result;
        string reason = result.SelfTestState switch
        {
            "failed" => "self-test failed",
            "switched off" => "switched off by the environment",
            "not run" => "feature missing or self-test not run",
            _ => "native dispatch or allocation fallback",
        };
        string error = $"Requested {variant}, actual {result.ActualPath}: {reason}. Timing rejected.";
        return result with { Check = new(false, result.Check.Cases, error), Speed = 0, Error = error };
    }

    public static Task<WorkerResult> CheckResultAsync(int mode, string variant, CancellationToken ct = default)
        => ExecuteAsync(mode, variant, 1, ProcessPriority.Normal, 0, CpuDiagnostics.CandidateLength(mode), 0, ct);

    public static async Task<CpuDiagnostics.CorrectnessResult> CheckAsync(int mode, string variant, CancellationToken ct = default)
        => (await CheckResultAsync(mode, variant, ct)).Check;

    public static Task<WorkerResult> MeasureAsync(int mode, string variant, int threads, ProcessPriority priority, int repeat, CancellationToken ct = default, int seconds = 3)
        => ExecuteAsync(mode, variant, threads, priority, repeat, CpuDiagnostics.CandidateLength(mode), seconds, ct);

    public static Task<WorkerResult> MeasureAutomaticAsync(int mode, string variant, int threads, int length, ProcessPriority priority, CancellationToken ct = default)
        => ExecuteAsync(mode, variant, threads, priority, 1, length, -1, ct);

    private static async Task<WorkerResult> ExecuteAsync(int mode, string variant, int threads, ProcessPriority priority, int repeat, int length, int seconds, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        string? directory = null;
        try
        {
            directory = Directory.CreateTempSubdirectory("rk-cpu-worker-").FullName;
            string output = Path.Combine(directory, "result.json");
            var start = SelfStartInfo();
            if (Math.Abs(mode) is 13600 or 22000 && variant != "default")
                start.Environment["RECOVERKIT_PBKDF2_SHA1_PATH"] = variant;
            foreach (var arg in new[] { Command, mode.ToString(CultureInfo.InvariantCulture), variant, threads.ToString(CultureInfo.InvariantCulture), priority.ToString(),
                repeat.ToString(CultureInfo.InvariantCulture), length.ToString(CultureInfo.InvariantCulture), seconds.ToString(CultureInfo.InvariantCulture), output }) start.ArgumentList.Add(arg);
            return await RunProcessAsync(start, output, TimeSpan.FromSeconds(seconds + 30), ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        { return Failed($"CPU worker could not start ({ex.GetType().Name})."); }
        finally
        {
            if (directory is not null)
                try { Directory.Delete(directory, true); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    internal static ProcessStartInfo SelfStartInfo()
    {
        string process = Environment.ProcessPath ?? throw new InvalidOperationException("The application executable is unavailable.");
        var start = new ProcessStartInfo(process);
        if (Path.GetFileNameWithoutExtension(process).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            string entry = Assembly.GetEntryAssembly()?.Location ?? "";
            if (entry.Length == 0) throw new InvalidOperationException("The managed application entrypoint is unavailable.");
            start.ArgumentList.Add(entry);
        }
        return start;
    }

    internal static async Task<WorkerResult> RunProcessAsync(ProcessStartInfo start, string output, TimeSpan timeout, CancellationToken ct)
    {
        var result = await RunJsonProcessAsync(start, output, timeout, ct);
        return result.Error is not null ? Failed(result.Error) : ReadResult(result.ExitCode, result.Json);
    }

    internal static async Task<(int ExitCode, string Json, string? Error)> RunJsonProcessAsync(ProcessStartInfo start, string output, TimeSpan timeout, CancellationToken ct, bool isolatedProcessGroup = false)
    {
        ct.ThrowIfCancellationRequested();
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        using var process = new Process { StartInfo = start };
        process.Start();
        // Drain both pipes without retaining process diagnostics, which can include runtime paths.
        var stdout = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
        var stderr = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(timeout);
        try { await process.WaitForExitAsync(deadline.Token); }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            if (isolatedProcessGroup) FiniteDiagnosticWorker.StopProcessGroup(process.Id);
            await process.WaitForExitAsync(CancellationToken.None);
            await Task.WhenAll(stdout, stderr);
            ct.ThrowIfCancellationRequested();
            return (-1, "", "Diagnostic worker exceeded its time limit.");
        }
        if (isolatedProcessGroup) FiniteDiagnosticWorker.StopProcessGroup(process.Id);
        await Task.WhenAll(stdout, stderr);
        string json = File.Exists(output) && new FileInfo(output).Length <= 1_000_000 ? await File.ReadAllTextAsync(output, ct) : "";
        return (process.ExitCode, json, null);
    }

    internal static WorkerResult ReadResult(int exitCode, string json)
    {
        if (exitCode != 0) return Failed($"CPU worker terminated (exit {exitCode}); the variant was not timed further.");
        try
        {
            var result = JsonSerializer.Deserialize<WorkerResult>(json);
            if (result is null || result.Check is null || result.Check.Passed && result.Check.Cases <= 0
                || !double.IsFinite(result.Speed) || result.Speed < 0 || !double.IsFinite(result.ElapsedSeconds) || result.ElapsedSeconds < 0)
                return Failed("CPU worker returned an invalid result.");
            return result;
        }
        catch (JsonException) { return Failed("CPU worker returned invalid JSON."); }
    }

    private static WorkerResult Failed(string message) => new(new(false, 0, message), 0, 0, "", message);
}
