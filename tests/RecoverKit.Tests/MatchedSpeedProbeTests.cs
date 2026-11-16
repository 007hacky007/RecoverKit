using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public class MatchedSpeedProbeTests
{
    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("matched-probe-test-").FullName;
        public void Dispose() => Directory.Delete(Path, true);
    }

    [Theory]
    [InlineData(12500, 4)]   // RAR 3's cost grows with the length: measured like the commercial product's figure
    [InlineData(17210, 7)]
    [InlineData(10700, 7)]
    [InlineData(13600, 7)]
    [InlineData(22000, 8)]
    [InlineData(29331, 7)]
    public void CpuAndGpuUseSameSyntheticFixtureAndMaskLength(int mode, int length)
    {
        var request = MatchedSpeedProbe.CreateRequest(mode, new Settings(), [], "probe", TimeSpan.FromSeconds(8), true);
        Assert.Equal(NativeKernels.BenchmarkHashes[mode], MatchedSpeedProbe.HashLine(mode));
        var space = MaskSpace.FromHashcatArgs(request.Attack.Args.Take(5).ToArray());
        Assert.NotNull(space);
        Assert.Equal(length, MatchedSpeedProbe.LengthFor(mode));
        Assert.Equal(length, space.MinLength);
        Assert.Equal(length, space.MaxLength);
        Assert.Equal("?u?d?s", request.Attack.Args[3]);
        Assert.DoesNotContain("-b", request.Attack.Args);
    }

    [Fact]
    public void ProbeRequestKeepsGuardsAndIsolatesWritesWithoutChangingPreferences()
    {
        var settings = new Settings { GpuTempGuard = true, GpuTempLimit = 74, GpuDutyPercent = 25, DontUsePasswordCache = false };
        settings.SpeedByMode[12500] = 123;
        var device = new BackendDevice { Id = 1, Name = "Test GPU", Type = "GPU" };
        var request = MatchedSpeedProbe.CreateRequest(12500, settings, [device], "probe", TimeSpan.FromSeconds(8), true);
        Assert.NotSame(settings, request.Settings);
        Assert.True(request.Settings.DontUsePasswordCache);
        Assert.False(settings.DontUsePasswordCache);
        Assert.Equal(123, settings.SpeedByMode[12500]);
        Assert.NotNull(request.Guard);
        Assert.True(request.Guard.TemperatureGuard);
        Assert.Equal(74, request.Guard.Limit);
        Assert.Equal(25, request.Settings.GpuDutyPercent);
        using var temp = new TempDir();
        var exe = Path.Combine(temp.Path, "hashcat");
        File.WriteAllText(exe, "");
        var args = new HashcatRunner(HashcatTool.Locate(exe, temp.Path, temp.Path)!) { HashcatMajorVersion = 8, KnownDevices = [device] }.BuildArguments(request);
        Assert.Contains("--potfile-disable", args);
        Assert.Contains("--restore-disable", args);
        Assert.Contains("--logfile-disable", args);
        Assert.Contains("--keep-guessing", args);
        Assert.Contains("--runtime", args);
        Assert.Equal("probe", request.SessionDir);
    }

    [Fact]
    public void HybridRateRequiresBothEngines()
    {
        Assert.Equal(0, MatchedSpeedProbe.CombinedRate(100, 0));
        Assert.Equal(0, MatchedSpeedProbe.CombinedRate(0, 100));
        Assert.Equal(250, MatchedSpeedProbe.CombinedRate(100, 150));
    }

    private static HashcatStatus Status(int state, double speed, long done = 100) => new()
    {
        Status = state, ProgressDone = done,
        Devices = [new() { Id = 1, Speed = speed }],
    };

    [Fact]
    public async Task RuntimeExitKeepsMeasuredFinalSpeedWithoutRunningSamples()
    {
        var final = Status(11, 150);
        var rates = await MatchedSpeedProbe.MeasureAsync(29331, TimeSpan.FromSeconds(8), (received, _) =>
        {
            received(final);
            return Task.FromResult(new RunResult { Outcome = RunOutcome.Aborted, ExitCode = 4, LastStatus = final });
        }, null, default);
        Assert.Equal((0d, 150d), rates);
    }

    [Fact]
    public async Task FinalRateUsesGuardAdjustedSpeed()
    {
        var rates = await MatchedSpeedProbe.MeasureAsync(29331, TimeSpan.FromSeconds(8), (received, _) =>
        {
            received(Status(11, 150)); // The guard accounts for a 25% GPU duty cycle.
            return Task.FromResult(new RunResult { Outcome = RunOutcome.Aborted, ExitCode = 4, LastStatus = Status(11, 600) });
        }, null, default);
        Assert.Equal((0d, 150d), rates);
    }

    [Theory]
    [InlineData(RunOutcome.Error, -1, 11, 150, 100)]
    [InlineData(RunOutcome.Aborted, 2, 7, 150, 100)]
    [InlineData(RunOutcome.Aborted, 4, 11, 0, 100)]
    [InlineData(RunOutcome.Aborted, 4, 11, 150, 0)]
    [InlineData(RunOutcome.Aborted, 4, 1, 150, 100)]
    public async Task FinalSpeedRequiresRuntimeExitAndCompletedWork(RunOutcome outcome, int exit, int state, double speed, long done)
    {
        var final = Status(state, speed, done);
        var rates = await MatchedSpeedProbe.MeasureAsync(29331, TimeSpan.FromSeconds(8), (received, _) =>
        {
            received(final);
            return Task.FromResult(new RunResult { Outcome = outcome, ExitCode = exit, LastStatus = final });
        }, null, default);
        Assert.Equal((0d, 0d), rates);
    }

    [Fact]
    public async Task GpuErrorDiscardsEarlierRunningSamples()
    {
        var rates = await MatchedSpeedProbe.MeasureAsync(29331, TimeSpan.FromSeconds(8), (received, _) =>
        {
            received(Status(3, 150));
            return Task.FromResult(new RunResult { Outcome = RunOutcome.Error, ExitCode = -1, Error = "CUDA self-test failed" });
        }, null, default);
        Assert.Equal((0d, 0d), rates);
    }

    [Theory]
    [InlineData(100, 999, 100)]
    [InlineData(0, 75, 75)]
    [InlineData(0, 0, 0)]
    public async Task InterruptedCpuWindowOnlyCountsWhenNoFullWindowSucceeded(double full, double partial, double expected)
    {
        var second = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int windows = 0;
        var rates = await MatchedSpeedProbe.MeasureAsync(29331, TimeSpan.FromSeconds(8), async (received, _) =>
        {
            await second.Task.WaitAsync(TimeSpan.FromSeconds(10));
            received(Status(3, 150));
            return new RunResult { Outcome = RunOutcome.Aborted, ExitCode = 4 };
        }, token =>
        {
            if (++windows == 1) return full;
            second.SetResult();
            token.WaitHandle.WaitOne();
            return partial;
        }, default);
        Assert.Equal((expected, 150d), rates);
    }

    [Fact]
    public async Task CpuExceptionDiscardsPreviousWindowAndDoesNotEscape()
    {
        var failed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int windows = 0;
        var rates = await MatchedSpeedProbe.MeasureAsync(29331, TimeSpan.FromSeconds(8), async (received, _) =>
        {
            await failed.Task.WaitAsync(TimeSpan.FromSeconds(10));
            received(Status(3, 150));
            return new RunResult { Outcome = RunOutcome.Aborted, ExitCode = 4 };
        }, _ =>
        {
            if (++windows == 1) return 100;
            failed.SetResult();
            throw new InvalidOperationException("rknative rejected the Whirlpool request");
        }, default);
        Assert.Equal((0d, 150d), rates);
    }

    [Fact]
    public async Task RunningMedianTakesPrecedenceOverFinalRate()
    {
        var final = Status(11, 999);
        var rates = await MatchedSpeedProbe.MeasureAsync(29331, TimeSpan.FromSeconds(8), (received, _) =>
        {
            foreach (double speed in new[] { 100d, 200, 300, 400, 500 }) received(Status(3, speed));
            received(final);
            return Task.FromResult(new RunResult { Outcome = RunOutcome.Aborted, ExitCode = 4, LastStatus = final });
        }, null, default);
        Assert.Equal((0d, 400d), rates);
    }

    [Fact]
    public async Task CancellationWaitsForCpuAndPropagates()
    {
        using var cancel = new CancellationTokenSource();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        bool finished = false;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => MatchedSpeedProbe.MeasureAsync(29331,
            TimeSpan.FromSeconds(8), async (_, token) =>
            {
                await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
                cancel.Cancel();
                token.ThrowIfCancellationRequested();
                return new RunResult();
            }, token =>
            {
                started.SetResult();
                token.WaitHandle.WaitOne();
                finished = true;
                return 0;
            }, cancel.Token));
        Assert.True(finished);
    }

    [Theory]
    [InlineData(12500)]
    [InlineData(13000)]
    [InlineData(17210)]
    [InlineData(10700)]
    [InlineData(9700)]
    [InlineData(29331)]
    public async Task FailedHybridLogsBothSides(int mode)
    {
        DebugLog.Start("matched-probe-test", "test", []);
        string log = DebugLog.CurrentFile!;
        try
        {
            var failed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var rates = await MatchedSpeedProbe.MeasureAsync(mode, TimeSpan.FromSeconds(8), async (received, _) =>
            {
                await failed.Task.WaitAsync(TimeSpan.FromSeconds(10));
                received(Status(1, 0));
                return new RunResult { Outcome = RunOutcome.Error, ExitCode = -1, Error = "CUDA self-test failed" };
            }, _ =>
            {
                failed.SetResult();
                throw new InvalidOperationException("test CPU kernel failure");
            }, default);
            Assert.Equal((0d, 0d), rates);
            // The log stays open for writing; Windows refuses File.ReadAllText's FileShare.Read.
            string text;
            using (var reader = new StreamReader(new FileStream(log, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)))
                text = reader.ReadToEnd();
            Assert.Contains($"Matched speed probe, mode {mode}: GPU failed", text);
            Assert.Contains("hashcat outcome Error, exit -1, error: CUDA self-test failed, status lines 1, running speed samples 0", text);
            Assert.Contains("CPU failed, rate 0", text);
            Assert.Contains("exception: test CPU kernel failure", text);
        }
        finally { DebugLog.Stop(); }
    }

    [Theory]
    [InlineData(2)]
    [InlineData(60)]
    [Trait("Category", "Slow")]
    public async Task WhirlpoolMeasuresBothEnginesWithRealHashcat(int statusInterval)
    {
        string? executable = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrWhiteSpace(executable), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8 copy.");
        Assert.True(RkNative.Available);
        var tool = HashcatTool.ForExe(executable!);
        var devices = await tool.DevicesAsync();
        Assert.Contains(devices, d => d.IsGpu);
        using var selection = KernelVariants.Select(29331, "scalar");
        // The long interval leaves only the final runtime status in an eight-second run.
        var settings = new Settings { Priority = ProcessPriority.Normal, ExtraArguments = $"--status-timer {statusInterval}" };
        var rates = await MatchedSpeedProbe.MeasureAsync(tool, settings,
            devices, 29331, Math.Max(1, Environment.ProcessorCount - 1), TimeSpan.FromSeconds(8), true, default);
        Assert.True(rates.Cpu > 0, $"CPU rate: {rates.Cpu}");
        Assert.True(rates.Gpu > 0, $"GPU rate: {rates.Gpu}");
    }
}
