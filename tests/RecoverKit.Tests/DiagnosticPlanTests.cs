using RecoverKit.Core.Diagnostics;
using Xunit;

namespace RecoverKit.Tests;

public class DiagnosticPlanTests
{
    [Fact]
    public async Task SkippedRepeatsAndActualDurationsDriveBothProgressAndEstimate()
    {
        var plan = new DiagnosticPlan();
        bool ran = false;
        plan.Add("cpu", "first", 2, () => Task.CompletedTask);
        plan.Add("cpu", "repeat", 2, () => { ran = true; return Task.CompletedTask; }, () => false);
        var initial = plan.Progress(TimeSpan.FromSeconds(1));
        Assert.Equal(4, initial.EstimatedRemaining.TotalSeconds);
        Assert.Equal(.2, initial.Fraction, 6);
        await plan.RunAsync(new(), () => { }, default);
        Assert.False(ran);
        Assert.Equal("skipped", plan.Steps[1].State);
        Assert.Equal(0, plan.Progress(TimeSpan.FromSeconds(1)).EstimatedRemaining.TotalSeconds);
        Assert.Equal(1, plan.Progress(TimeSpan.FromSeconds(1)).Fraction);
    }

    [Fact]
    public async Task ConditionalSlotsEnterEstimateOnlyWhenNeeded()
    {
        var plan = new DiagnosticPlan();
        plan.Add("gpu", "first", 5, () => Task.CompletedTask);
        plan.Add("gpu", "repeat if noisy", 5, () => Task.CompletedTask, () => true, conditional: true);
        Assert.Equal(5, plan.Progress(TimeSpan.Zero).EstimatedRemaining.TotalSeconds);
        await plan.RunAsync(new(), () => { }, default);
        Assert.All(plan.Steps, s => Assert.Equal("done", s.State));
    }

    [Fact]
    public void HashcatAveragesNeedConfirmationOnlyWhenObservedRatesAreNoisy()
    {
        Assert.Equal("False", DetailedBenchmarkRunner.ParseBenchmark("Speed.#1: 9.8 MH/s").Details["Noisy"]);
        Assert.Equal("True", DetailedBenchmarkRunner.ParseBenchmark("Speed.#1: 9 MH/s\nSpeed.#1: 11 MH/s").Details["Noisy"]);
    }

    [Fact]
    public void OnlyContendersNeedARepeat()
    {
        Assert.False(DiagnosticPlan.Contender(80, [100, 102, 80]));
        Assert.True(DiagnosticPlan.Contender(98, [100, 102, 98]));
        Assert.False(DiagnosticPlan.Contender(0, [0]));
    }

    [Fact]
    public void FiniteMaskTracksTheMeasuredRateWithoutExceedingBudget()
    {
        foreach (double speed in new[] { 5000d, 20000, 3e9 })
        {
            var mask = FiniteDiagnosticWorker.SizedMask(speed, 12);
            var space = RecoverKit.Core.Native.MaskSpace.FromHashcatArgs(mask)!;
            double seconds = (double)space.Keyspace(space.MaxLength) / speed;
            Assert.InRange(seconds, 10, 15);
        }
    }
    [Fact]
    public void AdaptiveSelectionConfirmsWinnerButDoesNotRepeatClearLoser()
    {
        DiagnosticMeasurement Row(string variant, double speed, int repeat) => new()
        {
            Mode = 17210, Target = "synthetic", Length = 7, Variant = variant, Engine = "cpu", Correct = true,
            Speed = speed, Repeat = repeat, Details = new() { ["Adaptive sampling"] = "True" },
        };
        var baseline = Row("default", 100, 1);
        Assert.Equal("default", PerformanceProfiles.Choose([baseline, Row("fast", 140, 1)], "default")!.Variant);
        Assert.Equal("fast", PerformanceProfiles.Choose([baseline, Row("fast", 140, 1), Row("fast", 141, 2)], "default")!.Variant);
    }

    [Fact]
    public void HybridWorkersFollowCpuScalingAndReserveOneThread()
    {
        Assert.Equal([7, 8], DetailedBenchmarkRunner.HybridWorkers([
            new() { Section = "cpu", Mode = 13000, Correct = true, Threads = 8, Speed = 100 },
            new() { Section = "cpu", Mode = 13000, Correct = true, Threads = 16, Speed = 90 },
            new() { Section = "cpu", Mode = 13000, Correct = false, Threads = 32, Speed = 200 }], 13000, 16));
    }
    [Fact]
    public void FailedMarkedBaselineCannotBeReplacedWithAnAliasByAccident()
    {
        var failed = new DiagnosticMeasurement { Mode = 13000, Variant = "default", Details = new() { ["Default"] = "True" } };
        var alias = new DiagnosticMeasurement { Mode = 13000, Variant = "default", Correct = true, Repeat = 1, Speed = 100,
            Details = new() { ["Adaptive sampling"] = "True", ["Internally averaged benchmark"] = "True" } };
        Assert.Null(PerformanceProfiles.Choose([failed, alias], "default"));
    }

    [Fact]
    public void BoundedGpuTuningIsLocalAndRestoresExistingBytes()
    {
        string directory = Directory.CreateTempSubdirectory("rk-tuning-test-").FullName;
        try
        {
            string exe = Path.Combine(directory, OperatingSystem.IsWindows() ? "hashcat.exe" : "hashcat");
            File.WriteAllText(exe, "");
            var tool = RecoverKit.Core.Hashcat.HashcatTool.Locate(exe, directory, directory)!;
            var device = new RecoverKit.Core.Hashcat.BackendDevice { Name = "Example GPU", Processors = 16 };
            using (DiagnosticGpuTuning.Apply(tool, [device]))
                Assert.Contains("Example_GPU 3 * N 64 1000", File.ReadAllText(Path.Combine(directory, "tunings", "RecoverKit-diagnostics.hctune")));
            Assert.Empty(Directory.GetFiles(Path.Combine(directory, "tunings")));
            string file = Path.Combine(directory, "tunings", "RecoverKit-diagnostics.hctune");
            File.WriteAllBytes(file, [1, 2, 3]);
            using (DiagnosticGpuTuning.Apply(tool, [device])) { }
            Assert.Equal(new byte[] { 1, 2, 3 }, File.ReadAllBytes(file));
        }
        finally { Directory.Delete(directory, true); }
    }
}

public class BoundedDiagnosticPlanTests
{
    [Fact]
    public async Task DeadlineCancelsSlowWorkAndRecordsUnmeasuredSteps()
    {
        var report = new DiagnosticReport();
        var plan = new DiagnosticPlan { TotalBudget = TimeSpan.FromMilliseconds(80) };
        plan.AddBounded("gpu", "slow startup", .05, async ct => await Task.Delay(10000, ct));
        plan.AddBounded("gpu", "lower priority", 1, _ => throw new Exception("Must not run"));
        await plan.RunAsync(report, () => { }, default);
        Assert.All(plan.Steps, s => Assert.Equal("not measured", s.State));
        Assert.All(report.Measurements, m => Assert.Contains("run the thorough test", m.Error));
        Assert.False(report.Cancelled);
    }

    [Fact]
    public async Task SectionBudgetDoesNotConsumeAnotherSectionsAllocation()
    {
        var plan = new DiagnosticPlan { SectionBudgets = new() { ["gpu"] = .01, ["cpu"] = 1 } };
        bool cpuRan = false;
        plan.AddBounded("gpu", "too expensive", 1, _ => throw new Exception("Must not run"));
        plan.AddBounded("cpu", "correctness", .1, _ => { cpuRan = true; return Task.CompletedTask; });
        await plan.RunAsync(new(), () => { }, default);
        Assert.True(cpuRan);
        Assert.Equal("not measured", plan.Steps[0].State);
    }
}

public class ShortBackendTests
{
    [Fact]
    public void BackendMustWinBothRepresentativeModes()
    {
        var baseline = new RecoverKit.Core.Hashcat.BackendDevice { Id = 1, Key = "CUDA|GPU|0" };
        var alternative = new RecoverKit.Core.Hashcat.BackendDevice { Id = 2, Key = "OpenCL|GPU|0", IsSkippedAlias = true };
        DiagnosticMeasurement Row(int mode, string key, double speed) => new() { Step = "backend probe", Mode = mode, DeviceKey = key, Correct = true, Speed = speed };
        var rows = new List<DiagnosticMeasurement> { Row(10500, baseline.Key, 100), Row(10500, alternative.Key, 120), Row(13000, baseline.Key, 100) };
        Assert.Null(DetailedBenchmarkRunner.ShortBackendWinner(rows, [baseline, alternative]));
        rows.Add(Row(13000, alternative.Key, 104));
        Assert.Null(DetailedBenchmarkRunner.ShortBackendWinner(rows, [baseline, alternative]));
        rows[^1].Speed = 120;
        Assert.Same(alternative, DetailedBenchmarkRunner.ShortBackendWinner(rows, [baseline, alternative]));
    }

    [Fact]
    public void SectionAllocationsLeaveFiveSecondsForCleanup()
        => Assert.Equal(CpuDiagnostics.HasWidePaths ? 267 : 115, DetailedBenchmarkRunner.ShortBudgets.Values.Sum());
}
