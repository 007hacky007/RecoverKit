using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class PerformanceProfileTests
{
    private static DiagnosticMeasurement Row(string variant, double speed, int repeat = 1, bool correct = true) => new()
    {
        Section = "cpu", Mode = 17210, Target = "synthetic-stored-29", Length = 7,
        Engine = "cpu", Variant = variant, Threads = 8, Speed = speed, Repeat = repeat, Correct = correct,
    };

    [Fact]
    public void ClearRepeatableWinnerReplacesDefault()
    {
        var d = PerformanceProfiles.Choose([Row("managed",100),Row("managed",102,2),Row("avx512",140),Row("avx512",142,2)], "managed");
        Assert.Equal("avx512", d!.Variant);
        Assert.True(d.Margin >= .35);
    }

    [Fact]
    public void NoiseAndFailedCorrectnessKeepDefault()
    {
        Assert.Equal("managed", PerformanceProfiles.Choose([Row("managed",100),Row("managed",100,2),Row("avx2",104),Row("avx2",104,2)], "managed")!.Variant);
        Assert.Equal("managed", PerformanceProfiles.Choose([Row("managed",100),Row("managed",100,2),Row("avx512",200,1,false),Row("avx512",200,2,false)], "managed")!.Variant);
    }

    [Fact]
    public void MismatchedTargetOrMissingRepeatCannotWin()
    {
        var wrong = Row("avx512",200,2); wrong.Target="different";
        Assert.Equal("managed", PerformanceProfiles.Choose([Row("managed",100),Row("managed",100,2),Row("avx512",200),wrong],"managed")!.Variant);
    }

    [Fact]
    public void DriverChangeDropsGpuDecisionsOnly()
    {
        var p = new PerformanceProfile { CpuFingerprint="cpu", GpuFingerprint="driver1", Decisions=[new() { Domain="cpu", Mode=17210 },new() {Domain="execution",Mode=13000},new(){Domain="gpu",Mode=9400}] };
        PerformanceProfiles.Invalidate(p,"cpu","driver2");
        Assert.Single(p.Decisions);
        Assert.Equal("cpu",p.Decisions[0].Domain);
    }

    [Fact]
    public void ExplicitChoicesAndMissingDeviceWin()
    {
        var d = new PerformanceDecision { Domain="execution",Mode=17210,Engine="cpu",Threads=4,DeviceKeys=["missing"] };
        Assert.Null(PerformanceProfiles.Apply(d,new Settings(),[]));
        d.DeviceKeys=[];
        Assert.Null(PerformanceProfiles.Apply(d,new Settings{Strategy=DeviceStrategy.FastGpu},[]));
        Assert.Null(PerformanceProfiles.Apply(d,new Settings{MaxCpuThreads=2},[]));
        Assert.Null(PerformanceProfiles.Apply(d,new Settings{PerformanceStrategyExplicit=true},[]));
    }

    [Fact]
    public void TinyAttacksSkipCalibration()
    {
        Assert.False(PerformanceProfiles.ShouldCalibrate(new Settings(),17210,100,1_000_000));
        Assert.True(PerformanceProfiles.ShouldCalibrate(new Settings(),17210,100_000_000,1000));
        Assert.False(PerformanceProfiles.ShouldCalibrate(new Settings{AutomaticPerformanceCalibration=false},17210,100_000_000,1000));
    }

    [Fact]
    public void SameVariantWithinNoiseKeepsExactDefaultWorkerCount()
    {
        var alternative1 = Row("managed", 104); alternative1.Threads = 7;
        var alternative2 = Row("managed", 104, 2); alternative2.Threads = 7;
        var result = PerformanceProfiles.Choose([Row("managed", 100), Row("managed", 100, 2), alternative1, alternative2], "managed");
        Assert.Equal(8, result!.Threads);
        Assert.Equal(0, result.Margin);
    }

    [Fact]
    public void SameVariantClearWorkerWinnerRecordsMargin()
    {
        var alternative1 = Row("managed", 110); alternative1.Threads = 7;
        var alternative2 = Row("managed", 111, 2); alternative2.Threads = 7;
        var result = PerformanceProfiles.Choose([Row("managed", 100), Row("managed", 100, 2), alternative1, alternative2], "managed");
        Assert.Equal(7, result!.Threads);
        Assert.True(result.Margin >= .1);
    }

    [Fact]
    public void ExplicitDefaultMarkerSelectsExactBaseline()
    {
        var first = Row("managed", 104); first.Threads = 4;
        var second = Row("managed", 104, 2); second.Threads = 4;
        var baseline = Row("managed", 100); baseline.Details["Default"] = "true";
        var baseline2 = Row("managed", 100, 2); baseline2.Details["Default"] = "true";
        Assert.Equal(8, PerformanceProfiles.Choose([first, second, baseline, baseline2], "managed")!.Threads);
    }

    [Fact]
    public void DeviceKeysKeepTheirInternalPipes()
    {
        const string key = "CUDA|Example GPU|1";
        var first = Row("default", 100); first.Engine = "gpu"; first.DeviceKey = key;
        var second = Row("default", 100, 2); second.Engine = "gpu"; second.DeviceKey = key;
        Assert.Equal(new[] { key }, PerformanceProfiles.Choose([first, second], "default")!.DeviceKeys);
    }

    [Fact]
    public void AnyCorrectnessFailureDisqualifiesTheConfiguration()
    {
        Assert.Equal("managed", PerformanceProfiles.Choose([
            Row("managed", 100), Row("managed", 100, 2),
            Row("avx512", 200), Row("avx512", 200, 2), Row("avx512", 0, 0, false)], "managed")!.Variant);
    }

    [Fact]
    public void DisabledMeasuredDeviceCannotBeApplied()
    {
        var device = new BackendDevice { Id = 1, Key = "CUDA|Example GPU|1", Type = "GPU" };
        var decision = new PerformanceDecision { Engine = "gpu", DeviceKeys = [device.Key] };
        Assert.Null(PerformanceProfiles.Apply(decision, new Settings { DisabledDeviceKeys = [device.Key] }, [device]));
    }

    [Fact]
    public void AutomaticMeasurementsAreStoredAndReused()
    {
        var directory = Directory.CreateTempSubdirectory("rk-profile-test-");
        try
        {
            string file = Path.Combine(directory.FullName, "profile.json");
            var first = Row("default", 100); first.Mode = 9700;
            var second = Row("default", 101, 2); second.Mode = 9700;
            var report = new DiagnosticReport { Measurements = [first, second] };
            PerformanceProfiles.Record(report, null, [], "automatic", file);
            var stored = PerformanceProfiles.Load(file);
            Assert.Equal("automatic", stored.Source);
            Assert.NotNull(stored.MeasuredAt);
            Assert.Equal(100.5, PerformanceProfiles.ForMode(stored, 9700, 7, "cpu")!.Speed);
            Assert.Single(stored.Decisions);
        }
        finally { directory.Delete(true); }
    }

    [Fact]
    public void FailedCpuVariantIsQuarantinedUntilCpuFingerprintChanges()
    {
        var directory = Directory.CreateTempSubdirectory("rk-profile-test-");
        try
        {
            string file = Path.Combine(directory.FullName, "profile.json");
            var report = new DiagnosticReport { Measurements = [Row("avx512", 0, 0, false)] };
            PerformanceProfiles.Record(report, null, [], "detailed", file);
            var stored = PerformanceProfiles.Load(file);
            Assert.True(PerformanceProfiles.IsCpuVariantFailed(stored, 17210, "avx512"));
            PerformanceProfiles.Invalidate(stored, stored.CpuFingerprint, "new driver");
            Assert.True(PerformanceProfiles.IsCpuVariantFailed(stored, 17210, "avx512"));
            PerformanceProfiles.Invalidate(stored, "new CPU or native software", "new driver");
            Assert.False(PerformanceProfiles.IsCpuVariantFailed(stored, 17210, "avx512"));
        }
        finally { directory.Delete(true); }
    }

    [Fact]
    public void ReportScrubsPathsSecretsAndScriptInjection()
    {
        var r = new DiagnosticReport();
        r.Measurements.Add(new() { Error="failed /Users/test-person/private/file.zip C:\\Users\\someone\\secret.zip /home/other/private/a.hash $pkzip2$secret*$/pkzip2$ password=secret", Step="</script><img src=x onerror=alert(1)>" });
        var html=DiagnosticHtml.Render(r);
        Assert.DoesNotContain("test-person",html);
        Assert.DoesNotContain("someone",html);
        Assert.DoesNotContain("/home/other",html);
        Assert.DoesNotContain("file.zip",html);
        Assert.DoesNotContain("$pkzip2$",html);
        Assert.DoesNotContain("password=secret",html);
        Assert.DoesNotContain("</script><img",html);
        Assert.Contains("application/json",html);
    }
}
