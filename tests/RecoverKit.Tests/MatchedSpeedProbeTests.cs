using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

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
}
