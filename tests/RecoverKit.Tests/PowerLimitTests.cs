using RecoverKit.Core;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class PowerLimitTests
{
    // nvidia-smi --query-gpu=index,name,power.min_limit,power.max_limit,power.default_limit,power.limit --format=csv,noheader,nounits
    private const string Sample =
        "0, NVIDIA GeForce RTX 4070, 100.00, 200.00, 200.00, 200.00\n" +
        "1, NVIDIA GeForce RTX 3060, 100.00, 170.00, 170.00, 150.00\r\n" +
        "2, NVIDIA GeForce MX450, [N/A], [N/A], [N/A], [N/A]\n";

    /// <summary>A fake nvidia-smi that tracks limits and records every call.</summary>
    private sealed class FakeSmi
    {
        public readonly Dictionary<int, double> Limits = new() { [0] = 200, [1] = 150 };
        public readonly List<string> Calls = new();
        public int FailSetOn = -1;

        public NvidiaSmi Smi => new("nvidia-smi", (_, args) =>
        {
            Calls.Add(string.Join(' ', args));
            if (args[0].StartsWith("--query-gpu", StringComparison.Ordinal))
                return (0, $"0, NVIDIA GeForce RTX 4070, 100.00, 200.00, 200.00, {Limits[0]:0.00}\n1, NVIDIA GeForce RTX 3060, 100.00, 170.00, 170.00, {Limits[1]:0.00}\n");
            int gpu = int.Parse(args[1]);
            if (gpu == FailSetOn) return (4, "Insufficient Permissions");
            Limits[gpu] = double.Parse(args[3], System.Globalization.CultureInfo.InvariantCulture);
            return (0, "");
        });
    }

    [Fact]
    public void ParsesNvidiaSmiAndSkipsGpusWithoutPowerManagement()
    {
        var gpus = NvidiaPower.Parse(Sample);
        Assert.Equal(2, gpus.Count);
        Assert.Equal(new GpuPowerInfo(0, "NVIDIA GeForce RTX 4070", 100, 200, 200, 200), gpus[0]);
        Assert.Equal(150, gpus[1].CurrentWatts);
        Assert.True(gpus[1].Allows(100) && gpus[1].Allows(170));
        Assert.False(gpus[1].Allows(99) || gpus[1].Allows(171));
        Assert.Empty(NvidiaPower.Parse("No devices were found\n"));
        Assert.Equal(113,NvidiaPower.Parse("0, X, 112.50, 300.00, 250.00, 250.00")[0].MinAllowed);
    }

    [Fact]
    public void RequestContainsOnlyEnabledChangedGpusInRange()
    {
        var gpus = NvidiaPower.Parse(Sample);
        Assert.Null(NvidiaPower.BuildRequest(new Settings { GpuPowerWatts = { [0] = 180 } }, gpus));   // off by default
        var s = new Settings { GpuPowerLimit = true, GpuPowerWatts = { [0] = 180, [1] = 150, [2] = 50 } };
        var r = NvidiaPower.BuildRequest(s, gpus)!;
        var t = Assert.Single(r.Targets);                        // GPU 1 is already at 150 W, GPU 2 has no limit
        Assert.Equal(new PowerTarget(0, "NVIDIA GeForce RTX 4070", 180, 200), t);
        Assert.Contains("180 W for NVIDIA GeForce RTX 4070", r.Explanation);
        Assert.Contains("restored to 200 W", r.Explanation);
        Assert.Contains("without administrator rights", r.Explanation);
        Assert.Null(NvidiaPower.BuildRequest(new Settings { GpuPowerLimit = true, GpuPowerWatts = { [0] = 500 } }, gpus));
    }

    [Fact]
    public void HelperCommandLineRoundTrips()
    {
        var line = PowerHelper.CommandLine(4242, [new PowerTarget(0, "a", 180, 200), new PowerTarget(1, "b", 120, 150)]);
        var a = PowerHelper.Parse(line);
        Assert.Equal(4242, a.ParentPid);
        Assert.Equal([(0, 180), (1, 120)], a.Targets);
        Assert.False(a.Simulate);
    }

    [Theory]
    [InlineData("power-helper")]
    [InlineData("power-helper --pid 12")]
    [InlineData("power-helper --gpu 0 --watts 180")]
    [InlineData("power-helper --pid 12 --gpu 0")]
    [InlineData("power-helper --pid 12 --watts 180")]
    [InlineData("power-helper --pid 12 --gpu 0 --watts -5")]
    [InlineData("power-helper --pid 12 --gpu 0 --watts 180.5")]
    [InlineData("power-helper --pid 12 --gpu 0 --watts 99999")]
    [InlineData("power-helper --pid 12 --gpu 64 --watts 180")]
    [InlineData("power-helper --pid 12 --gpu 0 --watts 180 --gpu 0 --watts 170")]
    [InlineData("power-helper --pid 12 --pid 13 --gpu 0 --watts 180")]
    [InlineData("power-helper --pid 12 --gpu 0 --watts 180 --exec calc")]
    [InlineData("power-helper --pid 12 --gpu 0 --watts 180;calc")]
    [InlineData("power-helper --pid 0 --gpu 0 --watts 180")]
    [InlineData("other --pid 12 --gpu 0 --watts 180")]
    public void HelperRejectsAnythingButStrictArguments(string line)
        => Assert.Throws<ArgumentException>(() => PowerHelper.Parse(line.Split(' ')));

    [Fact]
    public void ApplySetsLimitsAndRestoreGoesBackToTheOriginals()
    {
        var fake = new FakeSmi();
        var originals = PowerHelper.Apply(fake.Smi, [(0, 180), (1, 120)]);
        Assert.Equal(180, fake.Limits[0]);
        Assert.Equal(120, fake.Limits[1]);
        Assert.Contains("-i 0 -pl 180", fake.Calls);
        PowerHelper.Restore(fake.Smi, originals);
        Assert.Equal(200, fake.Limits[0]);
        Assert.Equal(150, fake.Limits[1]);
    }

    [Fact]
    public void ApplyRefusesValuesOutsideTheReportedRangeWithoutChangingAnything()
    {
        var fake = new FakeSmi();
        Assert.Throws<InvalidOperationException>(() => PowerHelper.Apply(fake.Smi, [(0, 180), (1, 300)]));
        Assert.Throws<InvalidOperationException>(() => PowerHelper.Apply(fake.Smi, [(5, 150)]));
        Assert.DoesNotContain(fake.Calls, c => c.Contains("-pl"));
    }

    [Fact]
    public void ApplyRestoresEarlierGpusWhenALaterOneFails()
    {
        var fake = new FakeSmi { FailSetOn = 1 };
        Assert.Throws<InvalidOperationException>(() => PowerHelper.Apply(fake.Smi, [(0, 150), (1, 120)]));
        Assert.Equal(200, fake.Limits[0]);
        Assert.Equal(150, fake.Limits[1]);
    }

    [Fact]
    public void NvidiaSmiIsOnlyTakenFromTrustedDriverPaths()
    {
        foreach (var p in NvidiaSmi.TrustedPaths())
            Assert.True(Path.IsPathRooted(p));
        if (OperatingSystem.IsMacOS()) Assert.Empty(NvidiaSmi.TrustedPaths());
    }
}
