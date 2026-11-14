using RecoverKit.Core.Diagnostics;
using Xunit;

namespace RecoverKit.Tests;

public class WhirlpoolCpuPathsTests
{
    private static CpuDiagnosticWorker.WorkerResult Sample(double speed, string path, string state = "passed")
        => new(new(true, 44), speed, 2, path, SelfTestState: state);

    [Fact]
    public void SummaryUsesPairedMediansRangesAndActualPaths()
    {
        var result = new WhirlpoolCpuPaths(
            [Sample(100, "native scalar"), Sample(300, "native scalar"), Sample(200, "native scalar")],
            [Sample(600, "native AVX-512"), Sample(400, "native AVX-512"), Sample(500, "native AVX-512")], 8);
        Assert.Contains("previous 200/s", result.Summary);
        Assert.Contains("AVX-512 500/s", result.Summary);
        Assert.Contains("2.50x", result.Summary);
        Assert.Contains("3 pairs", result.Summary);
        Assert.Contains("8 threads, length 7", result.Summary);
        Assert.Contains("AVX-512 off by default", result.Summary);
    }

    [Theory]
    [InlineData("failed", "self-test failed")]
    [InlineData("switched off", "switched off")]
    [InlineData("not run", "not run")]
    public void GuardFailuresHaveNoWideRateOrRatio(string state, string message)
    {
        var result = new WhirlpoolCpuPaths([Sample(100, "native scalar")], [Sample(900, "native scalar", state)], 1);
        Assert.Contains(message, result.Summary);
        Assert.DoesNotContain("900/s", result.Summary);
        Assert.DoesNotContain("x)", result.Summary);
    }

    [Fact]
    public void PassedGuardWithFallbackStillHasNoWideRate()
    {
        var result = new WhirlpoolCpuPaths([Sample(100, "native scalar")], [Sample(900, "native scalar")], 1);
        Assert.Contains("actual native scalar", result.Summary);
        Assert.DoesNotContain("900/s", result.Summary);
    }
}
