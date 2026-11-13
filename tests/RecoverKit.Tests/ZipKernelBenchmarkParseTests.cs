using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class ZipKernelBenchmarkParseTests
{
    private const string Samples = "{\"status\":3,\"devices\":[{\"speed\":100}]}\n{\"status\":3,\"devices\":[{\"speed\":200}]}\n{\"status\":3,\"devices\":[{\"speed\":30}]}\n{\"status\":3,\"devices\":[{\"speed\":50}]}\n{\"status\":3,\"devices\":[{\"speed\":40}]}\n";

    [Theory]
    [InlineData(-1)]
    [InlineData(255)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    public void RejectsPositiveSamplesWhenTheRunLaterFailsOrIsAbandoned(int exitCode)
    {
        Assert.Equal(0, ZipKernelBenchmark.ParseSpeed(exitCode, Samples));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    public void CompletedOrRuntimeLimitedRunUsesMedianAfterWarmup(int exitCode)
    {
        Assert.Equal(40, ZipKernelBenchmark.ParseSpeed(exitCode, Samples));
    }

    [Fact]
    public void NoRunningSamplesNeverBecomesAValidRate()
    {
        Assert.Equal(0, ZipKernelBenchmark.ParseSpeed(4, "{\"status\":13,\"devices\":[{\"speed\":999}]}"));
    }
}
