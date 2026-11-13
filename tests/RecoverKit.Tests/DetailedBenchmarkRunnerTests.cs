using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using Xunit;

namespace RecoverKit.Tests;

public class DetailedBenchmarkRunnerTests
{
    [Fact]
    public void SectionSelectionRejectsUnknownAndDeduplicates()
    {
        Assert.Throws<ArgumentException>(() => DetailedBenchmarkRunner.SelectSections(["typo"]));
        Assert.Equal(["system", "cpu"], DetailedBenchmarkRunner.SelectSections(["cpu", "system", "cpu"]));
    }

    [Fact]
    public void DeviceParserRetainsDriverVersion()
    {
        var devices = RecoverKit.Core.Hashcat.HashcatTool.ParseDevices("OpenCL Info:\nBackend Device ID #1\n  Name...........: Test GPU\n  Type...........: GPU\n  Driver.Version.: 123.45\n");
        Assert.Equal("123.45", Assert.Single(devices).DriverVersion);
    }

    [Fact]
    public void BenchmarkParserKeepsLaunchSettingsAndRate()
    {
        var row = DetailedBenchmarkRunner.ParseBenchmark("Kernel.Feature...: Optimized Kernel\nSpeed.#2.........:  12.34 kH/s (51.00ms) @ Accel:64 Loops:16384 Thr:128 Vec:1\n");
        Assert.Equal(12340, row.Speed);
        Assert.Equal("64", row.Details["Accel"]);
        Assert.Equal("16384", row.Details["Loops"]);
        Assert.Equal("128", row.Details["Thr"]);
        Assert.Equal("Optimized Kernel", row.Details["Kernel"]);
    }

    [Fact]
    public async Task CancellationRetainsPartialReportAndDoesNotChangeSettings()
    {
        var settings = new Settings { MaxCpuThreads = 3, GpuTempGuard = true, GpuDutyPercent = 50 };
        var before = System.Text.Json.JsonSerializer.Serialize(settings);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var report = await new DetailedBenchmarkRunner(null, settings, []).RunAsync(["system"], ct: cts.Token);
        Assert.True(report.Cancelled);
        Assert.Equal(before, System.Text.Json.JsonSerializer.Serialize(settings));
    }

    [Fact]
    public void IsolatedEngineCopyDoesNotTakePasswordsSessionsOrCaches()
    {
        string source = Directory.CreateTempSubdirectory("rk-copy-source-").FullName;
        string destination = Directory.CreateTempSubdirectory("rk-copy-dest-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(source, "hashcat"), "engine");
            Directory.CreateDirectory(Path.Combine(source, "OpenCL"));
            File.WriteAllText(Path.Combine(source, "OpenCL", "kernel.cl"), "kernel");
            foreach (string name in new[] { "hashcat.potfile", "attack.restore", "attack.outfiles", "private.hash", "hashcat.log" })
                File.WriteAllText(Path.Combine(source, name), "private data");
            Directory.CreateDirectory(Path.Combine(source, "cache"));
            File.WriteAllText(Path.Combine(source, "cache", "private"), "data");
            DetailedBenchmarkRunner.CopyEngine(source, destination, default);
            Assert.Equal(["hashcat"], Directory.GetFiles(destination).Select(Path.GetFileName));
            Assert.True(File.Exists(Path.Combine(destination, "OpenCL", "kernel.cl")));
            Assert.False(Directory.Exists(Path.Combine(destination, "cache")));
        }
        finally { Directory.Delete(source, true); Directory.Delete(destination, true); }
    }

    [Fact]
    public async Task EmptySelectionDoesNotRunOtherSections()
    {
        var report = await new DetailedBenchmarkRunner(null, new Settings(), []).RunAsync([]);
        Assert.Empty(report.Measurements);
        Assert.NotNull(report.Finished);
    }
}
