using System.Diagnostics;
using RecoverKit.Core;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class DeviceStrategyTests
{
    private static readonly BackendDevice Gpu = new() { Id = 1, Type = "GPU", Name = "Test GPU" };
    private static readonly BackendDevice Cpu = new() { Id = 2, Type = "CPU", Name = "Test CPU" };

    private static List<string> Args(DeviceStrategy s, params BackendDevice[] known)
        => HashcatRunner.DeviceArguments(new Settings { Strategy = s }, known);

    [Fact]
    public void DefaultStrategyLetsHashcatPickGpus()
        => Assert.Empty(Args(DeviceStrategy.GpuOnly, Gpu, Cpu));

    [Fact]
    public void GpuFirstStrategiesFallBackToTheProcessorWithoutAGpu()
    {
        Assert.Equal(["-D", "1"], Args(DeviceStrategy.GpuOnly, Cpu));
        Assert.Equal(["-D", "1"], Args(DeviceStrategy.FastGpu, Cpu));
    }

    [Fact]
    public void FastGpuUsesOnlyGpusWhenPresent()
        => Assert.Equal(["-D", "2"], Args(DeviceStrategy.FastGpu, Gpu, Cpu));

    [Fact]
    public void MaximumCpuUsesBothAndNoGpuUsesTheProcessor()
    {
        Assert.Equal(["-D", "1,2"], Args(DeviceStrategy.GpuAndCpu, Gpu, Cpu));
        Assert.Equal(["-D", "1", "--backend-ignore-cuda", "--backend-ignore-hip"], Args(DeviceStrategy.CpuOnly, Gpu, Cpu));
    }

    [Fact]
    public void UnknownDevicesAddNoFallback()
        => Assert.Empty(HashcatRunner.DeviceArguments(new Settings(), null));

    [Fact]
    public void CpuThreadLimitIsPassedToTheOpenClCpuRuntime()
    {
        var psi = new ProcessStartInfo("hashcat");
        CpuRuntime.ApplyTo(psi, 3);
        Assert.Equal("3", psi.Environment["CL_CONFIG_CPU_TBB_NUM_WORKERS"]);

        var auto = new ProcessStartInfo("hashcat");
        CpuRuntime.ApplyTo(auto, 0);
        Assert.False(auto.Environment.ContainsKey("CL_CONFIG_CPU_TBB_NUM_WORKERS"));
    }

    [Fact]
    public void OlderSettingsFilesStillLoadTheirStrategy()
    {
        var json = """{ "Strategy": "GpuAndCpu", "Priority": "Normal" }""";
        var s = System.Text.Json.JsonSerializer.Deserialize<Settings>(json,
            new System.Text.Json.JsonSerializerOptions { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } })!;
        Assert.Equal(DeviceStrategy.GpuAndCpu, s.Strategy);
        Assert.Equal(ProcessPriority.Normal, s.Priority);
        Assert.Equal(ProcessPriority.Idle, new Settings().Priority);
    }
}
