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
        Assert.Equal(["-D", "1"], Args(DeviceStrategy.CpuOnly, Gpu, Cpu));
    }

    [Fact]
    public void UnknownDevicesAddNoFallback()
        => Assert.Empty(HashcatRunner.DeviceArguments(new Settings(), null));

    [Fact]
    public void HybridRunsKeepTheProcessorOutOfHashcat()
    {
        var known = new[] { Gpu, Cpu };
        Assert.Equal(["-D", "2"], HashcatRunner.DeviceArguments(new Settings(), known, gpuOnly: true));
        Assert.Equal(["-D", "2"], HashcatRunner.DeviceArguments(new Settings { Strategy = DeviceStrategy.GpuAndCpu }, known, gpuOnly: true));
        // Without a GPU "GPU only" has nothing to run on; the normal fallback applies.
        Assert.Equal(["-D", "1"], HashcatRunner.DeviceArguments(new Settings(), [Cpu], gpuOnly: true));
    }

    [Fact]
    public void CpuNextToGpusIsOptionalAndNeedsACpuDevice()
    {
        var on = new Settings { HashcatCpuWithGpu = true };
        Assert.Equal(["-D", "1,2"], HashcatRunner.DeviceArguments(on, [Gpu, Cpu]));
        Assert.Empty(HashcatRunner.DeviceArguments(on, [Gpu]));                  // Apple silicon: no CPU device
        Assert.Empty(Args(DeviceStrategy.GpuOnly, Gpu, Cpu));                     // off by default
        Assert.Equal(["-D", "2"], HashcatRunner.DeviceArguments(on, [Gpu, Cpu], gpuOnly: true));
    }

    private const string TwoGpuInfo = """
        CUDA Info:
        ==========

        Backend Device ID #01
          Name...........: NVIDIA GeForce RTX 4060
          Processor(s)...: 24
          Memory.Total...: 8187 MB
          Memory.Unified.: 0

        HIP Info:
        =========

        Backend Device ID #02
          Name...........: AMD Radeon(TM) Graphics
          Processor(s)...: 1
          Memory.Total...: 512 MB
          Memory.Unified.: 1

        OpenCL Info:
        ============

        OpenCL Platform ID #1
          Vendor..: NVIDIA Corporation

          Backend Device ID #03 (Alias: #01)
            Type...........: GPU
            Name...........: NVIDIA GeForce RTX 4060
            Memory.Unified.: 0

        OpenCL Platform ID #2
          Vendor..: Advanced Micro Devices, Inc.

          Backend Device ID #04 (Alias: #02)
            Type...........: GPU
            Name...........: AMD Radeon(TM) Graphics
            Memory.Unified.: 1
        """;

    [Fact]
    public void DiscreteAndIntegratedGpusAreBothUsed()
    {
        // hashcat prints no "Type" for CUDA and HIP devices: they used to count as "not a GPU", and with
        // their OpenCL aliases skipped RecoverKit saw no GPU at all.
        var devs = HashcatTool.ParseDevices(TwoGpuInfo);
        Assert.Equal(4, devs.Count);
        var active = HashcatRunner.ActiveGpus(new Settings(), devs);
        Assert.Equal([1, 2], active.Select(d => d.Id));                       // one of each pair, both GPUs
        Assert.False(devs[0].IsIntegratedGpu);
        Assert.True(devs[1].IsIntegratedGpu);
        Assert.Empty(Args(DeviceStrategy.GpuOnly, [.. devs]));                  // hashcat's default already uses both
        Assert.Equal("CUDA|NVIDIA GeForce RTX 4060|0", devs[0].Key);
        Assert.Equal("OpenCL|AMD Radeon(TM) Graphics|0", devs[3].Key);
    }

    [Fact]
    public void UncheckedGpusAreRememberedByNameNotId()
    {
        var devs = new List<BackendDevice>
        {
            new() { Id = 1, Type = "GPU", Name = "dGPU", Key = "CUDA|dGPU|0" },
            new() { Id = 2, Type = "GPU", Name = "iGPU", Key = "HIP|iGPU|0", Unified = true },
        };
        var s = new Settings { DisabledDeviceKeys = ["HIP|iGPU|0"], DisabledDevices = [1] };   // stale id from an older numbering
        Assert.Equal(["-d", "1"], HashcatRunner.DeviceArguments(s, devs));
        Assert.Equal([1], HashcatRunner.ActiveGpus(s, devs).Select(d => d.Id));
        // Older settings files with ids only still work.
        Assert.Equal(["-d", "2"], HashcatRunner.DeviceArguments(new Settings { DisabledDevices = [1] }, devs));
        // A device left out for one run (slow integrated GPU in a hybrid attack).
        Assert.Equal(["-D", "2", "-d", "1"], HashcatRunner.DeviceArguments(new Settings(), devs, gpuOnly: true, exclude: [2]));
    }

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
