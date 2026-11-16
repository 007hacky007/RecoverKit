using RecoverKit.Core;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

[Collection("CudaFallback")]
public sealed class NvidiaBackendTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-backend-").FullName;
    internal static readonly BackendDevice[] Devices =
    [
        new() { Id = 1, AliasOf = 2, Key = "CUDA|NVIDIA GeForce RTX 4060|0", Type = "GPU", Backend = "CUDA", Name = "NVIDIA GeForce RTX 4060" },
        new() { Id = 2, AliasOf = 1, Key = "OpenCL|NVIDIA GeForce RTX 4060|0", Type = "GPU", Backend = "OpenCL", Name = "NVIDIA GeForce RTX 4060", DriverVersion = "test-backend" },
        new() { Id = 3, Key = "OpenCL|AMD Radeon Graphics|0", Type = "GPU", Backend = "OpenCL", Name = "AMD Radeon Graphics", Unified = true },
    ];

    public NvidiaBackendTests() => CudaFallback.ResetForTests(Path.Combine(_dir, "fallback.json"));
    public void Dispose()
    {
        CudaFallback.ResetForTests(Path.Combine(Settings.AppDataDir, "cuda-fallback.json"));
        Directory.Delete(_dir, true);
    }

    [Theory]
    [InlineData(NvidiaBackend.Automatic, false, 1)]
    [InlineData(NvidiaBackend.Automatic, true, 2)]
    [InlineData(NvidiaBackend.Cuda, false, 1)]
    [InlineData(NvidiaBackend.Cuda, true, 1)]
    [InlineData(NvidiaBackend.OpenCl, false, 2)]
    [InlineData(NvidiaBackend.OpenCl, true, 2)]
    public void PreferenceResolvesTheAliasWithoutIgnoringCuda(NvidiaBackend preference, bool fallback, int id)
    {
        if (fallback) CudaFallback.Activate(Devices, "kernel build failed");
        var settings = new Settings { NvidiaBackend = preference };
        Assert.Equal([id], HashcatRunner.ActiveGpus(settings, Devices).Select(d => d.Id));
        var args = HashcatRunner.DeviceArguments(settings, Devices);
        Assert.Equal(id.ToString(), args[args.IndexOf("-d") + 1]);
        Assert.DoesNotContain("--backend-ignore-cuda", args);
        Assert.Equal(id == 1 ? "CUDA" : "OpenCL", HashcatRunner.RunningBackend(settings, Devices[0], Devices));
    }

    [Fact]
    public void ExplicitTicksAndStrategiesOverrideIntegratedExclusion()
    {
        Assert.True(HashcatRunner.IsAutomaticallyExcluded(new Settings(), Devices[2], Devices));
        Assert.Equal([1, 3], HashcatRunner.ActiveGpus(new Settings { DeviceSelectionExplicit = true }, Devices).Select(d => d.Id));
        Assert.Equal([1, 3], HashcatRunner.ActiveGpus(new Settings { PerformanceStrategyExplicit = true }, Devices).Select(d => d.Id));
        Assert.Equal([1, 3], HashcatRunner.ActiveGpus(new Settings { Strategy = DeviceStrategy.GpuAndCpu }, Devices).Select(d => d.Id));
        Assert.Equal([3], HashcatRunner.ActiveGpus(new Settings(), [Devices[2]]).Select(d => d.Id));
        Assert.Equal([3], HashcatRunner.ActiveGpus(new Settings { DisabledDeviceKeys = [Devices[0].Key] }, Devices).Select(d => d.Id));
    }

    [Fact]
    public void ProfileForAnotherNvidiaBackendIsRejected()
    {
        var cuda = new PerformanceDecision { Domain = "execution", Engine = "hybrid", DeviceKeys = [Devices[0].Key] };
        var opencl = new PerformanceDecision { Domain = "gpu", Engine = "gpu", DeviceKeys = [Devices[1].Key] };
        Assert.NotNull(PerformanceProfiles.Apply(cuda, new Settings(), Devices));
        Assert.Null(PerformanceProfiles.Apply(cuda, new Settings { NvidiaBackend = NvidiaBackend.OpenCl }, Devices));
        Assert.Null(PerformanceProfiles.Apply(opencl, new Settings { NvidiaBackend = NvidiaBackend.Cuda }, Devices));
        CudaFallback.Activate(Devices, "test");
        Assert.Null(PerformanceProfiles.Apply(cuda, new Settings(), Devices));
        Assert.NotNull(PerformanceProfiles.Apply(opencl, new Settings(), Devices));
        // A stale runtime key must still select the requested twin and never produce an empty -d.
        var stale = new Settings { NvidiaBackend = NvidiaBackend.OpenCl, GpuPerformanceChoice = cuda };
        var args = HashcatRunner.DeviceArguments(stale, Devices, gpuOnly: true);
        Assert.Equal("2", args[args.IndexOf("-d") + 1]);
    }

    [Theory]
    [InlineData(NvidiaBackend.Automatic, 1)]
    [InlineData(NvidiaBackend.Cuda, 1)]
    [InlineData(NvidiaBackend.OpenCl, 2)]
    public void HybridGroupsCannotOverrideTheNvidiaPreference(NvidiaBackend preference, int id)
    {
        var rows = new[] { Devices[0], Devices[1] }.SelectMany(d => new[] { 1, 2 }.Select(repeat =>
            new DiagnosticMeasurement { Section = "gpu", Mode = 13000, DeviceKey = d.Key, Engine = "gpu", Variant = "default",
                Speed = d.Id == 2 ? 200 : 100, Correct = true, Repeat = repeat, Details = new() { ["Default"] = (d.Id == 1).ToString() } }));
        var groups = HybridBenchmarkDevices.Groups(new Settings { NvidiaBackend = preference }, Devices, 13000, rows);
        Assert.All(groups, group => Assert.Equal([id], group.Select(d => d.Id)));
    }

    [Fact]
    public void ExcludingEitherAliasCannotReviveTheSamePhysicalGpu()
    {
        foreach (int id in new[] { 1, 2 })
        {
            var args = HashcatRunner.DeviceArguments(new Settings { NvidiaBackend = NvidiaBackend.OpenCl }, Devices, gpuOnly: true, exclude: [id]);
            Assert.DoesNotContain("-d", args);
            Assert.Equal("1", args[args.IndexOf("-D") + 1]);
        }
    }

    [Fact]
    public void MissingExplicitBackendFailsClearly()
    {
        Assert.Contains("no OpenCL device", HashcatRunner.NvidiaBackendError(new Settings { NvidiaBackend = NvidiaBackend.OpenCl }, [Devices[0]]));
        Assert.Throws<InvalidOperationException>(() => HashcatRunner.DeviceArguments(new Settings { NvidiaBackend = NvidiaBackend.OpenCl }, [Devices[0]]));
        Assert.Null(HashcatRunner.NvidiaBackendError(new Settings(), [Devices[0]]));
    }

    [Fact]
    public void OldSettingsDefaultToAutomaticSelection()
    {
        var settings = System.Text.Json.JsonSerializer.Deserialize<Settings>("{}")!;
        Assert.Equal(NvidiaBackend.Automatic, settings.NvidiaBackend);
        Assert.False(settings.DeviceSelectionExplicit);
    }

    [Theory]
    [InlineData("--backend-ignore-cuda")]
    [InlineData("--backend-ignore-opencl")]
    [InlineData("--backend-ignore-hip")]
    [InlineData("--backend-ignore-metal")]
    [InlineData("-d 2")]
    [InlineData("-d2")]
    [InlineData("--backend-devices=2")]
    [InlineData("-D 2")]
    public void DetectsDeviceOverrides(string extra) => Assert.True(HashcatRunner.HasDeviceOverrides(extra));
}
