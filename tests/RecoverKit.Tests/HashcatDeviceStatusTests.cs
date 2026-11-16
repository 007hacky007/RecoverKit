using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public sealed class HashcatDeviceStatusTests : IDisposable
{
    private readonly string _dir = Directory.CreateDirectory(Path.Combine(Path.GetTempPath(), "rk-device-status-" + Guid.NewGuid().ToString("N"))).FullName;

    public void Dispose() => Directory.Delete(_dir, true);

    [Theory]
    [InlineData(false, 8)]
    [InlineData(true, 8)]
    [InlineData(false, 7)]
    public async Task IgnoredCudaBackendRestoresOriginalIdsBeforePublishingStatus(bool useGuard, int majorVersion)
    {
        if (OperatingSystem.IsWindows()) return;
        var known = new BackendDevice[]
        {
            new() { Id = 1, Backend = "CUDA", Type = "GPU", Name = "Disabled NVIDIA GPU" },
            new() { Id = 2, Backend = "HIP", Type = "GPU", Name = "Integrated AMD GPU", Unified = true },
            new() { Id = 3, Backend = "HIP", Type = "GPU", Name = "Discrete AMD GPU" },
        };
        var (runner, request) = Runner(known, new Settings { DisabledDevices = [1], DontUsePasswordCache = true }, """
            {"status":3,"progress":[120,1000],"restore_point":12,"devices":[{"device_id":1,"device_name":"Integrated AMD GPU","device_type":"GPU","speed":111,"temp":51,"util":75},{"device_id":2,"device_name":"Discrete AMD GPU","device_type":"GPU","speed":999,"temp":62,"util":95}]}
            """);
        runner.HashcatMajorVersion = majorVersion;
        runner.TemperatureSource = null;
        request = request with { Restore = majorVersion < 8, Guard = useGuard ? new ThermalGuard(true, 90, 5) : null };
        var emitted = new List<HashcatStatus>();
        runner.StatusReceived += emitted.Add;
        var result = await runner.RunAsync(request, CancellationToken.None);

        Assert.Equal(RunOutcome.Exhausted, result.Outcome);
        var status = Assert.Single(emitted);
        Assert.Equal([2, 3], status.Devices.Select(d => d.Id));
        Assert.Equal(["Integrated AMD GPU (HIP)", "Discrete AMD GPU (HIP)"], status.Devices.Select(d => d.Name));
        Assert.Equal([2, 3], result.LastStatus!.Devices.Select(d => d.Id));
        Assert.Equal(["Integrated AMD GPU (HIP)", "Discrete AMD GPU (HIP)"], result.LastStatus.Devices.Select(d => d.Name));
        Assert.Equal([111d, 999d], status.Devices.Select(d => d.Speed));
        Assert.Equal([51, 62], status.Devices.Select(d => d.Temperature));
        Assert.Equal([75, 95], status.Devices.Select(d => d.Utilization));
        Assert.Equal(120, status.ProgressDone);
        Assert.Equal(12, status.RestorePoint);
        Assert.Equal([2], status.Devices.Where(d => known.Single(k => k.Id == d.Id).IsIntegratedGpu).Select(d => d.Id));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnknownDevicesKeepTheirReportedIds(bool missingInventory)
    {
        if (OperatingSystem.IsWindows()) return;
        var known = missingInventory ? null : new BackendDevice[]
        {
            new() { Id = 1, Backend = "CUDA", Type = "GPU", Name = "Disabled NVIDIA GPU" },
            new() { Id = 2, Backend = "HIP", Type = "GPU", Name = "Known AMD GPU" },
        };
        var (runner, request) = Runner(known, new Settings { DisabledDevices = [1], DontUsePasswordCache = true, ExtraArguments = "--backend-ignore-cuda" }, """
            {"status":3,"devices":[{"device_id":99,"device_name":"Unknown GPU","speed":10}]}
            """);
        var emitted = new List<HashcatStatus>();
        runner.StatusReceived += emitted.Add;
        var result = await runner.RunAsync(request, CancellationToken.None);
        Assert.Equal(99, Assert.Single(Assert.Single(emitted).Devices).Id);
        Assert.Equal(99, Assert.Single(result.LastStatus!.Devices).Id);
    }

    [Fact]
    public async Task ExtraBackendIgnoreFlagsAlsoRestoreOriginalIds()
    {
        // On macOS every run also ignores OpenCL, which would leave hashcat no device here.
        if (OperatingSystem.IsWindows() || OperatingSystem.IsMacOS()) return;
        var known = new BackendDevice[]
        {
            new() { Id = 1, Backend = "HIP", Type = "GPU", Name = "AMD GPU" },
            new() { Id = 2, Backend = "OpenCL", Type = "CPU", Name = "Processor" },
        };
        var (runner, request) = Runner(known, new Settings { DontUsePasswordCache = true, ExtraArguments = "--backend-ignore-hip" }, """
            {"status":3,"devices":[{"device_id":1,"device_name":"Processor","device_type":"CPU","speed":10}]}
            """);
        var result = await runner.RunAsync(request, CancellationToken.None);
        var device = Assert.Single(result.LastStatus!.Devices);
        Assert.Equal(2, device.Id);
        Assert.Equal("Processor (OpenCL)", device.Name);
        Assert.Equal("CPU", device.Type);
    }

    private (HashcatRunner Runner, RunRequest Request) Runner(IReadOnlyList<BackendDevice>? known, Settings settings, string status)
    {
        string exe = Path.Combine(_dir, "hashcat");
        File.WriteAllText(exe, "#!/bin/sh\nprintf '%s\\n' '" + status + "'\nexit 1\n");
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return (new HashcatRunner(HashcatTool.Locate(exe)!) { KnownDevices = known, HashcatMajorVersion = 8 }, new RunRequest
        {
            Mode = 0, HashFile = Path.Combine(_dir, "target.hash"), SessionName = "status", SessionDir = _dir,
            Attack = new PreparedAttack { Description = "mask", Args = { "-a", "3", "?l?l" } },
            Settings = settings,
        });
    }
}
