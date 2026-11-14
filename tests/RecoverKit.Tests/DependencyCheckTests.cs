using RecoverKit.Core;
using RecoverKit.Core.Dependencies;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class DependencyCheckTests
{
    private const string Exe = @"C:\tools\hashcat\hashcat.exe";

    private static List<BackendDevice> Devices(string backend, string type, string vendor, string name, string header)
        => HashcatTool.ParseDevices($"""
            {header}

            Backend Device ID #01
              Type...........: {type}
              Vendor.ID......: 1
              Vendor.........: {vendor}
              Name...........: {name}
              Processor(s)...: 16
              Clock..........: 1000
              Memory.Total...: 8192 MB
            """);

    private static List<BackendDevice> NvidiaOpenCl() => Devices("OpenCL", "GPU", "NVIDIA Corporation", "NVIDIA GeForce RTX 4070", "OpenCL Info:\n============\n\nOpenCL Platform ID #1\n  Vendor..: NVIDIA\n  Name....: NVIDIA CUDA\n  Version.: OpenCL 3.0");
    private static List<BackendDevice> NvidiaCuda() => Devices("CUDA", "GPU", "NVIDIA", "NVIDIA GeForce RTX 4070", "CUDA Info:\n==========\n\nCUDA.Version.: 12.8");
    private static List<BackendDevice> CpuOnlyDevice() => Devices("OpenCL", "CPU", "Intel", "Intel(R) Core(TM) i7", "OpenCL Info:\n============\n\nOpenCL Platform ID #1\n  Vendor..: Intel\n  Name....: Intel\n  Version.: OpenCL 3.0");

    private static MachineFacts Win(IReadOnlyList<BackendDevice>? devices, Func<MachineFacts, MachineFacts>? tweak = null)
    {
        var f = new MachineFacts
        {
            IsWindows = true, HashcatExe = Exe, HashcatIsManaged = true, HashcatVersion = "v8.0.0",
            BundleAvailable = true, Devices = devices, NvidiaDriverCuda = (12, 8),
        };
        return tweak?.Invoke(f) ?? f;
    }

    private static DependencyItem Row(IReadOnlyList<DependencyItem> items, DependencyId id) => items.Single(i => i.Id == id);

    [Fact]
    public void EverythingGreenOnMacWithBundle()
    {
        var items = DependencyCheck.Evaluate(new MachineFacts
        {
            HashcatExe = "/app/hashcat", HashcatIsManaged = true, HashcatVersion = "v8.0.0", BundleAvailable = true, Devices = [],
        });
        Assert.Single(items);
        Assert.Equal(Light.Green, items[0].Light);
        Assert.False(DependencyCheck.ShouldShowAtStart(items, []));
    }

    [Fact]
    public void HashcatRedWithErrorWhenBundleCopyFailed()
    {
        var h = DependencyCheck.Evaluate(new MachineFacts { BundleAvailable = true, BundleCopyError = "Disk full" })[0];
        Assert.Equal(Light.Red, h.Light);
        Assert.Equal(DependencyAction.CopyBundledHashcat, h.Action);
        Assert.Contains("Disk full", h.Reason);
    }

    [Fact]
    public void NoBundleOnSourceBuildIsRedWithInstructions()
    {
        var h = DependencyCheck.Evaluate(new MachineFacts { BundleAvailable = false })[0];
        Assert.Equal(Light.Red, h.Light);
        Assert.Equal(DependencyAction.None, h.Action);
        Assert.Equal(HashcatInstaller.NoBundleMessage, h.Reason);
    }

    [Fact]
    public void HashcatThatFailsToRunIsRedAndOthersPending()
    {
        var items = DependencyCheck.Evaluate(Win(null, f => f with { HashcatError = "timed out" }));
        Assert.Equal(Light.Red, Row(items, DependencyId.Hashcat).Light);
        Assert.Contains("timed out", Row(items, DependencyId.Hashcat).Reason);
        Assert.True(Row(items, DependencyId.Nvrtc).Pending);
        Assert.True(Row(items, DependencyId.CpuRuntime).Pending);
    }

    [Fact]
    public void UsersOlderHashcatOffersSwitchToBundled()
    {
        var h = DependencyCheck.Evaluate(new MachineFacts
        {
            HashcatExe = Exe, HashcatVersion = "v7.1.2", HashcatIsManaged = false, BundleAvailable = true, Devices = [],
        })[0];
        Assert.Equal(Light.Yellow, h.Light);
        Assert.Equal(DependencyAction.UseBundledHashcat, h.Action);
        Assert.Contains(Exe, h.SkipKey);
        Assert.Contains("v7.1.2", h.SkipKey);
    }

    [Fact]
    public void ManagedOlderCopyIsNotOfferedAsSwitch()
    {
        var h = DependencyCheck.Evaluate(new MachineFacts
        {
            HashcatExe = Exe, HashcatVersion = "v7.1.2", HashcatIsManaged = true, BundleAvailable = true, Devices = [],
        })[0];
        Assert.Equal(Light.Green, h.Light);
    }

    [Fact]
    public void NvidiaOnOpenClWithNewDriverOffersNvrtc()
    {
        var n = Row(DependencyCheck.Evaluate(Win(NvidiaOpenCl(), f => f with { NvidiaDriverPresent = true })), DependencyId.Nvrtc);
        Assert.Equal(Light.Yellow, n.Light);
        Assert.Equal(DependencyAction.DownloadNvrtc, n.Action);
        Assert.Equal("12.8.93", n.NvrtcPackage!.Version);
        Assert.Equal("nvrtc|12.8.93", n.SkipKey);
        Assert.Equal(NvrtcRuntime.LicenseName, n.LicenseName);
    }

    [Fact]
    public void CudaDeviceMeansNvrtcNotNeeded()
    {
        var n = Row(DependencyCheck.Evaluate(Win(NvidiaCuda())), DependencyId.Nvrtc);
        Assert.Equal(Light.Green, n.Light);
        Assert.False(n.Pending);
    }

    [Fact]
    public void OldNvidiaDriverIsYellowWithoutAction()
    {
        var n = Row(DependencyCheck.Evaluate(Win(NvidiaOpenCl(), f => f with { NvidiaDriverCuda = (12, 2) })), DependencyId.Nvrtc);
        Assert.Equal(Light.Yellow, n.Light);
        Assert.Equal(DependencyAction.None, n.Action);
    }

    [Fact]
    public void UninstallableYellowDoesNotShowAtStart()
    {
        var items = DependencyCheck.Evaluate(Win(NvidiaOpenCl(), f => f with { Elevated = true, CpuRuntimeInstalled = false }));
        var n = Row(items, DependencyId.Nvrtc);
        Assert.Equal(Light.Yellow, n.Light);
        Assert.Equal(DependencyAction.None, n.Action);
        Assert.False(DependencyCheck.ShouldShowAtStart(items, []));
    }

    [Fact]
    public void NoDeviceAtAllNeedsCpuRuntime()
    {
        var items = DependencyCheck.Evaluate(Win([]));
        var c = Row(items, DependencyId.CpuRuntime);
        Assert.Equal(Light.Red, c.Light);
        Assert.Equal(DependencyAction.DownloadCpuRuntime, c.Action);
        Assert.Equal(CpuRuntime.LicenseName, c.LicenseName);
        Assert.Equal(Light.Green, Row(items, DependencyId.Nvrtc).Light);
        Assert.True(DependencyCheck.ShouldShowAtStart(items, []));
    }

    [Fact]
    public void CpuWithGpuWithoutCpuDeviceIsYellow()
    {
        var c = Row(DependencyCheck.Evaluate(Win(NvidiaCuda(), f => f with { HashcatCpuWithGpu = true })), DependencyId.CpuRuntime);
        Assert.Equal(Light.Yellow, c.Light);
        Assert.Equal(DependencyAction.DownloadCpuRuntime, c.Action);
        Assert.Equal("cpu-runtime|2026.1.2", c.SkipKey);
    }

    [Fact]
    public void CpuDeviceMakesCpuRuntimeNotNeeded()
    {
        var c = Row(DependencyCheck.Evaluate(Win(CpuOnlyDevice(), f => f with { Strategy = DeviceStrategy.CpuOnly })), DependencyId.CpuRuntime);
        Assert.Equal(Light.Green, c.Light);
    }

    [Fact]
    public void SkippedYellowDoesNotShowButRedAlwaysDoes()
    {
        var items = DependencyCheck.Evaluate(Win(NvidiaOpenCl()));
        Assert.False(DependencyCheck.ShouldShowAtStart(items, ["nvrtc|12.8.93"]));
        var withRed = items.Append(new DependencyItem(DependencyId.Hashcat, "hashcat", Light.Red, "x", DependencyAction.None)).ToList();
        Assert.True(DependencyCheck.ShouldShowAtStart(withRed, ["nvrtc|12.8.93"]));
    }

    [Fact]
    public void SkipIsForgottenWhenTheChosenPackageChanges()
    {
        var items = DependencyCheck.Evaluate(Win(NvidiaOpenCl()));
        Assert.True(DependencyCheck.ShouldShowAtStart(items, ["nvrtc|12.4.127"]));
    }
}
