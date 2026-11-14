using RecoverKit.Core;
using RecoverKit.Core.Dependencies;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class DependencyInstallerTests
{
    private static DependencyItem Item(DependencyId id, DependencyAction action)
        => new(id, id.ToString(), Light.Red, "r", action);

    private static DependencyItem Hashcat => Item(DependencyId.Hashcat, DependencyAction.CopyBundledHashcat);
    private static DependencyItem Nvrtc => Item(DependencyId.Nvrtc, DependencyAction.DownloadNvrtc);
    private static DependencyItem Cpu => Item(DependencyId.CpuRuntime, DependencyAction.DownloadCpuRuntime);

    [Fact]
    public async Task ItemsInstallInDependencyOrder()
    {
        var calls = new List<DependencyId>();
        var installer = new DependencyInstaller(new Settings(), (item, _, _) => { calls.Add(item.Id); return Task.CompletedTask; });
        var none = Item(DependencyId.Nvrtc, DependencyAction.None);

        await installer.InstallAllAsync([Cpu, Hashcat, Nvrtc, none with { Id = DependencyId.Hashcat }], null, default);

        Assert.Equal([DependencyId.Hashcat, DependencyId.Nvrtc, DependencyId.CpuRuntime], calls);
    }

    [Fact]
    public async Task FailedItemDoesNotStopTheOthers()
    {
        var calls = new List<DependencyId>();
        var installer = new DependencyInstaller(new Settings(), (item, _, _) =>
        {
            calls.Add(item.Id);
            if (item.Id == DependencyId.Hashcat) throw new InstallException("x");
            return Task.CompletedTask;
        });

        var results = await installer.InstallAllAsync([Nvrtc, Hashcat], null, default);

        Assert.Equal([DependencyId.Hashcat, DependencyId.Nvrtc], calls);
        Assert.Equal(DependencyId.Hashcat, results[0].Item.Id);
        Assert.IsType<InstallException>(results[0].Error);
        Assert.Null(results[1].Error);
    }

    [Fact]
    public async Task CancelStopsTheRemainingItems()
    {
        var calls = new List<DependencyId>();
        using var cts = new CancellationTokenSource();
        var installer = new DependencyInstaller(new Settings(), (item, _, ct) =>
        {
            calls.Add(item.Id);
            cts.Cancel();
            ct.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        });

        await Assert.ThrowsAsync<OperationCanceledException>(() => installer.InstallAllAsync([Hashcat, Nvrtc], null, cts.Token));
        Assert.Equal([DependencyId.Hashcat], calls);
    }

    [Fact]
    public void UseBundledPointsSettingsAtTheEnginesCopy()
    {
        var s = new Settings { HashcatPath = "/old/hashcat" };
        DependencyInstaller.PointAtEnginesCopy(s, "/engines/hashcat-8.0.0/hashcat");
        Assert.Equal("/engines/hashcat-8.0.0/hashcat", s.HashcatPath);
    }
}
