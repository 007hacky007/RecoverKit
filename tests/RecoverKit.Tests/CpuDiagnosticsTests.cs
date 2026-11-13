using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class CpuDiagnosticsTests
{
    [Fact]
    public void BrokenHeaderPathFailsAndIsNotTimed()
    {
        bool timed = false;
        var result = CpuDiagnostics.CheckThenMeasure(
            () => CpuDiagnostics.CheckZipPath(1, _ => []),
            () => { timed = true; return 42; });
        Assert.False(result.Check.Passed);
        Assert.False(timed);
        Assert.Equal(0, result.Speed);
    }

    [Fact]
    public void SupportedZipPathsPassKnownVectorsAndRandomHeaders()
    {
        int before = ZipCryptoNative.RequestedPath;
        foreach (var variant in CpuDiagnostics.Variants.Where(v => v.Supported))
        {
            var check = CpuDiagnostics.CheckZipPath(variant.Selector);
            Assert.True(check.Passed, $"{variant.Name}: {check.Error}");
            Assert.True(check.Cases >= 50);
        }
        Assert.Equal(before, ZipCryptoNative.RequestedPath);
    }

    [Fact]
    public async Task CancellationRestoresZipSelection()
    {
        int before = ZipCryptoNative.RequestedPath;
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CpuDiagnostics.RunAsync(_ => { }, _ => { }, cts.Token));
        Assert.Equal(before, ZipCryptoNative.RequestedPath);
    }

    [Fact]
    public void ExplicitZipSelectionOverridesProfile()
    {
        int before = ZipCryptoNative.RequestedPath;
        int? profile = ZipCryptoNative.ProfilePath;
        try
        {
            ZipCryptoNative.ProfilePath = -2;
            ZipCryptoNative.RequestedPath = -1;
            Assert.Equal(-1, ZipCryptoNative.EffectiveRequestedPath);
            ZipCryptoNative.RequestedPath = 0;
            Assert.Equal(-2, ZipCryptoNative.EffectiveRequestedPath);
        }
        finally { ZipCryptoNative.RequestedPath = before; ZipCryptoNative.ProfilePath = profile; }
    }

    [Fact]
    public void MachineFactsHaveNoMachineOrUserNames()
    {
        Assert.False(string.IsNullOrWhiteSpace(SystemFacts.CpuName()));
        Assert.InRange(SystemFacts.PhysicalCores(), 1, Environment.ProcessorCount);
        Assert.True(SystemFacts.RamBytes() > 0);
    }
}
