using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class KernelVariantsTests
{
    [Theory]
    [InlineData(9700)]
    [InlineData(9800)]
    [InlineData(10400)]
    [InlineData(10500)]
    [InlineData(10510)]
    [InlineData(12500)]
    public void ManagedAlternativesFollowHardwareAvailability(int mode)
    {
        var variants = KernelVariants.ForMode(mode);
        Assert.Contains(variants, v => v.Name == "default");
        Assert.Equal(RkNative.Available && System.Runtime.Intrinsics.Vector256.IsHardwareAccelerated,
            variants.Single(v => v.Name == "managed").Supported);
    }

    [Fact]
    public void KernelsWithoutSelectablePathsOnlyRegisterDefault()
    {
        Assert.Equal("default", Assert.Single(KernelVariants.ForMode(13000)).Name);
        Assert.False(KernelVariants.Supported(13000, "managed"));
        Assert.Null(KernelVariants.Select(13000, "default"));
    }

    [Fact]
    public void ZipVariantsUseTheExistingRegistryAndRestoreSelection()
    {
        int before = ZipCryptoNative.RequestedPath;
        Assert.Equal(CpuDiagnostics.Variants.Select(v => v.Name), KernelVariants.ForMode(17210).Select(v => v.Name));
        try
        {
            using var selected = KernelVariants.Select(17210, "managed-scalar");
            Assert.Equal(-2, ZipCryptoNative.RequestedPath);
        }
        finally { Assert.Equal(before, ZipCryptoNative.RequestedPath); }
    }

    [Fact]
    public void ManagedScopeRestoresNativeAvailabilityAfterFailure()
    {
        bool before = RkNative.Disabled;
        void FailingStep()
        {
            using var scope = KernelVariants.SelectManaged();
            Assert.True(RkNative.Disabled);
            throw new InvalidOperationException("simulated step failure");
        }
        Assert.Throws<InvalidOperationException>(FailingStep);
        Assert.Equal(before, RkNative.Disabled);
    }

    [Fact]
    public void UnsupportedSelectionDoesNotChangeNativeAvailability()
    {
        bool before = RkNative.Disabled;
        Assert.Null(KernelVariants.Select(13000, "avx512"));
        Assert.Equal(before, RkNative.Disabled);
    }
}
