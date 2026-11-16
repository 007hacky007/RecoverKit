using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

public sealed class Office2007RegistrationTests
{
    [Fact]
    public void BenchmarkTargetIsRegisteredAndVerifiesPublishedPassword()
    {
        Assert.True(NativeKernels.Supports(9400));
        var kernel = NativeKernels.TryCreate(9400, NativeKernels.BenchmarkHashes[9400]);
        Assert.NotNull(kernel);
        Assert.True(kernel.Verify("hashcat"u8));
        Assert.False(kernel.Verify("wrong"u8));
    }
}
