using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

public sealed class OfficeAgileRegistrationTests
{
    [Theory]
    [InlineData(9500, "$office$*2010*100000*128*16*34170046140146368675746031258762*de5bc114991bb3a5679a6e24320bdb09*1b72a4ddffba3dcd5395f6a5ff75b126cb832b733c298e86162028ca47a235a9")]
    [InlineData(9600, "$office$*2013*100000*256*16*67805436882475302087847656644837*0c392d3b9ca889656d1e615c54f9f3c9*612b79e33b96322c3253fc8a0f314463cd76bc4efe1352f7efffca0f374f7e4b")]
    public void PublishedHashcatTargetVerifiesAndIsRegistered(int mode, string hash)
    {
        var kernel = NativeKernels.TryCreate(mode, hash);
        Assert.NotNull(kernel);
        Assert.True(kernel.Verify("hashcat"u8));
        Assert.False(kernel.Verify("wrong"u8));
        Assert.True(NativeKernels.Supports(mode));
        Assert.Equal(hash, NativeKernels.BenchmarkHashes[mode]);
    }
}
