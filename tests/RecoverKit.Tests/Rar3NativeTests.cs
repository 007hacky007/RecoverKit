using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public class Rar3NativeTests
{
    private static readonly Rar3Kernel Kernel = Rar3Kernel.TryParse("$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317")!;

    [Fact]
    public void SelectedBatchWidthHonorsFeaturesAndSelfTest()
    {
        if (!RkNative.Available) return;
        var features = RkNative.Features;
        bool wide = features.HasFlag(RkNative.Feature.Avx512) && Environment.GetEnvironmentVariable("RECOVERKIT_RAR3_AVX512") != "0";
        Assert.Equal(wide ? 32 : RkNative.HasVectorPath ? 16 : 1, RkNative.Rar3Lanes());
        Assert.Equal(wide ? 2 : 1, Kernel.PrefixBatch(16));
        try
        {
            RkNative.LimitFeatures(features & ~RkNative.Feature.Avx512);
            Assert.Equal(RkNative.HasVectorPath ? 16 : 1, RkNative.Rar3Lanes());
            Assert.Equal(1, Kernel.PrefixBatch(16));
            RkNative.LimitFeatures(0);
            Assert.Equal(1, RkNative.Rar3Lanes());
        }
        finally { RkNative.LimitFeatures(features); }
    }

    private static unsafe byte[] Hash(byte[] passwords, int len, int n)
    {
        var salt = Convert.FromHexString("45109af8ab5f297a");
        // Sentinel bytes catch output writes beyond the last real candidate.
        var output = Enumerable.Repeat((byte)0xa5, n * 36 + 16).ToArray();
        fixed (byte* s = salt, p = passwords, o = output)
            Assert.Equal(0, RkNative.Rar3Hash(s, p, len, n, o));
        Assert.All(output.Skip(n * 36), b => Assert.Equal((byte)0xa5, b));
        return output[..(n * 36)];
    }

    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(22)]
    [InlineData(26)]
    public void DigestAndIvMatchReferenceAcrossBatchBoundaries(int len)
    {
        if (!RkNative.Available) return;
        const int count = 65;
        var pws = new byte[count * len];
        new Random(12500 + len).NextBytes(pws);
        var expected = new byte[count * 36];
        for (int i = 0; i < count; i++)
        {
            var (digest, iv) = Kernel.ReferenceHash(pws.AsSpan(i * len, len));
            digest.CopyTo(expected, i * 36);
            iv.CopyTo(expected, i * 36 + 20);
        }
        var features = RkNative.Features;
        try
        {
            foreach (var mask in new[] { features, features & ~RkNative.Feature.Avx512 })
            {
                RkNative.LimitFeatures(mask);
                foreach (int n in new[] { 1, 15, 16, 17, 31, 32, 33, 65 })
                    Assert.Equal(expected[..(n * 36)], Hash(pws, len, n));
            }
            RkNative.LimitFeatures(0);
            Assert.Equal(expected[..36], Hash(pws, len, 1));
        }
        finally { RkNative.LimitFeatures(features); }
    }

    [Fact]
    [Trait("Category", "Slow")]
    public void AllPasswordLengthsMatchReferenceAndNarrowPath()
    {
        if (!RkNative.Available) return;
        var features = RkNative.Features;
        try
        {
            for (int len = 1; len <= Kernel.MaxPasswordLength; len++)
            {
                const int n = 33;
                var pws = new byte[n * len];
                new Random(len).NextBytes(pws);
                RkNative.LimitFeatures(features);
                var actual = Hash(pws, len, n);
                RkNative.LimitFeatures(features & ~RkNative.Feature.Avx512);
                Assert.Equal(actual, Hash(pws, len, n));
                for (int i = 0; i < n; i++)
                {
                    var (digest, iv) = Kernel.ReferenceHash(pws.AsSpan(i * len, len));
                    Assert.Equal([.. digest, .. iv], actual.AsSpan(i * 36, 36).ToArray());
                }
            }
        }
        finally { RkNative.LimitFeatures(features); }
    }
}
