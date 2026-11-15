using System.Security.Cryptography;
using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class Pbkdf2Sha1Tests
{
    [Theory]
    [InlineData(1, "0c60c80f961f0e71f3a9b524af6012062fe037a6")]
    [InlineData(2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")]
    [InlineData(4096, "4b007901b765489abead49d926f721d065a429c1")]
    public unsafe void Rfc6070(int iterations, string answer)
    {
        if (!RkNative.Available) return;
        var actual = new byte[20];
        fixed (byte* pw = "password"u8, salt = "salt"u8, dk = actual)
            Assert.Equal(0, RkNative.Pbkdf2Sha1(pw, 8, null, 1, salt, 4, (uint)iterations, dk, 20));
        Assert.Equal(Convert.FromHexString(answer), actual);
    }

    [Fact]
    public unsafe void EveryPathMatchesScalarAndDotNetIncludingVerifierBlocks()
    {
        if (!RkNative.Available) return;
        var saved = RkNative.Features;
        var rng = new Random(13600);
        const int n = 35, stride = 256;
        var pws = new byte[n * stride];
        rng.NextBytes(pws);
        var lengths = Enumerable.Range(0, n).Select(i => new[] { 0, 1, 8, 63, 64, 65, 127, 256 }[i % 8]).ToArray();
        var features = RkNative.Features;
        var paths = new List<(string, int)> { ("scalar", 1) };
        if (features.HasFlag(RkNative.Feature.Avx2)) paths.Add(("avx2", 2));
        if (features.HasFlag(RkNative.Feature.Avx512)) paths.Add(("avx512", Environment.GetEnvironmentVariable("RECOVERKIT_PBKDF2_SHA1_AVX512") == "0"
            ? features.HasFlag(RkNative.Feature.Avx2) ? 2 : 1 : 4));
        if (features.HasFlag(RkNative.Feature.Neon)) paths.Add(("neon", 8));
        if (features.HasFlag(RkNative.Feature.ArmSha1)) paths.Add(("arm-sha1", 32));
        try
        {
            foreach (int saltLength in new[] { 0, 16, 51, 52, 60, 64, 129 })
            {
                var salt = new byte[saltLength];
                rng.NextBytes(salt);
                foreach (int iter in new[] { 1, 2, 17 })
                {
                    var expected = Enumerable.Range(0, n).SelectMany(i => Rfc2898DeriveBytes.Pbkdf2(pws.AsSpan(i * stride, lengths[i]), salt, iter, HashAlgorithmName.SHA1, 80)).ToArray();
                    foreach (var (path, bit) in paths)
                    {
                        RkNative.LimitFeatures(path switch
                        {
                            "scalar" => 0,
                            "avx2" => RkNative.Feature.Avx2,
                            "avx512" => RkNative.Feature.Avx512 | RkNative.Feature.Avx2,
                            "neon" => RkNative.Feature.Neon,
                            _ => RkNative.Feature.ArmSha1 | RkNative.Feature.Neon,
                        });
                        RkNative.ResetExecutedPaths(13600);
                        var full = new byte[n * 80];
                        fixed (byte* p = pws, s = salt, d = full)
                        fixed (int* l = lengths)
                            Assert.Equal(0, RkNative.Pbkdf2Sha1(p, stride, l, n, s, salt.Length, (uint)iter, d, 80));
                        Assert.Equal(expected, full);
                        Assert.Equal(iter == 1 ? 1 : bit, RkNative.Pbkdf2Sha1ExecutedPaths());
                        foreach (uint block in new uint[] { 1, 2, 3, 4 })
                        {
                            var part = new byte[n * 20];
                            fixed (byte* p = pws, s = salt, d = part)
                            fixed (int* l = lengths)
                                Assert.Equal(0, RkNative.Pbkdf2Sha1Block(p, stride, l, n, s, salt.Length, (uint)iter, block, d));
                            for (int i = 0; i < n; i++) Assert.Equal(expected.AsSpan(i * 80 + (int)(block - 1) * 20, 20).ToArray(), part.AsSpan(i * 20, 20).ToArray());
                        }
                    }
                }
            }
        }
        finally { RkNative.LimitFeatures(saved); }
    }

    [Fact]
    public unsafe void RejectsInvalidArgumentsBeforeWriting()
    {
        if (!RkNative.Available) return;
        byte* p = stackalloc byte[32];
        int len = 33;
        Assert.Equal(-1, RkNative.Pbkdf2Sha1(p, 32, &len, 1, p, 0, 1, p, 20));
        Assert.Equal(-1, RkNative.Pbkdf2Sha1(p, 32, null, 1, p, 0, 0, p, 20));
        Assert.Equal(-1, RkNative.Pbkdf2Sha1Block(p, 32, null, 1, p, 0, 1, 0, p));
        Assert.Equal(-1, RkNative.Pbkdf2Sha1(null, 32, null, 1, p, 0, 1, p, 20));
        Assert.Equal(0, RkNative.Pbkdf2Sha1(null, 0, null, 0, null, 0, 1, null, 20));
    }
}
