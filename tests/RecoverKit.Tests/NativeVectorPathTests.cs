using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

/// <summary>
/// The native vector paths (AVX2 on x64, NEON and the ARMv8 Crypto Extensions on arm64) against
/// hashes generated here from first principles, at every password length the layouts distinguish.
/// </summary>
public class NativeVectorPathTests
{
    [Fact]
    public void NativeFeaturesMatchTheRuntime()
    {
        if (!RkNative.Available) return;
        var f = RkNative.Features;
        if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
        {
            Assert.True(f.HasFlag(RkNative.Feature.Neon));
            Assert.Equal(System.Runtime.Intrinsics.Arm.Aes.IsSupported, f.HasFlag(RkNative.Feature.ArmAes));
            Assert.Equal(System.Runtime.Intrinsics.Arm.Sha1.IsSupported, f.HasFlag(RkNative.Feature.ArmSha1));
            Assert.Equal(System.Runtime.Intrinsics.Arm.Sha256.IsSupported, f.HasFlag(RkNative.Feature.ArmSha2));
            Assert.True(RkNative.HasVectorPath);
        }
        else if (RuntimeInformation.ProcessArchitecture == Architecture.X64)
        {
            Assert.Equal(System.Runtime.Intrinsics.X86.Avx2.IsSupported, f.HasFlag(RkNative.Feature.Avx2));
            Assert.Equal(System.Runtime.Intrinsics.X86.Aes.IsSupported, f.HasFlag(RkNative.Feature.AesNi));
            Assert.False(f.HasFlag(RkNative.Feature.Neon));
        }
        Assert.Contains("rknative", NativeKernels.CpuFeatures());
    }

    [Fact]
    public void VectorKernelsAreOfferedWhereTheNativePathRuns()
    {
        if (!RkNative.HasVectorPath) return;
        foreach (var mode in new[] { 9700, 9800, 10400, 10500, 12500 })
            Assert.NotNull(NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]));
        Assert.Equal(RkNative.HasPdf6Path, NativeKernels.TryCreate(10700, NativeKernels.BenchmarkHashes[10700]) is not null);
    }

    private static byte[] Rc4(byte[] key, byte[] data)
    {
        var s = new byte[256];
        for (int i = 0; i < 256; i++) s[i] = (byte)i;
        for (int i = 0, j = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) & 255;
            (s[i], s[j]) = (s[j], s[i]);
        }
        var o = new byte[data.Length];
        for (int q = 0, i = 0, j = 0; q < data.Length; q++)
        {
            i = (i + 1) & 255;
            j = (j + s[i]) & 255;
            (s[i], s[j]) = (s[j], s[i]);
            o[q] = (byte)(data[q] ^ s[(s[i] + s[j]) & 255]);
        }
        return o;
    }

    private static byte[] Utf16(byte[] pw) => pw.SelectMany(b => new[] { b, (byte)0 }).ToArray();

    private static string Office97Line(byte[] pw, Random rng)
    {
        var salt = new byte[16];
        var v = new byte[16];
        rng.NextBytes(salt); rng.NextBytes(v);
        var h0 = MD5.HashData(Utf16(pw));
        var buf = new byte[336];
        for (int k = 0; k < 16; k++) { h0.AsSpan(0, 5).CopyTo(buf.AsSpan(21 * k)); salt.CopyTo(buf, 21 * k + 5); }
        var h1 = MD5.HashData(buf);
        var key = MD5.HashData([.. h1.AsSpan(0, 5), 0, 0, 0, 0]);
        var enc = Rc4(key, [.. v, .. MD5.HashData(v)]);
        return $"$oldoffice$1*{Convert.ToHexString(salt)}*{Convert.ToHexString(enc, 0, 16)}*{Convert.ToHexString(enc, 16, 16)}";
    }

    private static string Office2003Line(byte[] pw, Random rng)
    {
        var salt = new byte[16];
        var v = new byte[16];
        rng.NextBytes(salt); rng.NextBytes(v);
        var h0 = SHA1.HashData([.. salt, .. Utf16(pw)]);
        var hf = SHA1.HashData([.. h0, 0, 0, 0, 0]);
        var key = new byte[16];
        hf.AsSpan(0, 5).CopyTo(key);
        var enc = Rc4(key, [.. v, .. SHA1.HashData(v)]);
        return $"$oldoffice$3*{Convert.ToHexString(salt)}*{Convert.ToHexString(enc, 0, 16)}*{Convert.ToHexString(enc, 16, 20)}";
    }

    private static readonly byte[] PdfPad = Convert.FromHexString("28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a");

    private static string PdfLine(byte[] pw, int r, int bits, Random rng)
    {
        var id = new byte[16];
        var o = new byte[32];
        rng.NextBytes(id); rng.NextBytes(o);
        int p = -4 - 4 * rng.Next(1000), kl = bits / 8;
        var input = new List<byte>();
        for (int i = 0; i < 32; i++) input.Add(i < pw.Length ? pw[i] : PdfPad[i - pw.Length]);
        input.AddRange(o);
        input.AddRange(BitConverter.GetBytes(p));
        input.AddRange(id);
        var h = MD5.HashData(input.ToArray());
        if (r >= 3) for (int i = 0; i < 50; i++) h = MD5.HashData(h.AsSpan(0, kl));
        var key = h[..kl];
        byte[] u;
        if (r == 2) u = Rc4(key, PdfPad);
        else
        {
            var y = MD5.HashData([.. PdfPad, .. id]);
            for (int i = 0; i < 20; i++) y = Rc4(key.Select(b => (byte)(b ^ i)).ToArray(), y);
            u = [.. y, .. new byte[16]];
        }
        return $"$pdf${(r == 2 ? 1 : 2)}*{r}*{bits}*{p}*1*16*{Convert.ToHexString(id)}*32*{Convert.ToHexString(u)}*32*{Convert.ToHexString(o)}";
    }

    /// <summary>
    /// 40 random candidates of length len with the password planted at 5 and 37: the native filter
    /// must report exactly the candidates equal to it (a false positive has probability ~2^-27).
    /// </summary>
    private static unsafe void AssertFilterFindsPlanted(NativeKernel k, byte[] pw, Random rng)
    {
        Assert.True(k.Verify(pw));
        int len = pw.Length, n = 40;
        var pws = new byte[n * len];
        for (int i = 0; i < pws.Length; i++) pws[i] = (byte)(0x21 + rng.Next(94));
        pw.CopyTo(pws, 5 * len);
        pw.CopyTo(pws, 37 * len);
        // Short random candidates can equal the password too.
        var expected = Enumerable.Range(0, n).Where(i => pws.AsSpan(i * len, len).SequenceEqual(pw)).ToArray();
        var hits = new int[64];
        int nh;
        fixed (byte* p = pws) fixed (int* h = hits) nh = ((INativeFilter)k).Filter(p, len, n, h, 64);
        Assert.Equal(expected, hits.Take(nh).Order().ToArray());
    }

    private static byte[] RandomPassword(Random rng, int len) => Enumerable.Range(0, len).Select(_ => (byte)(0x21 + rng.Next(94))).ToArray();

    [Fact]
    public void Office97FilterMatchesReferenceAtEveryLength()
    {
        if (!RkNative.HasVectorPath) return;
        var rng = new Random(97);
        for (int len = 1; len <= 15; len++)
        {
            var pw = RandomPassword(rng, len);
            AssertFilterFindsPlanted(Office97Kernel.TryParse(Office97Line(pw, rng))!, pw, rng);
        }
    }

    [Fact]
    public void Office2003FilterMatchesReferenceAtEveryLength()
    {
        if (!RkNative.HasVectorPath) return;
        var rng = new Random(2003);
        for (int len = 1; len <= 15; len++)
        {
            var pw = RandomPassword(rng, len);
            AssertFilterFindsPlanted(Office2003Kernel.TryParse(Office2003Line(pw, rng))!, pw, rng);
        }
    }

    [Theory]
    [InlineData(2, 40)]
    [InlineData(3, 40)]
    [InlineData(3, 56)]
    [InlineData(3, 120)]
    [InlineData(3, 128)]
    public void PdfRc4FilterMatchesReferenceAtEveryLength(int r, int bits)
    {
        if (!RkNative.HasVectorPath) return;
        var rng = new Random(r * 1000 + bits);
        for (int len = 1; len <= 32; len += len < 12 ? 1 : 5)
        {
            var pw = RandomPassword(rng, len);
            AssertFilterFindsPlanted(PdfRc4Kernel.TryParse(PdfLine(pw, r, bits, rng))!, pw, rng);
        }
    }

    [Fact]
    public void NativeEngineFindsPlantedPasswordsThroughTheFilters()
    {
        if (!RkNative.HasVectorPath) return;
        var rng = new Random(5);
        var pw = "Zq9!"u8.ToArray();
        foreach (var line in new[] { Office97Line(pw, rng), Office2003Line(pw, rng), PdfLine(pw, 2, 40, rng), PdfLine(pw, 3, 128, rng) })
        {
            var k = line.StartsWith("$pdf$") ? (NativeKernel)PdfRc4Kernel.TryParse(line)! : line[11] == '1' ? Office97Kernel.TryParse(line)! : Office2003Kernel.TryParse(line)!;
            Assert.IsType<NativeFilterWorker>(k.CreateWorker());
            Assert.Equal("Zq9!", NativeEngineTests.Find(k, "-a", "3", "-1", "Zz", "?1q?d?s"));
        }
    }

    [Fact]
    public void ZipCryptoAdvSimdAndScalarPathsAgree()
    {
        if (!System.Runtime.Intrinsics.Arm.AdvSimd.Arm64.IsSupported) return;
        bool saved = ZipCryptoKernel.UseAdvSimd;
        try
        {
            foreach (var simd in new[] { true, false })
            {
                ZipCryptoKernel.UseAdvSimd = simd;
                var stored = ZipCryptoKernel.TryParse(NativeEngineTests.Pkzip17210)!;
                // 26 x 26 last characters: full 16-lane groups and a partial one, the match inside.
                Assert.Equal("hashcat", NativeEngineTests.Find(stored, "-a", "3", "hash?l?l?l"));
                Assert.Equal("<Exhausted>", NativeEngineTests.Find(stored, "-a", "3", "hbs?l?l?l"));
                var deflate = ZipCryptoKernel.TryParse(NativeEngineTests.Pkzip17200)!;
                Assert.Equal("hashcat", NativeEngineTests.Find(deflate, "-a", "3", "-1", "acht", "?1?1s?1?1?l?1"));
            }
        }
        finally { ZipCryptoKernel.UseAdvSimd = saved; }
    }

    [Fact]
    public void NativeRar3MatchesReferenceForManyCandidates()
    {
        if (!Rar3Kernel.NativeFast) return;
        var k = Rar3Kernel.TryParse("$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317")!;
        // 3 prefixes x 13 last characters: a full 16-lane batch, a second one and a partial third.
        var batch = k.NativeHash("ab9XY3qq0"u8, 3, "0123456789xyz"u8);
        int i = 0;
        foreach (var pre in new[] { "ab9", "XY3", "qq0" })
            foreach (var c in "0123456789xyz")
            {
                var (d, iv) = k.ReferenceHash(Encoding.ASCII.GetBytes(pre + c));
                Assert.Equal([.. d, .. iv], batch.AsSpan(36 * i++, 36).ToArray());
            }
    }
}
