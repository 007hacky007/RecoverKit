using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using RecoverKit.Core.Native.Simd;
using Xunit;

namespace RecoverKit.Tests;

public class SimdHashTests
{
    /// <summary>Single-block messages of different lengths per lane, padded as MD5/SHA-1 require.</summary>
    private static byte[] PaddedBlocks(byte[][] msgs, bool bigEndianLength)
    {
        var blocks = new byte[8 * 64];
        for (int l = 0; l < 8; l++)
        {
            var m = msgs[l];
            m.CopyTo(blocks, l * 64);
            blocks[l * 64 + m.Length] = 0x80;
            ulong bits = (ulong)m.Length * 8;
            for (int i = 0; i < 8; i++)
                blocks[l * 64 + (bigEndianLength ? 63 - i : 56 + i)] = (byte)(bits >> (8 * i));
        }
        return blocks;
    }

    private static byte[][] RandomMessages()
    {
        var rng = new Random(1234);
        return Enumerable.Range(0, 8).Select(l => { var b = new byte[l * 7]; rng.NextBytes(b); return b; }).ToArray();
    }

    [Fact]
    public void Md5x8MatchesDotNetMd5()
    {
        var msgs = RandomMessages();
        Span<Vector256<uint>> w = stackalloc Vector256<uint>[16];
        Lanes.LoadBlock(PaddedBlocks(msgs, false), w, bigEndian: false);
        var a = Md5x8.IvA; var b = Md5x8.IvB; var c = Md5x8.IvC; var d = Md5x8.IvD;
        Md5x8.Compress(ref a, ref b, ref c, ref d, w);
        for (int l = 0; l < 8; l++)
        {
            var got = new byte[16];
            Lanes.DigestLe(got, l, a, b, c, d);
            Assert.Equal(MD5.HashData(msgs[l]), got);
        }
    }

    [Fact]
    public unsafe void InterleavedVariantsMatchSingleGroup()
    {
        var msgs = RandomMessages();
        var w = stackalloc Vector256<uint>[16];
        var x = stackalloc Vector256<uint>[16];
        var sw = new Vector256<uint>[16];
        Lanes.LoadBlock(PaddedBlocks(msgs, false), sw, bigEndian: false);
        for (int i = 0; i < 16; i++) { w[i] = sw[i]; x[i] = sw[i]; }
        var s = stackalloc Vector256<uint>[10];
        s[0] = Md5x8.IvA; s[1] = Md5x8.IvB; s[2] = Md5x8.IvC; s[3] = Md5x8.IvD;
        s[4] = Md5x8.IvA; s[5] = Md5x8.IvB; s[6] = Md5x8.IvC; s[7] = Md5x8.IvD;
        Md5x8.Compress2(s, w, x);
        for (int l = 0; l < 8; l++)
        {
            var got = new byte[16];
            Lanes.DigestLe(got, l, s[4], s[5], s[6], s[7]);
            Assert.Equal(MD5.HashData(msgs[l]), got);
        }

        Lanes.LoadBlock(PaddedBlocks(msgs, true), sw, bigEndian: true);
        for (int i = 0; i < 16; i++) { w[i] = sw[i]; x[i] = sw[i]; }
        s[0] = Sha1x8.IvA; s[1] = Sha1x8.IvB; s[2] = Sha1x8.IvC; s[3] = Sha1x8.IvD; s[4] = Sha1x8.IvE;
        s[5] = Sha1x8.IvA; s[6] = Sha1x8.IvB; s[7] = Sha1x8.IvC; s[8] = Sha1x8.IvD; s[9] = Sha1x8.IvE;
        Sha1x8.Compress2(s, w, x);
        for (int l = 0; l < 8; l++)
        {
            var got = new byte[20];
            Lanes.DigestBe(got, l, s[0], s[1], s[2], s[3], s[4]);
            Assert.Equal(SHA1.HashData(msgs[l]), got);
            Lanes.DigestBe(got, l, s[5], s[6], s[7], s[8], s[9]);
            Assert.Equal(SHA1.HashData(msgs[l]), got);
        }
    }

    [Fact]
    public unsafe void Rc4EightLanesMatchesSingleLane()
    {
        var rng = new Random(7);
        var keys = new byte[128]; rng.NextBytes(keys);
        var data = new byte[36]; rng.NextBytes(data);
        var states = new byte[2048];
        var outp = new byte[8 * 36];
        fixed (byte* s = states) fixed (byte* k = keys) fixed (byte* d = data) fixed (byte* o = outp)
        {
            Rc4.Ksa16x8(s, k);
            Rc4.Crypt8(s, d, o, 36);
        }
        for (int l = 0; l < 8; l++)
            Assert.Equal(Rc4.Apply(keys.AsSpan(16 * l, 16), data), outp.AsSpan(36 * l, 36).ToArray());
    }

    [Theory]
    [InlineData(16)]
    [InlineData(5)]
    public unsafe void Rc4InterleavedMatchesSingleLane(int keyLen)
    {
        var rng = new Random(11 + keyLen);
        var keys = new byte[8 * keyLen]; rng.NextBytes(keys);
        var data = new byte[36]; rng.NextBytes(data);
        var states = new byte[2048];
        var rows = new ulong[keyLen];
        for (int kk = 0; kk < keyLen; kk++)
            for (int l = 0; l < 8; l++) rows[kk] |= (ulong)keys[l * keyLen + kk] << (8 * l);
        var outp = new byte[8 * 36];
        fixed (byte* s = states) fixed (ulong* r = rows) fixed (byte* d = data) fixed (byte* o = outp)
        {
            Rc4.KsaInterleaved8(s, r, keyLen);
            Rc4.CryptInterleaved8(s, d, o, 36);
        }
        for (int l = 0; l < 8; l++)
            Assert.Equal(Rc4.Apply(keys.AsSpan(keyLen * l, keyLen), data), outp.AsSpan(36 * l, 36).ToArray());
    }

    [Fact]
    public unsafe void Rc4Fast4MatchesSingleLane()
    {
        var rng = new Random(99);
        var keys = new byte[64]; rng.NextBytes(keys);
        var data = new byte[20]; rng.NextBytes(data);
        var st = new byte[1024];
        var outp = new byte[20];
        fixed (byte* s = st) fixed (byte* k = keys) fixed (byte* d = data) fixed (byte* o = outp)
        {
            Rc4.Ksa16Fast4(s, s + 256, s + 512, s + 768, k, k + 16, k + 32, k + 48);
            for (int l = 0; l < 4; l++)
            {
                Rc4.Crypt(s + 256 * l, d, o, 20);
                Assert.Equal(Rc4.Apply(keys.AsSpan(16 * l, 16), data), outp);
            }
        }
    }

    [Fact]
    public void Sha1x8MatchesDotNetSha1()
    {
        var msgs = RandomMessages();
        Span<Vector256<uint>> w = stackalloc Vector256<uint>[16];
        Lanes.LoadBlock(PaddedBlocks(msgs, true), w, bigEndian: true);
        var a = Sha1x8.IvA; var b = Sha1x8.IvB; var c = Sha1x8.IvC; var d = Sha1x8.IvD; var e = Sha1x8.IvE;
        Sha1x8.Compress(ref a, ref b, ref c, ref d, ref e, w);
        for (int l = 0; l < 8; l++)
        {
            var got = new byte[20];
            Lanes.DigestBe(got, l, a, b, c, d, e);
            Assert.Equal(SHA1.HashData(msgs[l]), got);
        }
    }
}
