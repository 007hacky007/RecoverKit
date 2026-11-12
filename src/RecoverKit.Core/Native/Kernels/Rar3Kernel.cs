using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using RecoverKit.Core.Native.Simd;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>
/// RAR 3.x archives with encrypted headers (hashcat 12500, $RAR3$*0*). Key derivation is one SHA-1
/// over 262,144 rounds of (UTF-16 password || salt || 24-bit round counter), with an IV byte taken
/// every 16,384 rounds; the AES-128-CBC decrypted block must start with the end-of-archive header.
///
/// Eight candidates of equal length run per AVX2 vector. A round is P = 2L + 11 bytes, P is odd, so
/// the round layout over 64-byte blocks repeats every 64 rounds (P blocks). Inside such a period the
/// counter's high bytes are constant and its low byte is (64s &amp; 0xff) | r, so every message word is a
/// precomputed template OR'ed with the period's counter bytes and the lane's last character.
/// </summary>
public sealed unsafe class Rar3Kernel : NativeKernel
{
    private const int Rounds = 0x40000;
    private static readonly byte[] EndOfArchive = [0xc4, 0x3d, 0x7b, 0x00, 0x40, 0x07, 0x00, 0x00];

    private readonly byte[] _salt, _enc;

    public override string Name => "RAR 3.x (SHA-1 x 262144 + AES-128)";
    public override int MaxPasswordLength => 26;           // keeps one round within a 64-byte block
    public override double SpeedHint => 400;

    private Rar3Kernel(byte[] salt, byte[] enc) { _salt = salt; _enc = enc; }

    public static Rar3Kernel? TryParse(string line)
    {
        line = line.Trim();
        if (!line.StartsWith("$RAR3$*0*", StringComparison.Ordinal)) return null;
        var f = line["$RAR3$*0*".Length..].Split('*');
        try
        {
            if (f.Length != 2) return null;
            var salt = Convert.FromHexString(f[0]);
            var enc = Convert.FromHexString(f[1]);
            return salt.Length == 8 && enc.Length == 16 ? new Rar3Kernel(salt, enc) : null;
        }
        catch (FormatException) { return null; }
    }

    /// <summary>Reference implementation, independent of the vector path.</summary>
    public override bool Verify(ReadOnlySpan<byte> password)
    {
        if (password.Length > MaxPasswordLength) return false;
        var (d, iv) = ReferenceHash(password);
        return Decrypts(d, iv);
    }

    /// <summary>SHA-1 digest and IV of the RAR 3 key derivation, straight from the definition.</summary>
    internal (byte[] Digest, byte[] Iv) ReferenceHash(ReadOnlySpan<byte> password)
    {
        var data = new byte[password.Length * 2 + 8];
        for (int i = 0; i < password.Length; i++) data[2 * i] = password[i];
        _salt.CopyTo(data, password.Length * 2);
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        var iv = new byte[16];
        Span<byte> ctr = stackalloc byte[3];
        Span<byte> tmp = stackalloc byte[20];
        for (int i = 0; i < Rounds; i++)
        {
            h.AppendData(data);
            ctr[0] = (byte)i; ctr[1] = (byte)(i >> 8); ctr[2] = (byte)(i >> 16);
            h.AppendData(ctr);
            if (i % 0x4000 == 0) { h.GetCurrentHash(tmp); iv[i / 0x4000] = tmp[19]; }
        }
        return (h.GetHashAndReset(), iv);
    }

    internal bool Decrypts(ReadOnlySpan<byte> digest, ReadOnlySpan<byte> iv)
    {
        Span<byte> key = stackalloc byte[16];
        for (int k = 0; k < 4; k++)
            for (int b = 0; b < 4; b++) key[4 * k + b] = digest[4 * k + 3 - b];
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        var plain = aes.DecryptCbc(_enc, iv, PaddingMode.None);
        return plain.AsSpan(0, 8).SequenceEqual(EndOfArchive);
    }

    public override KernelWorker CreateWorker() => new Worker(this);

    /// <summary>The native library has a vector path for this kernel on this CPU.</summary>
    internal static bool NativeFast => RkNative.HasVectorPath;

    /// <summary>Digest + IV of every candidate prefix + last[i] from the native library (36 bytes each).</summary>
    internal byte[] NativeHash(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last) => NativeHash(prefix, 1, last);

    /// <summary>Digest + IV of prefixes[k] + last[i], in order k * last.Length + i.</summary>
    internal byte[] NativeHash(ReadOnlySpan<byte> prefixes, int count, ReadOnlySpan<byte> last)
    {
        int plen = prefixes.Length / count, len = plen + 1, n = count * last.Length;
        var pws = new byte[n * len];
        for (int k = 0, o = 0; k < count; k++)
            for (int i = 0; i < last.Length; i++, o += len)
            {
                prefixes.Slice(k * plen, plen).CopyTo(pws.AsSpan(o));
                pws[o + plen] = last[i];
            }
        var res = new byte[36 * n];
        fixed (byte* salt = _salt, pw = pws, o = res)
            if (RkNative.Rar3Hash(salt, pw, len, n, o) != 0)
                throw new InvalidOperationException("rknative rejected the RAR3 request");
        return res;
    }

    /// <summary>
    /// The native path tests 16 candidates per call group: take enough prefixes per call that the last
    /// group is (almost) full. With ?a (95) one prefix fills 6 groups of 16 to 99 %; with 69 characters
    /// three prefixes (207 candidates) fill 13 groups to 99.5 %.
    /// </summary>
    public override int PrefixBatch(int lastCount)
    {
        if (!NativeFast) return 1;
        for (int c = 1; c <= 8; c++)
        {
            int n = c * lastCount, groups = (n + 15) / 16;
            if (n >= 0.98 * 16 * groups) return c;
        }
        return 8;
    }

    private sealed class Worker(Rar3Kernel k) : KernelWorker
    {
        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
        {
            int len = prefix.Length + 1;
            if (len > k.MaxPasswordLength) return -1;
            if (NativeFast) return SearchBatch(prefix, 1, last);
            int p = 2 * len + 11;           // bytes per round (odd)
            int nb = p;                     // blocks per 64-round period
            int words = nb * 16;

            // Template of one period: password (last character zero), salt, counter low byte = r.
            var tpl = new byte[nb * 64];
            var role = new byte[nb * 64];   // 0 template, 1 counter byte 0, 2 counter byte 1, 3 counter byte 2, 4 last char
            for (int r = 0; r < 64; r++)
            {
                int o = r * p;
                for (int q = 0; q < prefix.Length; q++) tpl[o + 2 * q] = prefix[q];
                role[o + 2 * (len - 1)] = 4;
                k._salt.CopyTo(tpl, o + 2 * len);
                tpl[o + 2 * len + 8] = (byte)r; role[o + 2 * len + 8] = 1;
                role[o + 2 * len + 9] = 2;
                role[o + 2 * len + 10] = 3;
            }
            var pre = new uint[words];
            var m0 = new uint[words]; var m1 = new uint[words]; var m2 = new uint[words];
            var lcShift = new int[words];
            for (int w = 0; w < words; w++)
            {
                lcShift[w] = -1;
                for (int b = 0; b < 4; b++)
                {
                    int pos = 4 * w + b, sh = 8 * (3 - b);
                    pre[w] |= (uint)tpl[pos] << sh;
                    switch (role[pos])
                    {
                        case 1: m0[w] |= 0xffu << sh; break;
                        case 2: m1[w] |= 0xffu << sh; break;
                        case 3: m2[w] |= 0xffu << sh; break;
                        case 4: lcShift[w] = sh; break;
                    }
                }
            }

            var lc = new Vector256<uint>[words];
            var vbase = new Vector256<uint>[words];      // template | last char, per 8-candidate group
            // Words that carry counter bytes (the only ones that change between periods).
            var ctrWords = Enumerable.Range(0, words).Where(w => (m0[w] | m1[w] | m2[w]) != 0).ToArray();
            var ctrOfBlock = new int[nb + 1];
            for (int blk = 0, q = 0; blk <= nb; blk++) { while (q < ctrWords.Length && ctrWords[q] < 16 * blk) q++; ctrOfBlock[blk] = q; }
            var w16 = stackalloc Vector256<uint>[16];
            var cw = new uint[words];
            uint* lanes = stackalloc uint[8];
            uint* tmp = stackalloc uint[40];
            byte* iv = stackalloc byte[8 * 16];
            Span<byte> pw = stackalloc byte[len];
            Span<byte> digest = stackalloc byte[20];
            int n = last.Length;
            int cutBlock = p / 64, cutOff = p % 64;   // the first round of a period ends here

            for (int i = 0; i < n; i += 8)
            {
                for (int l = 0; l < 8; l++) lanes[l] = last[Math.Min(i + l, n - 1)];
                var cv = Vector256.Load(lanes);
                for (int w = 0; w < words; w++)
                {
                    lc[w] = lcShift[w] < 0 ? Vector256<uint>.Zero : Vector256.ShiftLeft(cv, lcShift[w]);
                    vbase[w] = Vector256.Create(pre[w]) | lc[w];
                }
                new Span<byte>(iv, 128).Clear();

                var a = Sha1x8.IvA; var b = Sha1x8.IvB; var c = Sha1x8.IvC; var d = Sha1x8.IvD; var e = Sha1x8.IvE;
                for (int s = 0; s < Rounds / 64; s++)
                {
                    uint b0 = (uint)((64 * s) & 0xff) * 0x01010101u;
                    uint c1 = (uint)((s >> 2) & 0xff) * 0x01010101u;
                    uint c2 = (uint)((s >> 10) & 0xff) * 0x01010101u;
                    foreach (int w in ctrWords) cw[w] = (b0 & m0[w]) | (c1 & m1[w]) | (c2 & m2[w]);
                    bool ivPoint = (s & 255) == 0;
                    for (int blk = 0; blk < nb; blk++)
                    {
                        int wb = blk * 16;
                        if (ivPoint && blk == cutBlock)
                        {
                            // IV byte: SHA-1 final of a copy after round 64s (its end lies inside this block).
                            for (int j = 0; j < 16; j++)
                            {
                                var v = vbase[wb + j] | Vector256.Create((m0[wb + j] | m1[wb + j] | m2[wb + j]) != 0 ? cw[wb + j] : 0u);
                                int start = 4 * j;
                                if (start >= cutOff) v = Vector256<uint>.Zero;
                                else if (start + 4 > cutOff) v &= Vector256.Create(0xffffffffu << (8 * (start + 4 - cutOff)));
                                w16[j] = v;
                            }
                            w16[cutOff / 4] |= Vector256.Create(0x80u << (8 * (3 - cutOff % 4)));
                            ulong bits = ((ulong)(64 * s) + 1) * (ulong)p * 8;
                            var ca = a; var cb = b; var cc = c; var cd = d; var ce = e;
                            if (cutOff <= 55)
                            {
                                w16[14] = Vector256.Create((uint)(bits >> 32));
                                w16[15] = Vector256.Create((uint)bits);
                                Sha1x8.CompressMem(ref ca, ref cb, ref cc, ref cd, ref ce, w16);
                            }
                            else
                            {
                                Sha1x8.CompressMem(ref ca, ref cb, ref cc, ref cd, ref ce, w16);
                                for (int j = 0; j < 14; j++) w16[j] = Vector256<uint>.Zero;
                                w16[14] = Vector256.Create((uint)(bits >> 32));
                                w16[15] = Vector256.Create((uint)bits);
                                Sha1x8.CompressMem(ref ca, ref cb, ref cc, ref cd, ref ce, w16);
                            }
                            ce.Store(tmp);
                            int ivIdx = s >> 8;
                            for (int l = 0; l < 8; l++) iv[16 * l + ivIdx] = (byte)tmp[l];
                        }
                        fixed (Vector256<uint>* src = &vbase[wb])
                            Buffer.MemoryCopy(src, w16, 16 * 32, 16 * 32);
                        for (int q = ctrOfBlock[blk]; q < ctrOfBlock[blk + 1]; q++)
                        {
                            int w = ctrWords[q];
                            w16[w - wb] |= Vector256.Create(cw[w]);
                        }
                        Sha1x8.CompressMem(ref a, ref b, ref c, ref d, ref e, w16);
                    }
                }
                // Final padding block (the total length is a multiple of 64 bytes).
                for (int j = 0; j < 16; j++) w16[j] = Vector256<uint>.Zero;
                w16[0] = Vector256.Create(0x80000000u);
                ulong total = (ulong)Rounds * (ulong)p * 8;
                w16[14] = Vector256.Create((uint)(total >> 32));
                w16[15] = Vector256.Create((uint)total);
                Sha1x8.CompressMem(ref a, ref b, ref c, ref d, ref e, w16);

                a.Store(tmp); b.Store(tmp + 8); c.Store(tmp + 16); d.Store(tmp + 24); e.Store(tmp + 32);
                for (int l = 0; l < 8 && i + l < n; l++)
                {
                    for (int q = 0; q < 5; q++) BinaryPrimitives.WriteUInt32BigEndian(digest[(4 * q)..], tmp[8 * q + l]);
                    if (!k.Decrypts(digest, new ReadOnlySpan<byte>(iv + 16 * l, 16))) continue;
                    prefix.CopyTo(pw);
                    pw[^1] = last[i + l];
                    if (k.Verify(pw)) return i + l;
                }
            }
            return -1;
        }

        public override int SearchBatch(ReadOnlySpan<byte> prefixes, int count, ReadOnlySpan<byte> last)
        {
            if (!NativeFast) return base.SearchBatch(prefixes, count, last);
            int plen = prefixes.Length / count;
            if (plen + 1 > k.MaxPasswordLength) return -1;
            var res = k.NativeHash(prefixes, count, last);
            Span<byte> pw = stackalloc byte[plen + 1];
            for (int i = 0; i < count * last.Length; i++)
            {
                if (!k.Decrypts(res.AsSpan(36 * i, 20), res.AsSpan(36 * i + 20, 16))) continue;
                prefixes.Slice(i / last.Length * plen, plen).CopyTo(pw);
                pw[^1] = last[i % last.Length];
                if (k.Verify(pw)) return i;
            }
            return -1;
        }
    }
}
