using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using RecoverKit.Core.Native.Simd;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>
/// MS Office XP-2003 RC4 CryptoAPI encryption (hashcat 9800, $oldoffice$3/4): SHA-1 over salt and
/// UTF-16 password, SHA-1 with block number 0, the first 40 bits zero-padded to a 128-bit RC4 key,
/// verifier checked against its SHA-1. Both SHA-1 stages and the check run on 8 candidates per
/// vector; RC4 runs per candidate.
/// </summary>
public sealed unsafe class Office2003Kernel : NativeKernel, INativeFilter
{
    private readonly byte[] _salt, _encrypted;   // verifier (16) + verifier hash (20)

    public override string Name => "MS Office XP-2003 (SHA-1 + RC4)";
    public override int MaxPasswordLength => 15;
    public override double SpeedHint => 2_000_000;

    private Office2003Kernel(byte[] salt, byte[] verifier, byte[] verifierHash)
    {
        _salt = salt;
        _encrypted = [.. verifier, .. verifierHash];
    }

    public static Office2003Kernel? TryParse(string line)
    {
        line = line.Trim();
        if (!line.StartsWith("$oldoffice$", StringComparison.Ordinal)) return null;
        var f = line["$oldoffice$".Length..].Split('*');
        if (f.Length != 4 || f[0] is not ("3" or "4")) return null;
        try
        {
            var salt = Convert.FromHexString(f[1]);
            var v = Convert.FromHexString(f[2]);
            var h = Convert.FromHexString(f[3]);
            return salt.Length == 16 && v.Length == 16 && h.Length == 20 ? new Office2003Kernel(salt, v, h) : null;
        }
        catch (FormatException) { return null; }
    }

    /// <summary>Reference implementation (MS-OFFCRYPTO 2.3.5.2), independent of the vector path.</summary>
    public override bool Verify(ReadOnlySpan<byte> password)
    {
        if (password.Length > MaxPasswordLength) return false;
        var pw16 = new byte[password.Length * 2];
        for (int i = 0; i < password.Length; i++) pw16[2 * i] = password[i];
        var h0 = SHA1.HashData([.. _salt, .. pw16]);
        var hf = SHA1.HashData([.. h0, 0, 0, 0, 0]);
        var key = new byte[16];
        hf.AsSpan(0, 5).CopyTo(key);
        var plain = Rc4.Apply(key, _encrypted);
        return SHA1.HashData(plain.AsSpan(0, 16)).AsSpan().SequenceEqual(plain.AsSpan(16, 20));
    }

    public override KernelWorker CreateWorker() => RkNative.HasAvx2 ? new NativeFilterWorker(this, this, new Worker(this)) : new Worker(this);

    public override int PrefixBatch(int lastCount) => RkNative.HasAvx2 ? RkNative.BatchFor(lastCount, 256) : 1;

    int INativeFilter.Filter(byte* pws, int len, int n, int* hits, int maxHits)
    {
        fixed (byte* salt = _salt, enc = _encrypted)
            return RkNative.Office2003Search(salt, enc, pws, len, n, hits, maxHits);
    }

    private sealed class Worker(Office2003Kernel k) : KernelWorker
    {
        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
        {
            int len = prefix.Length + 1;
            if (len > 15) return -1;
            // Block: salt (16) || UTF-16 password || 0x80 || ... || bit length (big-endian).
            Span<byte> blk = stackalloc byte[64];
            k._salt.CopyTo(blk);
            for (int i = 0; i < prefix.Length; i++) blk[16 + 2 * i] = prefix[i];
            blk[16 + 2 * len] = 0x80;
            BinaryPrimitives.WriteUInt32BigEndian(blk[60..], (uint)((16 + 2 * len) * 8));
            uint* baseW = stackalloc uint[16];
            for (int j = 0; j < 16; j++) baseW[j] = BinaryPrimitives.ReadUInt32BigEndian(blk[(4 * j)..]);
            int pos = 16 + 2 * (len - 1);
            int wl = pos / 4, shift = 8 * (3 - pos % 4);

            var w = stackalloc Vector256<uint>[16];
            uint* lanes = stackalloc uint[8];
            uint* tmp = stackalloc uint[16];
            byte* states = stackalloc byte[2048];
            byte* keys = stackalloc byte[128];
            byte* plain = stackalloc byte[160];
            uint* vw = stackalloc uint[40];
            Span<byte> pw = stackalloc byte[len];
            int n = last.Length;

            fixed (byte* enc = k._encrypted)
            for (int i = 0; i < n; i += 8)
            {
                for (int l = 0; l < 8; l++) lanes[l] = last[Math.Min(i + l, n - 1)];
                var cv = Vector256.Load(lanes);

                for (int j = 0; j < 16; j++) w[j] = Vector256.Create(baseW[j]);
                w[wl] |= Vector256.ShiftLeft(cv, shift);
                var a = Sha1x8.IvA; var b = Sha1x8.IvB; var c = Sha1x8.IvC; var d = Sha1x8.IvD; var e = Sha1x8.IvE;
                Sha1x8.CompressMem(ref a, ref b, ref c, ref d, ref e, w);

                // H-final = SHA-1(H0 || block number 0)
                for (int j = 0; j < 16; j++) w[j] = Vector256<uint>.Zero;
                w[0] = a; w[1] = b; w[2] = c; w[3] = d; w[4] = e;
                w[6] = Vector256.Create(0x80000000u);
                w[15] = Vector256.Create(192u);
                var fa = Sha1x8.IvA; var fb = Sha1x8.IvB; var fc = Sha1x8.IvC; var fd = Sha1x8.IvD; var fe = Sha1x8.IvE;
                Sha1x8.CompressMem(ref fa, ref fb, ref fc, ref fd, ref fe, w);

                // Keys: first 5 digest bytes (big-endian words), zero-padded to 16 bytes; RC4 for 8 lanes.
                fa.Store(tmp); fb.Store(tmp + 8);
                uint* kw = (uint*)keys;
                for (int l = 0; l < 8; l++) { kw[4 * l] = BinaryPrimitives.ReverseEndianness(tmp[l]); kw[4 * l + 1] = tmp[8 + l] >> 24; kw[4 * l + 2] = 0; kw[4 * l + 3] = 0; }
                Rc4.Ksa16Fast4(states, states + 256, states + 512, states + 768, keys, keys + 16, keys + 32, keys + 48);
                Rc4.Ksa16Fast4(states + 1024, states + 1280, states + 1536, states + 1792, keys + 64, keys + 80, keys + 96, keys + 112);
                Rc4.CryptFast4(states, states + 256, states + 512, states + 768, enc, plain, 20);
                Rc4.CryptFast4(states + 1024, states + 1280, states + 1536, states + 1792, enc, plain + 80, 20);
                for (int l = 0; l < 8; l++)
                {
                    byte* p = plain + 20 * l;
                    vw[l] = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(p));
                    vw[8 + l] = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(p + 4));
                    vw[16 + l] = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(p + 8));
                    vw[24 + l] = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(p + 12));
                    vw[32 + l] = BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<uint>(p + 16));
                }

                // SHA-1(verifier) compared with the decrypted hash's first word.
                for (int j = 0; j < 16; j++) w[j] = Vector256<uint>.Zero;
                for (int j = 0; j < 4; j++) w[j] = Vector256.Load(vw + 8 * j);
                w[4] = Vector256.Create(0x80000000u);
                w[15] = Vector256.Create(128u);
                var ha = Sha1x8.IvA; var hb = Sha1x8.IvB; var hc = Sha1x8.IvC; var hd = Sha1x8.IvD; var he = Sha1x8.IvE;
                Sha1x8.CompressMem(ref ha, ref hb, ref hc, ref hd, ref he, w);
                uint mask = Vector256.Equals(ha, Vector256.Load(vw + 32)).ExtractMostSignificantBits();
                while (mask != 0)
                {
                    int l = System.Numerics.BitOperations.TrailingZeroCount(mask);
                    mask &= mask - 1;
                    if (i + l >= n) continue;
                    prefix.CopyTo(pw);
                    pw[^1] = last[i + l];
                    if (k.Verify(pw)) return i + l;
                }
            }
            return -1;
        }
    }
}
