using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using RecoverKit.Core.Native.Simd;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>
/// MS Office 97-2000 RC4 encryption (hashcat 9700, $oldoffice$0/1): MD5 key derivation over the
/// UTF-16 password and salt, 128-bit RC4 key, verifier checked against its MD5. The three MD5
/// stages and the final check run on 8 candidates per AVX2 vector; RC4 runs per candidate.
/// </summary>
public sealed unsafe class Office97Kernel : NativeKernel, INativeFilter
{
    private readonly byte[] _salt, _encrypted;   // _encrypted = verifier (16) + verifier hash (16)

    // H1 = MD5(16 x (H0[0..5] || salt)) message layout: per word a constant plus up to 4 H0 bytes.
    private readonly uint[] _h1Const = new uint[96];
    private readonly byte[] _h1Count = new byte[96];
    private readonly byte[] _h1Idx = new byte[96 * 4];
    private readonly byte[] _h1Shift = new byte[96 * 4];

    public override string Name => "MS Office 97-2000 (MD5 + RC4)";
    public override int MaxPasswordLength => 15;
    public override double SpeedHint => 1_500_000;

    private Office97Kernel(byte[] salt, byte[] verifier, byte[] verifierHash)
    {
        _salt = salt;
        _encrypted = [.. verifier, .. verifierHash];
        var msg = new int[384];          // >= 0: salt/padding byte value; -1..-5: H0 byte index
        for (int p = 0; p < 384; p++)
        {
            if (p < 336) { int q = p % 21; msg[p] = q < 5 ? -(q + 1) : salt[q - 5]; }
            else if (p == 336) msg[p] = 0x80;
            else if (p >= 376) msg[p] = (int)((2688UL >> (8 * (p - 376))) & 0xff);
            else msg[p] = 0;
        }
        for (int w = 0; w < 96; w++)
            for (int b = 0; b < 4; b++)
            {
                int v = msg[w * 4 + b];
                if (v >= 0) _h1Const[w] |= (uint)v << (8 * b);
                else
                {
                    int e = w * 4 + _h1Count[w]++;
                    _h1Idx[e] = (byte)(-v - 1);
                    _h1Shift[e] = (byte)(8 * b);
                }
            }
    }

    public static Office97Kernel? TryParse(string line)
    {
        line = line.Trim();
        if (!line.StartsWith("$oldoffice$", StringComparison.Ordinal)) return null;
        var f = line["$oldoffice$".Length..].Split('*');
        if (f.Length != 4 || f[0] is not ("0" or "1")) return null;
        try
        {
            var salt = Convert.FromHexString(f[1]);
            var v = Convert.FromHexString(f[2]);
            var h = Convert.FromHexString(f[3]);
            return salt.Length == 16 && v.Length == 16 && h.Length == 16 ? new Office97Kernel(salt, v, h) : null;
        }
        catch (FormatException) { return null; }
    }

    /// <summary>Reference implementation (MS-OFFCRYPTO 2.3.6), independent of the vector path.</summary>
    public override bool Verify(ReadOnlySpan<byte> password)
    {
        if (password.Length > MaxPasswordLength) return false;
        var pw16 = new byte[password.Length * 2];
        for (int i = 0; i < password.Length; i++) pw16[2 * i] = password[i];
        var h0 = MD5.HashData(pw16);
        var buf = new byte[336];
        for (int k = 0; k < 16; k++) { h0.AsSpan(0, 5).CopyTo(buf.AsSpan(21 * k)); _salt.CopyTo(buf, 21 * k + 5); }
        var h1 = MD5.HashData(buf);
        var key = MD5.HashData([.. h1.AsSpan(0, 5), 0, 0, 0, 0]);
        var plain = Rc4.Apply(key, _encrypted);
        return MD5.HashData(plain.AsSpan(0, 16)).AsSpan().SequenceEqual(plain.AsSpan(16, 16));
    }

    public override KernelWorker CreateWorker() => RkNative.HasVectorPath ? new NativeFilterWorker(this, this, new Worker(this)) : new Worker(this);

    public override int PrefixBatch(int lastCount) => RkNative.HasVectorPath ? RkNative.BatchFor(lastCount, 256) : 1;

    int INativeFilter.Filter(byte* pws, int len, int n, int* hits, int maxHits)
    {
        fixed (byte* salt = _salt, enc = _encrypted)
            return RkNative.Office97Search(salt, enc, pws, len, n, hits, maxHits);
    }

    private sealed class Worker(Office97Kernel k) : KernelWorker
    {
        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
        {
            int len = prefix.Length + 1;
            if (len > 15) return -1;
            uint* baseW = stackalloc uint[16];
            new Span<uint>(baseW, 16).Clear();
            for (int i = 0; i < prefix.Length; i++) baseW[(2 * i) / 4] |= (uint)prefix[i] << (8 * ((2 * i) % 4));
            baseW[(2 * len) / 4] |= 0x80u << (8 * ((2 * len) % 4));
            baseW[14] = (uint)(16 * len);
            int wl = (2 * len - 2) / 4, shift = 8 * ((2 * len - 2) % 4);

            // Two groups of 8 candidates (A: lanes 0-7, B: lanes 8-15) share every MD5 call.
            var st = stackalloc Vector256<uint>[8];
            var wa = stackalloc Vector256<uint>[16];
            var wb = stackalloc Vector256<uint>[16];
            var tba = stackalloc Vector256<uint>[5];
            var tbb = stackalloc Vector256<uint>[5];
            uint* lanes = stackalloc uint[16];
            uint* tmp = stackalloc uint[32];
            byte* states = stackalloc byte[2048];
            byte* keys = stackalloc byte[128];
            byte* plain = stackalloc byte[160];
            uint* vw = stackalloc uint[80];            // per group: verifier words 0..3 + hash word 0, word-major
            Span<byte> pw = stackalloc byte[len];
            var ff = Vector256.Create(0xffu);
            int n = last.Length;

            fixed (byte* enc = k._encrypted)
            for (int i = 0; i < n; i += 16)
            {
                for (int l = 0; l < 16; l++) lanes[l] = last[Math.Min(i + l, n - 1)];
                var cva = Vector256.Load(lanes);
                var cvb = Vector256.Load(lanes + 8);

                // H0 = MD5(UTF-16 password)
                for (int j = 0; j < 16; j++) wa[j] = wb[j] = Vector256.Create(baseW[j]);
                wa[wl] |= Vector256.ShiftLeft(cva, shift);
                wb[wl] |= Vector256.ShiftLeft(cvb, shift);
                Iv(st);
                Md5x8.Compress2(st, wa, wb);
                Trunc(st, tba, ff);
                Trunc(st + 4, tbb, ff);

                // H1 = MD5(16 x (H0[0..5] || salt)), 6 blocks
                Iv(st);
                for (int blk = 0; blk < 6; blk++)
                {
                    for (int j = 0; j < 16; j++)
                    {
                        int wi = blk * 16 + j;
                        var va = Vector256.Create(k._h1Const[wi]);
                        var vb = va;
                        for (int e = 0; e < k._h1Count[wi]; e++)
                        {
                            int idx = k._h1Idx[wi * 4 + e], sh = k._h1Shift[wi * 4 + e];
                            va |= Vector256.ShiftLeft(tba[idx], sh);
                            vb |= Vector256.ShiftLeft(tbb[idx], sh);
                        }
                        wa[j] = va;
                        wb[j] = vb;
                    }
                    Md5x8.Compress2(st, wa, wb);
                }

                // RC4 key = MD5(H1[0..5] || block 0)
                for (int j = 0; j < 16; j++) wa[j] = wb[j] = Vector256<uint>.Zero;
                wa[0] = st[0]; wa[1] = st[1] & ff;
                wb[0] = st[4]; wb[1] = st[5] & ff;
                wa[2] = wb[2] = Vector256.Create(0x8000u);
                wa[14] = wb[14] = Vector256.Create(72u);
                Iv(st);
                Md5x8.Compress2(st, wa, wb);

                // RC4 over verifier + first hash word, 8 lanes at a time; then MD5(verifier) for both groups.
                for (int g = 0; g < 2; g++)
                {
                    var sg = st + 4 * g;
                    sg[0].Store(tmp); sg[1].Store(tmp + 8); sg[2].Store(tmp + 16); sg[3].Store(tmp + 24);
                    uint* kw = (uint*)keys;
                    for (int l = 0; l < 8; l++) { kw[4 * l] = tmp[l]; kw[4 * l + 1] = tmp[8 + l]; kw[4 * l + 2] = tmp[16 + l]; kw[4 * l + 3] = tmp[24 + l]; }
                    Rc4.Ksa16Fast4(states, states + 256, states + 512, states + 768, keys, keys + 16, keys + 32, keys + 48);
                    Rc4.Ksa16Fast4(states + 1024, states + 1280, states + 1536, states + 1792, keys + 64, keys + 80, keys + 96, keys + 112);
                    Rc4.CryptFast4(states, states + 256, states + 512, states + 768, enc, plain, 20);
                    Rc4.CryptFast4(states + 1024, states + 1280, states + 1536, states + 1792, enc, plain + 80, 20);
                    uint* v = vw + 40 * g;
                    for (int l = 0; l < 8; l++)
                    {
                        byte* p = plain + 20 * l;
                        v[l] = Unsafe.ReadUnaligned<uint>(p); v[8 + l] = Unsafe.ReadUnaligned<uint>(p + 4);
                        v[16 + l] = Unsafe.ReadUnaligned<uint>(p + 8); v[24 + l] = Unsafe.ReadUnaligned<uint>(p + 12);
                        v[32 + l] = Unsafe.ReadUnaligned<uint>(p + 16);
                    }
                }
                for (int j = 0; j < 16; j++) wa[j] = wb[j] = Vector256<uint>.Zero;
                for (int j = 0; j < 4; j++) { wa[j] = Vector256.Load(vw + 8 * j); wb[j] = Vector256.Load(vw + 40 + 8 * j); }
                wa[4] = wb[4] = Vector256.Create(0x80u);
                wa[14] = wb[14] = Vector256.Create(128u);
                Iv(st);
                Md5x8.Compress2(st, wa, wb);
                uint mask = Vector256.Equals(st[0], Vector256.Load(vw + 32)).ExtractMostSignificantBits()
                          | Vector256.Equals(st[4], Vector256.Load(vw + 72)).ExtractMostSignificantBits() << 8;
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

        private static void Iv(Vector256<uint>* s)
        {
            s[0] = s[4] = Md5x8.IvA; s[1] = s[5] = Md5x8.IvB; s[2] = s[6] = Md5x8.IvC; s[3] = s[7] = Md5x8.IvD;
        }

        /// <summary>The five bytes of H0[0..5] as separate lane vectors.</summary>
        private static void Trunc(Vector256<uint>* s, Vector256<uint>* tb, Vector256<uint> ff)
        {
            tb[0] = s[0] & ff; tb[1] = Vector256.ShiftRightLogical(s[0], 8) & ff; tb[2] = Vector256.ShiftRightLogical(s[0], 16) & ff;
            tb[3] = Vector256.ShiftRightLogical(s[0], 24); tb[4] = s[1] & ff;
        }
    }
}
