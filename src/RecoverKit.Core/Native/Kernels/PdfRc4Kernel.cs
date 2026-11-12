using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using RecoverKit.Core.Native.Simd;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>
/// PDF standard security handler revisions 2-4 (hashcat 10400, 10500 and 10510): MD5 key derivation (50
/// extra MD5 rounds for R3/R4) and RC4 checks of the /U entry (1 pass for R2, 20 for R3/R4). MD5 runs
/// on 16 candidates per step (two interleaved AVX2 groups). RC4 is an XOR stream, so byte k of the
/// result depends only on byte k of each keystream: the fast path computes just 4 bytes per pass.
/// </summary>
public sealed unsafe class PdfRc4Kernel : NativeKernel, INativeFilter
{
    private static readonly byte[] Pad = Convert.FromHexString("28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a");

    private readonly int _r, _keyLen;          // revision, key bytes (5 or up to 16)
    private readonly byte[] _o, _u, _id;
    private readonly int _p;
    private readonly bool _encryptMetadata;
    private readonly uint[] _block2 = new uint[16];   // second key-derivation block (P, ID, padding): constant
    private readonly bool _twoBlocks;
    private readonly uint _x0;                 // first 4 bytes of MD5(PAD || ID) (R3/R4 check input)
    private readonly uint _u0;                 // first 4 bytes of /U

    public override string Name => _r == 2 ? "PDF R2 (MD5 + RC4 40-bit)" : $"PDF R{_r} (MD5 + RC4 {_keyLen * 8}-bit)";
    public override int MaxPasswordLength => 32;
    public override double SpeedHint => _r == 2 ? 3_000_000 : 150_000;

    private PdfRc4Kernel(int r, int keyBits, int p, bool encMeta, byte[] id, byte[] u, byte[] o)
    {
        _r = r; _keyLen = r == 2 ? 5 : keyBits / 8; _p = p; _encryptMetadata = encMeta; _id = id; _u = u; _o = o;
        // Bytes after pad(pw) || O: P (4, LE) || ID || [FF FF FF FF] || 0x80 || ... || length.
        var tail = new List<byte>();
        tail.AddRange(BitConverter.GetBytes(p));
        tail.AddRange(id);
        if (r >= 4 && !encMeta) tail.AddRange([0xff, 0xff, 0xff, 0xff]);
        int total = 64 + tail.Count;
        _twoBlocks = total <= 64 + 55;
        if (_twoBlocks)
        {
            var b = new byte[64];
            tail.CopyTo(b);
            b[tail.Count] = 0x80;
            BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(56), (ulong)total * 8);
            for (int i = 0; i < 16; i++) _block2[i] = BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(4 * i));
        }
        _x0 = BinaryPrimitives.ReadUInt32LittleEndian(MD5.HashData([.. Pad, .. id]));
        _u0 = BinaryPrimitives.ReadUInt32LittleEndian(u);
    }

    public static PdfRc4Kernel? TryParse(string line)
    {
        line = line.Trim();
        if (!line.StartsWith("$pdf$", StringComparison.Ordinal)) return null;
        var f = line["$pdf$".Length..].Split('*');
        try
        {
            int r = int.Parse(f[1]);
            if (r is < 2 or > 4 || f.Length < 11) return null;
            int bits = int.Parse(f[2]);
            int p = int.Parse(f[3]);
            bool enc = f[4] != "0";
            var id = Convert.FromHexString(f[6]);
            var u = Convert.FromHexString(f[8]);
            var o = Convert.FromHexString(f[10]);
            if (u.Length < 16 || o.Length != 32 || bits is not (40 or > 40 and <= 128) || bits % 8 != 0) return null;
            return new PdfRc4Kernel(r, bits, p, enc, id, u, o);
        }
        catch (Exception ex) when (ex is FormatException or IndexOutOfRangeException or OverflowException) { return null; }
    }

    private byte[] Key(ReadOnlySpan<byte> password)
    {
        var input = new List<byte>(100);
        for (int i = 0; i < 32; i++) input.Add(i < password.Length ? password[i] : Pad[i - password.Length]);
        input.AddRange(_o);
        input.AddRange(BitConverter.GetBytes(_p));
        input.AddRange(_id);
        if (_r >= 4 && !_encryptMetadata) input.AddRange([0xff, 0xff, 0xff, 0xff]);
        var h = MD5.HashData(input.ToArray());
        if (_r >= 3) for (int i = 0; i < 50; i++) h = MD5.HashData(h.AsSpan(0, _keyLen));
        return h[.._keyLen];
    }

    /// <summary>Reference implementation (PDF 1.7, algorithms 3.2, 3.4 and 3.5).</summary>
    public override bool Verify(ReadOnlySpan<byte> password)
    {
        if (password.Length > 32) return false;
        var key = Key(password);
        if (_r == 2) return Rc4.Apply(key, Pad).AsSpan().SequenceEqual(_u.AsSpan(0, 32));
        var y = MD5.HashData([.. Pad, .. _id]);
        for (int i = 0; i < 20; i++)
        {
            var k = key.Select(b => (byte)(b ^ i)).ToArray();
            y = Rc4.Apply(k, y);
        }
        return y.AsSpan().SequenceEqual(_u.AsSpan(0, 16));
    }

    public override KernelWorker CreateWorker() =>
        !_twoBlocks ? new ScalarWorker(this)
        : RkNative.HasVectorPath ? new NativeFilterWorker(this, this, new Worker(this)) : new Worker(this);

    public override int PrefixBatch(int lastCount) => _twoBlocks && RkNative.HasVectorPath ? RkNative.BatchFor(lastCount, _r == 2 ? 256 : 32) : 1;

    int INativeFilter.Filter(byte* pws, int len, int n, int* hits, int maxHits)
    {
        RkNative.PdfParams p;
        p.R = _r; p.KeyLen = _keyLen;
        for (int i = 0; i < 32; i++) p.O[i] = _o[i];
        for (int i = 0; i < 16; i++) p.Block2[i] = _block2[i];
        p.X0 = _x0; p.U0 = _u0; p.Pad0 = BinaryPrimitives.ReadUInt32LittleEndian(Pad);
        return RkNative.PdfSearch(&p, pws, len, n, hits, maxHits);
    }

    /// <summary>Unusual layouts (very long IDs): plain reference checks.</summary>
    private sealed class ScalarWorker(PdfRc4Kernel k) : KernelWorker
    {
        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
        {
            Span<byte> pw = stackalloc byte[prefix.Length + 1];
            prefix.CopyTo(pw);
            for (int i = 0; i < last.Length; i++) { pw[^1] = last[i]; if (k.Verify(pw)) return i; }
            return -1;
        }
    }

    private sealed class Worker(PdfRc4Kernel k) : KernelWorker
    {
        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
        {
            int len = prefix.Length + 1;
            if (len > 32) return -1;
            // Block 1: pad(password) || O.
            byte* blk = stackalloc byte[64];
            for (int i = 0; i < 32; i++) blk[i] = i < prefix.Length ? prefix[i] : i == prefix.Length ? (byte)0 : Pad[i - len];
            for (int i = 0; i < 32; i++) blk[32 + i] = k._o[i];
            uint* baseW = (uint*)blk;
            int wl = (len - 1) / 4, shift = 8 * ((len - 1) % 4);
            int kl = k._keyLen;

            var st = stackalloc Vector256<uint>[8];
            var wa = stackalloc Vector256<uint>[16];
            var wb = stackalloc Vector256<uint>[16];
            uint* lanes = stackalloc uint[16];
            uint* tmp = stackalloc uint[64];
            byte* states = stackalloc byte[4096];
            byte* keys = stackalloc byte[16 * 16];      // lane l key at keys + 16*l
            byte* xkeys = stackalloc byte[16 * 16];
            byte* ks = stackalloc byte[64];             // 4 keystream bytes x 16 lanes
            byte* zero = stackalloc byte[32];
            new Span<byte>(zero, 32).Clear();
            uint* y = stackalloc uint[16];
            Span<byte> pw = stackalloc byte[len];
            int n = last.Length;

            for (int i = 0; i < n; i += 16)
            {
                for (int l = 0; l < 16; l++) lanes[l] = last[Math.Min(i + l, n - 1)];
                var cva = Vector256.Load(lanes);
                var cvb = Vector256.Load(lanes + 8);

                // key = MD5(pad(pw) || O || P || ID [|| FFFFFFFF])
                for (int j = 0; j < 16; j++) wa[j] = wb[j] = Vector256.Create(baseW[j]);
                wa[wl] |= Vector256.ShiftLeft(cva, shift);
                wb[wl] |= Vector256.ShiftLeft(cvb, shift);
                Iv(st);
                Md5x8.Compress2(st, wa, wb);
                for (int j = 0; j < 16; j++) wa[j] = wb[j] = Vector256.Create(k._block2[j]);
                Md5x8.Compress2(st, wa, wb);

                if (k._r >= 3)
                {
                    // 50 x MD5(first keyLen bytes)
                    for (int it = 0; it < 50; it++)
                    {
                        for (int j = 0; j < 16; j++) wa[j] = wb[j] = Vector256<uint>.Zero;
                        if (kl == 16)
                        {
                            wa[0] = st[0]; wa[1] = st[1]; wa[2] = st[2]; wa[3] = st[3];
                            wb[0] = st[4]; wb[1] = st[5]; wb[2] = st[6]; wb[3] = st[7];
                            wa[4] = wb[4] = Vector256.Create(0x80u);
                        }
                        else
                        {
                            // Generic key length: whole words, then the partial word with 0x80 appended.
                            var mask = Vector256.Create(kl % 4 == 0 ? 0u : (1u << (8 * (kl % 4))) - 1);
                            for (int q = 0; q < kl / 4; q++) { wa[q] = st[q]; wb[q] = st[4 + q]; }
                            int pq = kl / 4;
                            var pad = Vector256.Create(0x80u << (8 * (kl % 4)));
                            wa[pq] = (kl % 4 == 0 ? Vector256<uint>.Zero : st[pq] & mask) | pad;
                            wb[pq] = (kl % 4 == 0 ? Vector256<uint>.Zero : st[4 + pq] & mask) | pad;
                        }
                        wa[14] = wb[14] = Vector256.Create((uint)(kl * 8));
                        Iv(st);
                        Md5x8.Compress2(st, wa, wb);
                    }
                }

                // Per-lane RC4 keys.
                for (int q = 0; q < 4; q++) { st[q].Store(tmp + 8 * q); st[4 + q].Store(tmp + 32 + 8 * q); }
                for (int l = 0; l < 16; l++)
                {
                    uint* kw = (uint*)(keys + 16 * l);
                    int g = l < 8 ? 0 : 32, ll = l & 7;
                    kw[0] = tmp[g + ll]; kw[1] = tmp[g + 8 + ll]; kw[2] = tmp[g + 16 + ll]; kw[3] = tmp[g + 24 + ll];
                }

                uint mask16 = 0;
                if (k._r == 2)
                {
                    // U == RC4(key, PAD): first 4 bytes.
                    for (int g4 = 0; g4 < 4; g4++)
                    {
                        byte* s = states + 1024 * g4;
                        byte* kk = keys + 64 * g4;
                        Rc4.Ksa5Fast4(s, s + 256, s + 512, s + 768, kk, kk + 16, kk + 32, kk + 48);
                        Rc4.CryptFast4(s, s + 256, s + 512, s + 768, zero, ks + 16 * g4, 4);
                    }
                    uint pad0 = BinaryPrimitives.ReadUInt32LittleEndian(Pad);
                    for (int l = 0; l < 16; l++)
                        if ((Unsafe.ReadUnaligned<uint>(ks + 4 * l) ^ pad0) == k._u0) mask16 |= 1u << l;
                }
                else
                {
                    // y = MD5(PAD || ID); 20 passes y = RC4(key ^ i, y), 4 bytes only.
                    for (int l = 0; l < 16; l++) y[l] = k._x0;
                    for (int pass = 0; pass < 20; pass++)
                    {
                        uint x = (uint)pass * 0x01010101u;
                        for (int l = 0; l < 16; l++)
                        {
                            uint* src = (uint*)(keys + 16 * l), dst = (uint*)(xkeys + 16 * l);
                            dst[0] = src[0] ^ x; dst[1] = src[1] ^ x; dst[2] = src[2] ^ x; dst[3] = src[3] ^ x;
                        }
                        for (int g4 = 0; g4 < 4; g4++)
                        {
                            byte* s = states + 1024 * g4;
                            byte* kk = xkeys + 64 * g4;
                            if (kl == 16) Rc4.Ksa16Fast4(s, s + 256, s + 512, s + 768, kk, kk + 16, kk + 32, kk + 48);
                            else if (kl == 5) Rc4.Ksa5Fast4(s, s + 256, s + 512, s + 768, kk, kk + 16, kk + 32, kk + 48);
                            else for (int l = 0; l < 4; l++) Rc4.Ksa(s + 256 * l, kk + 16 * l, kl);
                            Rc4.CryptFast4(s, s + 256, s + 512, s + 768, zero, ks + 16 * g4, 4);
                        }
                        for (int l = 0; l < 16; l++) y[l] ^= Unsafe.ReadUnaligned<uint>(ks + 4 * l);
                    }
                    for (int l = 0; l < 16; l++) if (y[l] == k._u0) mask16 |= 1u << l;
                }

                while (mask16 != 0)
                {
                    int l = System.Numerics.BitOperations.TrailingZeroCount(mask16);
                    mask16 &= mask16 - 1;
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
    }
}
