using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>
/// Traditional PKWARE encryption (ZipCrypto), hashcat modes 17200 (deflate) and 17210 (stored).
/// The fast path decrypts the 12-byte encryption header and compares its check byte; survivors
/// (1 in 256) are confirmed by decrypting the whole entry and checking its CRC-32.
/// </summary>
public sealed class ZipCryptoKernel : NativeKernel
{
    internal static readonly uint[] Crc = BuildCrc();

    private readonly byte[] _header = new byte[12];
    private readonly Vector256<uint>[] _hdrVec;
    private readonly byte[] _data;          // full encrypted data, header included
    private readonly int _method;           // 0 stored, 8 deflate
    private readonly uint _crc;
    private readonly long _uncompressed;
    private readonly byte _check1, _check2; // expected last header byte (CRC- and time-based variants)
    private readonly bool _twoBytes;
    private readonly byte _check1Low;

    public override string Name => "ZipCrypto";
    public override double SpeedHint => 20_000_000;

    private ZipCryptoKernel(byte[] data, int method, uint crc, long uncompressed, int checkBytes, int checksum, int timeChecksum)
    {
        _data = data;
        _method = method;
        _crc = crc;
        _uncompressed = uncompressed;
        data.AsSpan(0, 12).CopyTo(_header);
        _hdrVec = new Vector256<uint>[11];
        for (int j = 0; j < 11; j++) _hdrVec[j] = Vector256.Create((uint)_header[j]);
        _check1 = (byte)(checksum >> 8);
        _check1Low = (byte)checksum;
        _check2 = (byte)(timeChecksum >> 8);
        _twoBytes = checkBytes == 2;
    }

    /// <summary>Parses a hashcat $pkzip2$ line (first file only, full data required).</summary>
    public static ZipCryptoKernel? TryParse(string line)
    {
        line = line.Trim();
        if (!line.StartsWith("$pkzip2$", StringComparison.Ordinal) || !line.EndsWith("*$/pkzip2$", StringComparison.Ordinal)) return null;
        var f = line["$pkzip2$".Length..^"*$/pkzip2$".Length].Split('*');
        try
        {
            int i = 0;
            int count = int.Parse(f[i++]);
            int checkBytes = int.Parse(f[i++]);
            if (count < 1) return null;
            int dataType = int.Parse(f[i++]);
            i++; // magic type
            if (dataType != 2) return null;     // only full-data hashes can be confirmed by CRC
            i++; // compressed length
            long uncompressed = Convert.ToInt64(f[i++], 16);
            uint crc = Convert.ToUInt32(f[i++], 16);
            i += 2; // offsets
            int method = int.Parse(f[i++]);
            int dataLen = Convert.ToInt32(f[i++], 16);
            int checksum = Convert.ToInt32(f[i++], 16);
            int timeChecksum = Convert.ToInt32(f[i++], 16);
            var data = Convert.FromHexString(f[i]);
            if (data.Length != dataLen || data.Length < 12 || method is not (0 or 8)) return null;
            return new ZipCryptoKernel(data, method, crc, uncompressed, checkBytes, checksum, timeChecksum);
        }
        catch (Exception ex) when (ex is FormatException or IndexOutOfRangeException or OverflowException) { return null; }
    }

    public override KernelWorker CreateWorker() => new Worker(this);

    public override bool Verify(ReadOnlySpan<byte> password)
    {
        uint k0 = 0x12345678, k1 = 0x23456789, k2 = 0x34567890;
        foreach (var b in password) Update(ref k0, ref k1, ref k2, b);
        byte prev = 0, lastHdr = 0;
        for (int i = 0; i < 12; i++)
        {
            uint t = (k2 | 2) & 0xffff;
            byte p = (byte)(_data[i] ^ (byte)((t * (t ^ 1)) >> 8));
            if (i == 10) prev = p;
            lastHdr = p;
            Update(ref k0, ref k1, ref k2, p);
        }
        if (!HeaderOk(lastHdr, prev)) return false;

        if (_method == 0)
        {
            // Stored: decrypt and CRC in one pass, no allocation.
            uint c = 0xffffffff;
            for (int i = 12; i < _data.Length; i++)
            {
                uint t = (k2 | 2) & 0xffff;
                byte p = (byte)(_data[i] ^ (byte)((t * (t ^ 1)) >> 8));
                c = (c >> 8) ^ Crc[(byte)(c ^ p)];
                Update(ref k0, ref k1, ref k2, p);
            }
            return ~c == _crc && (_uncompressed <= 0 || _uncompressed == _data.Length - 12);
        }

        var pool = System.Buffers.ArrayPool<byte>.Shared;
        var body = pool.Rent(_data.Length - 12);
        try
        {
            int len = _data.Length - 12;
            for (int i = 0; i < len; i++)
            {
                uint t = (k2 | 2) & 0xffff;
                byte p = (byte)(_data[12 + i] ^ (byte)((t * (t ^ 1)) >> 8));
                body[i] = p;
                Update(ref k0, ref k1, ref k2, p);
                if (i == 0 && ((p >> 1) & 3) == 3) return false;   // reserved deflate block type
            }
            using var ms = new MemoryStream(body, 0, len, writable: false);
            using var ds = new DeflateStream(ms, CompressionMode.Decompress);
            uint c = 0xffffffff;
            long total = 0;
            Span<byte> buf = stackalloc byte[4096];
            int r;
            while ((r = ds.Read(buf)) > 0)
            {
                foreach (var b in buf[..r]) c = (c >> 8) ^ Crc[(byte)(c ^ b)];
                total += r;
                if (_uncompressed > 0 && total > _uncompressed) return false;
            }
            return ~c == _crc && (_uncompressed <= 0 || total == _uncompressed);
        }
        catch (InvalidDataException) { return false; }
        finally { pool.Return(body); }
    }

    private bool HeaderOk(byte last, byte prev) =>
        _twoBytes ? last == _check1 && prev == _check1Low : last == _check1 || last == _check2;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Update(ref uint k0, ref uint k1, ref uint k2, byte c)
    {
        k0 = (k0 >> 8) ^ Crc[(byte)(k0 ^ c)];
        k1 = (k1 + (k0 & 0xff)) * 134775813 + 1;
        k2 = (k2 >> 8) ^ Crc[(byte)(k2 ^ (k1 >> 24))];
    }

    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint c = 0xffffffff;
        foreach (var b in data) c = (c >> 8) ^ Crc[(byte)(c ^ b)];
        return ~c;
    }

    private static uint[] BuildCrc()
    {
        var t = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
            t[n] = c;
        }
        return t;
    }

    private sealed class Worker(ZipCryptoKernel k) : KernelWorker
    {
        private readonly byte[] _cachedPrefix = new byte[64];
        private int _cachedLen = -1;
        private uint _p0, _p1, _p2;          // keys after the cached prefix minus its last byte
        private uint _q0, _q1, _q2;          // keys after the full cached prefix

        public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
        {
            PrefixKeys(prefix, out uint a0, out uint a1, out uint a2);
            if (Avx2.IsSupported) return SearchAvx2(prefix, last, a0, a1, a2);
            return SearchScalar(prefix, last, a0, a1, a2);
        }

        /// <summary>k1 = (k1 + (k0 &amp; 0xff)) * 134775813 + 1, with the multiply as shifts and adds (2^27+2^19+2^15+2^10+2^2+1).</summary>
        /// <summary>RECOVERKIT_ZIP_MUL=shift selects the shift/add form of the k1 multiply (tuning switch).</summary>
        internal static readonly bool ShiftMultiply = Environment.GetEnvironmentVariable("RECOVERKIT_ZIP_MUL") == "shift";
        private static readonly Vector256<uint> Mult = Vector256.Create(134775813u);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<uint> NextK1(Vector256<uint> k1, Vector256<uint> k0, Vector256<uint> ff, Vector256<uint> one)
        {
            var x = k1 + (k0 & ff);
            if (!ShiftMultiply) return Avx2.MultiplyLow(x, Mult) + one;
            var s1 = Avx2.ShiftLeftLogical(x, 27) + Avx2.ShiftLeftLogical(x, 19);
            var s2 = Avx2.ShiftLeftLogical(x, 15) + Avx2.ShiftLeftLogical(x, 10);
            var s3 = Avx2.ShiftLeftLogical(x, 2) + x;
            return s1 + s2 + (s3 + one);
        }

        /// <summary>Keystream byte ((t * (t ^ 1)) &gt;&gt; 8) &amp; 0xff with t = k2 | 2; only the low 16 bits of the product matter.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<uint> Keystream(Vector256<uint> k2, Vector256<uint> two, Vector256<uint> one, Vector256<uint> ff)
        {
            var t = k2 | two;
            var prod = Avx2.MultiplyLow(t.AsUInt16(), (t ^ one).AsUInt16()).AsUInt32();
            return Avx2.ShiftRightLogical(prod, 8) & ff;
        }

        /// <summary>
        /// Pinned lookup tables for a byte split 3+3+2 bits (the CRC byte table is linear over GF(2)):
        /// T[b] = A[b &amp; 7] ^ B[(b &gt;&gt; 3) &amp; 7] ^ C[(b &gt;&gt; 6) &amp; 3]. vpermd only reads the low 3 index bits,
        /// and C repeats its 4 entries, so no masking or blending is needed.
        /// </summary>
        private static readonly uint[] SplitTables = BuildSplitTables();
        private static uint[] BuildSplitTables()
        {
            var t = new uint[24];
            for (int i = 0; i < 8; i++) { t[i] = Crc[i]; t[8 + i] = Crc[i << 3]; t[16 + i] = Crc[(i & 3) << 6]; }
            return t;
        }

        /// <summary>CRC table lookup of each lane's low byte (upper bits ignored).</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe Vector256<uint> L(uint* t, Vector256<uint> idx) =>
            Avx2.PermuteVar8x32(Avx.LoadVector256(t), idx)
            ^ Avx2.PermuteVar8x32(Avx.LoadVector256(t + 8), Avx2.ShiftRightLogical(idx, 3))
            ^ Avx2.PermuteVar8x32(Avx.LoadVector256(t + 16), Avx2.ShiftRightLogical(idx, 6));

        /// <summary>Interleave depth (vectors of 8 candidates); RECOVERKIT_ZIP_VECTORS=2|3|4 overrides for tuning.</summary>
        internal static readonly int Vectors = int.TryParse(Environment.GetEnvironmentVariable("RECOVERKIT_ZIP_VECTORS"), out var v) && v is >= 2 and <= 4 ? v : 3;

        private unsafe int SearchAvx2(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last, uint p0, uint p1, uint p2)
        {
            fixed (uint* tbl = SplitTables)
                return Vectors switch
                {
                    2 => SearchAvx2x2(prefix, last, p0, p1, p2, tbl),
                    3 => SearchAvx2x3(prefix, last, p0, p1, p2, tbl),
                    _ => SearchAvx2x4(prefix, last, p0, p1, p2, tbl),
                };
        }

        /// <summary>16 candidates per iteration in 2 interleaved AVX2 vectors (generated).</summary>
        private unsafe int SearchAvx2x2(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last, uint p0, uint p1, uint p2, uint* tbl)
        {
            int n = last.Length;
            var one = Vector256.Create(1u);
            var two = Vector256.Create(2u);
            var ff = Vector256.Create(0xffu);
            var chk1 = Vector256.Create((uint)k._check1);
            var chk2 = Vector256.Create((uint)(k._twoBytes ? k._check1 : k._check2));
            var h11 = Vector256.Create((uint)k._header[11]);
            uint* lanes = stackalloc uint[16];
            var hdr = k._hdrVec;
            for (int i = 0; i < n; i += 16)
            {
                for (int l = 0; l < 16; l++) lanes[l] = last[Math.Min(i + l, n - 1)];
                var ac = Avx.LoadVector256(lanes + 0);
                Vector256<uint> a0 = Vector256.Create(p0), a1 = Vector256.Create(p1), a2 = Vector256.Create(p2);
                var bc = Avx.LoadVector256(lanes + 8);
                Vector256<uint> b0 = Vector256.Create(p0), b1 = Vector256.Create(p1), b2 = Vector256.Create(p2);
                a0 = Avx2.ShiftRightLogical(a0, 8) ^ L(tbl, a0 ^ ac);
                b0 = Avx2.ShiftRightLogical(b0, 8) ^ L(tbl, b0 ^ bc);
                a1 = NextK1(a1, a0, ff, one);
                b1 = NextK1(b1, b0, ff, one);
                a2 = Avx2.ShiftRightLogical(a2, 8) ^ L(tbl, a2 ^ Avx2.ShiftRightLogical(a1, 24));
                b2 = Avx2.ShiftRightLogical(b2, 8) ^ L(tbl, b2 ^ Avx2.ShiftRightLogical(b1, 24));
                for (int j = 0; j < 11; j++)
                {
                    var h = hdr[j];
                    var ap = Keystream(a2, two, one, ff) ^ h;
                    var bp = Keystream(b2, two, one, ff) ^ h;
                    a0 = Avx2.ShiftRightLogical(a0, 8) ^ L(tbl, a0 ^ ap);
                    b0 = Avx2.ShiftRightLogical(b0, 8) ^ L(tbl, b0 ^ bp);
                    a1 = NextK1(a1, a0, ff, one);
                    b1 = NextK1(b1, b0, ff, one);
                    a2 = Avx2.ShiftRightLogical(a2, 8) ^ L(tbl, a2 ^ Avx2.ShiftRightLogical(a1, 24));
                    b2 = Avx2.ShiftRightLogical(b2, 8) ^ L(tbl, b2 ^ Avx2.ShiftRightLogical(b1, 24));
                }
                ulong m = 0;
                var ax = Keystream(a2, two, one, ff) ^ h11;
                m |= (ulong)(uint)Avx.MoveMask((Avx2.CompareEqual(ax, chk1) | Avx2.CompareEqual(ax, chk2)).AsSingle()) << 0;
                var bx = Keystream(b2, two, one, ff) ^ h11;
                m |= (ulong)(uint)Avx.MoveMask((Avx2.CompareEqual(bx, chk1) | Avx2.CompareEqual(bx, chk2)).AsSingle()) << 8;
                while (m != 0)
                {
                    int l = System.Numerics.BitOperations.TrailingZeroCount(m);
                    m &= m - 1;
                    if (i + l < n && Confirm(prefix, last[i + l])) return i + l;
                }
            }
            return -1;
        }

        /// <summary>24 candidates per iteration in 3 interleaved AVX2 vectors (generated).</summary>
        private unsafe int SearchAvx2x3(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last, uint p0, uint p1, uint p2, uint* tbl)
        {
            int n = last.Length;
            var one = Vector256.Create(1u);
            var two = Vector256.Create(2u);
            var ff = Vector256.Create(0xffu);
            var chk1 = Vector256.Create((uint)k._check1);
            var chk2 = Vector256.Create((uint)(k._twoBytes ? k._check1 : k._check2));
            var h11 = Vector256.Create((uint)k._header[11]);
            uint* lanes = stackalloc uint[24];
            var hdr = k._hdrVec;
            for (int i = 0; i < n; i += 24)
            {
                for (int l = 0; l < 24; l++) lanes[l] = last[Math.Min(i + l, n - 1)];
                var ac = Avx.LoadVector256(lanes + 0);
                Vector256<uint> a0 = Vector256.Create(p0), a1 = Vector256.Create(p1), a2 = Vector256.Create(p2);
                var bc = Avx.LoadVector256(lanes + 8);
                Vector256<uint> b0 = Vector256.Create(p0), b1 = Vector256.Create(p1), b2 = Vector256.Create(p2);
                var cc = Avx.LoadVector256(lanes + 16);
                Vector256<uint> c0 = Vector256.Create(p0), c1 = Vector256.Create(p1), c2 = Vector256.Create(p2);
                a0 = Avx2.ShiftRightLogical(a0, 8) ^ L(tbl, a0 ^ ac);
                b0 = Avx2.ShiftRightLogical(b0, 8) ^ L(tbl, b0 ^ bc);
                c0 = Avx2.ShiftRightLogical(c0, 8) ^ L(tbl, c0 ^ cc);
                a1 = NextK1(a1, a0, ff, one);
                b1 = NextK1(b1, b0, ff, one);
                c1 = NextK1(c1, c0, ff, one);
                a2 = Avx2.ShiftRightLogical(a2, 8) ^ L(tbl, a2 ^ Avx2.ShiftRightLogical(a1, 24));
                b2 = Avx2.ShiftRightLogical(b2, 8) ^ L(tbl, b2 ^ Avx2.ShiftRightLogical(b1, 24));
                c2 = Avx2.ShiftRightLogical(c2, 8) ^ L(tbl, c2 ^ Avx2.ShiftRightLogical(c1, 24));
                for (int j = 0; j < 11; j++)
                {
                    var h = hdr[j];
                    var ap = Keystream(a2, two, one, ff) ^ h;
                    var bp = Keystream(b2, two, one, ff) ^ h;
                    var cp = Keystream(c2, two, one, ff) ^ h;
                    a0 = Avx2.ShiftRightLogical(a0, 8) ^ L(tbl, a0 ^ ap);
                    b0 = Avx2.ShiftRightLogical(b0, 8) ^ L(tbl, b0 ^ bp);
                    c0 = Avx2.ShiftRightLogical(c0, 8) ^ L(tbl, c0 ^ cp);
                    a1 = NextK1(a1, a0, ff, one);
                    b1 = NextK1(b1, b0, ff, one);
                    c1 = NextK1(c1, c0, ff, one);
                    a2 = Avx2.ShiftRightLogical(a2, 8) ^ L(tbl, a2 ^ Avx2.ShiftRightLogical(a1, 24));
                    b2 = Avx2.ShiftRightLogical(b2, 8) ^ L(tbl, b2 ^ Avx2.ShiftRightLogical(b1, 24));
                    c2 = Avx2.ShiftRightLogical(c2, 8) ^ L(tbl, c2 ^ Avx2.ShiftRightLogical(c1, 24));
                }
                ulong m = 0;
                var ax = Keystream(a2, two, one, ff) ^ h11;
                m |= (ulong)(uint)Avx.MoveMask((Avx2.CompareEqual(ax, chk1) | Avx2.CompareEqual(ax, chk2)).AsSingle()) << 0;
                var bx = Keystream(b2, two, one, ff) ^ h11;
                m |= (ulong)(uint)Avx.MoveMask((Avx2.CompareEqual(bx, chk1) | Avx2.CompareEqual(bx, chk2)).AsSingle()) << 8;
                var cx = Keystream(c2, two, one, ff) ^ h11;
                m |= (ulong)(uint)Avx.MoveMask((Avx2.CompareEqual(cx, chk1) | Avx2.CompareEqual(cx, chk2)).AsSingle()) << 16;
                while (m != 0)
                {
                    int l = System.Numerics.BitOperations.TrailingZeroCount(m);
                    m &= m - 1;
                    if (i + l < n && Confirm(prefix, last[i + l])) return i + l;
                }
            }
            return -1;
        }

        /// <summary>32 candidates per iteration in 4 interleaved AVX2 vectors (generated).</summary>
        private unsafe int SearchAvx2x4(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last, uint p0, uint p1, uint p2, uint* tbl)
        {
            int n = last.Length;
            var one = Vector256.Create(1u);
            var two = Vector256.Create(2u);
            var ff = Vector256.Create(0xffu);
            var chk1 = Vector256.Create((uint)k._check1);
            var chk2 = Vector256.Create((uint)(k._twoBytes ? k._check1 : k._check2));
            var h11 = Vector256.Create((uint)k._header[11]);
            uint* lanes = stackalloc uint[32];
            var hdr = k._hdrVec;
            for (int i = 0; i < n; i += 32)
            {
                for (int l = 0; l < 32; l++) lanes[l] = last[Math.Min(i + l, n - 1)];
                var ac = Avx.LoadVector256(lanes + 0);
                Vector256<uint> a0 = Vector256.Create(p0), a1 = Vector256.Create(p1), a2 = Vector256.Create(p2);
                var bc = Avx.LoadVector256(lanes + 8);
                Vector256<uint> b0 = Vector256.Create(p0), b1 = Vector256.Create(p1), b2 = Vector256.Create(p2);
                var cc = Avx.LoadVector256(lanes + 16);
                Vector256<uint> c0 = Vector256.Create(p0), c1 = Vector256.Create(p1), c2 = Vector256.Create(p2);
                var dc = Avx.LoadVector256(lanes + 24);
                Vector256<uint> d0 = Vector256.Create(p0), d1 = Vector256.Create(p1), d2 = Vector256.Create(p2);
                a0 = Avx2.ShiftRightLogical(a0, 8) ^ L(tbl, a0 ^ ac);
                b0 = Avx2.ShiftRightLogical(b0, 8) ^ L(tbl, b0 ^ bc);
                c0 = Avx2.ShiftRightLogical(c0, 8) ^ L(tbl, c0 ^ cc);
                d0 = Avx2.ShiftRightLogical(d0, 8) ^ L(tbl, d0 ^ dc);
                a1 = NextK1(a1, a0, ff, one);
                b1 = NextK1(b1, b0, ff, one);
                c1 = NextK1(c1, c0, ff, one);
                d1 = NextK1(d1, d0, ff, one);
                a2 = Avx2.ShiftRightLogical(a2, 8) ^ L(tbl, a2 ^ Avx2.ShiftRightLogical(a1, 24));
                b2 = Avx2.ShiftRightLogical(b2, 8) ^ L(tbl, b2 ^ Avx2.ShiftRightLogical(b1, 24));
                c2 = Avx2.ShiftRightLogical(c2, 8) ^ L(tbl, c2 ^ Avx2.ShiftRightLogical(c1, 24));
                d2 = Avx2.ShiftRightLogical(d2, 8) ^ L(tbl, d2 ^ Avx2.ShiftRightLogical(d1, 24));
                for (int j = 0; j < 11; j++)
                {
                    var h = hdr[j];
                    var ap = Keystream(a2, two, one, ff) ^ h;
                    var bp = Keystream(b2, two, one, ff) ^ h;
                    var cp = Keystream(c2, two, one, ff) ^ h;
                    var dp = Keystream(d2, two, one, ff) ^ h;
                    a0 = Avx2.ShiftRightLogical(a0, 8) ^ L(tbl, a0 ^ ap);
                    b0 = Avx2.ShiftRightLogical(b0, 8) ^ L(tbl, b0 ^ bp);
                    c0 = Avx2.ShiftRightLogical(c0, 8) ^ L(tbl, c0 ^ cp);
                    d0 = Avx2.ShiftRightLogical(d0, 8) ^ L(tbl, d0 ^ dp);
                    a1 = NextK1(a1, a0, ff, one);
                    b1 = NextK1(b1, b0, ff, one);
                    c1 = NextK1(c1, c0, ff, one);
                    d1 = NextK1(d1, d0, ff, one);
                    a2 = Avx2.ShiftRightLogical(a2, 8) ^ L(tbl, a2 ^ Avx2.ShiftRightLogical(a1, 24));
                    b2 = Avx2.ShiftRightLogical(b2, 8) ^ L(tbl, b2 ^ Avx2.ShiftRightLogical(b1, 24));
                    c2 = Avx2.ShiftRightLogical(c2, 8) ^ L(tbl, c2 ^ Avx2.ShiftRightLogical(c1, 24));
                    d2 = Avx2.ShiftRightLogical(d2, 8) ^ L(tbl, d2 ^ Avx2.ShiftRightLogical(d1, 24));
                }
                ulong m = 0;
                var ax = Keystream(a2, two, one, ff) ^ h11;
                m |= (ulong)(uint)Avx.MoveMask((Avx2.CompareEqual(ax, chk1) | Avx2.CompareEqual(ax, chk2)).AsSingle()) << 0;
                var bx = Keystream(b2, two, one, ff) ^ h11;
                m |= (ulong)(uint)Avx.MoveMask((Avx2.CompareEqual(bx, chk1) | Avx2.CompareEqual(bx, chk2)).AsSingle()) << 8;
                var cx = Keystream(c2, two, one, ff) ^ h11;
                m |= (ulong)(uint)Avx.MoveMask((Avx2.CompareEqual(cx, chk1) | Avx2.CompareEqual(cx, chk2)).AsSingle()) << 16;
                var dx = Keystream(d2, two, one, ff) ^ h11;
                m |= (ulong)(uint)Avx.MoveMask((Avx2.CompareEqual(dx, chk1) | Avx2.CompareEqual(dx, chk2)).AsSingle()) << 24;
                while (m != 0)
                {
                    int l = System.Numerics.BitOperations.TrailingZeroCount(m);
                    m &= m - 1;
                    if (i + l < n && Confirm(prefix, last[i + l])) return i + l;
                }
            }
            return -1;
        }

        private int SearchScalar(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last, uint a0, uint a1, uint a2)
        {
            ref uint crc = ref MemoryMarshal.GetArrayDataReference(Crc);
            ref byte h = ref MemoryMarshal.GetArrayDataReference(k._header);
            byte c1 = k._check1, c2 = k._twoBytes ? k._check1 : k._check2;

            int n = last.Length, i = 0;
            // Four independent candidates per iteration so their dependency chains overlap.
            for (; i + 4 <= n; i += 4)
            {
                uint x0 = a0, x1 = a1, x2 = a2, y0 = a0, y1 = a1, y2 = a2, z0 = a0, z1 = a1, z2 = a2, w0 = a0, w1 = a1, w2 = a2;
                Step(ref crc, ref x0, ref x1, ref x2, last[i]);
                Step(ref crc, ref y0, ref y1, ref y2, last[i + 1]);
                Step(ref crc, ref z0, ref z1, ref z2, last[i + 2]);
                Step(ref crc, ref w0, ref w1, ref w2, last[i + 3]);
                byte px = 0, py = 0, pz = 0, pw = 0;
                for (int b = 0; b < 12; b++)
                {
                    byte e = Unsafe.Add(ref h, b);
                    uint tx = (x2 | 2) & 0xffff, ty = (y2 | 2) & 0xffff, tz = (z2 | 2) & 0xffff, tw = (w2 | 2) & 0xffff;
                    px = (byte)(e ^ (byte)((tx * (tx ^ 1)) >> 8));
                    py = (byte)(e ^ (byte)((ty * (ty ^ 1)) >> 8));
                    pz = (byte)(e ^ (byte)((tz * (tz ^ 1)) >> 8));
                    pw = (byte)(e ^ (byte)((tw * (tw ^ 1)) >> 8));
                    if (b == 11) break;
                    Step(ref crc, ref x0, ref x1, ref x2, px);
                    Step(ref crc, ref y0, ref y1, ref y2, py);
                    Step(ref crc, ref z0, ref z1, ref z2, pz);
                    Step(ref crc, ref w0, ref w1, ref w2, pw);
                }
                if (px == c1 || px == c2) { if (Confirm(prefix, last[i])) return i; }
                if (py == c1 || py == c2) { if (Confirm(prefix, last[i + 1])) return i + 1; }
                if (pz == c1 || pz == c2) { if (Confirm(prefix, last[i + 2])) return i + 2; }
                if (pw == c1 || pw == c2) { if (Confirm(prefix, last[i + 3])) return i + 3; }
            }
            for (; i < n; i++)
            {
                uint x0 = a0, x1 = a1, x2 = a2;
                Step(ref crc, ref x0, ref x1, ref x2, last[i]);
                byte px = 0;
                for (int b = 0; b < 12; b++)
                {
                    uint tx = (x2 | 2) & 0xffff;
                    px = (byte)(Unsafe.Add(ref h, b) ^ (byte)((tx * (tx ^ 1)) >> 8));
                    if (b == 11) break;
                    Step(ref crc, ref x0, ref x1, ref x2, px);
                }
                if ((px == c1 || px == c2) && Confirm(prefix, last[i])) return i;
            }
            return -1;
        }

        private bool Confirm(ReadOnlySpan<byte> prefix, byte lastByte)
        {
            Span<byte> pw = stackalloc byte[prefix.Length + 1];
            prefix.CopyTo(pw);
            pw[^1] = lastByte;
            return k.Verify(pw);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Step(ref uint crc, ref uint k0, ref uint k1, ref uint k2, byte c)
        {
            k0 = (k0 >> 8) ^ Unsafe.Add(ref crc, (int)(byte)(k0 ^ c));
            k1 = (k1 + (k0 & 0xff)) * 134775813 + 1;
            k2 = (k2 >> 8) ^ Unsafe.Add(ref crc, (int)(byte)(k2 ^ (k1 >> 24)));
        }

        /// <summary>Keys after the prefix, reusing the previous prefix when only its last byte changed.</summary>
        private void PrefixKeys(ReadOnlySpan<byte> prefix, out uint k0, out uint k1, out uint k2)
        {
            int n = prefix.Length;
            if (n == 0) { k0 = 0x12345678; k1 = 0x23456789; k2 = 0x34567890; return; }
            if (n == _cachedLen && prefix[..^1].SequenceEqual(_cachedPrefix.AsSpan(0, n - 1)))
            {
                if (prefix[^1] != _cachedPrefix[n - 1])
                {
                    _q0 = _p0; _q1 = _p1; _q2 = _p2;
                    Update(ref _q0, ref _q1, ref _q2, prefix[^1]);
                    _cachedPrefix[n - 1] = prefix[^1];
                }
            }
            else
            {
                _p0 = 0x12345678; _p1 = 0x23456789; _p2 = 0x34567890;
                for (int i = 0; i < n - 1; i++) Update(ref _p0, ref _p1, ref _p2, prefix[i]);
                _q0 = _p0; _q1 = _p1; _q2 = _p2;
                Update(ref _q0, ref _q1, ref _q2, prefix[^1]);
                prefix.CopyTo(_cachedPrefix);
                _cachedLen = n;
            }
            k0 = _q0; k1 = _q1; k2 = _q2;
        }
    }
}
