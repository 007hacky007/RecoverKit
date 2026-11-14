using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>
/// Traditional PKWARE encryption (ZipCrypto), hashcat modes 17200 (deflate) and 17210 (stored).
/// The fast path decrypts the 12-byte encryption header and compares its check byte; survivors
/// (1 in 256) are confirmed by decrypting the whole entry and checking its CRC-32.
/// A large entry (<see cref="ZipPartialTarget"/>) is confirmed from the archive file, which costs as
/// much as thousands of candidates, so a survivor first has to pass the other entries' header checks
/// and, when deflated, inflate the prefix kept in memory (random data fails within its first bytes).
/// </summary>
public sealed class ZipCryptoKernel : NativeKernel
{
    internal static readonly uint[] Crc = BuildCrc();

    private readonly byte[] _header = new byte[12];
    private readonly Vector256<uint>[] _hdrVec;
    private readonly byte[] _data;          // full encrypted data, header included
    private readonly ZipPartialTarget? _partial;
    private readonly ZipHeaderCheck[] _siblings;
    private readonly int _method;           // 0 stored, 8 deflate
    private readonly uint _crc;
    private readonly long _uncompressed;
    private readonly byte _check1, _check2; // expected last header byte (CRC- and time-based variants)
    private readonly bool _twoBytes;
    private readonly byte _check1Low;

    public override string Name => "ZipCrypto";
    public override double SpeedHint => 20_000_000;

    private ZipCryptoKernel(byte[] data, int method, uint crc, long uncompressed, int checkBytes, int checksum, int timeChecksum,
        ZipPartialTarget? partial = null)
    {
        _data = data;
        _partial = partial;
        _siblings = partial?.Siblings.ToArray() ?? [];
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

    /// <summary>Parses the first file of a $pkzip2$ line; partial data requires the archive entry.</summary>
    public static ZipCryptoKernel? TryParse(string line, ZipPartialTarget? partial = null)
    {
        line = line.Trim();
        if (!line.StartsWith("$pkzip2$", StringComparison.Ordinal) || !line.EndsWith("*$/pkzip2$", StringComparison.Ordinal)) return null;
        var f = line["$pkzip2$".Length..^"*$/pkzip2$".Length].Split('*');
        try
        {
            int i = 0;
            int count = int.Parse(f[i++]);
            int checkBytes = int.Parse(f[i++]);
            if (count < 1 || checkBytes is not (1 or 2)) return null;
            int dataType = int.Parse(f[i++]);
            i++; // magic type
            long uncompressed;
            uint crc;
            if (dataType == 2)
            {
                i++; // compressed length
                uncompressed = Convert.ToInt64(f[i++], 16);
                crc = Convert.ToUInt32(f[i++], 16);
                i += 2; // offsets
            }
            else if (dataType == 1 && count == 1 && partial is not null)
            {
                uncompressed = partial.UncompressedLength;
                crc = partial.Crc;
            }
            else return null;
            int method = int.Parse(f[i++]);
            int dataLen = Convert.ToInt32(f[i++], 16);
            int checksum = Convert.ToInt32(f[i++], 16);
            int timeChecksum = Convert.ToInt32(f[i++], 16);
            var data = Convert.FromHexString(f[i]);
            if (data.Length != dataLen || data.Length < 12 || method is not (0 or 8)) return null;
            if (dataType == 1)
            {
                if (partial!.Method != method || partial.DataOffset < 0 || partial.CompressedLength < data.Length || uncompressed < 0)
                    return null;
                using var archive = File.OpenRead(partial.ArchivePath);
                if (partial.DataOffset > archive.Length || partial.CompressedLength > archive.Length - partial.DataOffset) return null;
                archive.Position = partial.DataOffset;
                var prefix = new byte[data.Length];
                archive.ReadExactly(prefix);
                if (!data.AsSpan().SequenceEqual(prefix)) return null;
            }
            return new ZipCryptoKernel(data, method, crc, uncompressed, checkBytes, checksum, timeChecksum,
                dataType == 1 ? partial : null);
        }
        catch (Exception ex) when (ex is FormatException or IndexOutOfRangeException or OverflowException
            or IOException or UnauthorizedAccessException or ArgumentException) { return null; }
    }

    public override KernelWorker CreateWorker() => new Worker(this);

    /// <summary>
    /// The AdvSimd path on arm64: ~1.6x the scalar one on an M1 Pro (docs/benchmarks/apple-m1-pro-native.txt).
    /// RECOVERKIT_ZIP_NEON=0 turns it off (tuning switch; tests run both).
    /// </summary>
    internal static bool UseAdvSimd { get; set; } = AdvSimd.Arm64.IsSupported && Environment.GetEnvironmentVariable("RECOVERKIT_ZIP_NEON") != "0";

    public override bool Verify(ReadOnlySpan<byte> password)
    {
        uint k0 = 0x12345678, k1 = 0x23456789, k2 = 0x34567890;
        foreach (var b in password) Update(ref k0, ref k1, ref k2, b);
        uint p0 = k0, p1 = k1, p2 = k2;     // the password's keys, for the sibling headers
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
        if (_partial is { } partial)
        {
            foreach (var s in _siblings)
            {
                byte b = HeaderCheckByte(p0, p1, p2, s.Header);
                if (b != s.CrcCheck && b != s.TimeCheck) return false;
            }
            if (_method == 8 && !PrefixInflates(k0, k1, k2)) return false;
            return VerifyArchive(partial, k0, k1, k2);
        }

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

    /// <summary>
    /// Deflate: whether the prefix kept in memory inflates with these keys, within the entry's size.
    /// Wrong keys give random data, which the inflater rejects within its first bytes (a reserved block
    /// type, a stored block whose length check fails, an over-subscribed code, a distance before the
    /// start), so the decryption is handed over in small pieces and almost never goes far.
    /// </summary>
    private bool PrefixInflates(uint k0, uint k1, uint k2)
    {
        // The first bytes by hand first: an inflater costs about 10 us to set up, a few thousand candidates' worth.
        Span<byte> head = stackalloc byte[DeflateHeadLength];
        int n = Math.Min(head.Length, _data.Length - 12);
        uint h0 = k0, h1 = k1, h2 = k2;
        for (int i = 0; i < n; i++)
        {
            uint t = (h2 | 2) & 0xffff;
            byte p = (byte)(_data[12 + i] ^ (byte)((t * (t ^ 1)) >> 8));
            head[i] = p;
            Update(ref h0, ref h1, ref h2, p);
        }
        if (!DeflateStartIsPlausible(head[..n], _uncompressed)) return false;
        try
        {
            using var decrypted = new DecryptStream(new MemoryStream(_data, 12, _data.Length - 12, writable: false),
                _data.Length - 12, k0, k1, k2) { Piece = 32 };
            using var inflated = new DeflateStream(decrypted, CompressionMode.Decompress);
            Span<byte> buffer = stackalloc byte[4096];
            long total = 0;
            int read;
            while ((read = inflated.Read(buffer)) > 0)
            {
                total += read;
                if (total > _uncompressed) return false;
            }
            return true;   // the prefix is consistent (or ran out): the whole entry decides
        }
        catch (InvalidDataException) { return false; }
    }

    internal const int DeflateHeadLength = 48;

    private static ReadOnlySpan<ushort> LengthBase => [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
    private static ReadOnlySpan<byte> LengthExtra => [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
    private static ReadOnlySpan<ushort> DistanceBase => [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
    private static ReadOnlySpan<byte> DistanceExtra => [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

    /// <summary>
    /// Whether <paramref name="plain"/>, the first bytes of a deflate stream, can be the start of a
    /// valid one with <paramref name="uncompressed"/> bytes of output. Only what an inflater would
    /// reject is rejected: a reserved block type, a stored block whose length check fails or does not
    /// fit the output, a dynamic block whose code-length code is not complete, and in a fixed-Huffman
    /// block an invalid symbol or a distance before the start of the output. Random bytes fail nearly
    /// always; a real stream never does. Runs out of bytes undecided (true).
    /// </summary>
    internal static bool DeflateStartIsPlausible(ReadOnlySpan<byte> plain, long uncompressed)
    {
        var bits = new BitReader(plain);
        if (!bits.Try(3, out uint header)) return true;
        bool final = (header & 1) != 0;
        switch (header >> 1)
        {
            case 3: return false;
            case 0:
            {
                // Stored: LEN and its one's complement after the byte boundary.
                bits.AlignToByte();
                if (!bits.Try(16, out uint len) || !bits.Try(16, out uint nlen)) return true;
                if ((len ^ nlen) != 0xffff) return false;
                return final ? len == uncompressed : len <= uncompressed;
            }
            case 2:
            {
                // Dynamic: HLIT <= 29, HDIST <= 29, and a complete code-length code (zlib rejects
                // over-subscribed and incomplete sets).
                if (!bits.Try(5, out uint hlit) || !bits.Try(5, out uint hdist) || !bits.Try(4, out uint hclen)) return true;
                if (hlit > 29 || hdist > 29) return false;
                int kraft = 0;
                for (int i = 0; i < hclen + 4; i++)
                {
                    if (!bits.Try(3, out uint l)) return true;
                    if (l > 0) kraft += 128 >> (int)l;
                }
                return kraft == 128;
            }
            default:
            {
                // Fixed Huffman: decode symbols until the bytes run out.
                long output = 0;
                while (true)
                {
                    if (!bits.TryCode(7, out uint code)) return true;
                    int symbol;
                    if (code < 24) symbol = 256 + (int)code;
                    else
                    {
                        if (!bits.TryBit(out uint b)) return true;
                        code = (code << 1) | b;
                        if (code is >= 48 and <= 191) symbol = (int)code - 48;
                        else if (code is >= 192 and <= 199) symbol = 280 + (int)code - 192;
                        else
                        {
                            if (!bits.TryBit(out b)) return true;
                            code = (code << 1) | b;
                            symbol = 144 + (int)code - 400;
                        }
                    }
                    if (symbol < 256) { if (++output > uncompressed) return false; continue; }
                    if (symbol == 256) return !final || output == uncompressed;
                    if (symbol > 285) return false;
                    int li = symbol - 257;
                    if (!bits.Try(LengthExtra[li], out uint lextra)) return true;
                    long length = LengthBase[li] + lextra;
                    if (!bits.TryCode(5, out uint dcode)) return true;
                    if (dcode > 29) return false;
                    if (!bits.Try(DistanceExtra[(int)dcode], out uint dextra)) return true;
                    long distance = DistanceBase[(int)dcode] + dextra;
                    if (distance > output) return false;
                    output += length;
                    if (output > uncompressed) return false;
                }
            }
        }
    }

    /// <summary>Deflate's bit order: least significant bit first; Huffman codes most significant bit first.</summary>
    private ref struct BitReader(ReadOnlySpan<byte> data)
    {
        private readonly ReadOnlySpan<byte> _data = data;
        private int _pos;   // in bits

        public bool TryBit(out uint bit)
        {
            if (_pos >> 3 >= _data.Length) { bit = 0; return false; }
            bit = (uint)(_data[_pos >> 3] >> (_pos & 7)) & 1;
            _pos++;
            return true;
        }

        public bool Try(int count, out uint value)
        {
            value = 0;
            for (int i = 0; i < count; i++)
            {
                if (!TryBit(out uint b)) return false;
                value |= b << i;
            }
            return true;
        }

        public bool TryCode(int count, out uint code)
        {
            code = 0;
            for (int i = 0; i < count; i++)
            {
                if (!TryBit(out uint b)) return false;
                code = (code << 1) | b;
            }
            return true;
        }

        public void AlignToByte() => _pos = (_pos + 7) & ~7;
    }

    private bool VerifyArchive(ZipPartialTarget partial, uint k0, uint k1, uint k2)
    {
        try
        {
            using var archive = File.OpenRead(partial.ArchivePath);
            if (partial.DataOffset > archive.Length || partial.CompressedLength > archive.Length - partial.DataOffset) return false;
            archive.Position = partial.DataOffset;
            Span<byte> header = stackalloc byte[12];
            archive.ReadExactly(header);
            if (!header.SequenceEqual(_header)) return false;
            using var decrypted = new DecryptStream(archive, partial.CompressedLength - 12, k0, k1, k2);
            using var inflated = _method == 8 ? new DeflateStream(decrypted, CompressionMode.Decompress, leaveOpen: true) : null;
            Stream content = inflated is not null ? inflated : decrypted;
            uint crc = 0xffffffff;
            long total = 0;
            Span<byte> buffer = stackalloc byte[8192];
            int read;
            while ((read = content.Read(buffer)) > 0)
            {
                if (read > _uncompressed - total) return false;
                foreach (byte b in buffer[..read]) crc = (crc >> 8) ^ Crc[(byte)(crc ^ b)];
                total += read;
            }
            return total == _uncompressed && ~crc == _crc && decrypted.Remaining == 0
                && (_method == 0 || !decrypted.RequestedPastEnd);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException) { return false; }
    }

    private sealed class DecryptStream(Stream archive, long remaining, uint k0, uint k1, uint k2) : Stream
    {
        public long Remaining { get; private set; } = remaining;
        public bool RequestedPastEnd { get; private set; }
        /// <summary>When set, at most this many bytes per read, doubling each time: an inflater that is going to fail gets little work first.</summary>
        public int Piece { get; set; }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            if (buffer.Length == 0) return 0;
            if (Remaining == 0)
            {
                // DeflateStream asks for more input when the final block is missing, then silently returns EOF.
                RequestedPastEnd = true;
                return 0;
            }
            long want = Math.Min(buffer.Length, Remaining);
            if (Piece > 0) { want = Math.Min(want, Piece); Piece = Math.Min(Piece * 2, 8192); }
            int read = archive.Read(buffer[..(int)want]);
            if (read == 0) throw new EndOfStreamException();
            Remaining -= read;
            for (int i = 0; i < read; i++)
            {
                uint t = (k2 | 2) & 0xffff;
                byte p = (byte)(buffer[i] ^ (byte)((t * (t ^ 1)) >> 8));
                buffer[i] = p;
                Update(ref k0, ref k1, ref k2, p);
            }
            return read;
        }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>
    /// The last byte of a 12-byte encryption header decrypted with <paramref name="password"/>: the
    /// entry's check byte (the CRC's high byte, or the DOS time's high byte with a data descriptor).
    /// </summary>
    public static byte HeaderCheckByte(ReadOnlySpan<byte> password, ReadOnlySpan<byte> header)
    {
        uint k0 = 0x12345678, k1 = 0x23456789, k2 = 0x34567890;
        foreach (var b in password) Update(ref k0, ref k1, ref k2, b);
        return HeaderCheckByte(k0, k1, k2, header);
    }

    /// <summary>The same, from the keys the password leaves (<paramref name="k0"/>..<paramref name="k2"/>).</summary>
    private static byte HeaderCheckByte(uint k0, uint k1, uint k2, ReadOnlySpan<byte> header)
    {
        byte p = 0;
        for (int i = 0; i < 12; i++)
        {
            uint t = (k2 | 2) & 0xffff;
            p = (byte)(header[i] ^ (byte)((t * (t ^ 1)) >> 8));
            Update(ref k0, ref k1, ref k2, p);
        }
        return p;
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
            int path = ZipCryptoNative.Path;
            if (path > 0)
            {
                int result = SearchNative(prefix, last, a0, a1, a2, path);
                if (result != -2) return result;
            }
            if (ZipCryptoNative.EffectiveRequestedPath != -2 && Avx2.IsSupported) return SearchAvx2(prefix, last, a0, a1, a2);
            if (ZipCryptoNative.EffectiveRequestedPath != -2 && AdvSimd.Arm64.IsSupported && UseAdvSimd) return SearchAdvSimd(prefix, last, a0, a1, a2);
            return SearchScalar(prefix, last, a0, a1, a2);
        }

        private unsafe int SearchNative(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last, uint a0, uint a1, uint a2, int path)
        {
            Span<int> hits = last.Length <= 256 ? stackalloc int[last.Length] : new int[last.Length];
            int count;
            fixed (byte* header = k._header, chars = last)
            fixed (int* output = hits)
                count = RkNative.ZipSearch(header, k._check1, k._twoBytes ? k._check1 : k._check2,
                    a0, a1, a2, chars, last.Length, output, hits.Length, path);
            if (count < 0 || count > hits.Length) return -2;
            for (int i = 0; i < count; i++)
                if (Confirm(prefix, last[hits[i]])) return hits[i];
            return -1;
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

        /// <summary>CRC byte table split 4+4 bits (it is linear over GF(2)): two 16-entry tables, 64 bytes each, for tbl.</summary>
        private static readonly byte[] NibbleTables = BuildNibbleTables();
        private static byte[] BuildNibbleTables()
        {
            var t = new byte[128];
            for (int i = 0; i < 16; i++)
            {
                BitConverter.TryWriteBytes(t.AsSpan(4 * i), Crc[i]);
                BitConverter.TryWriteBytes(t.AsSpan(64 + 4 * i), Crc[i << 4]);
            }
            return t;
        }

        /// <summary>T[x &amp; 0xff] for each lane: two tbl lookups (low and high nibble) of each lane's low byte, replicated.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> L4(Vector128<uint> x, Vector128<byte> lo0, Vector128<byte> lo1, Vector128<byte> lo2, Vector128<byte> lo3,
            Vector128<byte> hi0, Vector128<byte> hi1, Vector128<byte> hi2, Vector128<byte> hi3)
        {
            var rx = AdvSimd.Arm64.VectorTableLookup(x.AsByte(), Vector128.Create((byte)0, 0, 0, 0, 4, 4, 4, 4, 8, 8, 8, 8, 12, 12, 12, 12));
            var bytes = Vector128.Create(0x03020100u).AsByte();
            var il = (Vector128.ShiftLeft(rx, 2) & Vector128.Create((byte)0x3c)) | bytes;
            var ih = (Vector128.ShiftRightLogical(rx, 2) & Vector128.Create((byte)0x3c)) | bytes;
            return (AdvSimd.Arm64.VectorTableLookup((lo0, lo1, lo2, lo3), il) ^ AdvSimd.Arm64.VectorTableLookup((hi0, hi1, hi2, hi3), ih)).AsUInt32();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<uint> Ks4(Vector128<uint> k2)
        {
            var t = k2 | Vector128.Create(2u);
            return Vector128.ShiftRightLogical(AdvSimd.Multiply(t.AsUInt16(), (t ^ Vector128<uint>.One).AsUInt16()).AsUInt32(), 8) & Vector128.Create(0xffu);
        }

        /// <summary>16 candidates per iteration in 4 interleaved 4-lane vectors; table lookups through tbl.</summary>
        private unsafe int SearchAdvSimd(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last, uint p0, uint p1, uint p2)
        {
            int n = last.Length;
            Vector128<byte> lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3;
            fixed (byte* t = NibbleTables)
            {
                lo0 = Vector128.Load(t); lo1 = Vector128.Load(t + 16); lo2 = Vector128.Load(t + 32); lo3 = Vector128.Load(t + 48);
                hi0 = Vector128.Load(t + 64); hi1 = Vector128.Load(t + 80); hi2 = Vector128.Load(t + 96); hi3 = Vector128.Load(t + 112);
            }
            var one = Vector128.Create(1u);
            var ff = Vector128.Create(0xffu);
            var mult = Vector128.Create(134775813u);
            var chk1 = Vector128.Create((uint)k._check1);
            var chk2 = Vector128.Create((uint)(k._twoBytes ? k._check1 : k._check2));
            var h11 = Vector128.Create((uint)k._header[11]);
            uint* lanes = stackalloc uint[16];
            Vector128<uint>* hdr = stackalloc Vector128<uint>[11];
            for (int j = 0; j < 11; j++) hdr[j] = Vector128.Create((uint)k._header[j]);

            for (int i = 0; i < n; i += 16)
            {
                for (int l = 0; l < 16; l++) lanes[l] = last[Math.Min(i + l, n - 1)];
                Vector128<uint> a0 = Vector128.Create(p0), a1 = Vector128.Create(p1), a2 = Vector128.Create(p2);
                Vector128<uint> b0 = a0, b1 = a1, b2 = a2, c0 = a0, c1 = a1, c2 = a2, d0 = a0, d1 = a1, d2 = a2;
                var ap = Vector128.Load(lanes);
                var bp = Vector128.Load(lanes + 4);
                var cp = Vector128.Load(lanes + 8);
                var dp = Vector128.Load(lanes + 12);
                for (int j = 0; ; j++)
                {
                    a0 = Vector128.ShiftRightLogical(a0, 8) ^ L4(a0 ^ ap, lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3);
                    b0 = Vector128.ShiftRightLogical(b0, 8) ^ L4(b0 ^ bp, lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3);
                    c0 = Vector128.ShiftRightLogical(c0, 8) ^ L4(c0 ^ cp, lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3);
                    d0 = Vector128.ShiftRightLogical(d0, 8) ^ L4(d0 ^ dp, lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3);
                    a1 = (a1 + (a0 & ff)) * mult + one;
                    b1 = (b1 + (b0 & ff)) * mult + one;
                    c1 = (c1 + (c0 & ff)) * mult + one;
                    d1 = (d1 + (d0 & ff)) * mult + one;
                    a2 = Vector128.ShiftRightLogical(a2, 8) ^ L4(a2 ^ Vector128.ShiftRightLogical(a1, 24), lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3);
                    b2 = Vector128.ShiftRightLogical(b2, 8) ^ L4(b2 ^ Vector128.ShiftRightLogical(b1, 24), lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3);
                    c2 = Vector128.ShiftRightLogical(c2, 8) ^ L4(c2 ^ Vector128.ShiftRightLogical(c1, 24), lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3);
                    d2 = Vector128.ShiftRightLogical(d2, 8) ^ L4(d2 ^ Vector128.ShiftRightLogical(d1, 24), lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3);
                    if (j == 11) break;
                    var h = hdr[j];
                    ap = Ks4(a2) ^ h;
                    bp = Ks4(b2) ^ h;
                    cp = Ks4(c2) ^ h;
                    dp = Ks4(d2) ^ h;
                }
                var ax = Ks4(a2) ^ h11;
                var bx = Ks4(b2) ^ h11;
                var cx = Ks4(c2) ^ h11;
                var dx = Ks4(d2) ^ h11;
                uint m = Vector128.ExtractMostSignificantBits(Vector128.Equals(ax, chk1) | Vector128.Equals(ax, chk2))
                       | Vector128.ExtractMostSignificantBits(Vector128.Equals(bx, chk1) | Vector128.Equals(bx, chk2)) << 4
                       | Vector128.ExtractMostSignificantBits(Vector128.Equals(cx, chk1) | Vector128.Equals(cx, chk2)) << 8
                       | Vector128.ExtractMostSignificantBits(Vector128.Equals(dx, chk1) | Vector128.Equals(dx, chk2)) << 12;
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
