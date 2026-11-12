using System.IO.Compression;
using System.Text;

using RecoverKit.Core.Attacks.Stay;

namespace RecoverKit.Tests.Stay;

/// <summary>One entry to place in a generated archive.</summary>
public sealed class GeneratedEntry
{
    public required string Name { get; init; }
    public required byte[] Content { get; init; }   // uncompressed plaintext
    public int Method { get; init; } = 8;           // 0 stored, 8 deflate, other: CompData passed as-is
    public bool DataDescriptor { get; init; }       // flag bit 3: check bytes come from the DOS time
    public bool Classic { get; init; } = true;      // false: store unencrypted (no header, no RNG use)
    public byte[]? ExoticCompData { get; init; }    // raw "compressed" bytes for methods other than 0/8
    public long? ForceCompSize { get; init; }       // lie about the size in both headers (corrupt-entry tests)
    public bool FakeAes { get; init; }              // write a WinZip-AES extra field with fake AES data
}

public sealed class GeneratedEntryInfo
{
    public required string Name { get; init; }
    public required byte[] Content { get; init; }
    public required byte[] CompData { get; init; }
    public required int Method { get; init; }
    public required int CdMethod { get; init; }      // 99 for fake-AES entries, else Method
    public required bool DataDescriptor { get; init; }
    public required uint Crc { get; init; }
    public required ushort Flags { get; init; }
    public required uint DosTime { get; init; }     // 16-bit DOS time field
    public required long CompSize { get; init; }
    public required long LocalOffset { get; init; }
}

/// <summary>
/// A generated encrypted ZIP archive plus everything the attack's tests need to know
/// about it: the true initial cipher keys, the random header bytes, and the stored
/// (encrypted) 12-byte headers. Faithful to Info-ZIP crypt.c crypthead().
/// </summary>
public sealed class GeneratedZip
{
    public required byte[] Archive { get; init; }
    public required IReadOnlyList<GeneratedEntryInfo> Entries { get; init; }
    public required byte[][] R { get; init; }            // r[i][0..9], clear random bytes
    public required byte[][] C1 { get; init; }           // c1[i][0..9], pass-1 ciphertext (pass-2 plaintext)
    public required byte[][] StoredHeaders { get; init; } // stored[i][0..11], encrypted
    public required uint X { get; init; }
    public required uint Y { get; init; }
    public required uint Z { get; init; }
    public required uint Seed { get; init; }
    public required ZipRngVariant Variant { get; init; }
    public required int SessionFileCount { get; init; }

    /// <summary>The full encrypted entry body (12-byte header + compressed data) as it sits in the archive.</summary>
    public byte[] EncryptedBytes(int i)
    {
        var e = Entries[i];
        var name = Encoding.ASCII.GetBytes(e.Name);
        var start = e.LocalOffset + 30 + name.Length;
        return Archive[(int)start .. (int)(start + e.CompSize)];
    }
}

/// <summary>
/// Generates encrypted ZIP archives the way WinZip ≤ 8 / Info-ZIP-on-Windows did:
/// one srand() per process, 10 rand() bytes per file, two-pass encryption of the
/// 12-byte header, data continuing in the pass-2 stream. Also hosts an independent
/// ZipCrypto decrypt oracle used to verify production code.
/// </summary>
public static class ZipStayArchive
{
    private static readonly uint[] T = BuildCrcTable();

    public static GeneratedZip Generate(IReadOnlyList<GeneratedEntry> specs, string password, ZipRngVariant variant, uint seed,
        int filesInFirstSession = int.MaxValue)
    {
        var n = specs.Count;
        var r = new byte[n][];
        var c1 = new byte[n][];
        var stored = new byte[n][];
        var infos = new GeneratedEntryInfo[n];
        var bodies = new byte[n][];   // 12-byte header + encrypted compressed data
        byte[][]? extras = new byte[n][];  // central/local extra fields (fake AES; null = none)
        uint x = 0, y = 0, z = 0;
        InitKeys(password, ref x, ref y, ref z);

        uint s1 = seed;                                  // first session chain
        uint s2 = seed ^ 0x5eed_c0de;                    // later-session chain
        const uint dosTime = 0x4a21;                     // arbitrary fixed DOS time field
        const uint dosDate = 0x5bb1;

        var ms = new MemoryStream();
        var bw = new BinaryWriter(ms);
        var offsets = new long[n];

        for (int i = 0; i < n; i++)
        {
            var spec = specs[i];
            uint crc = Crc32(spec.Content);
            byte[] comp = spec.Method switch
            {
                0 => spec.Content,
                8 => Deflate(spec.Content),
                _ => spec.ExoticCompData ?? throw new ArgumentException("Exotic methods need ExoticCompData"),
            };

            // 10 fresh rand() bytes; headers beyond the first session come from the second chain
            var ri = Array.Empty<byte>();
            if (spec.Classic)
            {
                ref uint chain = ref (i < filesInFirstSession ? ref s1 : ref s2);
                ri = new byte[10];
                for (int j = 0; j < 10; j++)
                {
                    chain = unchecked(chain * 214013u + (variant == ZipRngVariant.Msvc ? 2531011u : 0u));
                    ri[j] = (byte)((chain >> 23) & 0xff);
                }
            }
            r[i] = ri;

            // check bytes: high word of the CRC, or the DOS time for data-descriptor entries
            byte check1 = spec.DataDescriptor ? (byte)(dosTime & 0xff) : (byte)((crc >> 16) & 0xff);
            byte check2 = spec.DataDescriptor ? (byte)((dosTime >> 8) & 0xff) : (byte)((crc >> 24) & 0xff);

            // pass 1: encrypt the random bytes (they land in c1), keys reset, pass 2: encrypt [c1, checks]
            byte[] body;
            ushort flags = (ushort)(spec.Classic ? 0x0001 : 0); // encrypted when classic
            ushort cdMethod = (ushort)spec.Method;
            byte[]? extra = null;
            if (!spec.Classic)
            {
                body = comp;
                c1[i] = [];
            }
            else if (spec.FakeAes)
            {
                // WinZip AES extra field (0x9901): version 2, vendor AE, strength 3, real method
                cdMethod = 99;
                extra = new byte[11];
                extra[0] = 0x01; extra[1] = 0x99;         // header id 0x9901
                extra[2] = 7; extra[3] = 0;               // data size
                extra[4] = 2; extra[5] = 0;               // version 2
                extra[6] = (byte)'A'; extra[7] = (byte)'E';
                extra[8] = 3;                             // strength: AES-256
                extra[9] = 8; extra[10] = 0;              // real compression method
                body = new byte[16 + 2 + 16 + 10];        // salt + pw verifier + body + auth (fake)
                new Random(42).NextBytes(body);
            }
            else
            {
            var header = new byte[12];
            uint tx = x, ty = y, tz = z;
            for (int j = 0; j < 10; j++)
                header[j] = Encode(ri[j], ref tx, ref ty, ref tz);
            c1[i] = header[..10];               // pass-1 ciphertext, before pass 2 re-encrypts in place
            tx = x; ty = y; tz = z;
            for (int j = 0; j < 10; j++)
                header[j] = Encode(header[j], ref tx, ref ty, ref tz);
            header[10] = Encode(check1, ref tx, ref ty, ref tz);
            header[11] = Encode(check2, ref tx, ref ty, ref tz);
            stored[i] = header;

            // entry data continues in the pass-2 stream
            var body2 = new byte[12 + comp.Length];
            Array.Copy(header, body2, 12);
            for (int j = 0; j < comp.Length; j++)
                body2[12 + j] = Encode(comp[j], ref tx, ref ty, ref tz);
            body = body2;
            }

            if (spec.DataDescriptor) flags |= 0x0008;
            if (!spec.Classic) stored[i] = [];
            long pos = ms.Position;
            offsets[i] = pos;
            var name = Encoding.ASCII.GetBytes(spec.Name);
            bw.Write(0x04034b50u);                        // local file header signature
            bw.Write((ushort)20);                         // version needed
            bw.Write(flags);
            bw.Write((ushort)spec.Method);
            bw.Write((ushort)dosTime);
            bw.Write((ushort)dosDate);
            bw.Write(crc);
            bw.Write((uint)(spec.ForceCompSize ?? body.Length)); // comp size incl. 12-byte header
            bw.Write((uint)spec.Content.Length);
            bw.Write((ushort)name.Length);
            bw.Write((ushort)(extra?.Length ?? 0));       // extra len
            bw.Write(name);
            if (extras[i] is { } ex) bw.Write(ex);
            bw.Write(body);
            if (spec.DataDescriptor)
            {
                bw.Write(0x08074b50u);                    // data descriptor signature
                bw.Write(crc);
                bw.Write((uint)body.Length);
                bw.Write((uint)spec.Content.Length);
            }

            extras[i] = extra;
            infos[i] = new GeneratedEntryInfo
            {
                Name = spec.Name, Content = spec.Content, CompData = comp, Method = spec.Method, CdMethod = cdMethod,
                DataDescriptor = spec.DataDescriptor, Crc = crc, Flags = flags, DosTime = dosTime,
                CompSize = spec.ForceCompSize ?? body.Length, LocalOffset = offsets[i],
            };
        }

        long cdOffset = ms.Position;
        for (int i = 0; i < n; i++)
        {
            var e = infos[i];
            var name = Encoding.ASCII.GetBytes(e.Name);
            bw.Write(0x02014b50u);                        // central directory signature
            bw.Write((ushort)((20 << 8) | 0));            // version made by (MS-DOS, zip 2.0)
            bw.Write((ushort)20);
            bw.Write(e.Flags);
            bw.Write((ushort)e.CdMethod);
            bw.Write((ushort)e.DosTime);
            bw.Write((ushort)0x5bb1);
            bw.Write(e.Crc);
            bw.Write((uint)e.CompSize);
            bw.Write((uint)e.Content.Length);
            bw.Write((ushort)name.Length);
            bw.Write((ushort)(extras[i]?.Length ?? 0)); bw.Write((ushort)0); // extra, comment
            bw.Write((ushort)0); bw.Write((ushort)0);     // disk start, internal attrs
            bw.Write(0u);                                 // external attrs
            bw.Write((uint)e.LocalOffset);
            bw.Write(name);
            if (extras[i] is { } ex) bw.Write(ex);
        }
        long cdSize = ms.Position - cdOffset;
        bw.Write(0x06054b50u);                            // end of central directory
        bw.Write((ushort)0); bw.Write((ushort)0);
        bw.Write((ushort)n); bw.Write((ushort)n);
        bw.Write((uint)cdSize);
        bw.Write((uint)cdOffset);
        bw.Write((ushort)0);
        bw.Flush();

        return new GeneratedZip
        {
            Archive = ms.ToArray(), Entries = infos, R = r, C1 = c1, StoredHeaders = stored,
            X = x, Y = y, Z = z, Seed = seed, Variant = variant,
            SessionFileCount = Math.Min(filesInFirstSession, n),
        };
    }

    // ---------------------------------------------------------------- cipher + oracle

    /// <summary>Independent ZipCrypto decryption from known initial keys. Input includes the 12-byte header.</summary>
    public static byte[] OracleDecrypt(byte[] dataWithHeader, uint x, uint y, uint z)
    {
        var outBytes = new byte[dataWithHeader.Length];
        uint k0 = x, k1 = y, k2 = z;
        for (int i = 0; i < dataWithHeader.Length; i++)
        {
            byte c = (byte)(dataWithHeader[i] ^ Keystream(k2));
            outBytes[i] = c;
            Update(ref k0, ref k1, ref k2, c);
        }
        return outBytes;
    }

    public static byte[] Deflate(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var ds = new DeflateStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            ds.Write(data, 0, data.Length);
        return ms.ToArray();
    }

    public static byte[] Inflate(byte[] compressed)
    {
        using var ms = new MemoryStream(compressed);
        using var ds = new DeflateStream(ms, CompressionMode.Decompress);
        using var outMs = new MemoryStream();
        ds.CopyTo(outMs);
        return outMs.ToArray();
    }

    internal static void InitKeys(string password, ref uint k0, ref uint k1, ref uint k2)
    {
        k0 = 0x12345678; k1 = 0x23456789; k2 = 0x34567890;
        foreach (var b in Encoding.ASCII.GetBytes(password))
            Update(ref k0, ref k1, ref k2, b);
    }

    internal static byte Encode(byte c, ref uint k0, ref uint k1, ref uint k2)
    {
        var e = (byte)(c ^ Keystream(k2));
        Update(ref k0, ref k1, ref k2, c);
        return e;
    }

    internal static byte Keystream(uint k2)
    {
        uint t = (k2 | 2) & 0xffff;
        return (byte)((t * (t ^ 1)) >> 8);
    }

    internal static void Update(ref uint k0, ref uint k1, ref uint k2, byte c)
    {
        k0 = (k0 >> 8) ^ T[(k0 ^ c) & 0xff];
        k1 = (k1 + (k0 & 0xff)) * 0x08088405u + 1;
        k2 = (k2 >> 8) ^ T[(k2 ^ (k1 >> 24)) & 0xff];
    }

    internal static uint Crc32(byte[] data)
    {
        uint crc = 0xffffffff;
        foreach (var b in data)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++)
                crc = (crc >> 1) ^ (0xedb88320 & (uint)-(int)(crc & 1));
        }
        return ~crc;
    }

    internal static uint[] BuildCrcTable()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
                c = (c >> 1) ^ (0xedb88320 & (uint)-(int)(c & 1));
            t[i] = c;
        }
        return t;
    }
}
