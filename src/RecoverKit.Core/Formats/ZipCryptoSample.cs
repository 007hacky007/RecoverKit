using System.IO.Compression;
using System.Text;

namespace RecoverKit.Core.Formats;

/// <summary>
/// Builds ZipCrypto (traditional PKWARE) encrypted ZIP archives in memory, the way Info-ZIP writes
/// them: a 12-byte encryption header whose last byte is the CRC's high byte (or the DOS time's high
/// byte with a data descriptor), then the stored or deflated data. Used by the GPU kernel benchmark
/// (recoverkit-cli bench-zip) and the kernel tests; the archive goes through the normal
/// <see cref="ZipExtractor"/>.
/// </summary>
public static class ZipCryptoSample
{
    /// <param name="Header">The first 10 bytes of the encryption header (random when null), for fixed test archives.</param>
    public sealed record Entry(string Name, byte[] Content, bool Deflate, bool DataDescriptor = false, byte[]? Header = null);

    private static readonly uint[] Crc = BuildCrc();

    private static uint[] BuildCrc()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        return t;
    }

    public static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint c = 0xffffffff;
        foreach (var b in data) c = Crc[(c ^ b) & 0xff] ^ (c >> 8);
        return ~c;
    }

    private struct Keys
    {
        public uint K0, K1, K2;

        public Keys(ReadOnlySpan<byte> password)
        {
            K0 = 0x12345678; K1 = 0x23456789; K2 = 0x34567890;
            foreach (var b in password) Update(b);
        }

        public void Update(byte p)
        {
            K0 = Crc[(K0 ^ p) & 0xff] ^ (K0 >> 8);
            K1 = unchecked((K1 + (K0 & 0xff)) * 0x08088405u + 1);
            K2 = Crc[(K2 ^ (K1 >> 24)) & 0xff] ^ (K2 >> 8);
        }

        public byte Encrypt(byte p)
        {
            uint t = (K2 | 2) & 0xffff;
            byte c = (byte)(p ^ (byte)((t * (t ^ 1)) >> 8));
            Update(p);
            return c;
        }
    }

    /// <summary>A ZIP archive with every entry encrypted with <paramref name="password"/>.</summary>
    public static byte[] Archive(IReadOnlyList<Entry> entries, ReadOnlySpan<byte> password, Random rng)
    {
        const ushort dosTime = 0x6d2b, dosDate = 0x5b6c;
        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        var central = new MemoryStream();
        var cw = new BinaryWriter(central);
        foreach (var e in entries)
        {
            uint crc = Crc32(e.Content);
            byte[] comp = e.Deflate ? DeflateRaw(e.Content) : e.Content;
            var keys = new Keys(password);
            var body = new byte[12 + comp.Length];
            for (int j = 0; j < 10; j++) body[j] = keys.Encrypt(e.Header?[j] ?? (byte)rng.Next(256));
            ushort check = e.DataDescriptor ? dosTime : (ushort)(crc >> 16);
            body[10] = keys.Encrypt((byte)check);
            body[11] = keys.Encrypt((byte)(check >> 8));
            for (int j = 0; j < comp.Length; j++) body[12 + j] = keys.Encrypt(comp[j]);

            ushort flags = (ushort)(e.DataDescriptor ? 0x0009 : 0x0001);
            ushort method = (ushort)(e.Deflate ? 8 : 0);
            var name = Encoding.UTF8.GetBytes(e.Name);
            long offset = ms.Position;
            w.Write(0x04034b50u); w.Write((ushort)20); w.Write(flags); w.Write(method);
            w.Write(dosTime); w.Write(dosDate);
            w.Write(e.DataDescriptor ? 0u : crc);
            w.Write(e.DataDescriptor ? 0u : (uint)body.Length);
            w.Write(e.DataDescriptor ? 0u : (uint)e.Content.Length);
            w.Write((ushort)name.Length); w.Write((ushort)0); w.Write(name);
            w.Write(body);
            if (e.DataDescriptor) { w.Write(0x08074b50u); w.Write(crc); w.Write((uint)body.Length); w.Write((uint)e.Content.Length); }

            cw.Write(0x02014b50u); cw.Write((ushort)20); cw.Write((ushort)20); cw.Write(flags); cw.Write(method);
            cw.Write(dosTime); cw.Write(dosDate); cw.Write(crc); cw.Write((uint)body.Length); cw.Write((uint)e.Content.Length);
            cw.Write((ushort)name.Length); cw.Write((ushort)0); cw.Write((ushort)0); cw.Write((ushort)0); cw.Write((ushort)0);
            cw.Write(0u); cw.Write((uint)offset); cw.Write(name);
        }
        long cdOffset = ms.Position;
        w.Write(central.ToArray());
        w.Write(0x06054b50u); w.Write((ushort)0); w.Write((ushort)0);
        w.Write((ushort)entries.Count); w.Write((ushort)entries.Count);
        w.Write((uint)central.Length); w.Write((uint)cdOffset); w.Write((ushort)0);
        return ms.ToArray();
    }

    /// <summary>The hash RecoverKit extracts from such an archive.</summary>
    public static HashTarget Extract(byte[] archive)
    {
        var d = new Detection { FilePath = "sample.zip" };
        using var s = new MemoryStream(archive);
        ZipExtractor.Extract(s, d);
        return d.Target ?? throw new FormatException(d.Message ?? "No hash extracted.");
    }

    private static byte[] DeflateRaw(byte[] data)
    {
        var ms = new MemoryStream();
        using (var d = new DeflateStream(ms, CompressionLevel.Optimal, leaveOpen: true)) d.Write(data);
        return ms.ToArray();
    }

    /// <summary>Text-like content (words from a fixed list) that deflates the way documents do.</summary>
    public static byte[] Text(int length, Random rng)
    {
        string[] words = ["the", "archive", "password", "recovery", "of", "and", "file", "data", "to", "in", "is", "report",
                          "quarterly", "invoice", "meeting", "notes", "project", "budget", "draft", "final", "a", "with"];
        var sb = new StringBuilder(length + 16);
        while (sb.Length < length) sb.Append(words[rng.Next(words.Length)]).Append(rng.Next(12) == 0 ? ".\n" : " ");
        return Encoding.ASCII.GetBytes(sb.ToString(0, length));
    }
}
