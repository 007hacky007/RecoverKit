using System.IO.Compression;
using System.Text;
using System.Xml.Linq;

namespace RecoverKit.Core.Formats;

/// <summary>
/// Reads a ZIP central directory and produces hashes for classic ZipCrypto
/// (PKZIP, modes 17200/17210), WinZip AES (13600) and encrypted OpenDocument
/// files (18400/18600). Also recognises unencrypted OOXML packages.
/// </summary>
public static class ZipExtractor
{
    internal sealed class ZipEntry
    {
        public string Name = "";
        public ushort Flags, Method, ModTime, ModDate;
        public uint Crc;
        public long CompSize, UncompSize, LocalOffset;
        public int AesStrength;     // 0 = not AES
        public ushort AesMethod;
        public bool Encrypted => (Flags & 1) != 0;
    }

    public static bool LooksLikeZip(Stream s) => FindEocd(s) >= 0;

    public static void Extract(Stream s, Detection d)
    {
        var entries = ReadCentralDirectory(s, out long delta, out _, out _);
        d.TypeName = "ZIP archive";
        d.Add("Entries", entries.Count.ToString());

        bool isOdf = entries.Any(e => e.Name == "mimetype") && entries.Any(e => e.Name == "META-INF/manifest.xml");
        if (isOdf) { ExtractOdf(s, entries, delta, d); return; }

        if (entries.Any(e => e.Name == "[Content_Types].xml"))
        {
            d.TypeName = "Office Open XML document";
            d.Message = "Document is not password protected to open (OOXML packages are only encrypted when stored as OLE containers).";
            return;
        }

        var enc = entries.Where(e => e.Encrypted && !e.Name.EndsWith('/')).ToList();
        if (enc.Count == 0) { d.Message = "Archive is not password protected."; return; }
        if (enc.Any(e => (e.Flags & 0x40) != 0))
        {
            d.Message = "PKWARE strong encryption is not supported.";
            return;
        }

        var aes = enc.Where(e => e.AesStrength > 0).OrderBy(e => e.CompSize).FirstOrDefault();
        if (aes is not null) { d.Target = WinZipAes(s, aes, delta, d); return; }

        var classic = enc.Where(e => e.Method is 0 or 8 && e.CompSize > 12).OrderBy(e => e.CompSize).FirstOrDefault();
        if (classic is null)
        {
            d.Message = "Encrypted entries use a compression method that hashcat cannot verify (only stored/deflate are supported).";
            return;
        }
        d.Target = Pkzip(s, classic, delta, d);
        d.Target.StayZip = CollectStayTarget(s, enc, delta);
    }

    /// <summary>
    /// Gathers every classic ZipCrypto entry (any compression method, header at least 12 bytes) in
    /// archive order, with its stored 12-byte encryption header — the payload for Stay's attack.
    /// </summary>
    private static ZipStayTarget? CollectStayTarget(Stream s, List<ZipEntry> enc, long delta)
    {
        var usable = enc.Where(e => e.AesStrength == 0 && e.CompSize >= 12).ToList();
        if (usable.Count < 2) return null;
        var entries = new List<ZipStayEntry>();
        foreach (var e in usable)
        {
            try
            {
                entries.Add(new ZipStayEntry
                {
                    Name = e.Name,
                    StoredHeader = ReadEntryData(s, e, delta)[..12],
                    Crc = e.Crc,
                    Flags = e.Flags,
                    Method = e.Method,
                    CompSize = e.CompSize,
                    UncompSize = e.UncompSize,
                    LocalOffset = e.LocalOffset,
                    DataOffset = EntryDataOffset(s, e, delta),
                });
            }
            catch (Exception ex) when (ex is FormatException or UnsupportedFormatException or IOException or OverflowException or ArgumentOutOfRangeException)
            {
                // a truncated/corrupt entry is skipped; it must not break the normal extraction path
            }
        }
        if (entries.Count < 2) return null;
        return new ZipStayTarget { Entries = entries };
    }

    private static HashTarget WinZipAes(Stream s, ZipEntry e, long delta, Detection d)
    {
        int saltLen = e.AesStrength switch { 1 => 8, 2 => 12, 3 => 16, _ => throw new FormatException("Bad AES strength.") };
        var data = ReadEntryData(s, e, delta);
        if (data.Length < saltLen + 2 + 10) throw new FormatException("AES entry is too short.");
        var salt = data.AsSpan(0, saltLen);
        var pv = data.AsSpan(saltLen, 2);
        var body = data.AsSpan(saltLen + 2, data.Length - saltLen - 2 - 10);
        var auth = data.AsSpan(data.Length - 10, 10);
        int bits = 64 * (e.AesStrength + 1);
        d.TypeName = "WinZip AES archive";
        d.Add("Attacked entry", $"{e.Name} ({e.CompSize:N0} bytes)");
        return new HashTarget
        {
            FormatId = "WZAE",
            FormatName = "WinZip AES archive",
            Protection = $"AES-{bits}, PBKDF2-SHA1 1000 iterations",
            Modes = [13600],
            HashLines = $"$zip2$*0*{e.AesStrength}*0*{Bin.Hex(salt)}*{Bin.Hex(pv)}*{body.Length:x}*{Bin.Hex(body)}*{Bin.Hex(auth)}*$/zip2$",
            Speed = SpeedClass.Medium,
        };
    }

    private static HashTarget Pkzip(Stream s, ZipEntry e, long delta, Detection d)
    {
        var data = ReadEntryData(s, e, delta);
        int checksumFromCrc = (int)(e.Crc >> 16);
        // The header's check byte is the CRC's high byte, or the modification time's high byte when
        // the entry uses a data descriptor (flag bit 3). Emitting the time checksum only in that case
        // lets hashcat and the built-in engine test one byte instead of two (half the false positives).
        int checksumFromTime = (e.Flags & 8) != 0 ? e.ModTime : checksumFromCrc;
        int mode = e.Method == 8 ? 17200 : 17210;
        d.TypeName = "ZIP archive (ZipCrypto)";
        d.Add("Attacked entry", $"{e.Name} ({e.CompSize:N0} bytes, {(e.Method == 8 ? "deflate" : "stored")})");
        string hash = string.Join('*',
            "$pkzip2$1", "1", "2", "0",
            e.CompSize.ToString("x"), e.UncompSize.ToString("x"), e.Crc.ToString("x8"),
            "0", "0", e.Method.ToString(), data.Length.ToString("x"),
            checksumFromCrc.ToString("x4"), checksumFromTime.ToString("x4"), Bin.Hex(data), "$/pkzip2$");
        return new HashTarget
        {
            FormatId = "ZIPC",
            FormatName = "ZIP archive (ZipCrypto)",
            Protection = "ZipCrypto (PKZIP 2.0)",
            Modes = [mode],
            HashLines = hash,
            Speed = SpeedClass.VeryFast,
        };
    }

    private static void ExtractOdf(Stream s, List<ZipEntry> entries, long delta, Detection d)
    {
        d.TypeName = "OpenDocument file";
        var manifestEntry = entries.First(e => e.Name == "META-INF/manifest.xml");
        var manifestBytes = ReadEntryContent(s, manifestEntry, delta);
        var doc = XDocument.Parse(Encoding.UTF8.GetString(manifestBytes).Trim('﻿'));
        XNamespace m = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

        var fileEntries = doc.Descendants(m + "file-entry").Where(fe => fe.Element(m + "encryption-data") is not null).ToList();
        if (fileEntries.Count == 0) { d.Message = "Document is not password protected to open."; return; }

        var fe = fileEntries.FirstOrDefault(x => (string?)x.Attribute(m + "full-path") == "content.xml") ?? fileEntries[0];
        string path = (string)fe.Attribute(m + "full-path")!;
        var ed = fe.Element(m + "encryption-data")!;
        var alg = ed.Element(m + "algorithm");
        var kd = ed.Element(m + "key-derivation");
        var skg = ed.Element(m + "start-key-generation");
        if (alg is null || kd is null) throw new FormatException("Manifest encryption data is incomplete.");

        string checksumType = (string?)ed.Attribute(m + "checksum-type") ?? "";
        var checksum = Convert.FromBase64String((string?)ed.Attribute(m + "checksum") ?? "");
        string algName = (string?)alg.Attribute(m + "algorithm-name") ?? "";
        var iv = Convert.FromBase64String((string?)alg.Attribute(m + "initialisation-vector") ?? "");
        string kdName = (string?)kd.Attribute(m + "key-derivation-name") ?? "";
        int iterations = int.Parse((string?)kd.Attribute(m + "iteration-count") ?? "1024");
        int keySize = int.Parse((string?)kd.Attribute(m + "key-size") ?? "16");
        var salt = Convert.FromBase64String((string?)kd.Attribute(m + "salt") ?? "");
        string startKey = (string?)skg?.Attribute(m + "start-key-generation-name") ?? "SHA1";

        if (kdName.Contains("argon2", StringComparison.OrdinalIgnoreCase) || algName.Contains("gcm", StringComparison.OrdinalIgnoreCase))
        {
            d.Message = "This document uses ODF 1.4 Argon2id/AES-GCM encryption, which hashcat does not support yet.";
            return;
        }

        var entry = entries.FirstOrDefault(e => e.Name == path) ?? throw new FormatException($"Encrypted part '{path}' is missing.");
        var data = ReadEntryContent(s, entry, delta);
        var head = data.AsSpan(0, Math.Min(1024, data.Length));

        bool aes = algName.Contains("aes256-cbc", StringComparison.OrdinalIgnoreCase);
        bool blowfish = algName.Contains("blowfish", StringComparison.OrdinalIgnoreCase);
        bool sha256Checksum = checksumType.Contains("sha256", StringComparison.OrdinalIgnoreCase);
        d.Add("Attacked part", path);

        if (aes && sha256Checksum && startKey.Contains("sha256", StringComparison.OrdinalIgnoreCase))
        {
            d.TypeName = "OpenDocument 1.2+ file";
            d.Target = new HashTarget
            {
                FormatId = "ODF2",
                FormatName = d.TypeName,
                Protection = $"AES-256-CBC, PBKDF2-SHA1 {iterations} iterations",
                Modes = [18400],
                HashLines = $"$odf$*1*1*{iterations}*{keySize}*{Bin.Hex(checksum)}*{iv.Length}*{Bin.Hex(iv)}*{salt.Length}*{Bin.Hex(salt)}*0*{Bin.Hex(head)}",
                Speed = SpeedClass.VerySlow,
            };
            return;
        }
        if (blowfish && !sha256Checksum)
        {
            d.TypeName = "OpenDocument 1.1 / OpenOffice 1.x-3.x file";
            d.Target = new HashTarget
            {
                FormatId = "OODF",
                FormatName = d.TypeName,
                Protection = $"Blowfish-CFB, PBKDF2-SHA1 {iterations} iterations",
                Modes = [18600],
                HashLines = $"$odf$*0*0*{iterations}*{keySize}*{Bin.Hex(checksum)}*{iv.Length}*{Bin.Hex(iv)}*{salt.Length}*{Bin.Hex(salt)}*0*{Bin.Hex(head)}",
                Speed = SpeedClass.Slow,
            };
            return;
        }
        d.Message = $"Unsupported OpenDocument encryption ({algName}, {checksumType}, start key {startKey}).";
    }

    // ---------------------------------------------------------------- parsing

    private static long FindEocd(Stream s)
    {
        if (s.Length < 22) return -1;
        int tail = (int)Math.Min(s.Length, 65535 + 22);
        var buf = Bin.ReadAt(s, s.Length - tail, tail);
        for (int i = buf.Length - 22; i >= 0; i--)
            if (buf[i] == 0x50 && buf[i + 1] == 0x4B && buf[i + 2] == 0x05 && buf[i + 3] == 0x06)
                return s.Length - tail + i;
        return -1;
    }

    internal static List<ZipEntry> ReadCentralDirectory(Stream s, out long delta, out long cdStart, out byte[] cd)
    {
        long eocd = FindEocd(s);
        if (eocd < 0) throw new FormatException("ZIP end of central directory not found.");
        var e = Bin.ReadAt(s, eocd, 22);
        long total = Bin.U16(e, 10), cdSize = Bin.U32(e, 12), cdOffset = Bin.U32(e, 16);
        long expectedEnd = eocd;

        if ((total == 0xFFFF || cdSize == 0xFFFFFFFF || cdOffset == 0xFFFFFFFF) && eocd >= 20)
        {
            var loc = Bin.ReadAt(s, eocd - 20, 20);
            if (Bin.U32(loc, 0) == 0x07064b50)
            {
                long z64 = (long)Bin.U64(loc, 8);
                var z = Bin.ReadAt(s, z64, 56);
                if (Bin.U32(z, 0) != 0x06064b50) throw new FormatException("Bad ZIP64 end of central directory.");
                total = (long)Bin.U64(z, 32);
                cdSize = (long)Bin.U64(z, 40);
                cdOffset = (long)Bin.U64(z, 48);
                expectedEnd = z64;
            }
        }
        delta = expectedEnd - (cdOffset + cdSize); // non-zero for self-extracting archives with a prefix
        if (delta < 0) delta = 0;
        cdStart = cdOffset + delta;
        if (cdSize > 256L * 1024 * 1024) throw new FormatException("ZIP central directory is too large.");

        var cdBytes = Bin.ReadAt(s, cdOffset + delta, (int)cdSize);
        cd = cdBytes;
        var list = new List<ZipEntry>();
        int p = 0;
        while (p + 46 <= cdBytes.Length && Bin.U32(cdBytes, p) == 0x02014b50)
        {
            var ze = new ZipEntry
            {
                Flags = Bin.U16(cd, p + 8),
                Method = Bin.U16(cd, p + 10),
                ModTime = Bin.U16(cd, p + 12),
                ModDate = Bin.U16(cd, p + 14),
                Crc = Bin.U32(cd, p + 16),
                CompSize = Bin.U32(cd, p + 20),
                UncompSize = Bin.U32(cd, p + 24),
                LocalOffset = Bin.U32(cd, p + 42),
            };
            int nameLen = Bin.U16(cd, p + 28), extraLen = Bin.U16(cd, p + 30), commentLen = Bin.U16(cd, p + 32);
            Bin.Need(cdBytes, p + 46, nameLen + extraLen);
            ze.Name = ((ze.Flags & 0x800) != 0 ? Encoding.UTF8 : Encoding.Latin1).GetString(cdBytes, p + 46, nameLen);
            ParseExtra(cdBytes, p + 46 + nameLen, extraLen, ze);
            list.Add(ze);
            p += 46 + nameLen + extraLen + commentLen;
        }
        return list;
    }

    private static void ParseExtra(byte[] b, int o, int len, ZipEntry ze)
    {
        int end = o + len;
        while (o + 4 <= end)
        {
            int id = Bin.U16(b, o), size = Bin.U16(b, o + 2);
            int d = o + 4;
            if (d + size > end) break;
            if (id == 0x0001)
            {
                int q = d;
                if (ze.UncompSize == 0xFFFFFFFF && q + 8 <= d + size) { ze.UncompSize = (long)Bin.U64(b, q); q += 8; }
                if (ze.CompSize == 0xFFFFFFFF && q + 8 <= d + size) { ze.CompSize = (long)Bin.U64(b, q); q += 8; }
                if (ze.LocalOffset == 0xFFFFFFFF && q + 8 <= d + size) { ze.LocalOffset = (long)Bin.U64(b, q); }
            }
            else if (id == 0x9901 && size >= 7)
            {
                ze.AesStrength = b[d + 4];
                ze.AesMethod = Bin.U16(b, d + 5);
            }
            o = d + size;
        }
    }

    /// <summary>Absolute offset of an entry's stored body (encryption header + data).</summary>
    private static long EntryDataOffset(Stream s, ZipEntry e, long delta)
    {
        long lh = e.LocalOffset + delta;
        var h = Bin.ReadAt(s, lh, 30);
        if (Bin.U32(h, 0) != 0x04034b50) throw new FormatException("Bad ZIP local header.");
        return lh + 30 + Bin.U16(h, 26) + Bin.U16(h, 28);
    }

    private static byte[] ReadEntryData(Stream s, ZipEntry e, long delta)
    {
        long lh = e.LocalOffset + delta;
        var h = Bin.ReadAt(s, lh, 30);
        if (Bin.U32(h, 0) != 0x04034b50) throw new FormatException("Bad ZIP local header.");
        long dataOff = lh + 30 + Bin.U16(h, 26) + Bin.U16(h, 28);
        if (e.CompSize > 64L * 1024 * 1024) throw new UnsupportedFormatException("Encrypted entry is too large to embed in a hash.");
        var data = Bin.ReadAt(s, dataOff, (int)e.CompSize);
        if (data.Length != e.CompSize) throw new FormatException("ZIP entry is truncated.");
        return data;
    }

    /// <summary>Returns an entry's stored bytes, inflating zip-level deflate when present (not decrypting).</summary>
    private static byte[] ReadEntryContent(Stream s, ZipEntry e, long delta)
    {
        var raw = ReadEntryData(s, e, delta);
        if (e.Method == 0) return raw;
        if (e.Method != 8) throw new UnsupportedFormatException($"Unsupported compression method {e.Method}.");
        using var inflate = new DeflateStream(new MemoryStream(raw), CompressionMode.Decompress);
        using var ms = new MemoryStream();
        inflate.CopyTo(ms);
        return ms.ToArray();
    }
}
