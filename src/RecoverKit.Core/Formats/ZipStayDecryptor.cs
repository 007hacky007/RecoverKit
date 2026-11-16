using System.Buffers.Binary;
using System.IO.Compression;
using RecoverKit.Core.Attacks.Stay;

namespace RecoverKit.Core.Formats;

/// <summary>
/// Writes a password-free copy of a classic ZipCrypto archive once Stay's attack has recovered
/// the internal keys: every entry the keys verifiably decrypt is re-emitted unencrypted (12-byte
/// header removed, encryption and data-descriptor flags cleared, data descriptor dropped), with
/// its compression method and bytes preserved. Entries the keys do not verifiably decrypt - a
/// different password, WinZip AES, PKWARE strong encryption, or anything corrupt - are copied
/// through untouched, still encrypted.
/// </summary>
public static class ZipStayDecryptor
{
    private const int HeaderLength = 12;

    /// <summary>Decrypts an entry body (12-byte encryption header + data) with the keys; returns the clear data.</summary>
    public static byte[] DecryptEntry(byte[] dataWithHeader, ZipStayKeys keys)
    {
        var (k0, k1, k2) = (keys.X, keys.Y, keys.Z);
        var plain = new byte[dataWithHeader.Length];
        for (int i = 0; i < dataWithHeader.Length; i++)
        {
            plain[i] = (byte)(dataWithHeader[i] ^ Keystream(k2));
            Update(ref k0, ref k1, ref k2, plain[i]);
        }
        return plain[HeaderLength..];
    }

    /// <summary>Where the decrypted copy of <paramref name="archivePath"/> would be written for these settings.</summary>
    public static string OutputPathFor(string archivePath, Settings s)
        => Path.Combine(
            string.IsNullOrEmpty(Path.GetDirectoryName(archivePath)) ? "." : Path.GetDirectoryName(archivePath)!,
            Path.GetFileNameWithoutExtension(archivePath) + s.DecryptSuffix + ".zip");

    /// <summary>
    /// Writes the decrypted copy. <paramref name="target"/> is the Stay payload of the archive
    /// (its entries drive nothing here - the per-entry decrypt-or-passthrough decision is made by
    /// re-parsing the archive and verifying each entry against the keys). Returns
    /// <paramref name="outputPath"/>; an existing file at that path is overwritten.
    /// </summary>
    public static string WriteDecryptedCopy(string archivePath, ZipStayTarget target, ZipStayKeys keys, string outputPath)
    {
        using var src = ZipArchiveSource.Open(archivePath);
        if (src is MultiVolumeStream)
            throw new UnsupportedFormatException("Stay key recovery and decrypted-copy writing are not supported for split ZIP archives. Use password recovery instead.");
        var entries = ZipExtractor.ReadCentralDirectory(src, out long delta, out long cdStart, out var cd);

        // local record extents: each entry runs from its local header to the next entry's (last: to the CD)
        var order = entries.Select((e, i) => (Entry: e, Index: i)).OrderBy(t => t.Entry.LocalOffset).ToList();
        for (int i = 0; i < order.Count - 1; i++)
            if (order[i].Entry.LocalOffset >= order[i + 1].Entry.LocalOffset)
                throw new FormatException("ZIP entries overlap or repeat local header offsets.");

        // plan: which entries decrypt (with their clear data), and each entry's raw extent
        byte[]?[] decrypted = new byte[entries.Count][];
        var extents = new (long Start, long End)[entries.Count];
        for (int i = 0; i < order.Count; i++)
        {
            var (e, idx) = order[i];
            long start = e.LocalOffset + delta;
            long end = i + 1 < order.Count ? order[i + 1].Entry.LocalOffset + delta : cdStart;
            extents[idx] = (start, end);
            decrypted[idx] = TryDecrypt(src, e, delta, keys);
        }

        using var dstStream = File.Create(outputPath);
        using var dst = new BinaryWriter(dstStream);

        // local records, in original archive order
        var newOffsets = new long[entries.Count];
        for (int i = 0; i < entries.Count; i++)
        {
            var e = entries[i];
            newOffsets[i] = dstStream.Position;
            var plain = decrypted[i] ?? [];
            var passthrough = decrypted[i] is null;
            if (passthrough)
            {
                CopyRaw(src, dstStream, extents[i].Start, extents[i].End);   // untouched, still encrypted
                continue;
            }

            var (dataStart, localName, localExtra) = LocalHead(src, e, delta);
            ushort flags = (ushort)(e.Flags & ~(0x0001 | 0x0008));   // encryption + data descriptor off
            dst.Write(0x04034b50u);
            dst.Write((ushort)20);
            dst.Write(flags);
            dst.Write(e.Method);
            dst.Write(e.ModTime);
            dst.Write(e.ModDate);
            dst.Write(e.Crc);
            dst.Write((uint)plain.Length);
            dst.Write((uint)e.UncompSize);
            dst.Write((ushort)localName.Length);
            dst.Write((ushort)localExtra.Length);
            dst.Write(localName);
            dst.Write(localExtra);
            dst.Write(plain);
        }

        // central directory: raw records with new local offsets, patched flags/sizes for decrypted entries
        long newCdOffset = dstStream.Position;
        int p = 0;
        for (int i = 0; i < entries.Count; i++)
        {
            var e = entries[i];
            int recLen = 46 + Bin.U16(cd, p + 28) + Bin.U16(cd, p + 30) + Bin.U16(cd, p + 32);
            var rec = cd[p .. (p + recLen)];
            var plain = decrypted[i];
            WriteU16(rec, 8, (ushort)(plain is null ? e.Flags : e.Flags & ~(0x0001 | 0x0008)));
            if (plain is not null) WriteU32(rec, 20, (uint)plain.Length);
            WriteU32(rec, 42, (uint)newOffsets[i]);
            dst.Write(rec);
            p += recLen;
        }
        long newCdSize = dstStream.Position - newCdOffset;

        dst.Write(0x06054b50u);
        dst.Write((ushort)0); dst.Write((ushort)0);
        dst.Write((ushort)entries.Count); dst.Write((ushort)entries.Count);
        dst.Write((uint)newCdSize);
        dst.Write((uint)newCdOffset);
        dst.Write((ushort)0);
        return outputPath;
    }

    /// <summary>Decrypts one classic ZipCrypto entry if the keys verifiably explain it; null to pass it through.</summary>
    private static byte[]? TryDecrypt(Stream src, ZipExtractor.ZipEntry e, long delta, ZipStayKeys keys)
    {
        if (!e.Encrypted || e.AesStrength != 0 || (e.Flags & 0x40) != 0 || e.CompSize < HeaderLength
            || e.CompSize > int.MaxValue) return null;
        try
        {
            var (dataStart, _, _) = LocalHead(src, e, delta);
            var enc = Bin.ReadAt(src, dataStart, (int)e.CompSize);
            if (enc.Length < e.CompSize) return null;   // truncated

            var (k0, k1, k2) = (keys.X, keys.Y, keys.Z);
            var plain = new byte[enc.Length];
            for (int i = 0; i < enc.Length; i++)
            {
                plain[i] = (byte)(enc[i] ^ Keystream(k2));
                Update(ref k0, ref k1, ref k2, plain[i]);
            }

            // data-descriptor + exotic method: the check bytes are time-based and the CRC cannot be
            // checked, so nothing about this entry is verifiable - leave it encrypted
            if ((e.Flags & 8) != 0 && e.Method is not (0 or 8)) return null;

            // check bytes: the high CRC word, except for data-descriptor entries (time-based there)
            if ((e.Flags & 8) == 0)
            {
                if (plain[10] != (byte)(e.Crc >> 16) || plain[11] != (byte)(e.Crc >> 24)) return null;
            }

            var body = plain[HeaderLength..];
            // CRC verification where we can inflate; exotic methods are trusted to the check bytes
            if (e.Method == 0)
            {
                if (Crc32(body) != e.Crc) return null;
            }
            else if (e.Method == 8)
            {
                try
                {
                    using var ds = new DeflateStream(new MemoryStream(body), CompressionMode.Decompress);
                    using var ms = new MemoryStream();
                    ds.CopyTo(ms);
                    if (Crc32(ms.ToArray()) != e.Crc) return null;
                }
                catch (InvalidDataException) { return null; }
            }
            return body;
        }
        catch (Exception ex) when (ex is FormatException or IOException or InvalidDataException)
        {
            return null;   // corrupt entry: copy through untouched
        }
    }

    private static (long DataStart, byte[] Name, byte[] Extra) LocalHead(Stream src, ZipExtractor.ZipEntry e, long delta)
    {
        long lh = e.LocalOffset + delta;
        var h = Bin.ReadAt(src, lh, 30);
        if (Bin.U32(h, 0) != 0x04034b50) throw new FormatException("Bad ZIP local header.");
        int nl = Bin.U16(h, 26), el = Bin.U16(h, 28);
        var rest = Bin.ReadAt(src, lh + 30, nl + el);
        return (lh + 30 + nl + el, rest[..nl], rest[nl..]);
    }

    private static void CopyRaw(Stream src, FileStream dst, long start, long end)
    {
        src.Position = start;
        var buf = new byte[80 * 1024];
        for (long left = end - start; left > 0;)
        {
            int n = (int)Math.Min(buf.Length, left);
            src.ReadExactly(buf, 0, n);
            dst.Write(buf, 0, n);
            left -= n;
        }
    }

    private static byte Keystream(uint k2)
    {
        uint t = (k2 & 0xffff) | 2;
        return (byte)((t * (t ^ 1)) >> 8);
    }

    private static void Update(ref uint k0, ref uint k1, ref uint k2, byte c)
    {
        k0 = (k0 >> 8) ^ StayTables.T[(k0 ^ c) & 0xff];
        k1 = unchecked((k1 + (k0 & 0xff)) * StayTables.M + 1);
        k2 = (k2 >> 8) ^ StayTables.T[(k2 ^ (k1 >> 24)) & 0xff];
    }

    private static uint Crc32(byte[] data)
    {
        uint crc = 0xffffffff;
        foreach (var b in data)
            crc = (crc >> 8) ^ StayTables.T[(crc ^ b) & 0xff];
        return crc ^ 0xffffffff;
    }

    private static void WriteU16(byte[] b, int o, ushort v) => BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(o, 2), v);
    private static void WriteU32(byte[] b, int o, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o, 4), v);
}
