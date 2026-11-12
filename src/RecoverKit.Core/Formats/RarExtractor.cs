namespace RecoverKit.Core.Formats;

/// <summary>
/// RAR5 (mode 13000) and RAR 3.x/4.x with encrypted headers (mode 12500)
/// or encrypted file data (modes 23700/23800). Handles self-extracting archives by locating
/// the signature inside the first few megabytes.
/// </summary>
public static class RarExtractor
{
    private static readonly byte[] Rar5Sig = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];
    private static readonly byte[] Rar4Sig = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];

    /// <summary>Returns signature offset and version (4 or 5), or (-1, 0).</summary>
    public static (long Offset, int Version) FindSignature(Stream s, int scanBytes = 4 * 1024 * 1024)
    {
        var buf = Bin.ReadAt(s, 0, (int)Math.Min(s.Length, scanBytes));
        int i5 = Bin.IndexOf(buf, Rar5Sig), i4 = Bin.IndexOf(buf, Rar4Sig);
        if (i5 >= 0 && (i4 < 0 || i5 <= i4)) return (i5, 5);
        if (i4 >= 0) return (i4, 4);
        return (-1, 0);
    }

    public static void Extract(Stream s, Detection d)
    {
        var (off, ver) = FindSignature(s);
        if (off < 0) throw new FormatException("RAR signature not found.");
        if (off > 0) d.Add("Self-extracting prefix", $"{off:N0} bytes");
        if (ver == 5) Rar5(s, off + Rar5Sig.Length, d);
        else Rar4(s, off + Rar4Sig.Length, d);
    }

    // ------------------------------------------------------------------ RAR5

    private static void Rar5(Stream s, long pos, Detection d)
    {
        d.TypeName = "RAR 5.x archive";
        for (int guard = 0; guard < 100000 && pos < s.Length; guard++)
        {
            var head = Bin.ReadAt(s, pos, 4 + 3 + 16);
            int p = 4;
            ulong headerSize = VInt(head, ref p);
            if (headerSize == 0 || headerSize > 2 * 1024 * 1024) throw new FormatException("Bad RAR5 header size.");
            long hStart = pos + p;
            var h = Bin.ReadAt(s, hStart, (int)headerSize);
            int q = 0;
            ulong type = VInt(h, ref q), flags = VInt(h, ref q);
            ulong extraSize = (flags & 1) != 0 ? VInt(h, ref q) : 0;
            ulong dataSize = (flags & 2) != 0 ? VInt(h, ref q) : 0;

            if (type == 4) // archive encryption header (-hp)
            {
                ulong encVer = VInt(h, ref q), encFlags = VInt(h, ref q);
                if (encVer != 0) throw new UnsupportedFormatException($"Unknown RAR5 encryption version {encVer}.");
                int kdf = h[q++];
                var salt = Bin.Slice(h, q, 16); q += 16;
                if ((encFlags & 1) == 0) throw new UnsupportedFormatException("RAR5 archive has no password check value.");
                var check = Bin.Slice(h, q, 8);
                long ivPos = hStart + (long)headerSize;
                var iv = ivPos + 16 <= s.Length ? Bin.ReadAt(s, ivPos, 16) : new byte[16];
                d.Add("Encrypted file names", "yes");
                d.Target = Rar5Target(salt, kdf, iv, check);
                return;
            }
            if (type is 2 or 3 && extraSize > 0)
            {
                int e = (int)(headerSize - extraSize);
                int end = (int)headerSize;
                while (e < end)
                {
                    ulong recSize = VInt(h, ref e);
                    int recStart = e;
                    ulong recType = VInt(h, ref e);
                    if (recType == 1) // file encryption record
                    {
                        ulong encVer = VInt(h, ref e), encFlags = VInt(h, ref e);
                        if (encVer != 0) throw new UnsupportedFormatException($"Unknown RAR5 encryption version {encVer}.");
                        int kdf = h[e++];
                        var salt = Bin.Slice(h, e, 16); e += 16;
                        var iv = Bin.Slice(h, e, 16); e += 16;
                        if ((encFlags & 1) == 0) throw new UnsupportedFormatException("RAR5 file has no password check value.");
                        var check = Bin.Slice(h, e, 8);
                        d.Add("Encrypted file names", "no");
                        d.Target = Rar5Target(salt, kdf, iv, check);
                        return;
                    }
                    e = recStart + (int)recSize;
                }
            }
            if (type == 5) break; // end of archive
            pos = hStart + (long)headerSize + (long)dataSize;
        }
        d.Message = "Archive is not password protected.";
    }

    private static HashTarget Rar5Target(byte[] salt, int kdf, byte[] iv, byte[] check) => new()
    {
        FormatId = "RAR5",
        FormatName = "RAR 5.x archive",
        Protection = $"AES-256, PBKDF2-HMAC-SHA256 {1 << kdf} iterations",
        Modes = [13000],
        HashLines = $"$rar5$16${Bin.Hex(salt)}${kdf}${Bin.Hex(iv)}$8${Bin.Hex(check)}",
        Speed = SpeedClass.VerySlow,
        MaxPasswordLength = 127,
    };

    private static ulong VInt(byte[] b, ref int p)
    {
        ulong v = 0;
        for (int shift = 0; shift < 64; shift += 7)
        {
            if (p >= b.Length) throw new FormatException("Truncated RAR5 header.");
            byte x = b[p++];
            v |= (ulong)(x & 0x7F) << shift;
            if ((x & 0x80) == 0) return v;
        }
        throw new FormatException("Bad RAR5 variable-length integer.");
    }

    // ------------------------------------------------------------------ RAR 3.x / 4.x

    private static void Rar4(Stream s, long pos, Detection d)
    {
        d.TypeName = "RAR 3.x archive";
        var mh = Bin.ReadAt(s, pos, 7);
        Bin.Need(mh, 0, 7);
        if (mh[2] != 0x73) throw new FormatException("RAR main header not found.");
        int flags = Bin.U16(mh, 3), size = Bin.U16(mh, 5);
        if (size < 13 || size > s.Length - pos) throw new FormatException("Bad RAR main header size.");
        if ((flags & 0x0080) != 0)
        {
            var tail = Bin.ReadAt(s, pos + size, 8 + 16);
            if (tail.Length < 24) throw new FormatException("Truncated encrypted RAR header.");
            d.Add("Encrypted file names", "yes");
            d.Target = new HashTarget
            {
                FormatId = "RAR3",
                FormatName = "RAR 3.x archive",
                Protection = "AES-128, SHA-1 x 262144",
                Modes = [12500],
                HashLines = $"$RAR3$*0*{Bin.Hex(tail, 0, 8)}*{Bin.Hex(tail, 8, 16)}",
                Speed = SpeedClass.VerySlow,
                MaxPasswordLength = 28,
            };
            return;
        }

        Rar3Entry? best = null;
        bool encrypted = false;
        long p = pos + size;
        for (int guard = 0; p < s.Length; guard++)
        {
            if (guard == 100000) throw new FormatException("Too many RAR blocks.");
            var bh = Bin.ReadAt(s, p, 7);
            Bin.Need(bh, 0, 7);
            int type = bh[2], bflags = Bin.U16(bh, 3), bsize = Bin.U16(bh, 5);
            if (bsize < 7 || bsize > s.Length - p) throw new FormatException("Bad RAR block size.");
            bh = Bin.ReadAt(s, p, bsize);
            if (type == 0x7b) break;
            ulong packed = 0;
            if ((bflags & 0x8000) != 0)
            {
                Bin.Need(bh, 7, 4);
                packed = Bin.U32(bh, 7);
            }
            if (type == 0x74)
            {
                Bin.Need(bh, 0, 32);
                if ((bflags & 0x8000) == 0) throw new FormatException("RAR file block has no data size.");
                ulong unpacked = Bin.U32(bh, 11);
                int nameOffset = 32;
                if ((bflags & 0x100) != 0)
                {
                    Bin.Need(bh, 32, 8);
                    packed |= (ulong)Bin.U32(bh, 32) << 32;
                    unpacked |= (ulong)Bin.U32(bh, 36) << 32;
                    nameOffset = 40;
                }
                int saltOffset = nameOffset + Bin.U16(bh, 26);
                Bin.Need(bh, nameOffset, saltOffset - nameOffset);
                if ((bflags & 0x400) != 0) Bin.Need(bh, saltOffset, 8);
                if ((bflags & 4) != 0)
                {
                    encrypted = true;
                    int method = bh[25];
                    // hashcat 7.1.2 limits the ciphertext hex token to 655056 characters.
                    bool usable = (bflags & 0x13) == 0 && (bflags & 0xe0) != 0xe0 &&
                        (bflags & 0x400) != 0 && bh[24] is >= 29 and <= 36 &&
                        method is >= 0x30 and <= 0x35 &&
                        packed is > 0 and <= 327528 && packed % 16 == 0 &&
                        unpacked is > 0 and <= 655360 &&
                        (method != 0x30 || packed == ((unpacked + 15) & ~15UL));
                    // Tiny entries provide weak CRC checks; prefer enough data to reject false passwords.
                    if (usable && (best is null ||
                        (unpacked >= 8 && best.Unpacked < 8) ||
                        (unpacked >= 8) == (best.Unpacked >= 8) &&
                        ((method == 0x30 && best.Method != 0x30) ||
                         (method == 0x30) == (best.Method == 0x30) && packed < (ulong)best.Packed)))
                    {
                        best = new Rar3Entry(p + bsize, (int)packed, (int)unpacked, method,
                            Bin.Slice(bh, saltOffset, 8), Bin.Slice(bh, 16, 4));
                    }
                }
            }
            if (packed > (ulong)(s.Length - p - bsize)) throw new FormatException("Truncated RAR file data.");
            p += bsize + (long)packed;
        }
        if (encrypted) d.Add("Encrypted file names", "no");
        if (best is not null)
        {
            var data = Bin.ReadAt(s, best.Offset, best.Packed);
            d.Target = new HashTarget
            {
                FormatId = "RAR3",
                FormatName = "RAR 3.x archive",
                Protection = "AES-128, SHA-1 x 262144",
                Modes = [best.Method == 0x30 ? 23700 : 23800],
                HashLines = $"$RAR3$*1*{Bin.Hex(best.Salt)}*{Bin.Hex(best.Crc)}*{best.Packed}*{best.Unpacked}*1*{Bin.Hex(data)}*{best.Method:x2}",
                Speed = SpeedClass.VerySlow,
                MaxPasswordLength = 128,
                Utf16Password = true,
                Notes = "Recovers the password for one encrypted file. Other files in the archive may use different passwords." +
                    (best.Unpacked < 8 ? " The selected file is very short: a reported password may be a false positive. Verify it by opening the archive." : ""),
            };
            return;
        }
        d.Message = encrypted
            ? "No usable encrypted RAR 3.x file found. Recovery needs a complete, salted RAR 3.x entry " +
              "that does not depend on earlier solid files, with at most 327,520 encrypted bytes and 655,360 unpacked bytes."
            : "Archive is not password protected.";
    }

    private sealed record Rar3Entry(long Offset, int Packed, int Unpacked, int Method, byte[] Salt, byte[] Crc);
}
