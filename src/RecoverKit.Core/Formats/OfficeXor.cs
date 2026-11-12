using System.Text;

namespace RecoverKit.Core.Formats;

/// <summary>Recovers XOR passwords from known plaintext, following MS-OFFCRYPTO 2.3.7.</summary>
internal static class OfficeXor
{
    private const int ReadLimit = 1 << 20;
    private static ReadOnlySpan<byte> Padding =>
        [0xbb, 0xff, 0xff, 0xba, 0xff, 0xff, 0xb9, 0x80, 0, 0xbe, 0x0f, 0, 0xbf, 0x0f, 0];

    internal static bool TryExtract(CompoundFile cf, Detection d)
    {
        // Encrypted OOXML can contain other streams; leave that dispatch alone.
        if (cf.HasStream("EncryptionInfo")) return false;
        if (cf.HasStream("WordDocument")) return TryWord(cf, d);
        if (cf.HasStream("Workbook") || cf.HasStream("Book")) return TryExcel(cf, d);
        return false;
    }

    private static bool TryWord(CompoundFile cf, Detection d)
    {
        var word = cf.ReadStream("WordDocument", ReadLimit)!;
        Bin.Need(word, 0, 0x20);
        int signature = Bin.U16(word, 0), version = Bin.U16(word, 2);
        bool old = version is >= 0x65 and <= 0x69;
        if (signature != 0xa5ec && !(old && signature == 0xa5dc))
            throw new FormatException("Invalid Word FIB signature.");
        int flags = Bin.U16(word, 0x0a);
        if (!old && (flags & 0x8100) != 0x8100) return false;
        d.TypeName = old ? "MS Word 6/95 document" : "MS Word 97-2003 document";
        if ((flags & 0x100) == 0)
        {
            d.Message = "Document is not password protected to open.";
            return true;
        }

        ushort verifier = Bin.U16(word, 0x0e), key = Bin.U16(word, 0x10);
        int start = old ? 52 : 68;
        Bin.Need(word, 0, start);
        var hints = WordHints(word, start);
        string? password = RecoverWord(word, start, key, verifier, hints);
        if (password is null && !old)
        {
            var table = cf.ReadStream((flags & 0x200) != 0 ? "1Table" : "0Table", ReadLimit);
            if (table is not null) password = RecoverWord(table, 0, key, verifier, hints);
        }
        Report(d, password);
        return true;
    }

    private static bool TryExcel(CompoundFile cf, Detection d)
    {
        var workbook = cf.ReadStream("Workbook", ReadLimit) ?? cf.ReadStream("Book", ReadLimit)!;
        Bin.Need(workbook, 0, 8);
        if (Bin.U16(workbook, 0) != 0x809) return false;
        int version = Bin.U16(workbook, 4);
        bool old = version == 0x500;
        if (!old && version != 0x600) return false;
        for (int pos = 0; pos + 4 <= workbook.Length;)
        {
            int type = Bin.U16(workbook, pos), length = Bin.U16(workbook, pos + 2);
            Bin.Need(workbook, pos + 4, length);
            if (type == 0x2f)
            {
                if (old ? length != 4 : length < 2)
                    throw new FormatException("Invalid Excel FILEPASS record length.");
                if (!old && Bin.U16(workbook, pos + 4) != 0) return false;
                if (!old && length != 6) throw new FormatException("Invalid XOR FILEPASS record length.");
                d.TypeName = old ? "MS Excel 5/95 workbook" : "MS Excel 97-2003 workbook";
                int offset = pos + (old ? 4 : 6);
                ushort key = Bin.U16(workbook, offset), verifier = Bin.U16(workbook, offset + 2);
                bool capped = (cf.Find("Workbook") ?? cf.Find("Book"))!.Size > ReadLimit;
                Report(d, RecoverExcel(workbook, pos + 4 + length, key, verifier, capped));
                return true;
            }
            if (type == 0x0a) break;
            pos += 4 + length;
        }
        if (!old) return false;
        d.TypeName = "MS Excel 5/95 workbook";
        d.Message = "Workbook is not password protected to open.";
        return true;
    }

    private static void Report(Detection d, string? password)
    {
        d.Add("Protection", "XOR obfuscation (16-bit key and password verifier)");
        if (password is null)
        {
            d.Message = "XOR obfuscation detected, but the password could not be recovered from the available " +
                        "known plaintext. A verifier/key collision alone cannot safely decrypt this file. " +
                        "Automatic recovery currently supports printable ASCII passwords up to 15 characters.";
            return;
        }
        d.Unlocks.Add(new InstantUnlock
        {
            Title = "Office XOR password recovered",
            Description = "Recovered from the document's XOR array and checked against its key and verifier. " +
                          "Use this password to open the original in Office or LibreOffice. Saving an unprotected copy is not provided.",
            Password = password,
        });
    }

    private static string? RecoverExcel(byte[] data, int start, ushort key, ushort verifier, bool capped)
    {
        var counts = new int[16, 256];
        for (int pos = start; pos + 4 <= data.Length;)
        {
            int type = Bin.U16(data, pos), length = Bin.U16(data, pos + 2);
            // The read cap can end inside a later record; the complete prefix is enough for recovery.
            if (pos + 4 + length > data.Length)
            {
                if (capped) break;
                throw new FormatException("Truncated Excel record after FILEPASS.");
            }
            int payload = pos + 4, end = payload + length;
            if (type is not (0x809 or 0x2f or 0xe1 or 0x194 or 0x195 or 0x196 or 0x138))
            {
                if (type == 0x5c && length >= 32) // WRITEACCESS has space-padded user information.
                {
                    var array = new int[16];
                    for (int i = length - 16; i < length; i++)
                        array[(end + i) & 15] = Rotate(data[payload + i], 3) ^ 0x20;
                    var found = FromArray(array, key, verifier, 2);
                    if (found is not null) return found;
                }
                // Zero is the commonest byte in BIFF structures. Keep record headers and the
                // unencrypted BOUNDSHEET stream offset out of the frequency counts.
                for (int i = type == 0x85 ? 4 : 0; i < length; i++)
                    counts[(end + i) & 15, Rotate(data[payload + i], 3)]++;
            }
            pos = end;
        }
        return FromArray(MostFrequent(counts, 0), key, verifier, 2);
    }

    private static string? RecoverWord(byte[] data, int start, ushort key, ushort verifier, List<int[]> hints)
    {
        // Word 6/95 font tables commonly include this 15-byte name. Zero plaintext
        // is skipped by Method 2, so it cannot reveal an XOR array byte.
        ReadOnlySpan<byte> font = "Times New Roman"u8;
        var array = new int[16];
        for (int pos = start; pos + font.Length <= data.Length; pos++)
        {
            if (data[pos] == 0) continue;
            Array.Fill(array, -1);
            bool valid = true;
            for (int i = 0; i < font.Length; i++)
            {
                byte cipher = data[pos + i];
                if (cipher == 0) { valid = false; break; }
                array[(pos + i) & 15] = cipher ^ font[i];
            }
            if (!valid) continue;
            var found = FromArray(array, key, verifier, 7);
            if (found is not null) return found;
        }

        foreach (var hint in hints)
        {
            var found = FromArray(hint, key, verifier, 7);
            if (found is not null) return found;
        }

        // A UTF-16 font name reveals eight array positions. Its repeated positions
        // must agree; the other eight can come from text in the WordDocument stream.
        var combined = new int[16];
        for (int pos = start; pos + font.Length * 2 <= data.Length; pos++)
        {
            Array.Fill(array, -1);
            bool valid = true;
            for (int i = 0; i < font.Length; i++)
            {
                int offset = pos + i * 2, index = offset & 15;
                int value = data[offset] ^ font[i];
                if (data[offset] == 0 || data[offset + 1] != 0 ||
                    (array[index] >= 0 && array[index] != value)) { valid = false; break; }
                array[index] = value;
            }
            if (!valid) continue;
            foreach (var hint in hints)
            {
                for (int i = 0; i < 16; i++) combined[i] = array[i] >= 0 ? array[i] : hint[i];
                var found = FromArray(combined, key, verifier, 7);
                if (found is not null) return found;
            }
        }
        return null;
    }

    private static List<int[]> WordHints(byte[] data, int start)
    {
        var counts = new int[16, 256];
        for (int i = start; i < data.Length; i++)
            if (data[i] != 0) counts[i & 15, data[i]]++;
        ReadOnlySpan<byte> common = [.. " etaoinsrhld\r"u8, 0xff];
        var hints = new List<int[]>();
        foreach (byte plain in common) hints.Add(MostFrequent(counts, plain));
        return hints;
    }

    private static int[] MostFrequent(int[,] counts, byte plain)
    {
        var array = new int[16];
        for (int i = 0; i < 16; i++)
        {
            int best = 0;
            for (int value = 1; value < 256; value++)
                if (counts[i, value] > counts[i, best]) best = value;
            array[i] = counts[i, best] == 0 ? -1 : best ^ plain;
        }
        return array;
    }

    private static string? FromArray(int[] array, ushort key, ushort verifier, int rotation)
    {
        Span<byte> password = stackalloc byte[15];
        for (int length = 1; length <= 15; length++)
        {
            bool valid = true;
            for (int i = length; i < 16; i++)
            {
                int expected = Rotate(Padding[i - length] ^ ((key >> (8 * (i & 1))) & 255), rotation);
                if (array[i] >= 0 && array[i] != expected) { valid = false; break; }
            }
            if (!valid) continue;
            int missing = -1;
            for (int i = 0; i < length; i++)
            {
                if (array[i] < 0)
                {
                    if (missing >= 0) { valid = false; break; }
                    missing = i;
                    password[i] = 0;
                }
                else
                {
                    password[i] = (byte)(Rotate(array[i], 8 - rotation) ^ (key >> (8 * (i & 1))));
                    if (password[i] is < 0x20 or > 0x7e) { valid = false; break; }
                }
            }
            if (!valid) continue;
            if (missing >= 0)
            {
                int residual = Verifier(password[..length]) ^ verifier;
                int shift = (missing + 1) % 15;
                int value = ((residual >> shift) | (residual << (15 - shift))) & 0x7fff;
                if (value is < 0x20 or > 0x7e) continue;
                password[missing] = (byte)value;
            }
            var candidate = password[..length];
            if (Verifier(candidate) == verifier && Key(candidate) == key)
                return Encoding.ASCII.GetString(candidate);
        }
        return null;
    }

    internal static ushort Verifier(ReadOnlySpan<byte> password)
    {
        int verifier = 0;
        for (int i = password.Length - 1; i >= 0; i--)
            verifier = (((verifier << 1) | (verifier >> 14)) & 0x7fff) ^ password[i];
        return (ushort)((((verifier << 1) | (verifier >> 14)) & 0x7fff) ^ password.Length ^ 0xce4b);
    }

    internal static ushort Key(ReadOnlySpan<byte> password)
    {
        // MS-OFFCRYPTO's initial codes and XOR matrix express CRC-16/CCITT (0x1021,
        // initial 0xffff), with the high bit of each password byte cleared.
        int crc = 0xffff;
        foreach (byte value in password)
        {
            crc ^= (value & 0x7f) << 8;
            for (int bit = 0; bit < 8; bit++)
                crc = ((crc << 1) ^ ((crc & 0x8000) != 0 ? 0x1021 : 0)) & 0xffff;
        }
        return (ushort)crc;
    }

    private static byte Rotate(int value, int bits)
        => (byte)(((value & 255) << bits) | ((value & 255) >> (8 - bits)));
}
