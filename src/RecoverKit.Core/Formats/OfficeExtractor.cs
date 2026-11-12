namespace RecoverKit.Core.Formats;

/// <summary>
/// Extracts hashcat hashes from MS Office documents stored as OLE compound files:
/// encrypted OOXML packages (Office 2007-2021, modes 9400/9500/9600) and legacy
/// Word/Excel 97-2003 RC4 encryption (modes 9700/9800).
/// </summary>
public static class OfficeExtractor
{
    public static void Extract(CompoundFile cf, Detection d)
    {
        if (cf.HasStream("EncryptionInfo") && cf.HasStream("EncryptedPackage"))
        {
            ExtractOoxml(cf, d);
        }
        else if (cf.HasStream("WordDocument"))
        {
            d.TypeName = "MS Word 97-2003 document";
            ExtractWord(cf, d);
        }
        else if (cf.HasStream("Workbook") || cf.HasStream("Book"))
        {
            d.TypeName = "MS Excel 97-2003 workbook";
            ExtractExcel(cf, d);
        }
        else if (cf.HasStream("PowerPoint Document"))
        {
            d.TypeName = "MS PowerPoint 97-2003 presentation";
            d.Message = "PowerPoint 97-2003 encryption is not supported by this version.";
        }
        else if (cf.HasStream("\u0005SummaryInformation") || cf.Entries.Count > 1)
        {
            d.TypeName = "OLE compound document";
            d.Message = "Unknown compound document type.";
        }
    }

    private static void ExtractOoxml(CompoundFile cf, Detection d)
    {
        var info = cf.ReadStream("EncryptionInfo", 1 << 20)!;
        Bin.Need(info, 0, 8);
        int vMajor = Bin.U16(info, 0), vMinor = Bin.U16(info, 2);
        d.TypeName = "MS Office 2007-2021 document";
        d.Add("Encryption info version", $"{vMajor}.{vMinor}");

        if (vMajor == 4 && vMinor == 4)
        {
            OfficeKnownPasswords.CheckOoxml(info, d);
            ExtractAgile(info, d);
            return;
        }
        if (vMinor == 2 && vMajor is 2 or 3 or 4)
        {
            ExtractStandard(info, d);
            OfficeKnownPasswords.CheckOoxml(info, d);
            return;
        }
        d.Message = $"Unsupported EncryptionInfo version {vMajor}.{vMinor}.";
    }

    private static void ExtractAgile(byte[] info, Detection d)
    {
        var key = OfficeKnownPasswords.AgileKey(info);

        string Attr(string n) => key.Attribute(n)?.Value ?? throw new FormatException($"Missing attribute '{n}'.");
        int spin = OfficeKnownPasswords.Number(Attr("spinCount"));
        int keyBits = OfficeKnownPasswords.Number(Attr("keyBits"));
        string hashAlg = OfficeDecryptor.HashName(Attr("hashAlgorithm"));
        string cipher = Attr("cipherAlgorithm");
        var salt = Convert.FromBase64String(Attr("saltValue"));
        var input = Convert.FromBase64String(Attr("encryptedVerifierHashInput"));
        var value = Convert.FromBase64String(Attr("encryptedVerifierHashValue"));

        (int mode, string ver, string id) = hashAlg switch
        {
            "SHA1" => (9500, "2010", "OF10"),
            "SHA512" => (9600, "2013", "OF13"),
            _ => throw new UnsupportedFormatException($"Agile encryption with {hashAlg} is not supported by hashcat."),
        };
        if (!cipher.Equals("AES", StringComparison.OrdinalIgnoreCase))
            throw new UnsupportedFormatException($"Agile encryption with cipher {cipher} is not supported by hashcat.");
        if (keyBits != (mode == 9500 ? 128 : 256))
            throw new UnsupportedFormatException($"Agile {hashAlg} with AES-{keyBits} is not supported by hashcat.");
        if (value.Length < 32) throw new FormatException("Encrypted verifier hash is too short.");

        d.TypeName = mode == 9600 ? "MS Office 2013-2021 document" : "MS Office 2010 document";
        d.Target = new HashTarget
        {
            FormatId = id,
            FormatName = d.TypeName,
            Protection = $"AES-{keyBits}, {hashAlg}, {spin} iterations",
            Modes = [mode],
            HashLines = $"$office$*{ver}*{spin}*{keyBits}*{salt.Length}*{Bin.Hex(salt)}*{Bin.Hex(input)}*{Bin.Hex(value.AsSpan(0, 32))}",
            Speed = SpeedClass.VerySlow,
            Utf16Password = true,
        };
    }

    private static void ExtractStandard(byte[] info, Detection d)
    {
        Bin.Need(info, 8, 4);
        int headerSize = (int)Bin.U32(info, 8);
        int h = 12;
        Bin.Need(info, h, 32);
        uint algId = Bin.U32(info, h + 8);
        int keySize = (int)Bin.U32(info, h + 16);
        int v = h + headerSize;
        Bin.Need(info, v, 4 + 16 + 16 + 4 + 20);
        int saltSize = (int)Bin.U32(info, v);
        if (saltSize != 16) throw new FormatException("Unexpected salt size.");
        var salt = Bin.Slice(info, v + 4, 16);
        var verifier = Bin.Slice(info, v + 20, 16);
        var verifierHash = Bin.Slice(info, v + 40, 20);

        if (algId is not (0x660E or 0x660F or 0x6610))
            throw new UnsupportedFormatException("Office 2007 standard encryption with RC4 is not supported.");

        d.TypeName = "MS Office 2007 document";
        d.Target = new HashTarget
        {
            FormatId = "OF07",
            FormatName = d.TypeName,
            Protection = $"AES-{keySize}, SHA-1, 50000 iterations",
            Modes = [9400],
            HashLines = $"$office$*2007*20*{keySize}*16*{Bin.Hex(salt)}*{Bin.Hex(verifier)}*{Bin.Hex(verifierHash)}",
            Speed = SpeedClass.Slow,
            Utf16Password = true,
        };
    }

    private static void ExtractWord(CompoundFile cf, Detection d)
    {
        var wd = cf.ReadStream("WordDocument", 4096)!;
        Bin.Need(wd, 0, 0x12);
        if (Bin.U16(wd, 0) != 0xA5EC) throw new FormatException("Invalid Word FIB signature.");
        ushort flags = Bin.U16(wd, 0x0A);
        bool encrypted = (flags & 0x0100) != 0;
        bool table1 = (flags & 0x0200) != 0;
        bool obfuscated = (flags & 0x8000) != 0;
        if (!encrypted) { d.Message = "Document is not password protected to open."; BinaryWordRestrictions.Extract(cf, d); return; }
        if (obfuscated) { d.Message = "Document uses XOR obfuscation (weak protection, instant removal is not implemented)."; return; }

        var table = cf.ReadStream(table1 ? "1Table" : "0Table", 4096)
                    ?? throw new FormatException("Word table stream is missing.");
        d.Target = Rc4Header(table, 0, "Word 97-2003", isWord: true);
        OfficeKnownPasswords.CheckRc4(table, 0, d, excel: false);
    }

    private static void ExtractExcel(CompoundFile cf, Detection d)
    {
        var wb = cf.ReadStream("Workbook", 1 << 16) ?? cf.ReadStream("Book", 1 << 16)!;
        int pos = 0;
        for (int n = 0; n < 64 && pos + 4 <= wb.Length; n++)
        {
            int type = Bin.U16(wb, pos), len = Bin.U16(wb, pos + 2);
            if (type == 0x002F) // FILEPASS
            {
                Bin.Need(wb, pos + 4, 2);
                int encType = Bin.U16(wb, pos + 4);
                if (encType == 0) { d.Message = "Workbook uses XOR obfuscation (weak protection, instant removal is not implemented)."; return; }
                d.Target = Rc4Header(wb, pos + 6, "Excel 97-2003", isWord: false);
                OfficeKnownPasswords.CheckRc4(wb, pos + 6, d, excel: true);
                return;
            }
            if (type == 0x000A) break; // EOF
            pos += 4 + len;
        }
        d.Message = "Workbook is not password protected to open.";
    }

    private static HashTarget Rc4Header(byte[] b, int o, string app, bool isWord)
    {
        Bin.Need(b, o, 4);
        int vMajor = Bin.U16(b, o), vMinor = Bin.U16(b, o + 2);
        if (vMajor == 1 && vMinor == 1)
        {
            Bin.Need(b, o + 4, 48);
            return new HashTarget
            {
                FormatId = "972K",
                FormatName = $"MS {app} document",
                Protection = "RC4 40-bit, MD5",
                Modes = [9700],
                HashLines = $"$oldoffice${(isWord ? 0 : 1)}*{Bin.Hex(b, o + 4, 16)}*{Bin.Hex(b, o + 20, 16)}*{Bin.Hex(b, o + 36, 16)}",
                Speed = SpeedClass.Fast,
                Utf16Password = true,
                MaxPasswordLength = 15,
                Notes = "40-bit RC4: the encryption key itself can also be searched exhaustively (hashcat modes 9710/9720).",
            };
        }
        if (vMinor == 2 && vMajor is 2 or 3 or 4)
        {
            Bin.Need(b, o, 12);
            int headerSize = (int)Bin.U32(b, o + 8);
            int h = o + 12;
            Bin.Need(b, h, 20);
            int keySize = (int)Bin.U32(b, h + 16);
            if (keySize == 0) keySize = 40;
            int v = h + headerSize;
            Bin.Need(b, v, 4 + 16 + 16 + 4 + 20);
            return new HashTarget
            {
                FormatId = "XP03",
                FormatName = $"MS {app} document",
                Protection = $"RC4 {keySize}-bit, SHA-1 (CryptoAPI)",
                Modes = [9800],
                HashLines = $"$oldoffice${(keySize == 40 ? 3 : 4)}*{Bin.Hex(b, v + 4, 16)}*{Bin.Hex(b, v + 20, 16)}*{Bin.Hex(b, v + 40, 20)}",
                Speed = SpeedClass.Fast,
                Utf16Password = true,
                MaxPasswordLength = 15,
            };
        }
        throw new UnsupportedFormatException($"Unsupported RC4 encryption header version {vMajor}.{vMinor}.");
    }
}
