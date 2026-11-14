namespace RecoverKit.Core.Formats;

/// <summary>Opens a file, recognises its format and extracts an attackable hash.</summary>
public static class FormatDetector
{
    public static readonly string[] OpenFilter =
    [
        "All supported files|*.doc;*.docx;*.docm;*.dotx;*.xls;*.xlsx;*.xlsm;*.xltx;*.xlsb;*.ppt;*.pptx;*.pptm;*.odt;*.ods;*.odp;*.odg;*.odf;*.zip;*.zipx;*.rar;*.7z;*.7z.001;*.pdf;*.22000;*.hccapx;*.hccap;*.exe;*.plist;*.ipd;*.kdbx;*.kdb;*.json;*.ldb;*.log;*.seco;UTC--*;default_wallet;*.ab;*.mdb;*.mde;*.accdb",
        "MS Office documents|*.doc;*.docx;*.docm;*.dotx;*.xls;*.xlsx;*.xlsm;*.xltx;*.xlsb;*.ppt;*.pptx;*.pptm",
        "Access databases|*.mdb;*.mde;*.accdb",
        "OpenDocument files|*.od?;*.sx?",
        "ZIP archives|*.zip;*.zipx",
        "RAR archives|*.rar",
        "7-Zip archives|*.7z;*.7z.001",
        "KeePass databases|*.kdbx;*.kdb",
        "PDF files|*.pdf",
        "WPA handshakes|*.22000;*.hccapx;*.hccap",
        "Apple iOS backup manifest|*.plist",
        "Android backups|*.ab",
        "Self-extracting archives|*.exe",
        "Cryptocurrency wallets|*.json;*.ldb;*.log;*.seco;UTC--*;default_wallet",
        "All files|*.*",
    ];

    public static Detection Detect(string path, string? keePassKeyfile = null)
    {
        var d = new Detection { FilePath = path };
        try
        {
            // A split 7z archive (.7z.001, .002, ...) is read across its parts as one file.
            var parts = MultiVolumeStream.SevenZipParts(path);
            using Stream s = parts is not null ? new MultiVolumeStream(parts) : new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (parts is not null) d.Add("Parts", parts.Count == 1 ? Path.GetFileName(parts[0]) : $"{parts.Count} ({Path.GetFileName(parts[0])} to {Path.GetFileName(parts[^1])})");
            d.Add("File size", $"{s.Length:N0} bytes");
            if (s.Length == 0) { d.Message = "File is empty."; return d; }
            var head = Bin.ReadAt(s, 0, 4096);
            if (keePassKeyfile is not null && !KeePassExtractor.IsKeePass(head))
                throw new UnsupportedFormatException("A KeePass keyfile can only be used with a KeePass database.");

            if (AccessExtractor.IsAccess(head))
            {
                AccessExtractor.Extract(s, d);
            }
            else if (CompoundFile.IsCompoundFile(head))
            {
                var cf = new CompoundFile(s);
                if (!SpreadsheetProtection.TryExtractBiff(cf, d)) OfficeExtractor.Extract(cf, d);
            }
            else if (head.Length >= 4 && head[0] == 'P' && head[1] == 'K' && ZipExtractor.LooksLikeZip(s))
            {
                if (!SpreadsheetProtection.TryExtractZip(s, d)) ZipExtractor.Extract(s, d);
            }
            else if (head.Length >= 7 && head[0] == 'R' && head[1] == 'a' && head[2] == 'r' && head[3] == '!')
            {
                RarExtractor.Extract(s, d);
            }
            else if (PdfExtractor.IsPdf(head))
            {
                PdfExtractor.Extract(s, d);
            }
            else if (SevenZipExtractor.IsSevenZip(head))
            {
                SevenZipExtractor.Extract(s, d);
            }
            else if (KeePassExtractor.IsKeePass(head))
            {
                KeePassExtractor.Extract(s, d, keePassKeyfile);
            }
            else if (AndroidBackupExtractor.IsBackup(head))
            {
                AndroidBackupExtractor.Extract(s, d);
            }
            else if (WpaExtractor.IsHashLines(head) || WpaExtractor.IsHccapx(head) || path.EndsWith(".hccap", StringComparison.OrdinalIgnoreCase))
            {
                WpaExtractor.Extract(s, path, head, d);
            }
            else if (head.Length >= 2 && head[0] == 'M' && head[1] == 'Z')
            {
                // Self-extracting archive: RAR SFX carries its own signature, ZIP SFX is found from the end.
                if (RarExtractor.FindSignature(s).Offset > 0) RarExtractor.Extract(s, d);
                else if (ZipExtractor.LooksLikeZip(s)) ZipExtractor.Extract(s, d);
                else if (SevenZipExtractor.FindSignature(s) > 0) SevenZipExtractor.Extract(s, d);
                else { d.TypeName = "Windows executable"; d.Message = "No embedded RAR, ZIP or 7z archive found."; }
            }
            else if (IsBlackBerry(head, path))
            {
                d.TypeName = "BlackBerry backup";
                d.Message = "BlackBerry .ipd backups are recognized but have no hashcat kernel, so passwords " +
                            "for them cannot be recovered with this engine.";
            }
            else if (AppleBackupExtractor.IsManifest(path, head))
            {
                AppleBackupExtractor.Extract(s, path, d);
            }
            else if (IsCapture(head))
            {
                d.TypeName = "Network capture";
                d.Message = "Raw captures must be converted to the hashcat 22000 format first, e.g. " +
                            "hcxpcapngtool -o handshake.22000 capture.pcapng, then open the .22000 file.";
            }
            else if (WalletExtractor.TryExtract(s, d))
            {
                // Wallets have varied names; the extractor validates their content.
            }
            else
            {
                d.Message = "File format is not recognized. If this is a TrueCrypt/VeraCrypt volume or you have a hash, " +
                            "use File > Open As...";
            }
        }
        catch (UnsupportedFormatException ex) { d.Message = ex.Message; }
        catch (FormatException ex) { d.Message = "File is damaged or has unexpected structure: " + ex.Message; }
        catch (IOException ex) { d.Message = "Cannot open file: " + ex.Message; }
        catch (UnauthorizedAccessException ex) { d.Message = "Cannot open file: " + ex.Message; }
        return d;
    }

    /// <summary>Builds a target from a hash the user typed or pasted (any hashcat mode).</summary>
    public static Detection FromManualHash(string label, int mode, string hashLines) => new()
    {
        FilePath = label,
        TypeName = $"Manual hash (hashcat mode {mode})",
        Target = new HashTarget
        {
            FormatId = "NONE",
            FormatName = $"hashcat mode {mode}",
            Protection = "user supplied",
            Modes = [mode],
            HashLines = hashLines.Trim(),
        },
    };

    private static bool IsBlackBerry(byte[] h, string path)
    {
        if (path.EndsWith(".ipd", StringComparison.OrdinalIgnoreCase)) return true;
        var sig = "Inter@ctive Pager Backup/Restore File"u8;
        return h.Length >= sig.Length && h.AsSpan(0, sig.Length).SequenceEqual(sig);
    }

    private static bool IsCapture(byte[] h) => h.Length >= 4 &&
        ((h[0] == 0xD4 && h[1] == 0xC3 && h[2] == 0xB2 && h[3] == 0xA1) ||
         (h[0] == 0xA1 && h[1] == 0xB2 && h[2] == 0xC3 && h[3] == 0xD4) ||
         (h[0] == 0x0A && h[1] == 0x0D && h[2] == 0x0D && h[3] == 0x0A));
}
