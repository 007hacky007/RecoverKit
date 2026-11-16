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
        public ushort Flags, Method, ModTime, ModDate, VersionNeeded;
        public uint Crc, Disk;
        public byte[] RawName = [];
        public long CompSize, UncompSize, LocalOffset;
        public int AesStrength;     // 0 = not AES
        public ushort AesMethod;
        public bool Encrypted => (Flags & 1) != 0;
    }

    public static bool LooksLikeZip(Stream s) => FindEocd(s) >= 0;

    public static void Extract(Stream s, Detection d) => Extract(s, d, legacy: false);

    private static void Extract(Stream s, Detection d, bool legacy)
    {
        var entries = ReadCentralDirectory(s, out long delta, out _, out _);
        d.TypeName = "ZIP archive";
        d.Add("Entries", entries.Count.ToString());

        bool isOdf = entries.Any(e => e.Name == "mimetype") && entries.Any(e => e.Name == "META-INF/manifest.xml") && entries.All(e => !e.Encrypted);
        if (isOdf) { ExtractOdf(s, entries, delta, d); return; }

        if (entries.Any(e => e.Name == "[Content_Types].xml") && entries.All(e => !e.Encrypted))
        {
            d.TypeName = "Office Open XML document";
            d.Message = "Document is not password protected to open (OOXML packages are only encrypted when stored as OLE containers).";
            WordRestrictions.ExtractPackage(s, d);
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

        var classic = ChooseClassic(enc, legacy);
        if (classic is null)
        {
            d.Message = "Encrypted entries use a compression method that hashcat cannot verify (only stored/deflate are supported).";
            return;
        }
        var confirmer = BuildConfirmer(s, enc, classic, delta);
        if (!legacy && confirmer is null && ChooseClassic(enc, legacy: true) is { } safer && safer != classic)
        {
            classic = safer;
            confirmer = BuildConfirmer(s, enc, classic, delta);
        }
        d.Target = Pkzip(s, classic, delta, d, confirmer, confirmer is null && classic.Method == 0
            ? "The archive has only one encrypted file and it is stored (not compressed): very rarely a wrong password " +
              "passes its check. Open the archive with the recovered password to make sure it is the right one."
            : null);
        if (confirmer is not null)
        {
            d.Target.ConfirmPassword = confirmer.Confirm;
            d.Add("Also checked against", $"{confirmer.Entries} other encrypted file(s)" +
                  (confirmer.FullChecks < confirmer.Entries ? $" ({confirmer.FullChecks} with their whole data)" : ""));
        }
        if (d.Target.ZipPartial is { } partial)
        {
            var kernel = Native.Kernels.ZipCryptoKernel.TryParse(d.Target.HashLines, partial)
                ?? throw new FormatException("The ZIP entry cannot be checked from the archive.");
            d.Target.ConfirmPassword = password => (confirmer?.Confirm(password) ?? true) && kernel.Verify(password);
        }
        if (s is MultiVolumeStream)
        {
            d.Add("Fast key search", "Stay key recovery and decrypted-copy writing are not supported for split ZIP archives. Use password recovery instead.");
        }
        else d.Target.StayZip = CollectStayTarget(s, enc, delta);
        if (!legacy)
        {
            d.Target.ZipCheckBytes = BuildCheckBytes(s, classic, delta, d.Target, confirmer);
            if (ChooseClassic(enc, legacy: true) != classic)
            {
                var old = new Detection { FilePath = d.FilePath };
                Extract(s, old, legacy: true);
                d.Target.LegacyZipTarget = old.Target;
            }
        }
    }

    // Live replacement-kernel estimates: stored 2484 M/s, deflate 781 M/s on Apple GPU.
    // Scale by encrypted bytes for survivor verification. Retune these two rates after NVIDIA runs.
    internal const double StoredRate = 2484, DeflatedRate = 781;

    private static ZipEntry? ChooseClassic(List<ZipEntry> enc, bool legacy)
    {
        var usable = enc.Where(e => e.Method is 0 or 8 && e.CompSize > 12).ToList();
        var fits = usable.Where(e => e.CompSize <= HashcatMaxData).ToList();
        if (fits.Count > 0) usable = fits;
        var deflated = usable.Where(e => e.Method == 8).MinBy(e => e.CompSize);
        var stored = usable.Where(e => e.Method == 0).MinBy(e => e.CompSize);
        if (deflated is null || stored is null) return deflated ?? stored;
        // A stored prefix cannot be checked safely on the GPU; keep a deflated fallback.
        if (!legacy && stored.CompSize > HashcatMaxData) return deflated;
        bool confirmation = enc.Any(e => e != stored && e.LocalOffset != stored.LocalOffset && e.AesStrength == 0 && e.CompSize >= 12);
        double ratio = !legacy && confirmation ? StoredRate / DeflatedRate : 1.0 / 8;
        return stored.CompSize <= deflated.CompSize * ratio ? stored : deflated;
    }

    private static ZipCheckBytesTarget? BuildCheckBytes(Stream s, ZipEntry attacked, long delta, HashTarget target, ZipPasswordConfirmer? confirmer)
    {
        ushort crc = (ushort)(attacked.Crc >> 16), time = (attacked.Flags & 8) != 0 ? attacked.ModTime : crc;
        var checks = new[] { new ZipPasswordConfirmer.Check(attacked.Name,
                Bin.ReadAt(s, EntryDataOffset(s, attacked, delta), 12), crc, time, null,
                attacked.VersionNeeded is > 0 and < 20 && (attacked.Flags & 8) == 0) }
            .Concat(confirmer?.Checks ?? []).DistinctBy(c => Bin.Hex(c.Header)).ToList();
        // A sibling's second byte is constrained only when its full verifier checks it too.
        var old = checks.Where(c => c.TwoCheckBytes).ToList();
        int checkBytes = old.Count * 16 >= ZipCheckBytesTarget.MinimumCheckBits ? 2 : 1;
        var used = (checkBytes == 2 ? old : checks).Take(ZipCheckBytesTarget.MaximumEntries).ToList();
        if (used.Count * checkBytes * 8 < ZipCheckBytesTarget.MinimumCheckBits) return null;
        var fields = new List<string> { "$pkzip2$" + used.Count, checkBytes.ToString() };
        foreach (var c in used)
            // 17230 accepts either field's high byte, exactly as the confirmer does. Method 0
            // prevents its extra deflate-byte check from narrowing that accepted set.
            fields.AddRange(["1", "0", "0", "c", c.CrcChecksum.ToString("x4"), c.TimeChecksum.ToString("x4"), Bin.Hex(c.Header)]);
        fields.Add("$/pkzip2$");
        var kernel = Native.Kernels.ZipCryptoKernel.TryParse(target.HashLines, target.ZipPartial);
        return kernel is null ? null : new(string.Join('*', fields),
            password => (target.ConfirmPassword?.Invoke(password) ?? true) && kernel.Verify(password));
    }

    private const long HashcatMaxData = 320 * 1024;
    // Crosses at least three 65535-byte stored deflate blocks; shorter prefixes admit too many header survivors.
    private const int PartialPrefixLength = 256 * 1024;

    // Limits for the confirmation entries: how many, and how much data is kept for full checks.
    private const int MaxConfirmEntries = 16;
    private const long MaxFullCheckEntry = 1 << 20;
    private const long FullCheckBudget = 4 << 20;

    /// <summary>
    /// The archive's other classic ZipCrypto entries, as a second check for candidates that pass the
    /// hash (null when there are none). Small stored and deflated entries are checked with their whole
    /// data, the others by the check byte of their encryption header only.
    /// </summary>
    private static ZipPasswordConfirmer? BuildConfirmer(Stream s, List<ZipEntry> enc, ZipEntry attacked, long delta)
    {
        var others = enc.Where(e => e != attacked && e.LocalOffset != attacked.LocalOffset && e.AesStrength == 0 && e.CompSize >= 12)
            .OrderBy(e => e.Method is 0 or 8 && e.CompSize <= MaxFullCheckEntry ? 0 : 1)
            .ThenBy(e => e.CompSize)
            .ToList();
        var checks = new List<ZipPasswordConfirmer.Check>();
        long budget = FullCheckBudget;
        foreach (var e in others)
        {
            if (checks.Count >= MaxConfirmEntries) break;
            try
            {
                bool full = e.Method is 0 or 8 && e.CompSize <= Math.Min(MaxFullCheckEntry, budget);
                byte[] data = full ? ReadEntryData(s, e, delta) : Bin.ReadAt(s, EntryDataOffset(s, e, delta), 12);
                if (data.Length < 12) continue;
                Native.Kernels.ZipCryptoKernel? kernel = null;
                if (full)
                {
                    kernel = Native.Kernels.ZipCryptoKernel.TryParse(PkzipLine(e, data));
                    budget -= e.CompSize;
                }
                ushort crcCheck = (ushort)(e.Crc >> 16);
                ushort timeCheck = (e.Flags & 8) != 0 ? e.ModTime : crcCheck;
                checks.Add(new ZipPasswordConfirmer.Check(e.Name, data[..12], crcCheck, timeCheck, kernel,
                    kernel is not null && e.VersionNeeded is > 0 and < 20 && (e.Flags & 8) == 0));
            }
            catch (Exception ex) when (s is not MultiVolumeStream && ex is (FormatException or UnsupportedFormatException or IOException or OverflowException or ArgumentOutOfRangeException))
            {
                // a truncated/corrupt entry cannot confirm anything; skip it
            }
        }
        return checks.Count == 0 ? null : new ZipPasswordConfirmer(checks);
    }

    /// <summary>
    /// Gathers every classic ZipCrypto entry (any compression method, header at least 12 bytes) in
    /// archive order, with its stored 12-byte encryption header - the payload for Stay's attack.
    /// </summary>
    private static ZipStayTarget? CollectStayTarget(Stream s, List<ZipEntry> enc, long delta)
    {
        // Stay's full-entry verification and decrypted copy use int-sized buffers.
        var usable = enc.Where(e => e.AesStrength == 0 && e.CompSize >= 12 && e.CompSize <= int.MaxValue).ToList();
        if (usable.Count < 2) return null;
        var entries = new List<ZipStayEntry>();
        foreach (var e in usable)
        {
            try
            {
                long dataOffset = EntryDataOffset(s, e, delta);
                if (dataOffset < 0 || e.CompSize > s.Length - dataOffset) continue;
                entries.Add(new ZipStayEntry
                {
                    Name = e.Name,
                    StoredHeader = Bin.ReadAt(s, dataOffset, 12),
                    Crc = e.Crc,
                    Flags = e.Flags,
                    Method = e.Method,
                    CompSize = e.CompSize,
                    UncompSize = e.UncompSize,
                    LocalOffset = e.LocalOffset,
                    DataOffset = dataOffset,
                });
            }
            catch (Exception ex) when (s is not MultiVolumeStream && ex is (FormatException or UnsupportedFormatException or IOException or OverflowException or ArgumentOutOfRangeException))
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

    private static HashTarget Pkzip(Stream s, ZipEntry e, long delta, Detection d, ZipPasswordConfirmer? confirmer, string? notes)
    {
        bool partial = e.CompSize > HashcatMaxData;
        long offset = EntryDataOffset(s, e, delta);
        if (offset < 0 || e.CompSize > s.Length - offset) throw new FormatException("ZIP entry is truncated.");
        var data = partial ? Bin.ReadAt(s, offset, PartialPrefixLength) : ReadEntryData(s, e, delta);
        int mode = e.Method == 8 ? 17200 : 17210;
        d.TypeName = "ZIP archive (ZipCrypto)";
        d.Add("Attacked entry", $"{e.Name} ({e.CompSize:N0} bytes, {(e.Method == 8 ? "deflate" : "stored")})");
        return new HashTarget
        {
            FormatId = "ZIPC",
            FormatName = "ZIP archive (ZipCrypto)",
            Protection = "ZipCrypto (PKZIP 2.0)",
            Modes = [mode],
            HashLines = PkzipLine(e, data, partial),
            Speed = SpeedClass.VeryFast,
            ZipPartial = partial
                ? new(d.FilePath, offset, e.CompSize, e.UncompSize, e.Crc, e.Method) { Siblings = confirmer?.HeaderChecks ?? [] }
                : null,
            Notes = partial
                ? e.Method == 0
                    ? "Only the beginning of the file fits the GPU check; this uncompressed file uses the CPU to avoid missing the password."
                    : "Only the beginning of the file is given to the GPU; passwords are checked against the whole file."
                : notes,
        };
    }

    /// <summary>hashcat's $pkzip2$ line for one entry, with full data or a bounded prefix.</summary>
    private static string PkzipLine(ZipEntry e, byte[] data, bool partial = false)
    {
        int checksumFromCrc = (int)(e.Crc >> 16);
        // The header's check byte is the CRC's high byte, or the modification time's high byte when
        // the entry uses a data descriptor (flag bit 3). Emitting the time checksum only in that case
        // lets hashcat and the built-in engine test one byte instead of two (half the false positives).
        int checksumFromTime = (e.Flags & 8) != 0 ? e.ModTime : checksumFromCrc;
        string checkBytes = e.VersionNeeded is > 0 and < 20 && (e.Flags & 8) == 0 ? "2" : "1";
        if (partial)
            return string.Join('*', "$pkzip2$1", checkBytes, "1", "0", e.Method.ToString(), data.Length.ToString("x"),
                checksumFromCrc.ToString("x4"), checksumFromTime.ToString("x4"), Bin.Hex(data), "$/pkzip2$");
        return string.Join('*',
            "$pkzip2$1", checkBytes, "2", "0",
            e.CompSize.ToString("x"), e.UncompSize.ToString("x"), e.Crc.ToString("x8"),
            "0", "0", e.Method.ToString(), data.Length.ToString("x"),
            checksumFromCrc.ToString("x4"), checksumFromTime.ToString("x4"), Bin.Hex(data), "$/pkzip2$");
    }

    private static void ExtractOdf(Stream s, List<ZipEntry> entries, long delta, Detection d)
    {
        d.TypeName = "OpenDocument file";
        using var package = new ZipArchive(s, ZipArchiveMode.Read, leaveOpen: true);
        var doc = RestrictionCopy.ReadXml(package, "META-INF/manifest.xml")
            ?? throw new FormatException("OpenDocument manifest is missing.");
        XNamespace m = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0";

        var fileEntries = doc.Descendants(m + "file-entry").Where(fe => fe.Element(m + "encryption-data") is not null).ToList();
        if (fileEntries.Count == 0) { d.Message = "Document is not password protected to open."; OdtRestrictions.ExtractPackage(s, d); return; }

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

    internal static long FindEocd(Stream s)
    {
        if (s.Length < 22) return -1;
        int tail = (int)Math.Min(s.Length, 65535 + 22);
        var buf = Bin.ReadAt(s, s.Length - tail, tail);
        for (int i = buf.Length - 22; i >= 0; i--)
            if (buf[i] == 0x50 && buf[i + 1] == 0x4B && buf[i + 2] == 0x05 && buf[i + 3] == 0x06
                && (s is not MultiVolumeStream || i + 22 + Bin.U16(buf, i + 20) == buf.Length))
                return s.Length - tail + i;
        return -1;
    }

    internal static List<ZipEntry> ReadCentralDirectory(Stream s, out long delta, out long cdStart, out byte[] cd)
    {
        long eocd = FindEocd(s);
        if (eocd < 0) throw new FormatException("ZIP end of central directory not found.");
        var e = Bin.ReadAt(s, eocd, 22);
        long total = Bin.U16(e, 10), cdSize = Bin.U32(e, 12), cdOffset = Bin.U32(e, 16);
        uint disk = Bin.U16(e, 4), cdDisk = Bin.U16(e, 6);
        var volumes = s as MultiVolumeStream;
        bool spanned = volumes?.DiskRelative == true;
        long expectedEnd = eocd;
        bool needs64 = cdSize == uint.MaxValue || cdOffset == uint.MaxValue
            || disk == ushort.MaxValue || cdDisk == ushort.MaxValue;
        bool has64 = false;
        if (eocd >= 20)
        {
            var loc = Bin.ReadAt(s, eocd - 20, 20);
            if (Bin.U32(loc, 0) == 0x07064b50)
            {
                has64 = true;
                uint zDisk = Bin.U32(loc, 4), disks = Bin.U32(loc, 16);
                long zOffset = Zip64Value(loc, 8);
                long z64 = ResolveOffset(s, zDisk, zOffset);
                var z = Bin.ReadAt(s, z64, 56);
                Bin.Need(z, 0, 56);
                if (Bin.U32(z, 0) != 0x06064b50 || Zip64Value(z, 4) < 44)
                    throw new FormatException("Bad ZIP64 end of central directory.");
                disk = Bin.U32(z, 16);
                cdDisk = Bin.U32(z, 20);
                // Some single-file ZIP64 writers store 0 as the total disk count.
                if (disks == 0 && !spanned) disks = 1;
                if (disk != zDisk || disks == 0 || disk >= disks)
                    throw new FormatException("Inconsistent ZIP64 disk numbers.");
                if (spanned) volumes!.ValidateDiskCount(disks);
                else if (disks != 1) throw new FormatException("ZIP64 archive requires split ZIP parts.");
                total = Zip64Value(z, 32);
                cdSize = Zip64Value(z, 40);
                cdOffset = Zip64Value(z, 48);
                expectedEnd = z64;
            }
        }
        if (needs64 && !has64) throw new FormatException("ZIP64 locator is missing.");
        if (cdSize > 256L * 1024 * 1024 || cdSize > expectedEnd)
            throw new FormatException("ZIP central directory is too large or truncated.");
        if (spanned)
        {
            // The ZIP64 record may precede the locator on another disk; the EOCD names the last disk.
            if (!has64) volumes!.ValidateDiskCount(disk + 1);
            delta = 0;
            cdStart = ResolveOffset(s, cdDisk, cdOffset);
        }
        else
        {
            if (disk != 0 || cdDisk != 0) throw new FormatException("ZIP archive requires split ZIP parts.");
            if (cdOffset > expectedEnd - cdSize)
                throw new FormatException("ZIP central directory offset is outside the archive.");
            delta = expectedEnd - cdOffset - cdSize; // self-extracting prefix
            cdStart = checked(cdOffset + delta);
        }
        if (cdSize > expectedEnd - cdStart)
            throw new FormatException("ZIP central directory is too large or truncated.");

        var cdBytes = Bin.ReadAt(s, cdStart, (int)cdSize);
        cd = cdBytes;
        var list = new List<ZipEntry>();
        int p = 0;
        while (p + 46 <= cdBytes.Length && Bin.U32(cdBytes, p) == 0x02014b50)
        {
            var ze = new ZipEntry
            {
                VersionNeeded = Bin.U16(cd, p + 6),
                Flags = Bin.U16(cd, p + 8),
                Method = Bin.U16(cd, p + 10),
                ModTime = Bin.U16(cd, p + 12),
                ModDate = Bin.U16(cd, p + 14),
                Crc = Bin.U32(cd, p + 16),
                CompSize = Bin.U32(cd, p + 20),
                UncompSize = Bin.U32(cd, p + 24),
                LocalOffset = Bin.U32(cd, p + 42),
                Disk = Bin.U16(cd, p + 34),
            };
            int nameLen = Bin.U16(cd, p + 28), extraLen = Bin.U16(cd, p + 30), commentLen = Bin.U16(cd, p + 32);
            Bin.Need(cdBytes, p + 46, nameLen + extraLen + commentLen);
            ze.RawName = cdBytes.AsSpan(p + 46, nameLen).ToArray();
            ze.Name = ((ze.Flags & 0x800) != 0 ? Encoding.UTF8 : Encoding.Latin1).GetString(cdBytes, p + 46, nameLen);
            bool needsExtra64 = ze.CompSize == uint.MaxValue || ze.UncompSize == uint.MaxValue
                || ze.LocalOffset == uint.MaxValue || ze.Disk == ushort.MaxValue;
            bool extra64 = ParseExtra(cdBytes, p + 46 + nameLen, extraLen, ze);
            if (needsExtra64 && !extra64)
                throw new FormatException("ZIP64 entry extra field is missing or incomplete.");
            ze.LocalOffset = ResolveOffset(s, ze.Disk, ze.LocalOffset);
            list.Add(ze);
            p += 46 + nameLen + extraLen + commentLen;
        }
        if (list.Count != total) throw new FormatException("ZIP central directory entry count does not match its records.");
        return list;
    }

    private static bool ParseExtra(byte[] b, int o, int len, ZipEntry ze)
    {
        bool zip64 = false;
        int end = o + len;
        while (o + 4 <= end)
        {
            int id = Bin.U16(b, o), size = Bin.U16(b, o + 2);
            int d = o + 4;
            if (d + size > end) throw new FormatException("Truncated ZIP extra field.");
            if (id == 0x0001)
            {
                zip64 = true;
                int q = d;
                long Value64()
                {
                    if (q + 8 > d + size) throw new FormatException("Truncated ZIP64 extra field.");
                    long value = Zip64Value(b, q); q += 8; return value;
                }
                if (ze.UncompSize == uint.MaxValue) ze.UncompSize = Value64();
                if (ze.CompSize == uint.MaxValue) ze.CompSize = Value64();
                if (ze.LocalOffset == uint.MaxValue) ze.LocalOffset = Value64();
                if (ze.Disk == ushort.MaxValue)
                {
                    if (q + 4 > d + size) throw new FormatException("Truncated ZIP64 disk number.");
                    ze.Disk = Bin.U32(b, q);
                }
            }
            else if (id == 0x9901 && size >= 7)
            {
                ze.AesStrength = b[d + 4];
                ze.AesMethod = Bin.U16(b, d + 5);
            }
            o = d + size;
        }
        return zip64;
    }

    private static long Zip64Value(byte[] bytes, int offset)
    {
        ulong value = Bin.U64(bytes, offset);
        return value <= long.MaxValue ? (long)value : throw new FormatException("ZIP64 value exceeds supported file size.");
    }

    private static long ResolveOffset(Stream s, uint disk, long offset)
    {
        if (s is MultiVolumeStream { DiskRelative: true } volumes) return volumes.DiskOffset(disk, offset);
        if (disk != 0) throw new FormatException("ZIP entry requires split ZIP parts.");
        return offset;
    }

    /// <summary>Absolute offset of an entry's stored body, after validating its local record.</summary>
    private static long EntryDataOffset(Stream s, ZipEntry e, long delta)
    {
        if (delta < 0 || delta > s.Length || e.LocalOffset < 0 || e.LocalOffset > s.Length - delta)
            throw new FormatException("ZIP local header offset is outside the archive.");
        long lh = e.LocalOffset + delta;
        var h = Bin.ReadAt(s, lh, 30);
        Bin.Need(h, 0, 30);
        if (Bin.U32(h, 0) != 0x04034b50) throw new FormatException("Bad ZIP local header.");
        int nameLen = Bin.U16(h, 26), extraLen = Bin.U16(h, 28);
        // Preserve the single-file reader's tolerance for legacy and repaired local headers.
        if (s is not MultiVolumeStream) return lh + 30 + nameLen + extraLen;
        var rest = Bin.ReadAt(s, lh + 30, nameLen + extraLen);
        Bin.Need(rest, 0, nameLen + extraLen);
        if (!rest.AsSpan(0, nameLen).SequenceEqual(e.RawName)
            || Bin.U16(h, 6) != e.Flags || Bin.U16(h, 8) != e.Method
            || Bin.U16(h, 10) != e.ModTime || Bin.U16(h, 12) != e.ModDate
            || (e.VersionNeeded is > 0 and < 20 && Bin.U16(h, 4) >= 20))
            throw new FormatException($"ZIP local header does not match the central directory for '{e.Name}'.");
        var local = new ZipEntry { CompSize = Bin.U32(h, 18), UncompSize = Bin.U32(h, 22) };
        bool needsLocal64 = local.CompSize == uint.MaxValue || local.UncompSize == uint.MaxValue;
        if (!ParseExtra(rest, nameLen, extraLen, local) && needsLocal64)
            throw new FormatException("ZIP64 local sizes are missing.");
        bool descriptor = (e.Flags & 8) != 0;
        bool Matches(long value, long expected) => value == expected || (descriptor && value == 0);
        if (!Matches(local.CompSize, e.CompSize) || !Matches(local.UncompSize, e.UncompSize)
            || (!descriptor && Bin.U32(h, 14) != e.Crc)
            || (descriptor && Bin.U32(h, 14) != 0 && Bin.U32(h, 14) != e.Crc)
            || local.AesStrength != e.AesStrength || local.AesMethod != e.AesMethod)
            throw new FormatException($"ZIP local sizes or encryption do not match the central directory for '{e.Name}'.");
        long dataOff = checked(lh + 30 + nameLen + extraLen);
        if (e.CompSize > s.Length - dataOff) throw new FormatException("ZIP entry is truncated.");
        return dataOff;
    }

    private static byte[] ReadEntryData(Stream s, ZipEntry e, long delta)
    {
        long dataOff = EntryDataOffset(s, e, delta);
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
