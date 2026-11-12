using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using System.Xml.Linq;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class SpreadsheetProtectionTests : IDisposable
{
    private const string Ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-sheets-").FullName;

    [Theory]
    [InlineData(".xlsx")]
    [InlineData(".xlsm")]
    [InlineData(".xltx")]
    [InlineData(".bin")]
    public async Task DetectsContentAndRemovesOnlySelectedProtection(string extension)
    {
        var path = Ooxml(extension);
        var original = File.ReadAllBytes(path);
        var d = FormatDetector.Detect(path);
        Assert.Null(d.Target);
        Assert.Equal(4, d.Unlocks.Count);
        var sheet = Assert.Single(d.Unlocks, u => u.Description.Contains("Budget"));
        Assert.Equal("Sheet protection can be removed", sheet.Title);
        Assert.Equal(0xDAA7, LegacyHash(sheet.Password!)); // openpyxl's hash for 'secret'
        Assert.Contains("equivalent", sheet.Description);
        string output = Path.Combine(_dir, "out" + extension);
        await sheet.SaveAsync(path, output);
        Assert.Equal(original, File.ReadAllBytes(path));
        using var before = ZipFile.OpenRead(path);
        using var after = ZipFile.OpenRead(output);
        Assert.DoesNotContain("sheetProtection", Read(after, "xl/worksheets/sheet1.xml"));
        foreach (var entry in before.Entries.Where(e => e.FullName != "xl/worksheets/sheet1.xml"))
            Assert.Equal(Read(before, entry.FullName), Read(after, entry.FullName));
        Assert.Contains("workbookProtection", Read(after, "xl/workbook.xml"));
        Assert.Equal(3, FormatDetector.Detect(output).Unlocks.Count);
    }

    [Fact]
    public async Task WorkbookAndReadOnlyFindingsHaveIndependentSaves()
    {
        var path = Ooxml(".xlsx");
        var d = FormatDetector.Detect(path);
        foreach (var u in d.Unlocks.Where(u => !u.Title.StartsWith("Sheet")))
        {
            var output = Path.Combine(_dir, Guid.NewGuid() + ".xlsx");
            await u.SaveAsync(path, output);
            using var zip = ZipFile.OpenRead(output);
            var xml = Read(zip, "xl/workbook.xml");
            var removed = u.Title.StartsWith("Workbook") ? "workbookProtection" : "fileSharing";
            var kept = removed == "fileSharing" ? "workbookProtection" : "fileSharing";
            Assert.DoesNotContain(removed, xml);
            Assert.Contains(kept, xml);
        }
    }

    [Fact]
    public void Sha512AndChartsheetsAreRemovableWithoutClaimingAPassword()
    {
        var d = FormatDetector.Detect(Ooxml(".xlsx"));
        var chart = Assert.Single(d.Unlocks, u => u.Description.Contains("Chart"));
        Assert.Null(chart.Password);
        Assert.Contains("SHA-512", chart.Description);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BiffWordsAreZeroedWithoutChangingOtherBytes(bool mini)
    {
        var path = Path.Combine(_dir, "legacy.dat");
        var wb = Biff();
        File.WriteAllBytes(path, Compound(wb, mini));
        var original = File.ReadAllBytes(path);
        var d = FormatDetector.Detect(path);
        Assert.Equal(2, d.Unlocks.Count);
        foreach (var u in d.Unlocks)
        {
            Assert.Equal(0xDAA7, LegacyHash(u.Password!));
            var output = Path.Combine(_dir, Guid.NewGuid() + ".xls");
            await u.SaveAsync(path, output);
            var saved = File.ReadAllBytes(output);
            Assert.Equal(original.Length, saved.Length);
            using var stream = File.OpenRead(output);
            var content = new CompoundFile(stream).ReadStream("Workbook")!;
            Assert.Equal(mini ? wb.Length : 4096, content.Length);
            Assert.Single(FormatDetector.Detect(output).Unlocks);
            // Only the selected two-byte flag/hash words can change, including mini-stream files.
            Assert.InRange(original.Zip(saved).Count(p => p.First != p.Second), 3, 6);
        }
        Assert.Equal(original, File.ReadAllBytes(path));
    }

    [Theory]
    [InlineData("<broken")]
    [InlineData("<!DOCTYPE x [<!ENTITY a 'x'>]><worksheet xmlns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'>&a;</worksheet>")]
    public void MalformedXmlBecomesADetectionError(string xml)
    {
        var path = Ooxml(".xlsx", xml);
        var d = FormatDetector.Detect(path);
        Assert.Empty(d.Unlocks);
        Assert.Contains("damaged", d.Message!);
    }

    [Fact]
    public void TruncatedBiffDoesNotOfferPartialUnlocks()
    {
        var path = Path.Combine(_dir, "bad.xls");
        File.WriteAllBytes(path, Compound(Biff()[..^1], true));
        var d = FormatDetector.Detect(path);
        Assert.Empty(d.Unlocks);
        Assert.Contains("damaged", d.Message!);
    }

    [Fact]
    public void FilepassAfterManyRecordsNeverOffersSheetUnlocks()
    {
        var path = Path.Combine(_dir, "encrypted.xls");
        byte[] wb = [.. Record(0x0809, [0, 6, 5, 0]),
            .. Enumerable.Range(0, 70).SelectMany(_ => Record(0x0086, [0, 0])),
            .. Record(0x002f, [0, 0]), .. Biff()];
        File.WriteAllBytes(path, Compound(wb, true));
        var d = FormatDetector.Detect(path);
        Assert.Empty(d.Unlocks);
        Assert.Contains(d.Info, p => p.Key == "Notes" && p.Value.Contains("decrypt", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task OdsTableAndStructureProtectionAreRemovedSeparately()
    {
        var path = Path.Combine(_dir, "tables.bin");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            Write(zip, "mimetype", "application/vnd.oasis.opendocument.spreadsheet");
            Write(zip, "META-INF/manifest.xml", "<manifest xmlns='urn:oasis:names:tc:opendocument:xmlns:manifest:1.0'/>");
            Write(zip, "content.xml", "<office:document-content xmlns:office='urn:oasis:names:tc:opendocument:xmlns:office:1.0' xmlns:table='urn:oasis:names:tc:opendocument:xmlns:table:1.0'><office:body><office:spreadsheet table:structure-protected='true' table:protection-key='abc'><table:table table:name='Data' table:protected='true' table:protection-key='def'/></office:spreadsheet></office:body></office:document-content>");
        }
        var d = FormatDetector.Detect(path);
        Assert.Equal(2, d.Unlocks.Count);
        foreach (var u in d.Unlocks)
        {
            var output = Path.Combine(_dir, Guid.NewGuid() + ".ods");
            await u.SaveAsync(path, output);
            Assert.Single(FormatDetector.Detect(output).Unlocks);
        }
    }

    [Fact]
    public async Task CancellationAndSourceChecksLeaveFilesIntact()
    {
        var path = Ooxml(".xlsx");
        var u = FormatDetector.Detect(path).Unlocks[0];
        var output = Path.Combine(_dir, "existing.xlsx");
        File.WriteAllText(output, "keep");
        await Assert.ThrowsAsync<IOException>(() => u.SaveAsync(path, path));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => u.SaveAsync(path, output, new CancellationToken(true)));
        Assert.Equal("keep", File.ReadAllText(output));
        Assert.DoesNotContain(Directory.GetFiles(_dir), p => p.EndsWith(".tmp"));
    }

    [Fact]
    public void IgnoresInactiveOoxmlProtectionElements()
    {
        var path = Ooxml(".xlsx");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            foreach (var part in new[] { "xl/workbook.xml", "xl/worksheets/sheet1.xml", "xl/chartsheets/sheet1.xml" })
            {
                var xml = Read(zip, part);
                var doc = XDocument.Parse(xml);
                foreach (var e in doc.Descendants().Where(e => e.Name.LocalName is "workbookProtection" or "sheetProtection" or "fileSharing"))
                {
                    e.RemoveAttributes();
                    if (e.Name.LocalName == "fileSharing") e.SetAttributeValue("readOnlyRecommended", "false");
                }
                zip.GetEntry(part)!.Delete();
                Write(zip, part, doc.ToString());
            }
        }
        Assert.Empty(FormatDetector.Detect(path).Unlocks);
    }

    [Fact]
    public void DuplicateSpreadsheetPartsAreRejected()
    {
        var path = Ooxml(".xlsx");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
            Write(zip, "xl/worksheets/sheet1.xml", $"<worksheet xmlns='{Ns}'><sheetProtection sheet='1'/></worksheet>");
        var d = FormatDetector.Detect(path);
        Assert.Empty(d.Unlocks);
        Assert.Contains("damaged", d.Message!);
    }

    [Theory]
    [InlineData(0x8000)]
    [InlineData(0xffff)]
    [InlineData(0xce4b)]
    [InlineData(0xdaa7)]
    [InlineData(0x1234)]
    public void EquivalentPasswordMatchesIndependentVerifier(ushort hash)
    {
        var password = SpreadsheetProtection.EquivalentPassword(hash);
        if (hash < 0x8000) Assert.Null(password);
        else Assert.Equal(hash, LegacyHash(Assert.IsType<string>(password)));
    }

    [Fact]
    public async Task UntouchedZipPayloadsRemainByteIdentical()
    {
        var path = Ooxml(".xlsm");
        var output = Path.Combine(_dir, "copy.xlsm");
        await FormatDetector.Detect(path).Unlocks[0].SaveAsync(path, output);
        using var before = File.OpenRead(path);
        using var after = File.OpenRead(output);
        var entries = ZipExtractor.ReadCentralDirectory(before, out long deltaBefore, out _, out _);
        var saved = ZipExtractor.ReadCentralDirectory(after, out long deltaAfter, out _, out _);
        foreach (var e in entries.Where(e => e.Name != "xl/worksheets/sheet1.xml"))
        {
            var copy = Assert.Single(saved, c => c.Name == e.Name);
            Assert.Equal(e.Crc, copy.Crc);
            Assert.Equal(e.Method, copy.Method);
            Assert.Equal(e.CompSize, copy.CompSize);
            Assert.Equal(Raw(before, e.LocalOffset + deltaBefore, e.CompSize),
                Raw(after, copy.LocalOffset + deltaAfter, copy.CompSize));
        }
        static byte[] Raw(Stream stream, long offset, long count)
        {
            var header = Bin.ReadAt(stream, offset, 30);
            long start = offset + 30 + Bin.U16(header, 26) + Bin.U16(header, 28);
            return Bin.ReadAt(stream, start, (int)count);
        }
    }

    [Fact]
    public async Task FailedSavePreservesExistingOutputAndCleansTemporaryCopy()
    {
        var path = Ooxml(".xlsx");
        var unlock = FormatDetector.Detect(path).Unlocks[0];
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update)) zip.GetEntry("xl/worksheets/sheet1.xml")!.Delete();
        var output = Path.Combine(_dir, "existing.xlsx");
        File.WriteAllText(output, "keep");
        await Assert.ThrowsAsync<FormatException>(() => unlock.SaveAsync(path, output));
        Assert.Equal("keep", File.ReadAllText(output));
        Assert.DoesNotContain(Directory.GetFiles(_dir), p => p.EndsWith(".tmp"));
    }

    [Theory]
    [InlineData("workbookProtection-sheet_password-2013.xlsx", "Sheet protection can be removed")]
    [InlineData("workbookProtection-workbook_password-2013.xlsx", "Workbook structure protection can be removed")]
    [InlineData("openpyxl-protected.xls", "Sheet protection can be removed")]
    public async Task RealProgramFixturesCanBeUnlocked(string name, string title)
    {
        var assembly = typeof(SpreadsheetProtectionTests).Assembly;
        using var resource = assembly.GetManifestResourceStream("RecoverKit.Tests.Fixtures.Spreadsheets." + name)!;
        var path = Path.Combine(_dir, name);
        using (var file = File.Create(path)) resource.CopyTo(file);
        var original = File.ReadAllBytes(path);
        var d = FormatDetector.Detect(path);
        var unlock = Assert.Single(d.Unlocks);
        Assert.Equal(title, unlock.Title);
        if (name.EndsWith(".xls")) Assert.Equal(0xdaa7, LegacyHash(unlock.Password!));
        else { Assert.Null(unlock.Password); Assert.Contains("SHA-512", unlock.Description); }
        var output = Path.Combine(_dir, "unlocked-" + name);
        await unlock.SaveAsync(path, output);
        Assert.Empty(FormatDetector.Detect(output).Unlocks);
        Assert.Equal(original, File.ReadAllBytes(path));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EncryptedBiffStillUsesOfficeExtraction(bool oversized)
    {
        byte[] workbook = [.. Record(0x0809, [0, 6, 5, 0]),
            .. Record(0x002f, [1, 0, 1, 0, 1, 0, .. new byte[48]]), .. Record(0x000a, [])];
        var container = Compound(workbook, false);
        if (oversized) BinaryPrimitives.WriteUInt32LittleEndian(container.AsSpan(1152 + 120), 64 * 1024 * 1024 + 1);
        var path = Path.Combine(_dir, "encrypted.xls");
        File.WriteAllBytes(path, container);
        var d = FormatDetector.Detect(path);
        Assert.Empty(d.Unlocks);
        Assert.Equal(new[] { 9700 }, d.Target!.Modes);
        Assert.Contains(d.Info, p => p.Key == "Notes");
    }

    [Fact]
    public async Task OoxmlSaveRemovesTheDirectProtectionElement()
    {
        var path = Ooxml(".xlsx", $"<worksheet xmlns='{Ns}'><extLst><ext uri='custom'><sheetProtection sheet='1'/></ext></extLst><sheetProtection sheet='1'/></worksheet>");
        var unlock = FormatDetector.Detect(path).Unlocks[0];
        var output = Path.Combine(_dir, "copy.xlsx");
        await unlock.SaveAsync(path, output);
        using var zip = ZipFile.OpenRead(output);
        var root = XDocument.Parse(Read(zip, "xl/worksheets/sheet1.xml")).Root!;
        Assert.Null(root.Element(XName.Get("sheetProtection", Ns)));
        Assert.Single(root.Descendants(XName.Get("sheetProtection", Ns)));
    }

    [Fact]
    public async Task DirectoryAliasesAndDirectDelegatesCannotReplaceTheOriginal()
    {
        if (OperatingSystem.IsWindows()) return; // Symbolic-link creation requires extra privileges on Windows.
        var path = Ooxml(".xlsx");
        var original = File.ReadAllBytes(path);
        string alias = _dir + "-alias";
        Directory.CreateSymbolicLink(alias, _dir);
        try
        {
            var unlock = FormatDetector.Detect(path).Unlocks[0];
            await Assert.ThrowsAsync<IOException>(() => unlock.SaveAsync(path, Path.Combine(alias, Path.GetFileName(path))));
            await Assert.ThrowsAsync<IOException>(() => unlock.SaveCopyAsync!(path, path, default));
            Assert.Equal(original, File.ReadAllBytes(path));
        }
        finally { Directory.Delete(alias); }
    }

    [Fact]
    public async Task NestedBiffChartDoesNotChangeWorksheetPasswordOrSavedWords()
    {
        byte[] chart = [.. Record(0x0809, [0, 6, 0x20, 0]), .. Record(0x12, [1, 0]),
            .. Record(0x13, [0xff, 0xff]), .. Record(0x0a, [])];
        var wb = Biff();
        byte[] data = [.. wb[..^4], .. chart, .. wb[^4..]];
        var path = Path.Combine(_dir, "chart.xls");
        File.WriteAllBytes(path, Compound(data, true));
        var sheet = Assert.Single(FormatDetector.Detect(path).Unlocks, u => u.Title.StartsWith("Sheet"));
        Assert.Equal(0xdaa7, LegacyHash(sheet.Password!));
        var output = Path.Combine(_dir, "copy.xls");
        await sheet.SaveAsync(path, output);
        using var file = File.OpenRead(output);
        var saved = new CompoundFile(file).ReadStream("Workbook")!;
        Assert.Equal(chart, saved.AsSpan(wb.Length - 4, chart.Length).ToArray());
    }

    [Fact]
    public void RejectsTruncatedZipAsAFormatError()
    {
        using var stream = new MemoryStream([0x50, 0x4b, 3, 4, 0, 0]);
        Assert.Throws<FormatException>(() => SpreadsheetProtection.TryExtractZip(stream, new Detection { FilePath = "bad.xlsx" }));
    }

    [Fact]
    public void RejectsInvalidBiffProtectionWordLength()
    {
        var data = Biff();
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(10), 1); // WINDOWPROTECT must contain two bytes.
        var path = Path.Combine(_dir, "bad.xls");
        File.WriteAllBytes(path, Compound(data, true));
        var d = FormatDetector.Detect(path);
        Assert.Empty(d.Unlocks);
        Assert.Contains("damaged", d.Message!);
    }

    [Fact]
    public void RejectsExcessiveBiffNesting()
    {
        byte[] data = [.. Enumerable.Range(0, 65).SelectMany(_ => Record(0x0809, [0, 6, 5, 0])),
            .. Enumerable.Range(0, 65).SelectMany(_ => Record(0x0a, []))];
        var path = Path.Combine(_dir, "nested.xls");
        File.WriteAllBytes(path, Compound(data, false));
        var d = FormatDetector.Detect(path);
        Assert.Empty(d.Unlocks);
        Assert.Contains("damaged", d.Message!);
    }

    [Fact]
    public void EncryptedBiffDoesNotReadPastTheExistingOfficePrefix()
    {
        byte[] workbook = [.. Record(0x0809, [0, 6, 5, 0]),
            .. Record(0x002f, [1, 0, 1, 0, 1, 0, .. new byte[48]]), .. Record(0x000a, [])];
        var container = Compound(workbook, false);
        BinaryPrimitives.WriteUInt32LittleEndian(container.AsSpan(1152 + 120), 1024 * 1024);
        BinaryPrimitives.WriteUInt32LittleEndian(container.AsSpan(512 + 9 * 4), 2);
        var path = Path.Combine(_dir, "encrypted.xls");
        File.WriteAllBytes(path, container);
        // Existing encrypted extraction reads only the first 64 KiB; the damaged tail is irrelevant.
        var d = FormatDetector.Detect(path);
        Assert.Empty(d.Unlocks);
        Assert.Equal(new[] { 9700 }, d.Target!.Modes);
    }

    private string Ooxml(string extension, string? sheetXml = null)
    {
        var path = Path.Combine(_dir, "book" + extension);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        Write(zip, "[Content_Types].xml", "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'/>");
        Write(zip, "xl/workbook.xml", $"<workbook xmlns='{Ns}' xmlns:r='http://schemas.openxmlformats.org/officeDocument/2006/relationships'><fileSharing readOnlyRecommended='1'/><workbookProtection workbookPassword='DAA7' lockStructure='1'/><sheets><sheet name='Budget' sheetId='1' r:id='r1'/><sheet name='Chart' sheetId='2' r:id='r2'/></sheets></workbook>");
        Write(zip, "xl/_rels/workbook.xml.rels", "<Relationships xmlns='http://schemas.openxmlformats.org/package/2006/relationships'><Relationship Id='r1' Target='worksheets/sheet1.xml' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet'/><Relationship Id='r2' Target='/xl/chartsheets/sheet1.xml' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/chartsheet'/></Relationships>");
        Write(zip, "xl/worksheets/sheet1.xml", sheetXml ?? $"<worksheet xmlns='{Ns}'><sheetData/><sheetProtection password='DAA7' sheet='1'/></worksheet>");
        Write(zip, "xl/chartsheets/sheet1.xml", $"<chartsheet xmlns='{Ns}'><sheetProtection algorithmName='SHA-512' hashValue='AA==' saltValue='AA==' spinCount='100000' content='1'/></chartsheet>");
        Write(zip, "xl/vbaProject.bin", "unchanged macro payload");
        return path;
    }

    private static void Write(ZipArchive zip, string name, string text)
    {
        using var writer = new StreamWriter(zip.CreateEntry(name).Open(), new UTF8Encoding(false));
        writer.Write(text);
    }
    private static string Read(ZipArchive zip, string name)
    {
        using var reader = new StreamReader(zip.GetEntry(name)!.Open());
        return reader.ReadToEnd();
    }

    // Independent forward verifier, also checked against openpyxl's known 'secret' value.
    private static int LegacyHash(string password)
    {
        int h = 0;
        for (int i = 0; i < password.Length; i++)
        {
            int v = password[i] << (i + 1);
            h ^= (v & 0x7fff) | (v >> 15);
        }
        return h ^ password.Length ^ 0xce4b;
    }

    private static byte[] Biff()
    {
        var globals = new byte[] { 0, 6, 5, 0 };
        byte[] sheet = [.. Record(0x0809, [0, 6, 0x10, 0]), .. Record(0x12, [1, 0]),
            .. Record(0x13, [0xa7, 0xda]), .. Record(0x63, [1, 0]), .. Record(0xdd, [1, 0]), .. Record(0x0a, [])];
        return [.. Record(0x0809, globals), .. Record(0x19, [1, 0]), .. Record(0x12, [1, 0]),
            .. Record(0x13, [0xa7, 0xda]), .. Record(0x0a, []), .. sheet];
    }

    private static byte[] Record(ushort id, byte[] data)
    {
        var b = new byte[data.Length + 4];
        BinaryPrimitives.WriteUInt16LittleEndian(b, id);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(2), (ushort)data.Length);
        data.CopyTo(b, 4);
        return b;
    }

    // Small valid CFB containers exercise both allocation paths without an external dependency.
    private static byte[] Compound(byte[] workbook, bool mini)
    {
        if (!mini) Array.Resize(ref workbook, 4096);
        int sectors = mini ? 5 : 10;
        var b = new byte[(sectors + 1) * 512];
        Convert.FromHexString("D0CF11E0A1B11AE1").CopyTo(b, 0);
        Set16(0x1c, 0xfffe); Set16(0x1e, 9); Set16(0x20, 6);
        Set32(0x2c, 1); Set32(0x30, 1); Set32(0x38, 4096);
        Set32(0x3c, mini ? 2u : 0xfffffffe); Set32(0x40, mini ? 1u : 0);
        Set32(0x44, 0xfffffffe);
        for (int i = 0; i < 109; i++) Set32(0x4c + i * 4, i == 0 ? 0u : 0xffffffff);
        for (int i = 0; i < 128; i++) Set32(512 + i * 4, 0xffffffff);
        Set32(512, 0xfffffffd); Set32(516, 0xfffffffe);
        Entry(1024, "Root Entry", 5, mini ? 3u : 0xfffffffe, mini ? 1024 : 0);
        Entry(1152, "Workbook", 2, mini ? 0u : 2u, workbook.Length);
        if (mini)
        {
            Set32(520, 0xfffffffe); Set32(524, 4); Set32(528, 0xfffffffe);
            for (int i = 0; i < 128; i++) Set32(1536 + i * 4, 0xffffffff);
            int count = (workbook.Length + 63) / 64;
            for (int i = 0; i < count; i++) Set32(1536 + i * 4, i + 1 == count ? 0xfffffffe : (uint)(i + 1));
            workbook.CopyTo(b, 2048);
        }
        else
        {
            for (int i = 2; i < 10; i++) Set32(512 + i * 4, i == 9 ? 0xfffffffe : (uint)(i + 1));
            workbook.CopyTo(b, 1536);
        }
        return b;
        void Set16(int o, ushort v) => BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(o), v);
        void Set32(int o, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o), v);
        void Entry(int o, string name, byte type, uint start, int size)
        {
            Encoding.Unicode.GetBytes(name).CopyTo(b, o); Set16(o + 64, (ushort)((name.Length + 1) * 2));
            b[o + 66] = type; Set32(o + 116, start); Set32(o + 120, (uint)size);
        }
    }

    public void Dispose() => Directory.Delete(_dir, true);
}
