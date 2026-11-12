using System.IO.Compression;
using System.Text;
using System.Xml.Linq;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public sealed class WordRestrictionsTests : IDisposable
{
    private const string W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-word").FullName;

    [Theory]
    [InlineData("readOnly")]
    [InlineData("comments")]
    [InlineData("forms")]
    [InlineData("trackedChanges")]
    public async Task RemovesEditingAndWriteRestrictionsWithoutChangingOtherParts(string edit)
    {
        string source = Package($"<w:documentProtection w:edit='{edit}' w:enforcement='1' w:cryptAlgorithmSid='14' w:hash='AQ=='/><w:writeProtection w:recommended='1'/>");
        byte[] original = File.ReadAllBytes(source);
        var detection = FormatDetector.Detect(source);
        Assert.Null(detection.Target);
        Assert.Equal(2, detection.Unlocks.Count);
        Assert.All(detection.Unlocks, u => Assert.Null(u.Password));
        string output = Path.Combine(_dir, "copy.docx");
        await detection.Unlocks[0].SaveAsync(source, output);
        Assert.Empty(FormatDetector.Detect(output).Unlocks);
        Assert.Equal(original, File.ReadAllBytes(source));
        using var before = ZipFile.OpenRead(source);
        using var after = ZipFile.OpenRead(output);
        Assert.Equal(before.Entries.Select(e => e.FullName), after.Entries.Select(e => e.FullName));
        foreach (var entry in before.Entries.Where(e => e.FullName != "word/settings.xml"))
            Assert.Equal(Read(entry), Read(after.GetEntry(entry.FullName)!));
        using var settingsStream = after.GetEntry("word/settings.xml")!.Open();
        var settings = XDocument.Load(settingsStream);
        Assert.NotNull(settings.Root!.Element(XName.Get("zoom", W)));
    }

    [Fact]
    public void DetectsStrictWordNamespaceByContent()
    {
        var path = Package("<w:documentProtection w:edit='forms' w:enforcement='true'/>", "http://purl.oclc.org/ooxml/wordprocessingml/main");
        Assert.Single(FormatDetector.Detect(path).Unlocks);
    }

    [Fact]
    public void ShowsEquivalentLegacy16BitPassword()
    {
        var path = Package("<w:writeProtection w:password='83AF'/>"); // verifier for "password"
        string password = Assert.Single(FormatDetector.Detect(path).Unlocks).Password!;
        Assert.NotNull(password);
        Assert.Equal(0x83AF, LegacyVerifier(password));
    }

    [Fact]
    public void DoesNotTreat32BitPasswordAs16Bit()
    {
        var path = Package("<w:documentProtection w:edit='forms' w:password='123483AF'/>");
        Assert.Null(Assert.Single(FormatDetector.Detect(path).Unlocks).Password);
    }

    [Theory]
    [InlineData("8000", 0x8000)]
    [InlineData("FFFF", 0xffff)]
    [InlineData("CE4B", 0xce4b)]
    public void EquivalentPasswordsCoverVerifierBits(string hex, int expected)
    {
        string? password = Assert.Single(FormatDetector.Detect(Package($"<w:documentProtection w:password='{hex}'/>")).Unlocks).Password;
        Assert.NotNull(password);
        Assert.Equal(expected, LegacyVerifier(password));
    }

    [Fact]
    public void ModernVerifierTakesPrecedenceOverLegacyAttribute()
    {
        var path = Package("<w:writeProtection w:password='83AF' w:hash='AQ=='/>");
        Assert.Null(Assert.Single(FormatDetector.Detect(path).Unlocks).Password);
    }

    [Fact]
    public async Task FailedSaveCleansTempFileAndKeepsOutput()
    {
        string source = Package("<w:documentProtection/>");
        var unlock = Assert.Single(FormatDetector.Detect(source).Unlocks);
        string output = Path.Combine(_dir, "existing.docx");
        File.WriteAllText(output, "keep");
        using (var zip = ZipFile.Open(source, ZipArchiveMode.Update)) zip.GetEntry("word/settings.xml")!.Delete();
        await Assert.ThrowsAsync<FormatException>(() => unlock.SaveAsync(source, output));
        Assert.Equal("keep", File.ReadAllText(output));
        Assert.Equal(2, Directory.GetFiles(_dir).Length);
    }

    [Fact]
    public async Task DirectoryAliasCannotOverwriteOriginal()
    {
        if (OperatingSystem.IsWindows()) return; // Creating directory symlinks can require administrator rights.
        string source = Package("<w:documentProtection/>");
        byte[] original = File.ReadAllBytes(source);
        string alias = Path.Combine(_dir, "alias");
        Directory.CreateSymbolicLink(alias, _dir);
        var unlock = Assert.Single(FormatDetector.Detect(source).Unlocks);
        try
        {
            await Assert.ThrowsAsync<IOException>(() => unlock.SaveAsync(source, Path.Combine(alias, Path.GetFileName(source))));
            Assert.Equal(original, File.ReadAllBytes(source));
        }
        finally { Directory.Delete(alias); }
    }

    [Fact]
    public void DuplicateAndOversizedSettingsAreRejected()
    {
        string duplicate = Package("<w:documentProtection/>");
        using (var zip = ZipFile.Open(duplicate, ZipArchiveMode.Update))
        {
            using var writer = new StreamWriter(zip.CreateEntry("word/settings.xml").Open());
            writer.Write("<settings/>");
        }
        Assert.Empty(FormatDetector.Detect(duplicate).Unlocks);
        Assert.Contains("damaged", FormatDetector.Detect(duplicate).Message);
        string oversized = Package("<w:documentProtection/>");
        using (var zip = ZipFile.Open(oversized, ZipArchiveMode.Update))
        {
            using var stream = zip.GetEntry("word/settings.xml")!.Open();
            stream.SetLength(4 * 1024 * 1024 + 1);
        }
        Assert.Empty(FormatDetector.Detect(oversized).Unlocks);
        Assert.Contains("limit", FormatDetector.Detect(oversized).Message);
    }

    [Fact]
    public void OrdinaryWordAndOtherXmlDoNotOfferUnlock()
    {
        Assert.Empty(FormatDetector.Detect(Package("<w:trackRevisions/>" )).Unlocks);
        Assert.Empty(FormatDetector.Detect(Package("<x:documentProtection xmlns:x='urn:unrelated'/>" )).Unlocks);
    }

    [Theory]
    [InlineData("<w:settings")]
    [InlineData("<!DOCTYPE settings [<!ENTITY x SYSTEM 'file:///nonexistent'>]><w:settings xmlns:w='http://schemas.openxmlformats.org/wordprocessingml/2006/main'>&x;</w:settings>")]
    public void MalformedSettingsAreReported(string xml)
    {
        string path = Package("");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            zip.GetEntry("word/settings.xml")!.Delete();
            using var writer = new StreamWriter(zip.CreateEntry("word/settings.xml").Open());
            writer.Write(xml);
        }
        var detection = FormatDetector.Detect(path);
        Assert.Empty(detection.Unlocks);
        Assert.Contains("damaged", detection.Message);
    }

    [Fact]
    public async Task CancelledSaveLeavesExistingOutputAndOriginalAlone()
    {
        string source = Package("<w:documentProtection w:edit='forms'/>");
        string output = Path.Combine(_dir, "existing.docx");
        File.WriteAllText(output, "keep");
        var unlock = Assert.Single(FormatDetector.Detect(source).Unlocks);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => unlock.SaveAsync(source, output, new CancellationToken(true)));
        Assert.Equal("keep", File.ReadAllText(output));
        Assert.Equal(2, Directory.GetFiles(_dir).Length);
        await Assert.ThrowsAsync<IOException>(() => unlock.SaveAsync(source, source));
    }

    private string Package(string protection, string ns = W)
    {
        string path = Path.Combine(_dir, Guid.NewGuid() + ".unknown");
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        Write("[Content_Types].xml", "<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'/>");
        Write("word/document.xml", $"<w:document xmlns:w='{ns}'><w:body/></w:document>");
        Write("word/settings.xml", $"<w:settings xmlns:w='{ns}'><w:zoom w:percent='100'/>{protection}</w:settings>");
        Write("word/vbaProject.bin", "unchanged macro bytes");
        return path;

        void Write(string name, string text)
        {
            using var writer = new StreamWriter(zip.CreateEntry(name).Open());
            writer.Write(text);
        }
    }

    private static byte[] Read(ZipArchiveEntry entry)
    {
        using var input = entry.Open();
        using var output = new MemoryStream();
        input.CopyTo(output);
        return output.ToArray();
    }

    private static int LegacyVerifier(string password)
    {
        int value = 0;
        foreach (char c in password.Reverse()) value = (((value << 1) & 0x7fff) | (value >> 14)) ^ c;
        return (((value << 1) & 0x7fff) | (value >> 14)) ^ password.Length ^ 0xCE4B;
    }

    public void Dispose() => Directory.Delete(_dir, true);
}
