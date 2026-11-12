using System.IO.Compression;
using System.Xml.Linq;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public sealed class OdtRestrictionsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-odt").FullName;

    [Fact]
    public async Task RemovesSectionProtectionAndLoadReadonlyPreservingText()
    {
        string source = Create();
        byte[] original = File.ReadAllBytes(source);
        var detection = FormatDetector.Detect(source);
        Assert.Equal(2, detection.Unlocks.Count);
        string output = Path.Combine(_dir, "unrestricted.odt");
        await detection.Unlocks[0].SaveAsync(source, output);
        Assert.Equal(original, File.ReadAllBytes(source));
        Assert.Empty(FormatDetector.Detect(output).Unlocks);
        using var zip = ZipFile.OpenRead(output);
        using var content = zip.GetEntry("content.xml")!.Open();
        var xml = XDocument.Load(content);
        XNamespace text = "urn:oasis:names:tc:opendocument:xmlns:text:1.0";
        Assert.Equal("Keep this text", xml.Descendants(text + "p").Single().Value);
        Assert.Empty(xml.Descendants().Attributes(text + "protected"));
        Assert.Empty(xml.Descendants().Attributes(text + "protection-key"));
        using var mimetype = new StreamReader(zip.GetEntry("mimetype")!.Open());
        Assert.Equal("application/vnd.oasis.opendocument.text", mimetype.ReadToEnd());
    }

    [Fact]
    public void DoesNotOfferSectionRemovalForEncryptedContent()
    {
        var detection = FormatDetector.Detect(Create(encrypted: true));
        Assert.Empty(detection.Unlocks);
    }

    [Theory]
    [InlineData("content.xml")]
    [InlineData("settings.xml")]
    [InlineData("META-INF/manifest.xml")]
    public void DamagedXmlIsReported(string part)
    {
        string path = Create();
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Update))
        {
            zip.GetEntry(part)!.Delete();
            using var writer = new StreamWriter(zip.CreateEntry(part).Open());
            writer.Write("<broken");
        }
        var detection = FormatDetector.Detect(path);
        Assert.Empty(detection.Unlocks);
        Assert.Contains("damaged", detection.Message);
    }

    private string Create(bool encrypted = false)
    {
        string path = Path.Combine(_dir, Guid.NewGuid() + ".unknown");
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        Write("mimetype", "application/vnd.oasis.opendocument.text");
        Write("META-INF/manifest.xml", "<m:manifest xmlns:m='urn:oasis:names:tc:opendocument:xmlns:manifest:1.0'><m:file-entry m:full-path='content.xml'>" +
            (encrypted ? "<m:encryption-data><m:algorithm m:algorithm-name='aes256-gcm'/><m:key-derivation/></m:encryption-data>" : "") + "</m:file-entry></m:manifest>");
        Write("content.xml", "<o:document-content xmlns:o='urn:oasis:names:tc:opendocument:xmlns:office:1.0' xmlns:t='urn:oasis:names:tc:opendocument:xmlns:text:1.0'><o:body><o:text><t:section t:name='Section1' t:protected='true' t:protection-key='AQ=='><t:p>Keep this text</t:p></t:section></o:text></o:body></o:document-content>");
        Write("settings.xml", "<o:document-settings xmlns:o='urn:oasis:names:tc:opendocument:xmlns:office:1.0' xmlns:c='urn:oasis:names:tc:opendocument:xmlns:config:1.0'><o:settings><c:config-item-set c:name='ooo:configuration-settings'><c:config-item c:name='LoadReadonly' c:type='boolean'>true</c:config-item></c:config-item-set></o:settings></o:document-settings>");
        return path;

        void Write(string name, string value)
        {
            using var writer = new StreamWriter(zip.CreateEntry(name, CompressionLevel.NoCompression).Open(), new System.Text.UTF8Encoding(false));
            writer.Write(value);
        }
    }

    public void Dispose() => Directory.Delete(_dir, true);
}
