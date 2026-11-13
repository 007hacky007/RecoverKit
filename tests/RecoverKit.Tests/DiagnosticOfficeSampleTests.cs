using System.IO.Compression;
using System.Xml.Linq;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class DiagnosticOfficeSampleTests
{
    [Theory]
    [InlineData(false, 9400, "sample-pass")]
    [InlineData(true, 9600, "sample-pass")]
    [InlineData(false, 9400, "")]
    [InlineData(true, 9600, "")]
    public void CreatesDeterministicEncryptedDocument(bool agile, int mode, string password)
    {
        byte[] sample = DiagnosticOfficeSample.Create(agile, password);
        Assert.Equal(sample, DiagnosticOfficeSample.Create(agile, password));
        using (var stream = new MemoryStream(sample))
        {
            var compound = new CompoundFile(stream);
            Assert.All(compound.Entries.Where(e => e.Type == 2), e => Assert.True(e.Size >= 4096));
            if (agile)
            {
                byte[] info = compound.ReadStream("EncryptionInfo")!;
                Assert.NotNull(XDocument.Parse(System.Text.Encoding.UTF8.GetString(info, 8, info.Length - 8)).Root);
            }
            var detection = new Detection { FilePath = "sample.docx" };
            OfficeExtractor.Extract(compound, detection);
            Assert.Equal([mode], detection.Target!.Modes);
            Assert.StartsWith(agile ? "$office$*2013*100000*256*16*" : "$office$*2007*20*128*16*", detection.Target.HashLines);
            if (password.Length == 0) Assert.Equal("", Assert.Single(detection.Unlocks).Password);
            else Assert.Empty(detection.Unlocks);
        }

        string directory = Directory.CreateTempSubdirectory("office-sample-").FullName;
        try
        {
            string source = Path.Combine(directory, "encrypted.docx");
            string output = Path.Combine(directory, "decrypted.docx");
            File.WriteAllBytes(source, sample);
            Assert.Throws<UnsupportedFormatException>(() => OfficeDecryptor.DecryptToFile(source, "wrong-password", output));
            OfficeDecryptor.DecryptToFile(source, password, output);
            using var zip = ZipFile.OpenRead(output);
            Assert.Equal(["[Content_Types].xml", "_rels/.rels", "word/document.xml"], zip.Entries.Select(e => e.FullName));
            foreach (var entry in zip.Entries)
            {
                using var input = entry.Open();
                Assert.NotNull(XDocument.Load(input).Root);
            }
            using var document = zip.GetEntry("word/document.xml")!.Open();
            var xml = XDocument.Load(document);
            XNamespace word = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
            Assert.Single(xml.Descendants(word + "p"));
            Assert.StartsWith("Synthetic diagnostic document.", Assert.Single(xml.Descendants(word + "t")).Value);
        }
        finally { Directory.Delete(directory, true); }
    }
}
