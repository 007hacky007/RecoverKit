using System.Text;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class AndroidBackupExtractorTests
{
    // Published hashcat 7.1.2 example, password "hashcat".
    private const string Example = "$ab$5*0*10000*b8900e4885ff9cad8f01ee1957a43bd633fea12491440514ae27aa83f2f5c006ec7e7fa0bce040add619919b4eb60608304b7d571a2ed87fd58c9ad6bc5fcf4c*7d254d93e16be9312fb1ccbfc6265c40cb0c5eab7b605a95a116e2383fb1cf12b688223f96221dcd2bf5410d4ca6f90e0789ee00157fa91658b42665d6b6844c*fc9f6be604d1c59ac32664ec2c5b9b30*00c4972149af3adcc235899e9d20611ea6e8de2212afcb9fcfefde7e35b691c2d0994eb47e4f9a260526ba47f4caea71af9c7fadcd5685d50126276f6acdd59966528b13ccc26036a0eaba2f2451aa64b05766d0edd03c988dcf87e2a9eec52d";

    [Theory]
    [InlineData(1, "$ab$1*0*10000*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f*404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f*000102030405060708090a0b0c0d0e0f*de6cfef3e3a63bb5b9869ad58ac1d079d9c9b106a5b8f1dce20b8f56ee1476e5798c1155c3fbfee7dd77882bf79350b07c62648abdd2ac8a114d998b4e868a1d513ea185ecbda802418f58ed475201f48c677d7e9017324132abc082b4211331")]
    [InlineData(5, "$ab$5*0*10000*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f*404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f*000102030405060708090a0b0c0d0e0f*de6cfef3e3a63bb5b9869ad58ac1d079d9c9b106a5b8f1dce20b8f56ee1476e5798c1155c3fbfee7dd77882bf79350b080c583bbda06f5003501e1a2c9403b83ee45d9124b8aa10e4e81f29cbdb57719ca5b640aa334bfac86aef6e860562c79")]
    public void ExtractsGeneratedBackups(int version, string expected)
    {
        // Python cryptography fixtures: 10000 rounds, signed Java byte checksum conversion,
        // AES-CBC encrypted key blob and tar payload. Password: backup-test.
        using var stream = typeof(AndroidBackupExtractorTests).Assembly.GetManifestResourceStream(
            $"RecoverKit.Tests.Fixtures.android-v{version}.ab")!;
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        var d = Detect(buffer.ToArray());
        Assert.NotNull(d.Target);
        Assert.Equal(expected, d.Target.HashLines);
        Assert.Equal([18900], d.Target.Modes);
        Assert.Equal("ANDB", d.Target.FormatId);
        Assert.Equal(SpeedClass.VerySlow, d.Target.Speed);
        Assert.Equal(256, d.Target.MaxPasswordLength);
        Assert.Contains("10000", d.Target.Protection);
        Assert.Contains(ScenarioParser.LoadDefault(), s => s.DefaultFor.Contains(d.Target.FormatId));
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(2, 1)]
    [InlineData(3, 0)]
    [InlineData(4, 1)]
    [InlineData(5, 1)]
    public void PreservesVersionAndNormalizesHex(int version, int compressed)
    {
        var lines = Header(Example).Split('\n');
        lines[1] = version.ToString();
        lines[2] = compressed.ToString();
        foreach (int i in new[] { 4, 5, 7, 8 }) lines[i] = lines[i].ToUpperInvariant();
        var d = Detect(Encoding.ASCII.GetBytes(string.Join('\n', lines)));
        Assert.Equal("$ab$" + version + Example[5..], d.Target!.HashLines);
    }

    [Theory]
    [InlineData(".zip")]
    [InlineData(".hccap")]
    [InlineData(".ipd")]
    public void ReproducesHashcatExampleWithMisleadingExtension(string extension)
    {
        var d = Detect(Encoding.ASCII.GetBytes(Header(Example)), extension);
        Assert.Equal(Example, d.Target!.HashLines);
        Assert.Equal("Android backup", d.TypeName);
    }

    [Fact]
    public void DoesNotDetectByExtensionAlone()
    {
        var d = Detect("not a backup"u8.ToArray(), ".ab");
        Assert.Null(d.Target);
        Assert.DoesNotContain("Android", d.TypeName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void ReportsUnencryptedBackup(int compressed)
    {
        var d = Detect(Encoding.ASCII.GetBytes($"ANDROID BACKUP\n5\n{compressed}\nnone\n"));
        Assert.Null(d.Target);
        Assert.Contains("not password protected", d.Message!);
    }

    [Fact]
    public void EveryTruncatedHeaderIsHandled()
    {
        var bytes = Encoding.ASCII.GetBytes(Header(Example));
        for (int length = "ANDROID BACKUP\n"u8.Length; length < bytes.Length; length++)
        {
            var d = Detect(bytes[..length]);
            Assert.Null(d.Target);
            Assert.Contains("damaged", d.Message!);
        }
    }

    [Theory]
    [InlineData(1, "")]
    [InlineData(1, "-1")]
    [InlineData(1, "99999999999999999999")]
    [InlineData(2, "2")]
    [InlineData(2, "-1")]
    [InlineData(4, "00")]
    [InlineData(5, "gg")]
    [InlineData(6, "0")]
    [InlineData(6, "-1")]
    [InlineData(6, "1000000")]
    [InlineData(6, " 10000")]
    [InlineData(6, "+10000")]
    [InlineData(7, "00")]
    [InlineData(8, "00")]
    public void RejectsMalformedFields(int field, string value)
    {
        var lines = Header(Example).Split('\n');
        lines[field] = value;
        var d = Detect(Encoding.ASCII.GetBytes(string.Join('\n', lines)));
        Assert.Null(d.Target);
        Assert.Contains("damaged", d.Message!);
    }

    [Theory]
    [InlineData(1, "6")]
    [InlineData(3, "AES-128")]
    public void ReportsUnsupportedVariants(int field, string value)
    {
        var lines = Header(Example).Split('\n');
        lines[field] = value;
        var d = Detect(Encoding.ASCII.GetBytes(string.Join('\n', lines)));
        Assert.Null(d.Target);
        Assert.Contains("Unsupported", d.Message!);
        Assert.DoesNotContain("not password protected", d.Message!);
    }

    [Fact]
    public void RejectsOverlongAndNonAsciiLines()
    {
        foreach (var value in new[] { new string('0', 100000), "\u0080" })
        {
            var d = Detect(Encoding.Latin1.GetBytes("ANDROID BACKUP\n" + value + "\n"));
            Assert.Null(d.Target);
            Assert.Contains("damaged", d.Message!);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(999999)]
    public void AcceptsHashcatIterationBoundaries(int rounds)
    {
        var header = Header(Example).Replace("\n10000\n", $"\n{rounds}\n");
        var d = Detect(Encoding.ASCII.GetBytes(header));
        Assert.Equal(Example.Replace("*10000*", $"*{rounds}*"), d.Target!.HashLines);
    }

    [Theory]
    [InlineData(4, 128)]
    [InlineData(5, 128)]
    [InlineData(7, 32)]
    [InlineData(8, 192)]
    public void RejectsInvalidHexAtCorrectLength(int field, int length)
    {
        var lines = Header(Example).Split('\n');
        lines[field] = new string('0', length - 1) + "g";
        var d = Detect(Encoding.ASCII.GetBytes(string.Join('\n', lines)));
        Assert.Null(d.Target);
        Assert.Contains("damaged", d.Message!);
    }

    private static string Header(string hash)
    {
        var f = hash[4..].Split('*');
        return $"ANDROID BACKUP\n{f[0]}\n1\nAES-256\n{f[3]}\n{f[4]}\n{f[2]}\n{f[5]}\n{f[6]}\n";
    }

    private static Detection Detect(byte[] bytes, string extension = ".data")
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + extension);
        try
        {
            File.WriteAllBytes(path, bytes);
            return FormatDetector.Detect(path);
        }
        finally { File.Delete(path); }
    }
}
