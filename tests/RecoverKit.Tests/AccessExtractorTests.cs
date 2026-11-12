using System.Buffers.Binary;
using System.Text;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class AccessExtractorTests
{
    [Fact]
    public void RecoversRealJet4PasswordWithoutAttackOrSaveAction()
    {
        var d = Extract(Fixture("jet4-protected"));
        var unlock = Assert.Single(d.Unlocks);
        Assert.Equal("testpassword", unlock.Password);
        Assert.Null(unlock.SaveCopyAsync);
        Assert.Null(unlock.SaveLabel);
        Assert.Null(d.Target);
        Assert.DoesNotContain("testpassword", d.Message ?? "");
        Assert.DoesNotContain(d.Info, item => item.Value.Contains("testpassword"));
    }

    [Theory]
    [InlineData("jet3-plain")]
    [InlineData("jet4-plain")]
    public void RealUnprotectedDatabasesHaveNoUnlock(string fixture)
    {
        var d = Extract(Fixture(fixture));
        Assert.Empty(d.Unlocks);
        Assert.Null(d.Target);
        Assert.Contains("not password protected", d.Message);
    }

    [Theory]
    [InlineData(0, "password", 1252)]
    [InlineData(0, "caf\u00e9", 1252)]
    [InlineData(0, "heslo\u010d", 1250)]
    [InlineData(0, "12345678901234567890", 1252)]
    [InlineData(1, "password", 1252)]
    [InlineData(1, "\u0100\u010d\u5bc6\u78bc", 1252)]
    [InlineData(1, "12345678901234567890", 1252)]
    public void RecoversBothLayoutsAndFullPasswordFields(int version, string password, int codePage)
    {
        var d = Extract(Header(version, password, codePage));
        Assert.Equal(password, Assert.Single(d.Unlocks).Password);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void EmptyPasswordHasNoUnlock(int version)
        => Assert.Empty(Extract(Header(version, "")).Unlocks);

    [Theory]
    [InlineData("ace-encrypted", "encrypted")]
    [InlineData("ace-plain", "not password protected")]
    public void RecognizesAceWithoutRecoveringItsPassword(string fixture, string message)
    {
        var d = Extract(Fixture(fixture));
        Assert.Contains("Access 2007+", d.TypeName);
        Assert.Contains(message, d.Message);
        Assert.Empty(d.Unlocks);
        Assert.Null(d.Target);
        if (fixture == "ace-encrypted") Assert.Contains("not supported", d.Message);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(0, 19)]
    [InlineData(0, 20)]
    [InlineData(0, 2047)]
    [InlineData(1, 121)]
    [InlineData(1, 4095)]
    public void TruncatedHeaderThrowsFormatException(int version, int length)
        => Assert.Throws<FormatException>(() => Extract(Header(version, "secret")[..length]));

    [Theory]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(2147483648d)]
    public void InvalidCreationDateThrowsFormatException(double date)
    {
        var h = Header(1, "secret");
        SetDate(h, date);
        Assert.Throws<FormatException>(() => Extract(h));
    }

    [Fact]
    public void MalformedUtf16ThrowsFormatException()
    {
        var h = Header(1, "x");
        h[66] ^= (byte)'x'; h[67] ^= 0xd8; // An unpaired high surrogate.
        Assert.Throws<FormatException>(() => Extract(h));
    }

    [Fact]
    public void UnsupportedJet3CodePageIsExplicit()
    {
        var h = Header(0, "secret");
        h[60] ^= (byte)(1252 & 255); h[61] ^= (byte)(1252 >> 8);
        h[60] ^= 0xff; h[61] ^= 0xff;
        Assert.Throws<UnsupportedFormatException>(() => Extract(h));
    }

    [Theory]
    [InlineData(".bin")]
    [InlineData(".mdb")]
    [InlineData(".mde")]
    public void DetectorUsesContentRegardlessOfExtension(string extension)
    {
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + extension);
        try
        {
            File.WriteAllBytes(path, Fixture("jet4-protected"));
            Assert.Equal("testpassword", Assert.Single(FormatDetector.Detect(path).Unlocks).Password);
            File.WriteAllBytes(path, "ordinary text"u8.ToArray());
            Assert.Equal("Unknown", FormatDetector.Detect(path).TypeName);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void WorkgroupSecurityIsExplicitlyUnsupported()
    {
        var d = Extract(Fixture("jet4-plain"), "test.mdw");
        Assert.Contains("user-level security", d.Message);
        Assert.Contains("not supported", d.Message);
        Assert.Empty(d.Unlocks);
    }

    [Fact]
    public void UnsupportedVersionNeverProducesAnUnlock()
    {
        var h = Header(1, "secret"); h[20] = 7;
        Assert.Throws<UnsupportedFormatException>(() => Extract(h));
    }

    [Fact]
    public void InvalidMagicThrowsFormatException()
    {
        var h = Header(1, "secret"); h[4] = 0;
        Assert.False(AccessExtractor.IsAccess(h));
        Assert.Throws<FormatException>(() => Extract(h));
    }

    [Fact]
    public void FiltersIncludeAccessDatabases()
    {
        Assert.Contains("Access databases|*.mdb;*.mde;*.accdb", FormatDetector.OpenFilter);
        Assert.Contains("*.mdb;*.mde;*.accdb", FormatDetector.OpenFilter[0]);
    }

    private static Detection Extract(byte[] header, string path = "test.mdb")
    {
        var d = new Detection { FilePath = path };
        using var s = new MemoryStream(header);
        AccessExtractor.Extract(s, d);
        return d;
    }

    private static byte[] Fixture(string name)
    {
        using var s = typeof(AccessExtractorTests).Assembly.GetManifestResourceStream(
            $"RecoverKit.Tests.Fixtures.Access.{name}.bin")!;
        using var output = new MemoryStream(); s.CopyTo(output);
        return output.ToArray();
    }

    // Independent vectors: fixed-key RC4 output calculated in scratch with Python.
    private static byte[] Header(int version, string password, int codePage = 1252)
    {
        var h = new byte[version == 0 ? 2048 : 4096];
        h[1] = 1; "Standard Jet DB\0"u8.CopyTo(h.AsSpan(4)); h[20] = (byte)version;
        var mask = Convert.FromHexString("86fbec375d449cfac65e28e613b68a6054947b36f572dfb177f41343cfafb1333461795b92b57c2a05f1");
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        var bytes = (version == 0 ? Encoding.GetEncoding(codePage) : Encoding.Unicode).GetBytes(password);
        for (int i = 0; i < (version == 0 ? 20 : 40); i++)
            h[66 + i] = (byte)(mask[i] ^ (i < bytes.Length ? bytes[i] : 0) ^ (version == 1 ? new byte[] { 0x40, 0x9c, 0, 0 }[i % 4] : 0));
        h[60] = (byte)((codePage & 255) ^ 0x7b); h[61] = (byte)((codePage >> 8) ^ 0x42);
        if (version == 1) SetDate(h, 40000.875); // Truncate, do not round to 40001.
        return h;
    }

    private static void SetDate(byte[] h, double date)
    {
        BinaryPrimitives.WriteDoubleLittleEndian(h.AsSpan(114), date);
        var mask = Convert.FromHexString("124f4a946c3e6026");
        for (int i = 0; i < 8; i++) h[114 + i] ^= mask[i];
    }
}
