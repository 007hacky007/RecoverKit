using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public sealed class KeePassKeyfileTests : IDisposable
{
    private readonly string _path = Path.GetTempFileName();
    private static readonly byte[] Key = Enumerable.Range(0, 32).Select(x => (byte)x).ToArray();

    [Theory]
    [InlineData("binary")]
    [InlineData("hex")]
    [InlineData("xml1")]
    [InlineData("xml2")]
    public void SupportedKeyRepresentationsHaveTheSameComponent(string format)
    {
        byte[] data = format switch
        {
            "binary" => Key,
            "hex" => Encoding.ASCII.GetBytes(Convert.ToHexString(Key)),
            "xml1" => Xml("1.00", Convert.ToBase64String(Key)),
            _ => Xml("2.0", "\n  " + Convert.ToHexString(Key.AsSpan(0, 16)) + "\n  " + Convert.ToHexString(Key.AsSpan(16)),
                Convert.ToHexString(SHA256.HashData(Key).AsSpan(0, 4))),
        };
        File.WriteAllBytes(_path, data);
        Assert.Equal(Key, KeePassKeyfile.Read(_path));
    }

    [Theory]
    [InlineData("")]
    [InlineData("some arbitrary keyfile data")]
    [InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")]
    [InlineData("<other>valid XML but not a KeePass key</other>")]
    [InlineData("<invalid XML")]
    public void ArbitraryFilesUseSha256(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        File.WriteAllBytes(_path, bytes);
        Assert.Equal(SHA256.HashData(bytes), KeePassKeyfile.Read(_path));
    }

    [Fact]
    public void LegacyKdbHashesXmlAsAnArbitraryFile()
    {
        byte[] bytes = Xml("1.00", Convert.ToBase64String(Key));
        File.WriteAllBytes(_path, bytes);
        Assert.Equal(SHA256.HashData(bytes), KeePassKeyfile.Read(_path, legacy: true));
    }

    [Theory]
    [InlineData("2.0", "000102", "00000000")]
    [InlineData("2.0", "invalid", "00000000")]
    [InlineData("1.00", "AA==", "")]
    [InlineData("1.00", "invalid", "")]
    [InlineData("3.0", "", "")]
    public void InvalidXmlKeyDataIsRejected(string version, string data, string checksum)
    {
        File.WriteAllBytes(_path, Xml(version, data, checksum));
        Assert.Throws<FormatException>(() => KeePassKeyfile.Read(_path));
    }

    [Fact]
    public void XmlV2ChecksumIsRequiredAndChecked()
    {
        foreach (var checksum in new[] { "00000000", "" })
        {
            File.WriteAllBytes(_path, Xml("2.0", Convert.ToHexString(Key), checksum));
            Assert.Throws<FormatException>(() => KeePassKeyfile.Read(_path));
        }
    }

    [Fact]
    public void LargeArbitraryFilesAreStreamed()
    {
        var data = new byte[1024 * 1024 + 1];
        File.WriteAllBytes(_path, data);
        Assert.Equal(SHA256.HashData(data), KeePassKeyfile.Read(_path));
    }

    [Fact]
    public void OversizedXmlKeyfilesAreRejectedInsteadOfHashingTheirXml()
    {
        File.WriteAllText(_path, "<KeyFile><!--" + new string('a', 1024 * 1024) + "--></KeyFile>");
        Assert.Throws<FormatException>(() => KeePassKeyfile.Read(_path));
    }

    [Fact]
    public void MalformedXmlKeyfilesAreRejectedInsteadOfHashingTheirXml()
    {
        File.WriteAllText(_path, "<KeyFile><Meta>");
        Assert.Throws<FormatException>(() => KeePassKeyfile.Read(_path));
    }

    private static byte[] Xml(string version, string data, string checksum = "")
        => Encoding.UTF8.GetBytes($"<?xml version=\"1.0\"?><KeyFile><Meta><Version>{version}</Version></Meta><Key><Data Hash=\"{checksum}\">{data}</Data></Key></KeyFile>");

    public void Dispose() => File.Delete(_path);
}
