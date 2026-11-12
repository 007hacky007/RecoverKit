using System.Reflection;
using System.Text;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class PdfOwnerTests
{
    internal static byte[] Fixture(string name)
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("RecoverKit.Tests.Fixtures.Pdf." + name + ".pdf")!;
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    internal static Detection Extract(byte[] bytes)
    {
        var d = new Detection { FilePath = "owner.data" };
        using var stream = new MemoryStream(bytes);
        PdfExtractor.Extract(stream, d);
        return d;
    }

    [Theory]
    [InlineData("RC4-40")]
    [InlineData("RC4-128")]
    [InlineData("AES-128")]
    [InlineData("AES-256-R5")]
    [InlineData("AES-256")]
    [InlineData("crypt-identity")]
    [InlineData("crypt-stdcf")]
    [InlineData("eff")]
    [InlineData("objstm")]
    [InlineData("identity-strings")]
    [InlineData("identity-streams")]
    [InlineData("identity-both")]
    [InlineData("metadata-128")]
    [InlineData("metadata-256")]
    public async Task EmptyUserPasswordOffersUnencryptedCopy(string algorithm)
    {
        var bytes = Fixture(algorithm);
        var d = Extract(bytes);
        var unlock = Assert.Single(d.Unlocks);
        Assert.Null(d.Target);
        Assert.Contains("printing", unlock.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("copying", unlock.Description, StringComparison.OrdinalIgnoreCase);
        var dir = Directory.CreateTempSubdirectory("rk-pdf").FullName;
        try
        {
            var src = Path.Combine(dir, "original.data");
            var dst = Path.Combine(dir, "unlocked.pdf");
            await File.WriteAllBytesAsync(src, bytes);
            await unlock.SaveAsync(src, dst);
            Assert.Equal(bytes, await File.ReadAllBytesAsync(src));
            var saved = Encoding.Latin1.GetString(await File.ReadAllBytesAsync(dst));
            Assert.DoesNotContain("/Encrypt", saved);
            var document = new PdfDocument(await File.ReadAllBytesAsync(dst));
            var info = Assert.IsType<PdfDictionary>(document.Resolve(document.Trailer.Get("Info")));
            Assert.Equal("Owner restriction test", Encoding.Latin1.GetString(info.Bytes("Title")));
            var content = document.ObjectNumbers.Select(document.Get).Where(o => o.Stream is not null)
                .Select(o => Encoding.Latin1.GetString(document.Decode(o.Stream!, (PdfDictionary)o.Value)));
            Assert.Contains(content, text => text.Contains("RecoverKit owner permission test"));
            if (algorithm == "eff") Assert.Contains(content, text => text == "embedded file data");
            if (algorithm.StartsWith("metadata-"))
                Assert.Contains(content, text => text.Contains("metadata is unchanged"));
            Assert.Empty(FormatDetector.Detect(dst).Unlocks);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("truncated")]
    [InlineData("length")]
    [InlineData("offset")]
    [InlineData("aes")]
    public async Task MalformedSaveKeepsSourceAndExistingOutput(string kind)
    {
        byte[] bytes = Fixture("AES-128");
        var unlock = Assert.Single(Extract(bytes).Unlocks);
        string text = Encoding.Latin1.GetString(bytes);
        if (kind == "truncated") bytes = bytes[..^15];
        else if (kind == "length") bytes = Encoding.Latin1.GetBytes(text.Replace("/Length 80", "/Length 01"));
        else if (kind == "offset") bytes = Encoding.Latin1.GetBytes(text.Replace("startxref\n", "startxref\n999999999"));
        else
        {
            int start = text.IndexOf("stream\n", StringComparison.Ordinal) + 7;
            bytes[start + 16] ^= 1;
            bytes[start + 79] ^= 128;
        }
        // The length mutation must actually change the fixture.
        Assert.False(Fixture("AES-128").SequenceEqual(bytes));
        var dir = Directory.CreateTempSubdirectory("rk-pdf-bad").FullName;
        try
        {
            var src = Path.Combine(dir, "source.pdf");
            var dst = Path.Combine(dir, "existing.pdf");
            await File.WriteAllBytesAsync(src, bytes);
            await File.WriteAllBytesAsync(dst, "keep output"u8.ToArray());
            await Assert.ThrowsAsync<FormatException>(() => unlock.SaveAsync(src, dst));
            Assert.Equal(bytes, await File.ReadAllBytesAsync(src));
            Assert.Equal("keep output", await File.ReadAllTextAsync(dst));
            Assert.Equal(2, Directory.GetFiles(dir).Length);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task CancellationAndSamePathNeverReplaceSource()
    {
        var dir = Directory.CreateTempSubdirectory("rk-pdf-cancel").FullName;
        try
        {
            var src = Path.Combine(dir, "source.pdf");
            var bytes = Fixture("AES-256");
            await File.WriteAllBytesAsync(src, bytes);
            var unlock = Assert.Single(FormatDetector.Detect(src).Unlocks);
            await Assert.ThrowsAsync<IOException>(() => unlock.SaveAsync(src, src));
            using var cts = new CancellationTokenSource(); cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => unlock.SaveAsync(src, Path.Combine(dir, "out.pdf"), cts.Token));
            Assert.Equal(bytes, await File.ReadAllBytesAsync(src));
            Assert.Single(Directory.GetFiles(dir));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SymlinkAliasesNeverReplaceSource(bool directoryAlias)
    {
        if (OperatingSystem.IsWindows()) return; // Windows symlink creation requires extra privileges.
        var dir = Directory.CreateTempSubdirectory("rk-pdf-link").FullName;
        try
        {
            var real = Path.Combine(dir, "real"); Directory.CreateDirectory(real);
            var src = Path.Combine(real, "source.pdf");
            var bytes = Fixture("AES-128"); await File.WriteAllBytesAsync(src, bytes);
            string alias;
            if (directoryAlias)
            {
                Directory.CreateSymbolicLink(Path.Combine(dir, "alias"), real);
                alias = Path.Combine(dir, "alias", "source.pdf");
            }
            else
            {
                alias = Path.Combine(dir, "alias.pdf"); File.CreateSymbolicLink(alias, src);
            }
            var unlock = Assert.Single(FormatDetector.Detect(alias).Unlocks);
            await Assert.ThrowsAsync<IOException>(() => unlock.SaveAsync(alias, src));
            Assert.Equal(bytes, await File.ReadAllBytesAsync(src));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task Pdf20VersionIsPreserved()
    {
        var bytes = Encoding.Latin1.GetBytes(Encoding.Latin1.GetString(Fixture("AES-256")).Replace("%PDF-1.3", "%PDF-2.0"));
        Assert.StartsWith("%PDF-2.0", Encoding.Latin1.GetString(bytes));
        var dir = Directory.CreateTempSubdirectory("rk-pdf-version").FullName;
        try
        {
            var src = Path.Combine(dir, "source.pdf"); var dst = Path.Combine(dir, "out.pdf");
            await File.WriteAllBytesAsync(src, bytes);
            await Assert.Single(FormatDetector.Detect(src).Unlocks).SaveAsync(src, dst);
            Assert.StartsWith("%PDF-2.0", Encoding.Latin1.GetString(await File.ReadAllBytesAsync(dst)));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("RC4-40", 10400)]
    [InlineData("RC4-128", 10500)]
    [InlineData("AES-128", 10500)]
    [InlineData("AES-256-R5", 10600)]
    [InlineData("AES-256", 10700)]
    public void NonemptyUserPasswordStillProducesAttack(string algorithm, int mode)
    {
        var d = Extract(Fixture(algorithm + "-user"));
        Assert.Empty(d.Unlocks);
        Assert.Equal([mode], d.Target!.Modes);
    }
}
