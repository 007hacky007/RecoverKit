using System.Text;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

public class PdfExtractorTests
{
    // pypdf 7.0.1 Encryption.make((V, 3, 40), ...), password r3-test-42.
    // Both complete one-page PDFs were also reopened with pikepdf 10.18.0.
    private const string V2 = "JVBERi0xLjMKJeLjz9MKMSAwIG9iago8PAovUHJvZHVjZXIgPDBlZjQ3YmJhYzM+Cj4+CmVuZG9iagoyIDAgb2JqCjw8Ci9UeXBlIC9QYWdlcwovQ291bnQgMQovS2lkcyBbIDQgMCBSIF0KPj4KZW5kb2JqCjMgMCBvYmoKPDwKL1R5cGUgL0NhdGFsb2cKL1BhZ2VzIDIgMCBSCj4+CmVuZG9iago0IDAgb2JqCjw8Ci9UeXBlIC9QYWdlCi9SZXNvdXJjZXMgPDwKPj4KL01lZGlhQm94IFsgMC4wIDAuMCA3MiA3MiBdCi9QYXJlbnQgMiAwIFIKPj4KZW5kb2JqCjUgMCBvYmoKPDwKL1YgMgovUiAzCi9MZW5ndGggNDAKL1AgNDI5NDk2NzI5MgovRmlsdGVyIC9TdGFuZGFyZAovTyA8N2JkYjBlY2NiNDdlMzRlZjU5Nzg4YTYyZDQxNTY2NWIxOWRlMjQ0MWIwMTgyMWIyMjlkODkyNWQ4OWVmYWYyYz4KL1UgPDZjZjhkZjc5OGEyZTY5MmMwN2QzY2UxNWUxNWIwOTIzMjhiZjRlNWU0ZTc1OGE0MTY0MDA0ZTU2ZmZmYTAxMDg+Cj4+CmVuZG9iagp4cmVmCjAgNgowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwMTUgMDAwMDAgbiAKMDAwMDAwMDA1OSAwMDAwMCBuIAowMDAwMDAwMTE4IDAwMDAwIG4gCjAwMDAwMDAxNjcgMDAwMDAgbiAKMDAwMDAwMDI1OSAwMDAwMCBuIAp0cmFpbGVyCjw8Ci9TaXplIDYKL1Jvb3QgMyAwIFIKL0luZm8gMSAwIFIKL0lEIFsgPDAwMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmPiA8MDAwMTAyMDMwNDA1MDYwNzA4MDkwYTBiMGMwZDBlMGY+IF0KL0VuY3J5cHQgNSAwIFIKPj4Kc3RhcnR4cmVmCjQ3MwolJUVPRgo=";
    private const string V1 = "JVBERi0xLjMKJeLjz9MKMSAwIG9iago8PAovUHJvZHVjZXIgPDI0MWQ4OWJiOTg+Cj4+CmVuZG9iagoyIDAgb2JqCjw8Ci9UeXBlIC9QYWdlcwovQ291bnQgMQovS2lkcyBbIDQgMCBSIF0KPj4KZW5kb2JqCjMgMCBvYmoKPDwKL1R5cGUgL0NhdGFsb2cKL1BhZ2VzIDIgMCBSCj4+CmVuZG9iago0IDAgb2JqCjw8Ci9UeXBlIC9QYWdlCi9SZXNvdXJjZXMgPDwKPj4KL01lZGlhQm94IFsgMC4wIDAuMCA3MiA3MiBdCi9QYXJlbnQgMiAwIFIKPj4KZW5kb2JqCjUgMCBvYmoKPDwKL1YgMQovUiAzCi9MZW5ndGggNDAKL1AgNDI5NDk2NzI5MgovRmlsdGVyIC9TdGFuZGFyZAovTyA8N2JkYjBlY2NiNDdlMzRlZjU5Nzg4YTYyZDQxNTY2NWIxOWRlMjQ0MWIwMTgyMWIyMjlkODkyNWQ4OWVmYWYyYz4KL1UgPDlmMzRlYjc4Mzg0MWI3NDY4OTJiNGU1YjVhYzdiYWVlMjhiZjRlNWU0ZTc1OGE0MTY0MDA0ZTU2ZmZmYTAxMDg+Cj4+CmVuZG9iagp4cmVmCjAgNgowMDAwMDAwMDAwIDY1NTM1IGYgCjAwMDAwMDAwMTUgMDAwMDAgbiAKMDAwMDAwMDA1OSAwMDAwMCBuIAowMDAwMDAwMTE4IDAwMDAwIG4gCjAwMDAwMDAxNjcgMDAwMDAgbiAKMDAwMDAwMDI1OSAwMDAwMCBuIAp0cmFpbGVyCjw8Ci9TaXplIDYKL1Jvb3QgMyAwIFIKL0luZm8gMSAwIFIKL0lEIFsgPDAwMDEwMjAzMDQwNTA2MDcwODA5MGEwYjBjMGQwZTBmMTAxMTEyMTMxNDE1MTYxNzE4MTkxYTFiMWMxZDFlMWY+IDwwMDAxMDIwMzA0MDUwNjA3MDgwOTBhMGIwYzBkMGUwZjEwMTExMjEzMTQxNTE2MTcxODE5MWExYjFjMWQxZTFmPiBdCi9FbmNyeXB0IDUgMCBSCj4+CnN0YXJ0eHJlZgo0NzMKJSVFT0YK";
    private const string HashV2 = "$pdf$2*3*40*-4*1*16*000102030405060708090a0b0c0d0e0f*32*6cf8df798a2e692c07d3ce15e15b092328bf4e5e4e758a4164004e56fffa0108*32*7bdb0eccb47e34ef59788a62d415665b19de2441b01821b229d8925d89efaf2c";
    private const string HashV1 = "$pdf$1*3*40*-4*1*32*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f*32*9f34eb783841b746892b4e5b5ac7baee28bf4e5e4e758a4164004e56fffa0108*32*7bdb0eccb47e34ef59788a62d415665b19de2441b01821b229d8925d89efaf2c";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DetectsR3Rc440ByContentAndMatchesReferenceHash(bool v1)
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, Fixture(v1));
            var d = FormatDetector.Detect(path);
            var t = Assert.IsType<HashTarget>(d.Target);
            Assert.Equal("P340", t.FormatId);
            Assert.Equal([10510], t.Modes);
            Assert.Equal(v1 ? HashV1 : HashV2, t.HashLines);
            Assert.Equal("RC4 40-bit, MD5", t.Protection);
            Assert.Equal(SpeedClass.Fast, t.Speed);
            Assert.Equal(32, t.MaxPasswordLength);
            Assert.False(t.Utf16Password);
            Assert.Contains("no guaranteed key search", t.Notes!);
            Assert.False(KeySearch.Supports(t));
            Assert.Throws<AttackPlanException>(() => KeySearch.Prepare(new AttackSpec { Kind = AttackKind.KeySearch }, t));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void ScenarioOffersPasswordAttacksWithoutUnsupportedKeySearch()
    {
        var scenario = Assert.Single(ScenarioParser.LoadDefault(), s => s.DefaultFor.Contains("P340"));
        Assert.Contains("PDF3", scenario.DefaultFor);
        Assert.Contains(scenario.Steps, s => s.Kind == AttackKind.Dictionary);
        Assert.DoesNotContain(scenario.Steps, s => s.Kind == AttackKind.KeySearch);
    }

    [Fact]
    public void UsesDefault40BitLengthAndIgnoresR3MetadataFlag()
    {
        var d = Extract(Text().Replace("/Length 40", "/EncryptMetadata false"));
        Assert.Equal([10510], d.Target!.Modes);
        Assert.Equal(HashV2, d.Target.HashLines);
    }

    [Theory]
    [InlineData("/R 3", "/R 2", "PDF2", 10400)]
    [InlineData("/Length 40", "/Length 128", "PDF3", 10500)]
    [InlineData("/V 2\n/R 3", "/V 4\n/R 4", "PDF3", 10500)]
    public void PreservesOtherPdfVariants(string before, string after, string format, int mode)
    {
        var d = Extract(Text().Replace(before, after));
        Assert.Equal(format, d.Target!.FormatId);
        Assert.Equal([mode], d.Target.Modes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExistingCpuKernelVerifiesR3Rc440(bool v1)
    {
        string hash = v1 ? HashV1 : HashV2;
        var kernel = Assert.IsType<PdfRc4Kernel>(PdfRc4Kernel.TryParse(hash));
        Assert.True(kernel.Verify("r3-test-42"u8));
        Assert.False(kernel.Verify("r3-test-43"u8));
        // Exercise the worker's five-byte KDF and RC4 path on only two candidates.
        var worker = kernel.CreateWorker();
        Assert.Equal(1, worker.Search("r3-test-4"u8, "32"u8));
        Assert.True(NativeKernels.Supports(10510));
        Assert.Equal(NativeKernels.TryCreate(10500, hash) is not null,
            NativeKernels.TryCreate(10510, hash) is not null);
    }

    [Theory]
    [InlineData("/Length 40", "/Length 56")]
    [InlineData("/V 2", "/V 4")]
    public void RejectsR3ParametersWithoutAHashcatMode(string before, string after)
        => Assert.Throws<UnsupportedFormatException>(() => Extract(Text().Replace(before, after)));

    [Theory]
    [InlineData("O", "<00>")]
    [InlineData("U", "<00>")]
    [InlineData("O", "<zz>")]
    [InlineData("U", "(unterminated")]
    public void RejectsMalformedSecurityStrings(string key, string replacement)
    {
        string text = System.Text.RegularExpressions.Regex.Replace(Text(), $@"/{key} <[^>]+>", $"/{key} {replacement}");
        Assert.Throws<FormatException>(() => Extract(text));
    }

    [Theory]
    [InlineData("/R 3", "/R 9999999999999999999999999")]
    [InlineData("/Length 40", "/Length 4294967336")]
    [InlineData("/O <", "/Missing <")]
    [InlineData("/ID [ <000102030405060708090a0b0c0d0e0f>", "/ID [ <0001>")]
    public void RejectsMissingOrInvalidFields(string before, string after)
        => Assert.Throws<FormatException>(() => Extract(Text().Replace(before, after)));

    [Fact]
    public void RejectsTruncatedEncryptionDictionary()
    {
        string text = Text();
        int start = text.IndexOf("/Filter /Standard", StringComparison.Ordinal);
        Assert.Throws<FormatException>(() => Extract(text[..(start + 10)] + "\n/Encrypt 5 0 R"));
    }

    private static byte[] Fixture(bool v1 = false) => Convert.FromBase64String(v1 ? V1 : V2);
    private static string Text() => Encoding.Latin1.GetString(Fixture());
    private static Detection Extract(string text)
    {
        var d = new Detection { FilePath = "test.pdf" };
        using var s = new MemoryStream(Encoding.Latin1.GetBytes(text));
        PdfExtractor.Extract(s, d);
        return d;
    }
}
