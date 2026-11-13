using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native.Kernels;
using RecoverKit.Core.Native.Simd;
using Xunit;

namespace RecoverKit.Tests;

public class DiagnosticPdfSampleTests
{
    [Theory]
    [InlineData(false, 10500)]
    [InlineData(true, 10700)]
    public void GeneratesDeterministicReadableEncryptedPage(bool revision6, int mode)
    {
        const string password = "sample-42";
        byte[] bytes = DiagnosticPdfSample.Create(revision6, password);
        Assert.Equal(bytes, DiagnosticPdfSample.Create(revision6, password));
        Assert.DoesNotContain("Synthetic diagnostic sample", Encoding.Latin1.GetString(bytes));

        var detection = new Detection { FilePath = "sample.pdf" };
        using var stream = new MemoryStream(bytes);
        PdfExtractor.Extract(stream, detection);
        Assert.Equal([mode], detection.Target!.Modes);
        var pdf = new PdfDocument(bytes);
        var catalog = Assert.IsType<PdfDictionary>(pdf.Resolve(pdf.Trailer.Get("Root")));
        var pages = Assert.IsType<PdfDictionary>(pdf.Resolve(catalog.Get("Pages")));
        Assert.Equal(1, pages.Int("Count"));
        Assert.Null(pdf.Trailer.Get("Info"));
        var security = Assert.IsType<PdfDictionary>(pdf.Resolve(pdf.Trailer.Get("Encrypt")));
        var content = Assert.Single(pdf.ObjectNumbers.Select(pdf.Get), o => o.Stream is not null);
        byte[] clear;
        if (revision6)
        {
            var kernel = Assert.IsType<PdfR6Kernel>(PdfR6Kernel.TryParse(detection.Target.HashLines));
            Assert.True(kernel.Verify(Encoding.ASCII.GetBytes(password)));
            Assert.False(kernel.Verify("wrong"u8));
            using var aes = Aes.Create();
            aes.Key = PdfR6Kernel.Hash(Encoding.ASCII.GetBytes(password), security.Bytes("U").AsSpan(40, 8));
            byte[] key = aes.DecryptCbc(security.Bytes("UE"), new byte[16], PaddingMode.None);
            aes.Key = key;
            byte[] encrypted = content.Stream!;
            clear = aes.DecryptCbc(encrypted.AsSpan(16), encrypted.AsSpan(0, 16), PaddingMode.PKCS7);
            byte[] permissions = aes.DecryptEcb(security.Bytes("Perms"), PaddingMode.None);
            Assert.Equal("Tadb", Encoding.ASCII.GetString(permissions, 8, 4));
            Assert.Equal(48, security.Bytes("O").Length);
            Assert.Equal(32, security.Bytes("OE").Length);
        }
        else
        {
            var kernel = Assert.IsType<PdfRc4Kernel>(PdfRc4Kernel.TryParse(detection.Target.HashLines));
            Assert.True(kernel.Verify(Encoding.ASCII.GetBytes(password)));
            Assert.False(kernel.Verify("wrong"u8));
            byte[] key = kernel.Key(Encoding.ASCII.GetBytes(password));
            byte[] suffix = [(byte)content.Number, (byte)(content.Number >> 8), (byte)(content.Number >> 16), 0, 0];
            byte[] objectKey = MD5.HashData([.. key, .. suffix]);
            clear = Rc4.Apply(objectKey, content.Stream!);
        }
        Assert.Contains("(Synthetic diagnostic sample) Tj", Encoding.ASCII.GetString(clear));
    }
}
