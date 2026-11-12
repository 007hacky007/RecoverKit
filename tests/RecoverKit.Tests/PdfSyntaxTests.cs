using System.Text;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class PdfSyntaxTests
{
    [Theory]
    [InlineData("[0 0 612.0 792.0]")]
    [InlineData("[1 2147483648]")]
    public void NumericLookaheadPreservesRealAndLargeNumbers(string text)
    {
        var array = Assert.IsType<PdfArray>(new PdfSyntax(Encoding.ASCII.GetBytes(text)).Read());
        Assert.All(array.Items, v => Assert.IsType<PdfNumber>(v));
    }

    [Fact]
    public void StringsHandleEscapesNestingCommentsAndNameEscapes()
    {
        var dict = Assert.IsType<PdfDictionary>(new PdfSyntax("<< % /Fake 0\n /A#42 (a(b)c\\053\\\r\nd\r\ne) /Hex <0 a b> >>"u8.ToArray()).Read());
        Assert.Equal("a(b)c+d\ne"u8.ToArray(), dict.Bytes("AB"));
        Assert.Equal(new byte[] { 10, 176 }, dict.Bytes("Hex"));
    }

    [Theory]
    [InlineData("(unclosed")]
    [InlineData("<zz>")]
    [InlineData("<< /A 1 /A 2 >>")]
    [InlineData("[1 2")]
    [InlineData("/A#xx")]
    [InlineData("<< /x >>")]
    public void MalformedSyntaxFailsWithFormatException(string text) =>
        Assert.Throws<FormatException>(() => new PdfSyntax(Encoding.ASCII.GetBytes(text)).Read());

    [Fact]
    public void DeepNestingFailsBeforeStackOverflow() => Assert.Throws<FormatException>(() =>
        new PdfSyntax(Encoding.ASCII.GetBytes(new string('[', 10000))).Read());
}
