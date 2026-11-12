using System.Numerics;
using RecoverKit.Core.Attacks;
using Xunit;

namespace RecoverKit.Tests;

public class CharsetTests
{
    [Fact]
    public void BuildDeduplicatesAndOrders()
    {
        var a = new AttackSpec { Smalls = true, Digits = true, UseUserCharset = true, UserCharset = "abc123xyz" };
        var cs = Charsets.Build(a);
        Assert.Equal(cs.Length, cs.Distinct().Count());
        Assert.Contains('x', cs);
        Assert.Equal(36, cs.Length); // 26 smalls + 10 digits, user chars already present
    }

    [Fact]
    public void NationalAlphabetAddsLetters()
    {
        var a = new AttackSpec { Smalls = true, Caps = false, Digits = false, Alphabet = "Czech/Slovak" };
        var cs = Charsets.Build(a);
        Assert.Contains('č', cs);
        Assert.True(cs.Length > 26);
    }

    [Fact]
    public void BruteKeyspaceSumsLengths()
    {
        var a = new AttackSpec { Smalls = false, Digits = true, Caps = false, MinLength = 1, MaxLength = 3 };
        Assert.Equal(new BigInteger(10 + 100 + 1000), Charsets.BruteKeyspace(a));
    }

    [Fact]
    public void BruteKeyspaceWithMaskCountsUnknownPositions()
    {
        var a = new AttackSpec { Smalls = false, Digits = true, Mask = "pw??", MaskSymbol = '?' };
        Assert.Equal(new BigInteger(100), Charsets.BruteKeyspace(a));
    }

    [Fact]
    public void MaskPositionsSizes()
    {
        var pos = Charsets.MaskPositions("?l?d?u?s", new string[8]);
        Assert.Equal([26, 10, 26, 33], pos);
    }

    [Fact]
    public void MaskKeyspaceProduct()
    {
        var ks = Charsets.MaskKeyspace("?d?d?d", new string[8], increment: false, 0, 0);
        Assert.Equal(new BigInteger(1000), ks);
    }

    [Fact]
    public void MaskKeyspaceIncrementSumsPrefixes()
    {
        var ks = Charsets.MaskKeyspace("?d?d?d", new string[8], increment: true, 1, 3);
        Assert.Equal(new BigInteger(10 + 100 + 1000), ks);
    }

    [Fact]
    public void CustomCharsetReferencedInMask()
    {
        var custom = new string[8];
        custom[0] = "?l?u";
        var pos = Charsets.MaskPositions("?1?1", custom);
        Assert.Equal([52, 52], pos);
    }

    [Fact]
    public void AsciiDetection()
    {
        Assert.True(Charsets.IsAscii("abcABC123"));
        Assert.False(Charsets.IsAscii("abcč"));
    }
}
