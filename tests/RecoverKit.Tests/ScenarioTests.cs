using RecoverKit.Core.Attacks;
using Xunit;

namespace RecoverKit.Tests;

public class ScenarioTests
{
    [Fact]
    public void BruteForceLineParsesCharsetAndLengths()
    {
        var a = ScenarioParser.ParseLine("/a:b /c:sd /min:1 /max:6");
        Assert.Equal(AttackKind.BruteForce, a.Kind);
        Assert.True(a.Smalls);
        Assert.True(a.Digits);
        Assert.False(a.Caps);
        Assert.Equal(1, a.MinLength);
        Assert.Equal(6, a.MaxLength);
    }

    [Fact]
    public void CharsetAllEqualsAllFour()
    {
        var a = ScenarioParser.ParseLine("/a:b /c:a /min:1 /max:3");
        Assert.True(a.Caps && a.Smalls && a.Digits && a.Specials);
    }

    [Fact]
    public void DictionaryWithRulesParses()
    {
        var a = ScenarioParser.ParseLine("/a:r /r:*1s.rul /d:*medium_en.dic /d:*small_en.dic");
        Assert.Equal(AttackKind.Dictionary, a.Kind);
        Assert.Equal(RulesPreset.Simple, a.Rules);
        Assert.Equal("*medium_en.dic", a.Dictionaries[0]);
        Assert.Equal("*small_en.dic", a.Dictionaries[1]);
    }

    [Theory]
    [InlineData("*1s.rul", RulesPreset.Simple)]
    [InlineData("*1a.rul", RulesPreset.Advanced)]
    [InlineData("*1c.rul", RulesPreset.Complex)]
    [InlineData("*2s.rul", RulesPreset.TwoWords)]
    [InlineData("*2a_2.rul", RulesPreset.TwoWordsAdvanced)]
    [InlineData("*3s.rul", RulesPreset.ThreeWords)]
    public void BuiltInRuleNamesMap(string file, RulesPreset expected)
    {
        var a = ScenarioParser.ParseLine($"/a:r /r:{file} /d:*d.dic");
        Assert.Equal(expected, a.Rules);
    }

    [Fact]
    public void QuotedUserCharsetWithEscapes()
    {
        var a = ScenarioParser.ParseLine("/a:b /u:\"12\\x20\\X0041\" /min:1 /max:2");
        Assert.True(a.UseUserCharset);
        Assert.Equal("12 A", a.UserCharset);
    }

    [Fact]
    public void DoubledQuoteIsLiteralQuote()
    {
        var a = ScenarioParser.ParseLine("/a:b /u:\"\"\"\" /min:1 /max:1");
        Assert.Equal("\"", a.UserCharset);
    }

    [Fact]
    public void MaskAttackParsesCustomCharsets()
    {
        var a = ScenarioParser.ParseLine("/a:m /1:?l?u /m:?1?l?l?l?l?d?d");
        Assert.Equal(AttackKind.Mask, a.Kind);
        Assert.Equal("?l?u", a.CustomCharsets[0]);
        Assert.Equal("?1?l?l?l?l?d?d", a.HashcatMask);
    }

    [Fact]
    public void UnknownSwitchThrows()
        => Assert.Throws<FormatException>(() => ScenarioParser.ParseLine("/a:b /zz:1"));

    [Fact]
    public void FullScenarioFileParses()
    {
        const string text = "First\nOF13 RAR5\n/a:b /c:d /min:1 /max:4\n/a:d /d:*default\n\nSecond\nNONE\n/a:b /c:a /min:1 /max:2\n";
        var list = ScenarioParser.Parse(text, out var errors);
        Assert.Empty(errors);
        Assert.Equal(2, list.Count);
        Assert.Equal("First", list[0].Name);
        Assert.Contains("OF13", list[0].DefaultFor);
        Assert.Equal(2, list[0].Steps.Count);
        Assert.Empty(list[1].DefaultFor); // NONE
    }

    [Fact]
    public void DefaultScenariosResourceLoads()
    {
        var list = ScenarioParser.LoadDefault();
        Assert.NotEmpty(list);
        Assert.Contains(list, s => s.DefaultFor.Contains("RAR5"));
        Assert.All(list, s => Assert.NotEmpty(s.Steps));
    }
}
