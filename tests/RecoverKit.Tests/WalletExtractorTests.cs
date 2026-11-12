using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class WalletExtractorTests
{
    public static IEnumerable<object[]> Wallets() => Directory.GetFiles(
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "Wallets"), "*.json")
        .Select(path => new object[] { File.ReadAllText(path) });

    [Theory]
    [MemberData(nameof(Wallets))]
    public void ExtractsGeneratedWalletsExactly(string fixture)
    {
        var f = JsonNode.Parse(fixture)!;
        string content = f["content"]!.GetValue<string>();
        var d = Extract(content);
        Assert.NotNull(d.Target);
        Assert.Equal(f["hash"]!.GetValue<string>(), d.Target.HashLines);
        Assert.Equal([f["mode"]!.GetValue<int>()], d.Target.Modes);
        Assert.Equal(f["formatId"]!.GetValue<string>(), d.Target.FormatId);
        Assert.Equal(256, d.Target.MaxPasswordLength);
        Assert.Contains("own device", d.Target.Notes!);
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, content);
            var detected = FormatDetector.Detect(path);
            Assert.Equal(d.Target.HashLines, detected.Target?.HashLines);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void ReadsEscapedNestedAndLevelDbVaults()
    {
        string vault = Fixture("metamask-new");
        string expected = Extract(vault).Target!.HashLines;
        Assert.Equal(expected, Extract(JsonSerializer.Serialize(new { vault })).Target!.HashLines);
        Assert.Equal(expected, Extract("\0leveldb\xff" + vault + "\0trailer").Target!.HashLines);
        Assert.Equal(expected, Extract("\0prefix" + JsonSerializer.Serialize(vault) + "\0trailer").Target!.HashLines);
    }

    [Theory]
    [InlineData("{\"crypto\":null,\"version\":3}")]
    [InlineData("{\"crypto\":{},\"version\":3}")]
    [InlineData("{\"data\":\"bad\",\"iv\":false,\"salt\":null}")]
    [InlineData("{\"payload\":\"!!\",\"version\":2,\"pbkdf2_iterations\":0}")]
    [InlineData("{\"seed_version\":4,\"seed\":\"!\",\"wallet_type\":\"old\"}")]
    [InlineData("{\"wallet_type\":\"standard\",\"keystore\":[]}")]
    [InlineData("{\"crypto\":")]
    [InlineData("QklFMQ==")]
    public void RejectsMalformedInputAsFormatException(string input)
        => Assert.Throws<FormatException>(() => Extract(input));

    [Theory]
    [InlineData("metamask", "iv", "AA==")]
    [InlineData("metamask", "salt", "AA==")]
    [InlineData("metamask", "data", "AA==")]
    public void RejectsInvalidLengths(string name, string property, string value)
    {
        var wallet = JsonNode.Parse(Fixture(name))!;
        wallet[property] = value;
        Assert.Throws<FormatException>(() => Extract(wallet.ToJsonString()));
    }

    [Fact]
    public void RejectsUnknownKdfsAndInvalidScryptParameters()
    {
        var eth = JsonNode.Parse(Fixture("eth-scrypt"))!;
        eth["crypto"]!["kdfparams"]!["n"] = 16;
        Assert.Throws<UnsupportedFormatException>(() => Extract(eth.ToJsonString()));
        eth["crypto"]!["kdf"] = "unknown";
        Assert.Throws<UnsupportedFormatException>(() => Extract(eth.ToJsonString()));
        var mm = JsonNode.Parse(Fixture("metamask-new"))!;
        mm["keyMetadata"]!["algorithm"] = "scrypt";
        Assert.Throws<UnsupportedFormatException>(() => Extract(mm.ToJsonString()));
    }

    [Theory]
    [InlineData("{\"data\":\"bad\",\"iv\":\"bad\",\"salt\":\"bad\"}")]
    [InlineData("unsupported")]
    public void SkipsDamagedOrUnsupportedDatabaseRecords(string first)
    {
        if (first == "unsupported")
        {
            var vault = JsonNode.Parse(Fixture("metamask-new"))!;
            vault["keyMetadata"]!["algorithm"] = "unknown";
            first = vault.ToJsonString();
        }
        string valid = Fixture("metamask");
        Assert.Equal(Extract(valid).Target!.HashLines,
            Extract("\0prefix" + first + "\0next" + valid).Target!.HashLines);
    }

    [Fact]
    public void HandlesMixedPythonQuotesAndUnicodeLabels()
    {
        string wallet = Fixture("electrum-1");
        wallet = wallet[..^1] + ", 'labels': {'address': \"John's and Jane's wallet\", 'other': u'caf\\u00e9'}}";
        Assert.Equal(Extract(Fixture("electrum-1")).Target!.HashLines, Extract(wallet).Target!.HashLines);
    }

    [Fact]
    public void RejectsUnsupportedScryptSaltLength()
    {
        var wallet = JsonNode.Parse(Fixture("eth-scrypt"))!;
        wallet["crypto"]!["kdfparams"]!["salt"] = new string('a', 32);
        Assert.Throws<UnsupportedFormatException>(() => Extract(wallet.ToJsonString()));
    }

    [Fact]
    public void DoesNotAttackUnencryptedOrUnrelatedJson()
    {
        Assert.Null(Extract("{\"wallet_type\":\"standard\",\"use_encryption\":false}").Target);
        Assert.False(TryExtract("{\"some\":\"data\"}", new Detection { FilePath = "test" }));
        Assert.False(TryExtract("unrelated", new Detection { FilePath = "test" }));
    }

    [Fact]
    public void RejectsInvalidElectrumCurvePoint()
    {
        byte[] data = Convert.FromBase64String(Fixture("electrum-full"));
        data.AsSpan(5, 32).Fill(255);
        Assert.Throws<FormatException>(() => Extract(Convert.ToBase64String(data)));
    }

    [Fact]
    public void BoundsDatabaseSizeBeforeReadingIt()
    {
        string path = Path.GetTempFileName();
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite);
            stream.Write("{\"data\":"u8);
            stream.SetLength(32L * 1024 * 1024 + 1);
            Assert.Throws<UnsupportedFormatException>(() => WalletExtractor.TryExtract(stream, new Detection { FilePath = path }));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void BoundsNestedVaultsAndDatabaseCandidates()
    {
        string vault = Fixture("metamask");
        for (int i = 0; i < 17; i++) vault = "{\"nested\":" + vault + "}";
        Assert.Throws<FormatException>(() => Extract(vault));
        string candidates = "\0" + string.Concat(Enumerable.Repeat("{\"data\":0}\0", 257));
        Assert.Throws<FormatException>(() => Extract(candidates));
    }

    [Fact]
    public void SupportsOlderAndMultisigElectrumLayouts()
    {
        var wallet = JsonNode.Parse(Fixture("electrum-2"))!;
        var store = wallet["keystore"]!.DeepClone();
        wallet.AsObject().Remove("keystore");
        wallet["master_private_keys"] = new JsonObject { ["x/"] = store["xprv"]!.DeepClone() };
        string expected = Extract(Fixture("electrum-2")).Target!.HashLines;
        Assert.Equal(expected, Extract(wallet.ToJsonString()).Target!.HashLines);
        wallet.AsObject().Remove("master_private_keys");
        wallet["x1/"] = store;
        Assert.Equal(expected, Extract(wallet.ToJsonString()).Target!.HashLines);
        var old = JsonNode.Parse(JsonSerializer.Serialize(new { wallet_type = "old", keystore = new { type = "old", seed = "" } }))!;
        string literal = Fixture("electrum-1");
        string seed = System.Text.RegularExpressions.Regex.Match(literal, "'seed': '([^']+)'").Groups[1].Value;
        old["keystore"]!["seed"] = seed;
        Assert.Equal(Extract(literal).Target!.HashLines, Extract(old.ToJsonString()).Target!.HashLines);
    }

    [Fact]
    public void ProvidesScenarioAndSpeedMetadata()
    {
        Assert.Equal(SpeedClass.VerySlow, Extract(Fixture("eth-scrypt")).Target!.Speed);
        Assert.Equal(SpeedClass.Slow, Extract(Fixture("metamask")).Target!.Speed);
        Assert.Equal(SpeedClass.VerySlow, Extract(Fixture("metamask-new")).Target!.Speed);
        Assert.Contains("without the GCM tag", Extract(Fixture("metamask-large")).Target!.Notes!);
        Assert.Contains("without the MAC", Extract(Fixture("electrum-large")).Target!.Notes!);
        var scenarios = RecoverKit.Core.Attacks.ScenarioParser.LoadDefault();
        foreach (string id in new[] { "ETH3", "ELCT", "MTMK", "BLCH" })
            Assert.Contains(scenarios, s => s.DefaultFor.Contains(id));
    }

    [Fact]
    public void ReportsExodusLimitation()
    {
        var d = Extract("SECO" + new string('\0', 100));
        Assert.Null(d.Target);
        Assert.Contains("not supported", d.Message!);
    }

    private static string Fixture(string name) => JsonNode.Parse(File.ReadAllText(
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "Wallets", name + ".json")))!["content"]!.GetValue<string>();

    private static Detection Extract(string text)
    {
        var d = new Detection { FilePath = "test" };
        Assert.True(TryExtract(text, d));
        return d;
    }

    private static bool TryExtract(string text, Detection d)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(text));
        return WalletExtractor.TryExtract(stream, d);
    }
}
