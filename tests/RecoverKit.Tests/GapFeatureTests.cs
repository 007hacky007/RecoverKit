using System.Text;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class GapFeatureTests
{
    private static HashTarget Target(string id) => new() { FormatId = id, FormatName = id, Protection = "", Modes = [0], HashLines = "x" };

    [Fact]
    public void KeySearchAppliesTo40BitRc4FormatsOnly()
    {
        Assert.Equal((9710, 9720, 15), KeySearch.ModesFor("972K"));
        Assert.Equal((9810, 9820, 15), KeySearch.ModesFor("XP03"));
        Assert.Equal((10410, 10420, 32), KeySearch.ModesFor("PDF2"));
        Assert.Null(KeySearch.ModesFor("OF13"));

        var p = AttackPlanner.Prepare(new AttackSpec { Kind = AttackKind.KeySearch }, Target("PDF2"), new PlannerContext());
        Assert.Equal(["-a", "3", "?b?b?b?b?b"], p.Args);
        Assert.Equal(KeySearch.KeyCount, (long)p.Keyspace);
        Assert.Throws<AttackPlanException>(() => AttackPlanner.Prepare(new AttackSpec { Kind = AttackKind.KeySearch }, Target("ZIPC"), new PlannerContext()));
        Assert.Equal(AttackKind.KeySearch, ScenarioParser.ParseLine("/a:k").Kind);
    }

    [Fact]
    public void KeyHexAndKeyCacheRoundTrip()
    {
        Assert.Equal("6a8aedccb7", KeySearch.KeyHex("$HEX[6A8AEDCCB7]"));
        Assert.Null(KeySearch.KeyHex("toolong"));
        var path = Path.GetTempFileName();
        try
        {
            KeyCache.Store(path, "$pdf$1*2*40*abc", "6a8aedccb7");
            KeyCache.Store(path, "$pdf$1*2*40*abc", "6a8aedccb7");
            Assert.Single(File.ReadAllLines(path));
            Assert.Equal("6a8aedccb7", KeyCache.Lookup(path, "$PDF$1*2*40*ABC"));
            Assert.Null(KeyCache.Lookup(path, "$pdf$1*2*40*other"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task PmkTableMatchesIeeeTestVectorAndRoundTrips()
    {
        // IEEE 802.11i-2004 H.4: PMK("password", "IEEE")
        const string expected = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e";
        var path = Path.GetTempFileName();
        try
        {
            var attack = new PreparedAttack { Description = "t" };
            attack.Stdin = () => ["password", "short", "longerpassword"];
            attack.Args.AddRange(["-a", "0"]);
            long n = await CandidateExport.WritePmkTableAsync([attack], null!, path, "IEEE", 2, null, CancellationToken.None);
            Assert.Equal(2, n);   // "short" is below the WPA minimum of 8 characters
            var t = PmkTable.TryOpen(path)!;
            Assert.Equal("IEEE"u8.ToArray(), t.Ssid);
            Assert.Equal("password", t.PasswordFor(expected));
            var list = path + ".list";
            Assert.Equal(2, t.WritePmkWordlist(list));
            Assert.Equal(expected, File.ReadLines(list).First());
            File.Delete(list);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void DictionaryAttackStatusLinesParse()
    {
        const string line = "{ \"session\": \"s\", \"guess\": { \"guess_base\": \"C:\\\\w.txt\", \"guess_base_count\": 1, \"guess_base_offset\": 1, \"guess_base_percent\": 100.00, \"guess_mask_length\": 4294967295, \"guess_mod\": null, \"guess_mod_count\": 1, \"guess_mod_offset\": 1, \"guess_mod_percent\": 100.00, \"guess_mode\": 1 }, \"status\": 6, \"target\": \"h\", \"progress\": [3, 3], \"restore_point\": 0, \"recovered_hashes\": [1, 1], \"recovered_salts\": [1, 1], \"rejected\": 0, \"devices\": [ { \"device_id\": 1, \"device_name\": \"CPU\", \"device_type\": \"CPU\", \"speed\": 7390, \"temp\": -1, \"util\": -1 } ], \"time_start\": 1794483502, \"estimated_stop\": 1794483502 }";
        var s = RecoverKit.Core.Hashcat.HashcatStatus.TryParse(line)!;
        Assert.NotNull(s);
        Assert.Null(s.MaskLength);
        Assert.Equal(6, s.Status);
        Assert.Equal(3, s.ProgressTotal);
        Assert.Equal(7390, s.TotalSpeed);
    }

    [Fact]
    public void StdinAttacksShowTheCountRecoverKitFeeds()
    {
        // hashcat reports progress [done, done] for candidates read from stdin.
        const string line = "{ \"guess\": { \"guess_base\": \"stdin\", \"guess_mod\": \"rules.rule\" }, \"status\": 3, \"progress\": [1000, 1000], \"devices\": [ { \"device_id\": 1, \"speed\": 100 } ] }";
        var s = RecoverKit.Core.Hashcat.HashcatStatus.TryParse(line)!;
        Assert.Equal(1, s.Fraction);
        var fed = s.WithStdinTotal(4000);
        Assert.Equal(4000, fed.ProgressTotal);
        Assert.Equal(0.25, fed.Fraction);
        Assert.Equal(1000, s.WithStdinTotal(10).ProgressTotal);                        // never below what is done
        Assert.Equal(long.MaxValue, s.WithStdinTotal(System.Numerics.BigInteger.Pow(10, 30)).ProgressTotal);
        Assert.Same(s, s.WithStdinTotal(0));                                           // count unknown
        var exhausted = RecoverKit.Core.Hashcat.HashcatStatus.TryParse(line.Replace("\"status\": 3", "\"status\": 5"))!;
        Assert.Equal(1000, exhausted.WithStdinTotal(4000).ProgressTotal);              // the run is over: the bar fills
    }

    [Fact]
    public void ExportEncodingsMatchTheOriginalChoices()
    {
        Assert.Equal(["UTF8", "UTF8-BOM", "UTF16", "ANSI/CSL"], CandidateExport.Encodings);
        Assert.Empty(CandidateExport.EncodingFor("UTF8").GetPreamble());
        Assert.Equal(Encoding.UTF8.GetPreamble(), CandidateExport.EncodingFor("UTF8-BOM").GetPreamble());
        Assert.Equal(new byte[] { 0xff, 0xfe }, CandidateExport.EncodingFor("UTF16").GetPreamble());
    }
}
