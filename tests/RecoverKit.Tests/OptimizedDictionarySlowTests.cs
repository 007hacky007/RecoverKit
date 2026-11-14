using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native.Kernels;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

[Trait("Category", "Slow")]
public class OptimizedDictionarySlowTests(ITestOutputHelper output)
{
    [Fact]
    public async Task RuleBoundsCoverRealHashcatOutput()
    {
        string? configured = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        if (string.IsNullOrEmpty(configured)) { output.WriteLine("Not run: set RECOVERKIT_TEST_HASHCAT to a private hashcat copy."); return; }
        var tool = HashcatTool.Locate(configured);
        Assert.NotNull(tool);
        string dir = Directory.CreateTempSubdirectory("rk-opt-rules").FullName;
        try
        {
            string words = Path.Combine(dir, "words.txt"), rules = Path.Combine(dir, "test.rule");
            File.WriteAllText(words, "abcd\n");
            File.WriteAllLines(rules, [":", "$1 ^2 i0x", "d", "f", "q", "p2", "z2 Z3", "y2 Y3", "] $1", "x12 $1"]);
            var args = new List<string> { "--stdout", words, "-r", rules, "--quiet" };
            if (int.TryParse(Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT_DEVICE"), out int id)) args.AddRange(["-d", id.ToString()]);
            var (code, stdout, stderr) = await tool.RunAsync(args, TimeSpan.FromMinutes(2));
            Assert.True(code == 0, $"hashcat exit {code}: {stderr}");
            var candidates = stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(new[] { "abcd", "x2abcd1", "abcdabcd", "abcddcba", "aabbccdd", "abcdabcdabcd", "aaabcdddd", "ababcdbcd", "abc1", "bc1" }, candidates);
            var attack = new PreparedAttack { Description = "rules", Args = { "-a", "0", words, "-r", rules } };
            Assert.Equal(12, await OptimizedCandidateBounds.MaximumAsync(attack));
            output.WriteLine("10 real rule outputs matched; maximum 12 bytes matches the conservative bound.");
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(6)]
    [InlineData(7)]
    public async Task CombinationsAndHybridDictionariesMatchPure(int attackMode)
    {
        string? configured = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        if (string.IsNullOrEmpty(configured)) { output.WriteLine("Not run: set RECOVERKIT_TEST_HASHCAT to a private hashcat copy."); return; }
        var tool = HashcatTool.Locate(configured);
        Assert.NotNull(tool);
        var devices = await tool.DevicesAsync();
        string dir = Directory.CreateTempSubdirectory("rk-opt-combination").FullName;
        try
        {
            string words = Path.Combine(dir, "words.txt"), other = Path.Combine(dir, "other.txt"), hash = Path.Combine(dir, "target.hash");
            File.WriteAllText(words, "wrong\nab\n12\n");
            File.WriteAllText(other, "no\n12\n");
            File.WriteAllText(hash, Target("ab12"u8.ToArray()).HashLines + "\n");
            var attack = new PreparedAttack { Description = "combined", Args = { "-a", attackMode.ToString() } };
            attack.Args.AddRange(attackMode == 1 ? [words, other] : attackMode == 6 ? [words, "?d?d"] : ["?l?l", words]);
            Assert.True(await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, true));
            foreach (bool optimized in new[] { false, true })
            {
                var runner = new HashcatRunner(tool) { HashcatMajorVersion = 8, KnownDevices = devices };
                var result = await runner.RunAsync(new RunRequest
                {
                    Mode = 12500, HashFile = hash, Attack = attack, SessionName = "rk-opt-combination-" + Guid.NewGuid().ToString("N"),
                    SessionDir = dir, UseOptimizedKernel = optimized, Settings = SettingsFor(devices, dir, optimized: true),
                }, default);
                Assert.Equal(RunOutcome.Cracked, result.Outcome);
                Assert.Equal("ab12", Assert.Single(result.Passwords));
                output.WriteLine($"-a {attackMode}, optimized {optimized}: recovered ab12, rejected {result.LastStatus?.Rejected}");
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("dictionary-test", null, true)]
    [InlineData("dictionary-test", "$1", true)]
    [InlineData("123456789012345678901", ":", false)]
    [InlineData("12345678901234567890", "$1", false)]
    [InlineData("éééééééééé", ":", true)]
    [InlineData("ééééééééééa", ":", false)]
    public async Task Rar3MatchesPureIncludingOverLimitWordsAndRules(string word, string? rule, bool expectedOptimized)
    {
        string? configured = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        if (string.IsNullOrEmpty(configured)) { output.WriteLine("Not run: set RECOVERKIT_TEST_HASHCAT to a private hashcat copy."); return; }
        var tool = HashcatTool.Locate(configured);
        Assert.NotNull(tool);
        var devices = await tool.DevicesAsync();
        string dir = Directory.CreateTempSubdirectory("rk-opt-dictionary").FullName;
        try
        {
            // The reference widens Latin-1 bytes; hashcat decodes the UTF-8 dictionary to UTF-16.
            string password = rule == "$1" ? word + "1" : word;
            var target = Target(Encoding.Latin1.GetBytes(password));
            string words = Path.Combine(dir, "words.txt"), rules = Path.Combine(dir, "test.rule");
            File.WriteAllLines(words, Enumerable.Range(0, 8192).Select(i => $"wrong-word-{i:D5}").Append(word));
            if (rule is not null) File.WriteAllText(rules, rule + "\n");
            var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = rule is null ? RulesPreset.AsIs : RulesPreset.CustomFile, RulesFile = rules };
            spec.Dictionaries[0] = words;
            var attack = AttackPlanner.Prepare(spec, target, new());
            Assert.Equal(expectedOptimized, await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, true));

            int repeats = word.All(char.IsAscii) ? 3 : 1;
            for (int repeat = 0; repeat < repeats; repeat++)
                foreach (bool enabled in new[] { false, true })
                {
                    var settings = SettingsFor(devices, dir, enabled);
                    HashcatStatus? status = null;
                    var session = new RecoverySession(tool, settings) { Devices = devices };
                    session.Status += s => status = s;
                    var log = new List<string>();
                    session.Log += (_, line) => log.Add(line);
                    var timer = Stopwatch.StartNew();
                    var result = await session.RunAsync(target, "synthetic.rar", [spec], null, default);
                    output.WriteLine($"repeat {repeat + 1}, optimized {enabled && expectedOptimized}: {status?.TotalSpeed:F0}/s, {timer.Elapsed.TotalSeconds:F2}s, rejected {status?.Rejected}, outcome {result.Outcome}, progress {status?.ProgressDone}/{status?.ProgressTotal}");
                    if (result.Outcome != SessionOutcome.Found) foreach (string line in log) output.WriteLine(line);
                    Assert.Equal(SessionOutcome.Found, result.Outcome);
                    Assert.Equal(password, Assert.Single(result.Passwords));
                    Assert.NotNull(status);
                    Assert.Equal(0, status.Rejected);
                }

            if (!expectedOptimized)
            {
                // Characterize what an unsafe -O choice would do on exactly the same candidates.
                string hash = Path.Combine(dir, "raw.hash");
                File.WriteAllText(hash, target.HashLines + "\n");
                var runner = new HashcatRunner(tool) { HashcatMajorVersion = 8, KnownDevices = devices };
                var result = await runner.RunAsync(new RunRequest
                {
                    Mode = 12500, HashFile = hash, Attack = attack, SessionName = "rk-opt-unsafe-" + Guid.NewGuid().ToString("N"),
                    SessionDir = dir, UseOptimizedKernel = true, Settings = SettingsFor(devices, dir, optimized: true),
                }, default);
                Assert.Equal(RunOutcome.Exhausted, result.Outcome);
                output.WriteLine($"forced -O: exhausted, rejected {result.LastStatus?.Rejected}, {result.LastStatus?.TotalSpeed:F0}/s, password missed");
                if (rule == ":") Assert.True(result.LastStatus?.Rejected > 0);
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    internal static Settings SettingsFor(List<BackendDevice> devices, string dir, bool optimized)
    {
        var settings = new Settings
        {
            SessionsDir = dir, DontUsePasswordCache = true, UseNativeCpuEngine = false,
            OptimizedKernels = optimized, AutomaticPerformanceCalibration = false,
        };
        if (int.TryParse(Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT_DEVICE"), out int id))
        {
            var device = Assert.Single(devices, d => d.Id == id);
            settings.GpuPerformanceChoice = new() { DeviceKeys = [device.Key] };
        }
        return settings;
    }

    internal static HashTarget Target(byte[] password)
    {
        byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8];
        var reference = Rar3Kernel.TryParse("$RAR3$*0*0102030405060708*00000000000000000000000000000000")!;
        var (digest, iv) = reference.ReferenceHash(password);
        var key = new byte[16];
        for (int i = 0; i < 4; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(key.AsSpan(i * 4), BinaryPrimitives.ReadUInt32BigEndian(digest.AsSpan(i * 4)));
        using var aes = Aes.Create();
        aes.Key = key;
        byte[] block = [0xc4, 0x3d, 0x7b, 0, 0x40, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        string hash = $"$RAR3$*0*{Convert.ToHexString(salt).ToLowerInvariant()}*{Convert.ToHexString(aes.EncryptCbc(block, iv, PaddingMode.None)).ToLowerInvariant()}";
        return new HashTarget { FormatId = "TEST", FormatName = "RAR3", Protection = "test", Modes = [12500], HashLines = hash };
    }
}
