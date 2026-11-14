using System.Diagnostics;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

[Trait("Category", "Slow")]
[Collection("NativeFeatures")]   // one hashcat at a time: GPU tests must not run in parallel
public sealed class DictionarySplitSlowTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-dictionary-split").FullName;
    public void Dispose() => Directory.Delete(_dir, true);

    private HashcatTool? Tool()
    {
        string? path = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        if (string.IsNullOrWhiteSpace(path)) { output.WriteLine("Not run: set RECOVERKIT_TEST_HASHCAT to a private writable copy."); return null; }
        var tool = HashcatTool.Locate(path);
        Assert.NotNull(tool);
        return tool;
    }

    private async Task<HashSet<string>> Candidates(HashcatTool tool, IReadOnlyList<string> args)
    {
        var command = new List<string> { "--stdout", "--quiet", "--session", "rk-union-" + Guid.NewGuid().ToString("N"), "--restore-disable" };
        command.AddRange(args);
        if (int.TryParse(Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT_DEVICE"), out int id)) command.AddRange(["-d", id.ToString()]);
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        using var process = Process.Start(tool.StartInfo(command))!;
        using var stdout = new MemoryStream();
        var copy = process.StandardOutput.BaseStream.CopyToAsync(stdout, timeout.Token);
        var error = process.StandardError.ReadToEndAsync(timeout.Token);
        try { await Task.WhenAll(copy, error, process.WaitForExitAsync(timeout.Token)); }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        Assert.True(process.ExitCode == 0, $"hashcat exit {process.ExitCode}: {await error}");
        // Rules can split a UTF-8 sequence. Compare bytes without replacement-character decoding.
        var candidates = new HashSet<string>(StringComparer.Ordinal);
        var bytes = stdout.ToArray();
        int start = 0;
        for (int i = 0; i < bytes.Length; i++)
            if (bytes[i] == '\n')
            {
                int length = i - start;
                if (length > 0 && bytes[i - 1] == '\r') length--;
                var candidate = bytes.AsSpan(start, length);
                // hashcat autohex-encodes output containing invalid UTF-8 or control bytes.
                candidates.Add(candidate.StartsWith("$HEX["u8) && candidate.EndsWith("]"u8)
                    ? Convert.ToHexString(Convert.FromHexString(Encoding.ASCII.GetString(candidate[5..^1])))
                    : Convert.ToHexString(candidate));
                start = i + 1;
            }
        return candidates;
    }

    [Theory]
    [InlineData(":\n", null)]
    [InlineData(":\n$1\n", null)]
    [InlineData("]\n$1 ]\n] $1\n", null)]
    [InlineData(":\nd\n", "]\n$1\n")]
    [InlineData(":\nxZ1 d\nx04 d\n", null)]
    public async Task GuaranteedOptimizedInputsAndPureTailHaveTheSameUnionAsPure(string firstRules, string? secondRules)
    {
        var tool = Tool();
        if (tool is null) return;
        string words = Path.Combine(_dir, "words.txt"), safe = Path.Combine(_dir, "safe.txt");
        string[] edge = ["", new string('d', 15), new string('a', 19), new string('b', 20), new string('c', 21),
            new string('é', 9) + "a", new string('é', 10), new string('é', 10) + "a"];
        File.WriteAllLines(words, Enumerable.Repeat("short", 12000).Concat(edge), new UTF8Encoding(false));
        using (var file = File.Open(words, FileMode.Append))
            file.Write([0xff, .. Enumerable.Repeat((byte)'x', 21), (byte)'\n']);
        Assert.True(Wordlists.HashcatCanReadDirectly(words));
        var spec = new AttackSpec { Kind = AttackKind.Dictionary };
        spec.Dictionaries[0] = words;
        var prepared = new PreparedAttack { Description = "union", Args = { "-a", "0", words } };
        int number = 0;
        foreach (string rules in new[] { firstRules, secondRules }.OfType<string>())
        {
            string path = Path.Combine(_dir, $"rules{number++}.rule");
            File.WriteAllText(path, rules);
            prepared.Args.AddRange(["-r", path]);
        }
        var passes = await DictionaryKernelPlanner.PlanAsync(spec, prepared, 20, 100, 200,
            Path.Combine(_dir, "tail.txt"), cacheDirectory: Path.Combine(_dir, "cache"));
        Assert.Equal(2, passes.Count);
        var a = passes[0].DictionaryKernel!;
        var b = passes[1].DictionaryKernel!;
        File.WriteAllLines(safe, File.ReadAllLines(words).Where(w => Encoding.UTF8.GetByteCount(w) <= a.Threshold));
        var safeArgs = a.Arguments!.ToList();
        safeArgs[2] = safe;
        var pure = await Candidates(tool, prepared.Args);
        // These are the inputs whose every intermediate rule result is guaranteed to fit pass A.
        var guaranteed = await Candidates(tool, safeArgs);
        Assert.All(guaranteed, hex => Assert.True(hex.Length <= 40));
        if (firstRules.StartsWith("]\n", StringComparison.Ordinal))
            Assert.Contains(Convert.ToHexString(Encoding.UTF8.GetBytes(new string('é', 9))) + "C3", pure);
        if (firstRules.Contains("xZ1", StringComparison.Ordinal))
            Assert.Contains(Convert.ToHexString(Encoding.ASCII.GetBytes(new string('d', 30))), pure);
        guaranteed.UnionWith(await Candidates(tool, b.Arguments!));
        Assert.True(pure.SetEquals(guaranteed), $"pure {pure.Count} distinct candidates, union {guaranteed.Count}, threshold {a.Threshold}");
        output.WriteLine($"pure and pass union: {pure.Count} distinct candidates, threshold {a.Threshold}, tail {b.Words} words");
    }

    [Fact]
    public async Task EscapedRuleOperandsStayPureAndKeepTheirActualGrowth()
    {
        var tool = Tool();
        if (tool is null) return;
        string words = Path.Combine(_dir, "escaped.txt"), rules = Path.Combine(_dir, "escaped.rule");
        string word = new('a', 19);
        File.WriteAllText(words, word + "\n");
        File.WriteAllText(rules, "$\\x30d\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = OptimizedDictionarySlowTests.Target("unused"u8.ToArray());
        var attack = AttackPlanner.Prepare(spec, target, new());
        var passes = await DictionaryKernelPlanner.PlanAsync(spec, attack, 20, 100, 200,
            Path.Combine(_dir, "tail.txt"), cacheDirectory: Path.Combine(_dir, "cache"));
        var pass = Assert.Single(passes);
        Assert.False(pass.DictionaryKernel!.Optimized);
        var pure = await Candidates(tool, attack.Args);
        Assert.Contains(Convert.ToHexString(Encoding.ASCII.GetBytes(word + "0" + word + "0")), pure);
        Assert.True(pure.SetEquals(await Candidates(tool, AttackPlanner.Prepare(pass, target, new()).Args)));
        output.WriteLine("Escaped append followed by doubling produces 40 bytes from 19 bytes; the full attack remains pure.");
    }

    [Fact]
    public async Task OverLimitRuleOutputIsCoveredEvenIfOptimizedDropsOrTruncatesIt()
    {
        var tool = Tool();
        if (tool is null) return;
        var devices = await tool.DevicesAsync();
        string prefix = new('g', 20), password = prefix + "1";
        string hash = Path.Combine(_dir, "target.hash"), words = Path.Combine(_dir, "words.txt"), rules = Path.Combine(_dir, "test.rule");
        File.WriteAllLines(hash, [OptimizedDictionarySlowTests.Target(Encoding.ASCII.GetBytes(password)).HashLines,
            OptimizedDictionarySlowTests.Target(Encoding.ASCII.GetBytes(prefix)).HashLines]);
        File.WriteAllText(words, prefix + "\n");
        File.WriteAllText(rules, "$1\n");
        var attack = new PreparedAttack { Description = "rule overflow", Args = { "-a", "0", words, "-r", rules } };
        foreach (bool optimized in new[] { false, true })
        {
            var result = await new HashcatRunner(tool) { HashcatMajorVersion = 8, KnownDevices = devices }.RunAsync(new RunRequest
            {
                Mode = 12500, HashFile = hash, Attack = attack, SessionName = "rk-overflow-" + Guid.NewGuid().ToString("N"), SessionDir = _dir,
                UseOptimizedKernel = optimized, Settings = OptimizedDictionarySlowTests.SettingsFor(devices, _dir, optimized),
            }, default);
            Assert.True(result.Outcome is RunOutcome.Cracked or RunOutcome.Exhausted, result.Error);
            if (!optimized) Assert.Equal(password, Assert.Single(result.Passwords));
            else Assert.DoesNotContain(password, result.Passwords);
            output.WriteLine($"optimized {optimized}: {result.Outcome}, rejected {result.LastStatus?.Rejected}, real output found {result.Passwords.Contains(password)}, truncated prefix found {result.Passwords.Contains(prefix)}");
        }
    }

    private (string Words, string Rules) LargeDictionary()
    {
        string words = Path.Combine(_dir, "real-shaped.txt"), rules = Path.Combine(_dir, "test.rule");
        File.WriteAllLines(words, Enumerable.Range(0, 240000).Select(i => $"w{i:D7}")
            .Concat([new string('x', 21), new string('g', 20)]));
        File.WriteAllText(rules, ":\n$1\n");
        return (words, rules);
    }

    [Fact]
    public async Task ShippedBest66FindsACappedThenDuplicatedPasswordInPassA()
    {
        var tool = Tool();
        if (tool is null) return;
        var devices = await tool.DevicesAsync();
        string words = Path.Combine(_dir, "best66.txt"), rules = Path.Combine(tool.Directory, "rules", "best66.rule");
        File.WriteAllLines(words, Enumerable.Repeat("short", 200).Concat(["abcdefghij", new string('x', 21)]));
        Assert.Equal(10, OptimizedCandidateBounds.SafeInputLength([rules], 20));
        Assert.Contains(Convert.ToHexString("efghefgh"u8), await Candidates(tool, ["-a", "0", words, "-r", rules]));
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = OptimizedDictionarySlowTests.Target("efghefgh"u8.ToArray());
        foreach (bool enabled in new[] { false, true })
        {
            var session = new RecoverySession(tool, OptimizedDictionarySlowTests.SettingsFor(devices, _dir, enabled)) { Devices = devices };
            int step = -1, count = 0;
            session.StepStarted += (i, n, _, _) => { step = i; count = n; };
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            var result = await session.RunAsync(target, "synthetic.rar", [spec], null, timeout.Token);
            Assert.Equal(SessionOutcome.Found, result.Outcome);
            Assert.Equal("efghefgh", Assert.Single(result.Passwords));
            Assert.Equal(0, step);
            Assert.Equal(enabled ? 2 : 1, count);
            output.WriteLine($"best66, optimized enabled {enabled}: found efghefgh in pass A, safe input length 10");
        }
    }

    [Theory]
    [InlineData("w0123456", 0)]
    [InlineData("xxxxxxxxxxxxxxxxxxxxx", 1)]
    [InlineData("gggggggggggggggggggg1", 1)]
    public async Task RealShapedDictionaryFindsEachPasswordInTheExpectedPass(string password, int expectedPass)
    {
        var tool = Tool();
        if (tool is null) return;
        var devices = await tool.DevicesAsync();
        var (words, rules) = LargeDictionary();
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = OptimizedDictionarySlowTests.Target(Encoding.ASCII.GetBytes(password));
        foreach (bool enabled in new[] { false, true })
        {
            var session = new RecoverySession(tool, OptimizedDictionarySlowTests.SettingsFor(devices, _dir, enabled)) { Devices = devices };
            var seen = new List<(int Index, int Count, System.Numerics.BigInteger Candidates)>();
            session.StepStarted += (i, n, _, count) => seen.Add((i, n, count));
            var timer = Stopwatch.StartNew();
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(10));
            var result = await session.RunAsync(target, "synthetic.rar", [spec], null, timeout.Token);
            Assert.Equal(SessionOutcome.Found, result.Outcome);
            Assert.Equal(password, Assert.Single(result.Passwords));
            Assert.Equal(enabled ? expectedPass : 0, seen[^1].Index);
            Assert.Equal(enabled ? 2 : 1, seen[^1].Count);
            if (enabled) Assert.Equal(expectedPass == 0 ? 480004 : 4, seen[^1].Candidates);
            Assert.Empty(Directory.GetFiles(_dir, SessionState.KeyFor(target) + ".dictionary-*"));
            output.WriteLine($"optimized enabled {enabled}: found in step {seen[^1].Index + 1}/{seen[^1].Count}, {timer.Elapsed.TotalSeconds:F2}s, step candidates {seen[^1].Candidates}");
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task PureAndSplitTimingPair(int repeat)
    {
        var tool = Tool();
        if (tool is null) return;
        var devices = await tool.DevicesAsync();
        var (words, rules) = LargeDictionary();
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = OptimizedDictionarySlowTests.Target("outside-list"u8.ToArray());
        foreach (bool enabled in new[] { false, true })
        {
            var session = new RecoverySession(tool, OptimizedDictionarySlowTests.SettingsFor(devices, _dir, enabled)) { Devices = devices };
            double lastSpeed = 0;
            int steps = 0;
            session.Status += s => lastSpeed = s.TotalSpeed;
            session.StepStarted += (_, _, _, _) => steps++;
            var timer = Stopwatch.StartNew();
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(10));
            var result = await session.RunAsync(target, "synthetic.rar", [spec], null, timeout.Token);
            string rate = result.Outcome == SessionOutcome.NotFound ? $"{480004 / timer.Elapsed.TotalSeconds:F0} original candidates/s including startup" : "incomplete";
            string record = $"pair {repeat}, split {enabled}: {timer.Elapsed.TotalSeconds:F2}s, {rate}, final pass {lastSpeed:F0}/s, {result.Outcome}";
            output.WriteLine(record);
            File.AppendAllText(Path.Combine(_dir, "timings.log"), record + Environment.NewLine);
            Assert.Equal(SessionOutcome.NotFound, result.Outcome);
            Assert.Equal(enabled ? 2 : 1, steps);
        }
    }
}
