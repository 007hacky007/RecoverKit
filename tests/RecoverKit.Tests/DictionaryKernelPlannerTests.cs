using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public sealed class DictionaryKernelPlannerTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-dictionary-plan").FullName;
    public void Dispose() => Directory.Delete(_dir, true);

    [Fact]
    public void FixedLengthCapsPreventInflatingLaterGrowthInBest66()
    {
        string rules = Path.Combine(_dir, "caps.rule");
        File.WriteAllText(rules, "] ] ] d\n} } } } } } Y4 '4 d\n");
        Assert.Equal(10, OptimizedCandidateBounds.SafeInputLength([rules], 20));
        Assert.Equal(20, OptimizedCandidateBounds.MaximumWithRules([rules], 10));
        Assert.Equal(22, OptimizedCandidateBounds.MaximumWithRules([rules], 11));
    }

    [Theory]
    [InlineData("xZ1 d\n", 30, 10)]
    [InlineData("x04 d\n", 15, 20)]
    [InlineData("x44 d\n", 16, 20)]
    public void ExtractionMayLeaveTheWordUnchangedWhenItsRangeDoesNotFit(string text, int maximum, int threshold)
    {
        string rules = Path.Combine(_dir, "extract.rule");
        File.WriteAllText(rules, text);
        Assert.Equal(maximum, OptimizedCandidateBounds.MaximumWithRules([rules], 15));
        Assert.Equal(threshold, OptimizedCandidateBounds.SafeInputLength([rules], 20));
    }

    [Theory]
    [InlineData("$\\x30d\n")]
    [InlineData("^\\x30d\n")]
    [InlineData("i0\\x30d\n")]
    [InlineData("o0\\x30d\n")]
    [InlineData("s0\\x30d\n")]
    public void EscapedRuleOperandsCannotBeMistakenForExtraction(string text)
    {
        string rules = Path.Combine(_dir, "escaped.rule");
        File.WriteAllText(rules, text);
        Assert.Null(OptimizedCandidateBounds.SafeInputLength([rules], 20));
    }

    private async Task<IReadOnlyList<AttackSpec>> Plan(string text, string[] rules, double optimized = 200)
    {
        string words = Path.Combine(_dir, "words.txt");
        File.WriteAllText(words, text, new UTF8Encoding(false));
        var spec = new AttackSpec { Kind = AttackKind.Dictionary };
        spec.Dictionaries[0] = words;
        var prepared = new PreparedAttack { Description = "words", Args = { "-a", "0", words } };
        for (int i = 0; i < rules.Length; i++)
        {
            string path = Path.Combine(_dir, $"rules{i}.rule");
            File.WriteAllText(path, rules[i]);
            prepared.Args.AddRange(["-r", path]);
        }
        return await DictionaryKernelPlanner.PlanAsync(spec, prepared, 20, 100, optimized,
            Path.Combine(_dir, "tail.txt"), cacheDirectory: Path.Combine(_dir, "cache"));
    }

    [Fact]
    public async Task TailPreservesByteLengthsAndLineContentsIncludingUtf8()
    {
        var lines = new[] { "", new string('a', 19), new string('b', 20), new string('c', 21), new string('é', 10), new string('é', 10) + "x" };
        string text = string.Concat(Enumerable.Repeat("short\r\n", 200)) + string.Join("\r\n", lines);
        var passes = await Plan(text, ["$1\n"]);
        Assert.Equal(2, passes.Count);
        var a = passes[0].DictionaryKernel!;
        var b = passes[1].DictionaryKernel!;
        Assert.True(a.Optimized);
        Assert.False(b.Optimized);
        Assert.Equal(19, a.Threshold);
        Assert.Equal(206, a.Words);
        Assert.Equal(4, b.Words);
        Assert.Equal(lines.Where(w => Encoding.UTF8.GetByteCount(w) > 19), File.ReadAllLines(b.TailPath!));
        Assert.Equal(a.Arguments![2], passes[0].Dictionaries[0]);
        Assert.Equal(b.TailPath, b.Arguments![2]);
        Assert.Equal(a.Arguments.Skip(3), b.Arguments.Skip(3));
    }

    [Theory]
    [InlineData(200, 70, false)]
    [InlineData(200, 10, true)]
    [InlineData(110, 10, false)]
    [InlineData(300, 55, true)]
    public async Task SplitDecisionUsesBothPassDurations(double optimized, int longWords, bool split)
    {
        string text = string.Concat(Enumerable.Repeat("short\n", 100 - longWords))
            + string.Concat(Enumerable.Repeat(new string('a', 21) + "\n", longWords));
        var passes = await Plan(text, [], optimized);
        Assert.Equal(split ? 2 : 1, passes.Count);
        Assert.Equal(split, passes[0].DictionaryKernel!.Optimized);
    }

    [Fact]
    public async Task DoublingAndMultipleRuleFilesUseASafeInputThreshold()
    {
        string text = string.Concat(Enumerable.Repeat("small\n", 200)) + "abcdefghij\n";
        var passes = await Plan(text, [":\nd\n] ] ] d\n", "$1\n"]);
        Assert.Equal(2, passes.Count);
        Assert.Equal(9, passes[0].DictionaryKernel!.Threshold);
        Assert.Equal(3, passes[0].DictionaryKernel!.RuleCount);
        Assert.Equal("abcdefghij", Assert.Single(File.ReadAllLines(passes[1].DictionaryKernel!.TailPath!)));
        Assert.Equal(4, passes[0].DictionaryKernel!.Arguments!.Skip(3).Count());
    }

    [Fact]
    public async Task UnknownMemoryRulesRemainPure()
    {
        var passes = await Plan("short\n" + new string('a', 21), ["M4\n"]);
        Assert.Single(passes);
        Assert.False(passes[0].DictionaryKernel!.Optimized);
        Assert.False(File.Exists(Path.Combine(_dir, "tail.txt")));
    }

    [Theory]
    [InlineData("PK\u0003\u0004")]
    [InlineData("\ufeff")]
    public async Task NewTailHeaderCannotChangeDictionaryInterpretation(string prefix)
    {
        var passes = await Plan(string.Concat(Enumerable.Repeat("short\n", 200)) + prefix + new string('a', 24), []);
        Assert.Single(passes);
        Assert.False(passes[0].DictionaryKernel!.Optimized);
        Assert.False(File.Exists(Path.Combine(_dir, "tail.txt")));
    }

    [Theory]
    [InlineData(0, true)]      // no CPU engine for this attack: the optimized passes run
    [InlineData(150, true)]    // pure kernel plus CPU is slower than the optimized passes
    [InlineData(400, false)]   // pure kernel plus CPU is faster: stay pure so the CPU engine can join
    public async Task OptimizedPassesMustBeatThePureKernelWithTheCpuEngine(double hybridRate, bool optimized)
    {
        foreach (bool longWord in new[] { false, true })
        {
            string words = Path.Combine(_dir, $"hybrid-{hybridRate}-{longWord}.txt");
            File.WriteAllText(words, string.Concat(Enumerable.Repeat("short\n", 12000)) + (longWord ? new string('a', 21) + "\n" : ""));
            var spec = new AttackSpec { Kind = AttackKind.Dictionary };
            spec.Dictionaries[0] = words;
            var prepared = new PreparedAttack { Description = "words", Args = { "-a", "0", words } };
            var passes = await DictionaryKernelPlanner.PlanAsync(spec, prepared, 20, 100, 200,
                Path.Combine(_dir, $"tail-{hybridRate}-{longWord}.txt"), cacheDirectory: Path.Combine(_dir, "cache"), hybridRate: hybridRate);
            Assert.Equal(optimized && longWord ? 2 : 1, passes.Count);
            Assert.Equal(optimized, passes[0].DictionaryKernel!.Optimized);
        }
    }

    [Fact]
    public async Task TailKeepsRawBytesEvenWhenItsFirstWordIsNotUtf8()
    {
        string words = Path.Combine(_dir, "raw.txt");
        byte[] longWord = [0xff, .. Enumerable.Repeat((byte)'a', 21)];
        File.WriteAllBytes(words, [.. Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("short\n", 12000))), .. longWord, (byte)'\n']);
        Assert.True(Wordlists.HashcatCanReadDirectly(words));
        var spec = new AttackSpec { Kind = AttackKind.Dictionary };
        spec.Dictionaries[0] = words;
        var prepared = new PreparedAttack { Description = "raw", Args = { "-a", "0", words } };
        var passes = await DictionaryKernelPlanner.PlanAsync(spec, prepared, 20, 100, 200,
            Path.Combine(_dir, "tail.txt"), cacheDirectory: Path.Combine(_dir, "cache"));
        Assert.Equal(2, passes.Count);
        Assert.Equal([.. longWord, (byte)'\n'], File.ReadAllBytes(passes[1].DictionaryKernel!.TailPath!));
        var target = new HashTarget { FormatId = "RAR", FormatName = "RAR", Protection = "RAR3", HashLines = "unused", Modes = [12500] };
        Assert.Null(AttackPlanner.Prepare(passes[1], target, new()).Stdin);
    }

    [Fact]
    public async Task MissingOrModifiedTailIsRebuiltIdenticallyButChangedSourcesAreRefused()
    {
        var passes = await Plan(string.Concat(Enumerable.Repeat("short\n", 200)) + new string('a', 21), []);
        var pass = passes[1].DictionaryKernel!;
        byte[] expected = File.ReadAllBytes(pass.TailPath!);
        File.Delete(pass.TailPath!);
        await DictionaryKernelPlanner.PreparePassAsync(pass, null, default);
        Assert.Equal(expected, File.ReadAllBytes(pass.TailPath!));
        File.WriteAllText(pass.TailPath!, "incorrect\n");
        await DictionaryKernelPlanner.PreparePassAsync(pass, null, default);
        Assert.Equal(expected, File.ReadAllBytes(pass.TailPath!));
        File.AppendAllText(pass.Source!.Path, "changed\n");
        await Assert.ThrowsAsync<InvalidDataException>(() => DictionaryKernelPlanner.PreparePassAsync(pass, null, default));
    }

    [Fact]
    public async Task ChangedRulesAreRefusedOnResume()
    {
        var passes = await Plan(string.Concat(Enumerable.Repeat("short\n", 200)) + new string('a', 21), ["$1\n"]);
        var pass = passes[1].DictionaryKernel!;
        File.AppendAllText(pass.Rules[0].Path, "$2\n");
        await Assert.ThrowsAsync<InvalidDataException>(() => DictionaryKernelPlanner.PreparePassAsync(pass, null, default));
    }

    [Fact]
    public void DiscardingASessionRemovesItsSubsetAndInterruptedWritesOnly()
    {
        var settings = new Settings { SessionsDir = _dir };
        File.WriteAllText(Path.Combine(_dir, "session.dictionary-0.txt"), "long\n");
        File.WriteAllText(Path.Combine(_dir, "session.dictionary-0.txt.partial.tmp"), "partial");
        File.WriteAllText(Path.Combine(_dir, "different.dictionary-0.txt"), "keep");
        SessionState.Delete(settings, "session");
        Assert.Empty(Directory.GetFiles(_dir, "session.dictionary-*"));
        Assert.True(File.Exists(Path.Combine(_dir, "different.dictionary-0.txt")));
    }

    [Theory]
    [InlineData(false, "Windows", true)]
    [InlineData(false, "Linux", true)]
    [InlineData(true, "macOS", false)]
    public void MacGuardCannotAlterOtherPlatforms(bool isMacOS, string platform, bool expected)
    {
        var attack = new PreparedAttack { Description = platform, Args = { "-a", "0", "words" } };
        Assert.Equal(expected, RecoverySession.OptimizedDictionaryBackendAllowed(12500, attack, new(),
            [new BackendDevice { Id = 1, Type = "GPU", Backend = "OpenCL", Vendor = "Apple" }], isMacOS));
        Assert.True(RecoverySession.OptimizedDictionaryBackendAllowed(12500, attack, new(), null, isMacOS: false));
        // Every format runs through Metal on macOS, so the same applies beyond RAR 3.
        Assert.Equal(expected, RecoverySession.OptimizedDictionaryBackendAllowed(13000, attack, new(),
            [new BackendDevice { Id = 1, Type = "GPU", Backend = "OpenCL", Vendor = "Apple" }], isMacOS));
    }
}
