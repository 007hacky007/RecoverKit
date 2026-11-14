using System.Text.Json.Nodes;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using Xunit;

namespace RecoverKit.Tests;

public class OptimizedKernelTests
{
    private const string Pure = """
        {"12500":{"name":"RAR3-hp","slow_hash":true,"kernel_type":["pure","optimized"],"password_len_max":128}}
        """;
    private const string Optimized = """
        {"12500":{"name":"RAR3-hp","kernel_type_filter":["optimized"],"attack_mode_filter":3,"password_len_max":20,"benchmark_mask":"?l?l?l?l?l","benchmark_charset1":"N/A"}}
        """;

    private static PreparedAttack Mask(int length) => new() { Description = "test", Args = { "-a", "3", new string('a', length) } };

    [Fact]
    public async Task RareLongDictionaryWordsBecomeTwoSavedSteps()
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        string words = Path.Combine(t.Path, "mixed.txt");
        File.WriteAllLines(words, Enumerable.Repeat("short", 10000).Append(new string('a', 21)));
        var settings = new Settings { SessionsDir = t.Path, DontUsePasswordCache = true, UseNativeCpuEngine = false };
        var spec = new AttackSpec { Kind = AttackKind.Dictionary };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "TEST", FormatName = "test", Protection = "test", Modes = [12500], HashLines = "test" };
        var session = new RecoverySession(tool, settings) { Devices = [new BackendDevice { Id = 1, Type = "GPU", Backend = "Metal" }] };
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [spec], null, default)).Outcome);
        var state = SessionState.Load(settings, target)!;
        Assert.Equal(2, state.Steps.Count);
        Assert.Equal(0, state.StepIndex);
        Assert.True(state.UseOptimizedKernel);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SplitResumesTheSavedPassAndRebuildsItsTail(bool stopInPurePass)
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        string words = Path.Combine(t.Path, "mixed.txt");
        File.WriteAllLines(words, Enumerable.Repeat("short", 10000).Append(new string('a', 21)));
        File.AppendAllLines(words, Enumerable.Range(0, 99).Select(i => new string('b', 21) + i));
        var settings = new Settings { SessionsDir = t.Path, DontUsePasswordCache = true, UseNativeCpuEngine = false };
        var spec = new AttackSpec { Kind = AttackKind.Dictionary };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "TEST", FormatName = "test", Protection = "test", Modes = [12500], HashLines = "test" };
        var session = new RecoverySession(tool, settings) { Devices = [new BackendDevice { Id = 1, Type = "GPU", Backend = "Metal" }] };
        if (stopInPurePass) File.WriteAllText(Path.Combine(t.Path, "exhaust-optimized"), "");
        File.WriteAllText(Path.Combine(t.Path, "emit-speeds"), "");
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [spec], null, default)).Outcome);
        var state = SessionState.Load(settings, target)!;
        Assert.Equal(stopInPurePass ? 1 : 0, state.StepIndex);
        Assert.Equal(!stopInPurePass, state.UseOptimizedKernel);
        Assert.Equal(1000, settings.SpeedByMode[12500]);
        string tail = state.Steps[0].DictionaryKernel!.TailPath!;
        byte[] expected = File.ReadAllBytes(tail);
        string restore = HashcatRunner.RestoreFile(t.Path, state.HashcatSession);
        var checkpoint = new byte[280];
        BitConverter.GetBytes(3L).CopyTo(checkpoint, 272);
        File.WriteAllBytes(restore, checkpoint);
        File.Delete(tail);
        settings.OptimizedKernels = false;
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [], state, default)).Outcome);
        Assert.Equal(expected, File.ReadAllBytes(tail));
        var args = File.ReadAllLines(Path.Combine(t.Path, "run.args"));
        Assert.Contains("--restore-position", args);
        Assert.Equal(restore, args[Array.IndexOf(args, "--restore-file-path") + 1]);
        Assert.Equal(checkpoint, File.ReadAllBytes(restore));
        Assert.Equal(3, RecoverKit.Core.Native.HybridRunner.ReadRestorePoint(restore));
        Assert.Equal(!stopInPurePass, args.Contains("-O"));
        Assert.Equal(stopInPurePass ? 1 : 0, SessionState.Load(settings, target)!.StepIndex);
        File.WriteAllText(Path.Combine(t.Path, "exit-code"), "1\n");
        File.Delete(Path.Combine(t.Path, "exhaust-optimized"));
        Assert.Equal(SessionOutcome.NotFound, (await session.RunAsync(target, "fixture", [], SessionState.Load(settings, target), default)).Outcome);
        Assert.False(File.Exists(tail));
        Assert.Null(SessionState.Load(settings, target));
    }

    [Fact]
    public async Task OlderMixedDictionarySessionIsNotExpanded()
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        string words = Path.Combine(t.Path, "mixed.txt");
        File.WriteAllLines(words, Enumerable.Repeat("short", 10000).Append(new string('a', 21)));
        var settings = new Settings { SessionsDir = t.Path, DontUsePasswordCache = true, UseNativeCpuEngine = false };
        var spec = new AttackSpec { Kind = AttackKind.Dictionary };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "TEST", FormatName = "test", Protection = "test", Modes = [12500], HashLines = "test" };
        var state = new SessionState { Key = SessionState.KeyFor(target), Steps = [spec], Modes = [12500], HashcatSession = "old-dictionary", Restorable = true };
        state.Save(settings);
        var json = JsonNode.Parse(File.ReadAllText(SessionState.PathFor(settings, state.Key)))!.AsObject();
        json.Remove("DictionaryPlanPending");
        json.Remove("UseOptimizedKernel");
        File.WriteAllText(SessionState.PathFor(settings, state.Key), json.ToJsonString());
        File.WriteAllText(HashcatRunner.RestoreFile(t.Path, state.HashcatSession), "");
        var session = new RecoverySession(tool, settings) { Devices = [new BackendDevice { Id = 1, Type = "GPU", Backend = "Metal" }] };
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [], SessionState.Load(settings, target), default)).Outcome);
        Assert.Single(SessionState.Load(settings, target)!.Steps);
        Assert.DoesNotContain("-O", File.ReadAllLines(Path.Combine(t.Path, "run.args")));
        Assert.Empty(Directory.GetFiles(t.Path, state.Key + ".dictionary-*"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SplitResumeRefusesChangedInputsOrCandidateArguments(bool changeArguments)
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        string words = Path.Combine(t.Path, "mixed.txt");
        File.WriteAllLines(words, Enumerable.Repeat("short", 10000).Append(new string('a', 21)));
        var settings = new Settings { SessionsDir = t.Path, DontUsePasswordCache = true, UseNativeCpuEngine = false };
        var spec = new AttackSpec { Kind = AttackKind.Dictionary };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "TEST", FormatName = "test", Protection = "test", Modes = [12500], HashLines = "test" };
        var session = new RecoverySession(tool, settings) { Devices = [new BackendDevice { Id = 1, Type = "GPU", Backend = "Metal" }] };
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [spec], null, default)).Outcome);
        if (changeArguments) settings.ExtraArguments = "-j p4";
        else File.AppendAllText(words, "changed\n");
        var result = await session.RunAsync(target, "fixture", [], SessionState.Load(settings, target), default);
        Assert.Equal(SessionOutcome.Error, result.Outcome);
        Assert.Contains("changed", result.Error!, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Directory.GetFiles(t.Path, SessionState.KeyFor(target) + ".dictionary-*"));
    }

    [Fact]
    public async Task CancellationDuringCombinationLengthScanSavesAnUnstartedStep()
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        string words = Path.Combine(t.Path, "words.txt");
        File.WriteAllText(words, "short\n");
        var settings = new Settings { SessionsDir = t.Path, DontUsePasswordCache = true, UseNativeCpuEngine = false };
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.TwoWords };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "TEST", FormatName = "test", Protection = "test", Modes = [12500], HashLines = "test" };
        var session = new RecoverySession(tool, settings) { Devices = [new BackendDevice { Id = 1, Type = "GPU", Backend = "Metal" }] };
        using var cancelled = new CancellationTokenSource();
        session.Log += (_, message) => { if (message.StartsWith("Checking word lengths", StringComparison.Ordinal)) cancelled.Cancel(); };
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [spec], null, cancelled.Token)).Outcome);
        var saved = SessionState.Load(settings, target)!;
        Assert.False(saved.Restorable);
        Assert.Equal(0, saved.StepIndex);
        Assert.False(File.Exists(Path.Combine(t.Path, "run.args")));
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [], saved, default)).Outcome);
        Assert.DoesNotContain("--restore-position", File.ReadAllLines(Path.Combine(t.Path, "run.args")));
    }

    [Theory]
    [InlineData(19, true)]
    [InlineData(20, true)]
    [InlineData(21, false)]
    public void UsesTheReportedLimitForMasks(int length, bool expected)
        => Assert.Equal(expected, RecoverySession.CanUseOptimizedKernel(HashcatTool.ParseModeInfo(12500, Pure, Optimized), Mask(length)));

    [Theory]
    [InlineData(null)]
    [InlineData("{}")]
    [InlineData("not json")]
    [InlineData("{\"12500\":{\"password_len_max\":20}}")]
    [InlineData("{\"12500\":{\"kernel_type_filter\":[\"pure\"],\"password_len_max\":128}}")]
    [InlineData("{\"12500\":{\"kernel_type_filter\":[\"optimized\"],\"password_len_max\":0}}")]
    [InlineData("{\"12500\":{\"kernel_type_filter\":[\"optimized\"],\"password_len_max\":\"20\"}}")]
    public void UnknownOrUnselectedOptimizedLimitUsesPure(string? optimized)
    {
        var info = HashcatTool.ParseModeInfo(12500, Pure, optimized);
        Assert.Equal(128, info.PasswordLenMax);
        Assert.False(RecoverySession.CanUseOptimizedKernel(info, Mask(1)));
        Assert.False(RecoverySession.CanUseOptimizedKernel(null, Mask(1)));
    }

    [Fact]
    public void MeasuresThePreparedAttackIncludingIncrementAndUtf8()
    {
        var info = HashcatTool.ParseModeInfo(12500, Pure, Optimized);
        var target = new HashTarget { FormatId = "TEST", FormatName = "test", Protection = "test", Modes = [12500], HashLines = "test" };
        var brute = new AttackSpec { MaxLength = 21 };
        Assert.False(RecoverySession.CanUseOptimizedKernel(info, AttackPlanner.Prepare(brute, target, new())));
        brute.Mask = new string('a', 20) + "?";
        brute.MaxLength = 1;
        Assert.False(RecoverySession.CanUseOptimizedKernel(info, AttackPlanner.Prepare(brute, target, new())));
        brute.Mask = new string('a', 18) + "é?"; // 21 UTF-8 bytes in hashcat's hex mask
        Assert.False(RecoverySession.CanUseOptimizedKernel(info, AttackPlanner.Prepare(brute, target, new())));
        var increment = Mask(21);
        increment.Args.InsertRange(2, ["-i", "--increment-min", "1", "--increment-max", "20"]);
        Assert.True(RecoverySession.CanUseOptimizedKernel(info, increment));
        Assert.False(RecoverySession.CanUseOptimizedKernel(info, new PreparedAttack { Description = "words", Args = { "-a", "0", "words", "-r", "rules" } }));
        var streamed = Mask(1);
        streamed.Stdin = () => ["a"];
        Assert.False(RecoverySession.CanUseOptimizedKernel(info, streamed));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(null, true)]
    public async Task ResumeUsesSavedChoiceWithoutQueryingChangedSettings(bool? saved, bool enabled)
    {
        using var t = new TempDir();
        string exe = Path.Combine(t.Path, "missing-engine");
        File.WriteAllText(exe, "");
        var tool = HashcatTool.Locate(exe, t.Path, t.Path)!;
        Assert.Equal(saved ?? false, await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, Mask(21), enabled, restore: true, savedChoice: saved));
    }

    [Theory]
    [InlineData(true, false, false)]
    [InlineData(false, false, false)]
    [InlineData(true, true, false)]
    [InlineData(false, true, false)]
    [InlineData(true, false, true)]
    [InlineData(false, false, true)]
    public async Task SessionSavesChoiceBeforeRunAndHonoursItOnResume(bool enabled, bool keySearch, bool dictionary)
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        int mode = keySearch ? 9710 : 12500;
        var tool = FakeTool(t.Path, mode);
        var settings = new Settings { SessionsDir = t.Path, DontUsePasswordCache = true, DontUseKeyCache = true, UseNativeCpuEngine = false, OptimizedKernels = enabled };
        var target = new HashTarget { FormatId = keySearch ? "972K" : "TEST", FormatName = "test", Protection = "test", Modes = [mode], HashLines = "test" };
        var session = new RecoverySession(tool, settings)
        {
            Devices = dictionary ? [new BackendDevice { Id = 1, Type = "GPU", Backend = "Metal" }] : null,
        };
        var attack = new AttackSpec { Kind = keySearch ? AttackKind.KeySearch : dictionary ? AttackKind.Dictionary : AttackKind.Mask, HashcatMask = "?d?d?d" };
        if (dictionary)
        {
            attack.Dictionaries[0] = Path.Combine(t.Path, "words.txt");
            File.WriteAllText(attack.Dictionaries[0]!, "short\n");
        }
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [attack], null, default)).Outcome);
        var state = SessionState.Load(settings, target)!;
        Assert.Equal(enabled, state.UseOptimizedKernel);
        Assert.Equal(enabled, JsonNode.Parse(File.ReadAllText(Path.Combine(t.Path, "state-at-start.json")))!["UseOptimizedKernel"]!.GetValue<bool>());
        Assert.Equal(enabled, File.ReadAllLines(Path.Combine(t.Path, "run.args")).Contains("-O"));
        if (dictionary) session.Devices = [new BackendDevice { Id = 1, Type = "GPU", Backend = "OpenCL" }];
        settings.OptimizedKernels = !enabled;
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [], state, default)).Outcome);
        var args = File.ReadAllLines(Path.Combine(t.Path, "run.args"));
        Assert.Contains("--restore-position", args);
        Assert.Equal(enabled, args.Contains("-O"));

        // An actual pre-field JSON file must keep the old pure-kernel resume behavior.
        string path = SessionState.PathFor(settings, state.Key);
        var json = JsonNode.Parse(File.ReadAllText(path))!;
        json.AsObject().Remove("UseOptimizedKernel");
        File.WriteAllText(path, json.ToJsonString());
        state = SessionState.Load(settings, target)!;
        Assert.Null(state.UseOptimizedKernel);
        settings.OptimizedKernels = true;
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [], state, default)).Outcome);
        Assert.DoesNotContain("-O", File.ReadAllLines(Path.Combine(t.Path, "run.args")));
    }

    [Fact]
    public async Task LookupQueriesSelectedMaskKernelAndCachesPerVersion()
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        Assert.Equal(20, (await tool.ModeInfoAsync(12500, 3))!.OptimizedPasswordLenMax);
        File.WriteAllText(Path.Combine(t.Path, "optimized.json"), Optimized.Replace(":20", ":18"));
        Assert.Equal(20, (await tool.ModeInfoAsync(12500, 3))!.OptimizedPasswordLenMax);
        File.WriteAllText(Path.Combine(t.Path, "version"), "v8.0.1");
        Assert.Equal(18, (await tool.ModeInfoAsync(12500, 3))!.OptimizedPasswordLenMax);
        File.WriteAllText(Path.Combine(t.Path, "version"), "v8.0.2");
        File.WriteAllText(Path.Combine(t.Path, "fail-info"), "");
        Assert.Null(await tool.ModeInfoAsync(12500, 3));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task BenchmarkUsesTheSameDecisionWithoutHashcat8ForcingOptimized(bool enabled)
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        // hashcat 8 refuses -B (pure) together with -O, also when the caller passes -O itself.
        await tool.BenchmarkAsync(12500, ["-O", "-d", "1"], default, enabled);
        var args = File.ReadAllLines(Path.Combine(t.Path, "run.args"));
        Assert.Equal(enabled, args.Contains("-b"));
        Assert.Equal(!enabled, args.Contains("-B"));
        Assert.Equal(enabled ? 1 : 0, args.Count(a => a == "-O"));
        Assert.Contains("-d", args);
    }

    [Fact]
    public void ExtraArgumentsCannotOverrideTheSavedKernelChoice()
    {
        using var t = new TempDir();
        string exe = Path.Combine(t.Path, "hashcat");
        File.WriteAllText(exe, "");
        var runner = new HashcatRunner(HashcatTool.Locate(exe, t.Path, t.Path)!) { HashcatMajorVersion = 8 };
        var args = runner.BuildArguments(new RunRequest
        {
            Mode = 12500, HashFile = "fixture.hash", SessionName = "test", SessionDir = t.Path, Attack = Mask(21), Restore = true,
            Settings = new Settings { ExtraArguments = "-O --optimized-kernel-enable --force" },
        });
        Assert.DoesNotContain("-O", args);
        Assert.DoesNotContain("--optimized-kernel-enable", args);
        Assert.Contains("--force", args);
    }


    [Theory]
    [InlineData("short", null, true)]
    [InlineData("12345678901234567890", null, true)]
    [InlineData("123456789012345678901", null, false)]
    [InlineData("éééééééééé", null, true)]
    [InlineData("ééééééééééa", null, false)]
    [InlineData("1234567890123456789", "$1", true)]
    [InlineData("12345678901234567890", "$1", false)]
    [InlineData("12345678901234567890", "] $1", false)]
    [InlineData("1234567890", "d", true)]
    [InlineData("12345678901", "d", false)]
    [InlineData("short", "M4", false)]
    public async Task DictionaryBoundsIncludeBytesAndRuleGrowth(string word, string? rule, bool expected)
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        string words = Path.Combine(t.Path, "words.txt");
        File.WriteAllText(words, "wrong\r\n" + word + "\r\n");
        var attack = new PreparedAttack { Description = "words", Args = { "-a", "0", words } };
        if (rule is not null)
        {
            string rules = Path.Combine(t.Path, "test.rule");
            File.WriteAllText(rules, "# comment\n:\n" + rule + "\n");
            attack.Args.AddRange(["-r", rules]);
        }
        Assert.Equal(expected, await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, true));
        Assert.False(await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, false));
        attack.Stdin = () => [word];
        Assert.False(await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, true));
    }

    [Theory]
    [InlineData(1, 10, 10, true)]
    [InlineData(1, 10, 11, false)]
    [InlineData(6, 18, 2, true)]
    [InlineData(6, 19, 2, false)]
    [InlineData(7, 18, 2, true)]
    [InlineData(7, 19, 2, false)]
    public async Task CombinationAndHybridBoundsIncludeBothInputs(int mode, int first, int second, bool expected)
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        string words = Path.Combine(t.Path, "words.txt"), other = Path.Combine(t.Path, "other.txt");
        File.WriteAllText(words, new string('a', first));
        File.WriteAllText(other, new string('b', second));
        string mask = string.Concat(Enumerable.Repeat("?d", second));
        var attack = new PreparedAttack { Description = "combined", Args = { "-a", mode.ToString() } };
        attack.Args.AddRange(mode == 1 ? [words, other] : mode == 6 ? [words, mask] : [mask, words]);
        Assert.Equal(expected, await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, true));
    }

    [Fact]
    public async Task WordlistCacheInvalidatesOnSizeOrModificationTime()
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        string words = Path.Combine(t.Path, "words.txt");
        var attack = new PreparedAttack { Description = "words", Args = { "-a", "0", words } };
        File.WriteAllText(words, "short");
        Assert.True(await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, true));
        File.WriteAllText(words, new string('a', 21));
        Assert.False(await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, true));
        File.WriteAllText(words, new string('a', 20) + "\n");
        File.SetLastWriteTimeUtc(words, DateTime.UtcNow.AddMinutes(1));
        Assert.True(await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, true));
    }

    [Theory]
    [InlineData("l u c C t r { } k K E T0 o0a sa@ *01 L0 R0", 4)]
    [InlineData("[ ] D0 '1 x01 O01", 4)]
    [InlineData("$a ^b i0c", 7)]
    [InlineData("d f q p2", 96)]
    [InlineData("z2 Z3 y2 Y3", 14)]
    [InlineData("$  $a", 6)]
    [InlineData("$  $\\", null)]
    [InlineData("i", null)]
    [InlineData("p!", null)]
    [InlineData("M4", null)]
    [InlineData("X014", null)]
    [InlineData("?", null)]
    public async Task BoundsRuleOperationsWithoutRelyingOnShortening(string rule, int? expected)
    {
        using var t = new TempDir();
        string words = Path.Combine(t.Path, "words.txt"), rules = Path.Combine(t.Path, "test.rule");
        File.WriteAllText(words, "test\n");
        File.WriteAllText(rules, rule + "\n");
        var attack = new PreparedAttack { Description = "rules", Args = { "-a", "0", words, "-r", rules } };
        Assert.Equal(expected, await OptimizedCandidateBounds.MaximumAsync(attack));
    }

    [Fact]
    public async Task MultipleRulesFilesComposeGrowthAndChangedRulesAreRescanned()
    {
        using var t = new TempDir();
        string words = Path.Combine(t.Path, "words.txt"), rules = Path.Combine(t.Path, "test.rule");
        File.WriteAllText(words, "test\n");
        File.WriteAllText(rules, "$a\n$1 $2\n");
        var attack = new PreparedAttack { Description = "rules", Args = { "-a", "0", words, "-r", rules, "-r", rules } };
        Assert.Equal(8, await OptimizedCandidateBounds.MaximumAsync(attack));
        File.WriteAllText(rules, "d\n");
        Assert.Equal(16, await OptimizedCandidateBounds.MaximumAsync(attack));
    }

    [Fact]
    public async Task DictionaryUsesItsAttackModeLimitAndRejectsExtraCandidateArguments()
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        File.WriteAllText(Path.Combine(t.Path, "optimized-a0.json"), Optimized.Replace(":20", ":4"));
        string words = Path.Combine(t.Path, "words.txt");
        File.WriteAllText(words, "short\n");
        var attack = new PreparedAttack { Description = "words", Args = { "-a", "0", words } };
        Assert.False(await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, true));
        File.WriteAllText(words, "tiny\n");
        Assert.True(await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, true));
        Assert.False(await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, true, extraArguments: "-j d"));
        Assert.False(await RecoverySession.SelectOptimizedKernelAsync(tool, 12500, attack, true, extraArguments: "--encoding-to UTF-16LE"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MeasuredPureChoiceWinsForDictionary(bool executionPrefersOptimized)
    {
        if (OperatingSystem.IsWindows()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        string words = Path.Combine(t.Path, "words.txt");
        File.WriteAllText(words, "short\n");
        var settings = new Settings
        {
            SessionsDir = t.Path, DontUsePasswordCache = true, UseNativeCpuEngine = false,
            GpuPerformanceChoice = new() { Optimized = false },
            PerformanceChoice = executionPrefersOptimized ? new() { Optimized = true } : null,
        };
        var spec = new AttackSpec { Kind = AttackKind.Dictionary };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "TEST", FormatName = "test", Protection = "test", Modes = [12500], HashLines = "test" };
        var session = new RecoverySession(tool, settings) { Devices = [new BackendDevice { Id = 1, Type = "GPU", Backend = "Metal" }] };
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [spec], null, default)).Outcome);
        Assert.False(SessionState.Load(settings, target)!.UseOptimizedKernel);
        Assert.DoesNotContain("-O", File.ReadAllLines(Path.Combine(t.Path, "run.args")));
    }

    [Fact]
    public async Task CompressedWordlistsAndMaskFilesHaveUnknownBounds()
    {
        using var t = new TempDir();
        string words = Path.Combine(t.Path, "words.gz"), mask = Path.Combine(t.Path, "mask.hcmask");
        using (var file = File.Create(words))
        using (var zip = new System.IO.Compression.GZipStream(file, System.IO.Compression.CompressionLevel.SmallestSize))
            zip.Write("a-long-password-hidden-in-a-compressed-dictionary\n"u8);
        var attack = new PreparedAttack { Description = "compressed", Args = { "-a", "0", words } };
        Assert.Null(await OptimizedCandidateBounds.MaximumAsync(attack));
        File.WriteAllText(words, "short\n");
        File.WriteAllText(mask, new string('a', 21));
        attack.Args.Clear();
        attack.Args.AddRange(["-a", "6", words, mask]);
        Assert.Null(await OptimizedCandidateBounds.MaximumAsync(attack));
    }

    [Fact]
    public async Task CountsBytesAcrossBufferBoundariesAndHandlesEmptyFinalLines()
    {
        using var t = new TempDir();
        string words = Path.Combine(t.Path, "words.txt");
        File.WriteAllText(words, new string('\n', 65533) + "éé\r\n\nlast");
        var attack = new PreparedAttack { Description = "bytes", Args = { "-a", "0", words } };
        Assert.Equal(4, await OptimizedCandidateBounds.MaximumAsync(attack));
    }

    [Fact]
    public async Task ResolvesRelativeInputsInHashcatsWorkingDirectory()
    {
        using var t = new TempDir();
        File.WriteAllText(Path.Combine(t.Path, "words.txt"), "test\n");
        File.WriteAllText(Path.Combine(t.Path, "test.rule"), "$1\n");
        var attack = new PreparedAttack { Description = "relative", Args = { "-a", "0", "words.txt", "-r", "test.rule" } };
        Assert.Equal(5, await OptimizedCandidateBounds.MaximumAsync(attack, workingDirectory: t.Path));
        attack.Args.Clear();
        attack.Args.AddRange(["-a", "6", "words.txt", "test.rule"]);
        Assert.Null(await OptimizedCandidateBounds.MaximumAsync(attack, workingDirectory: t.Path));
    }

    [Fact]
    public async Task DoesNotTreatEmbeddedCarriageReturnsAsSeparateRules()
    {
        using var t = new TempDir();
        string words = Path.Combine(t.Path, "words.txt"), rules = Path.Combine(t.Path, "test.rule");
        File.WriteAllText(words, "test\n");
        File.WriteAllText(rules, "d\rd\n");
        var attack = new PreparedAttack { Description = "rules", Args = { "-a", "0", words, "-r", rules } };
        Assert.Null(await OptimizedCandidateBounds.MaximumAsync(attack));
    }

    [Theory]
    [InlineData("OpenCL", false)]
    [InlineData("Metal", true)]
    [InlineData(null, false)]
    [InlineData("stale", false)]
    public async Task MacRar3DictionaryRequiresVerifiedMetalBackend(string? backend, bool expected)
    {
        if (!OperatingSystem.IsMacOS()) return;
        using var t = new TempDir();
        var tool = FakeTool(t.Path);
        string words = Path.Combine(t.Path, "words.txt");
        File.WriteAllText(words, "short\n");
        var settings = new Settings { SessionsDir = t.Path, DontUsePasswordCache = true, UseNativeCpuEngine = false };
        if (backend == "stale") settings.GpuPerformanceChoice = new() { DeviceKeys = ["missing"] };
        var attack = new AttackSpec { Kind = AttackKind.Dictionary };
        attack.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "TEST", FormatName = "test", Protection = "test", Modes = [12500], HashLines = "test" };
        var session = new RecoverySession(tool, settings)
        {
            Devices = backend is null ? null : [new BackendDevice { Id = 1, Type = "GPU", Backend = backend == "stale" ? "Metal" : backend, Vendor = "Apple" }],
        };
        Assert.Equal(SessionOutcome.Stopped, (await session.RunAsync(target, "fixture", [attack], null, default)).Outcome);
        Assert.Equal(expected, SessionState.Load(settings, target)!.UseOptimizedKernel);
    }

    private static HashcatTool FakeTool(string dir, int mode = 12500)
    {
        File.WriteAllText(Path.Combine(dir, "pure.json"), Pure.Replace("12500", mode.ToString()));
        File.WriteAllText(Path.Combine(dir, "optimized.json"), Optimized.Replace("12500", mode.ToString()));
        File.WriteAllText(Path.Combine(dir, "version"), "v8.0.0");
        string exe = Path.Combine(dir, "hashcat");
        File.WriteAllText(exe, """
            #!/bin/sh
            if [ "$1" = "--version" ]; then cat version; exit; fi
            case " $* " in
              *" --hash-info "*)
                test -f fail-info && exit 1
                case " $* " in
                  *" -O "*)
                    case " $* " in *" -a 0 "*) test -f optimized-a0.json && { cat optimized-a0.json; exit; };; esac
                    case " $* " in *" --hash-info --hash-info "*" -a "*) cat optimized.json;; *) exit 1;; esac;;
                  *) cat pure.json;;
                esac
                exit;;
            esac
            printf '%s\n' "$@" > run.args
            run_exit=2
            test -f exit-code && read run_exit < exit-code
            if test -f exhaust-optimized; then case " $* " in *" -O "*) run_exit=1;; esac; fi
            if test -f emit-speeds; then
              run_speed=2
              case " $* " in *" -O "*) run_speed=1000;; esac
              printf '{"status":3,"progress":[0,10000],"devices":[{"device_id":1,"speed":%s}]}\n' "$run_speed"
            fi
            for state in *.session.json; do test -f "$state" && cp "$state" state-at-start.json; done
            while [ "$#" -gt 0 ]; do
              if [ "$1" = "--restore-file-path" ]; then shift; touch "$1"; fi
              shift
            done
            exit "$run_exit"
            """);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return HashcatTool.Locate(exe, dir, dir)!;
    }

    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = Directory.CreateTempSubdirectory("rk-optimized").FullName;
        public void Dispose() => Directory.Delete(Path, true);
    }
}
