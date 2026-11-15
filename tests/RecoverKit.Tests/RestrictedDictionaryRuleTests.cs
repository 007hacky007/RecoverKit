using System.Text;
using System.Diagnostics;
using System.IO.Compression;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

[Trait("Category", "Slow")]
[Collection("NativeFeatures")]
public sealed class RestrictedDictionaryRuleTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-rule-lengths-").FullName;
    private readonly long _fileLimit = RuleRescue.MaximumFileCandidates;
    private readonly Func<string, long> _availableBytes = RuleRescue.AvailableBytes;
    public void Dispose()
    {
        RuleRescue.MaximumFileCandidates = _fileLimit;
        RuleRescue.AvailableBytes = _availableBytes;
        Directory.Delete(_dir, true);
    }
    private static HashcatTool Tool()
    {
        string? executable = Environment.GetEnvironmentVariable("RECOVERKIT_TEST_HASHCAT");
        Assert.False(string.IsNullOrWhiteSpace(executable), "Set RECOVERKIT_TEST_HASHCAT to a private hashcat 8 copy.");
        return HashcatTool.Locate(executable)!;
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task WpaRulesRecoverFromShortAndLongBaseWords(bool hybrid, bool truncate)
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules"), hash = NativeKernels.BenchmarkHashes[22000];
        await File.WriteAllLinesAsync(words, [truncate ? "hashcat!" + new string('x', 60) : "hashcat"]);
        await File.WriteAllTextAsync(rules, truncate ? "'8\n" : "$!\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var settings = new Settings
        {
            SessionsDir = _dir, DontUsePasswordCache = true, HybridCpuGpu = hybrid,
            PerformanceStrategyExplicit = true, OptimizedKernels = false, AutomaticPerformanceCalibration = false,
        };
        var target = new HashTarget { FormatId = "WPAH", FormatName = "WPA", Protection = "test", Modes = [22000], HashLines = hash };
        var devices = await tool.DevicesAsync();
        if (!hybrid)
        {
            string hashFile = Path.Combine(_dir, "raw.hash");
            await File.WriteAllTextAsync(hashFile, hash);
            var raw = await new HashcatRunner(tool) { KnownDevices = devices }.RunAsync(new RunRequest
            {
                Mode = 22000, HashFile = hashFile, SessionName = "raw-rule", SessionDir = _dir, Settings = settings,
                Attack = new PreparedAttack { Description = "raw rule", Args = { "-a", "0", words, "-r", rules } },
            }, default);
            Assert.Equal(RunOutcome.Exhausted, raw.Outcome);
            Assert.Empty(raw.Passwords);
            output.WriteLine($"raw hashcat before fix, truncate={truncate}: {raw.Outcome}, rejected={raw.LastStatus?.Rejected}");
        }
        var session = new RecoverySession(tool, settings) { Devices = devices };
        session.Log += (_, line) => output.WriteLine(line);
        using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var result = await session.RunAsync(target, "unused", [spec], null, stop.Token);
        Assert.True(result.Outcome == SessionOutcome.Found, result.Error ?? result.Outcome.ToString());
        Assert.Contains("hashcat!", result.Passwords);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RescueMatchesSlowRuleExpansionWithBinaryAutohexAndCompressedWords(bool compressed)
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), selected = Path.Combine(_dir, "selected"), rule1 = Path.Combine(_dir, "rules1"), rule2 = Path.Combine(_dir, "rules2");
        byte[][] outside = ["hashcat"u8.ToArray(), "PKword!"u8.ToArray(), [0xff, 97, 97, 97, 97, 97, 97],
            [0xef, 0xbb, 0xbf, 97, 97, 97, 97], "$HEX[68617368636174]"u8.ToArray(), Encoding.UTF8.GetBytes("éééx"), new byte[64], Enumerable.Repeat((byte)'x', 256).ToArray()];
        byte[] Bytes(IEnumerable<byte[]> lines) => lines.SelectMany(b => b.Concat(new byte[] { 13, 10 })).ToArray();
        await File.WriteAllBytesAsync(selected, Bytes(outside));
        byte[] source = Bytes(new[] { "in-range"u8.ToArray() }.Concat(outside));
        if (compressed)
        {
            await using var file = File.Create(words);
            await using var gzip = new GZipStream(file, CompressionLevel.Fastest);
            await gzip.WriteAsync(source);
        }
        else await File.WriteAllBytesAsync(words, source);
        await File.WriteAllTextAsync(rule1, "$!\n'8\n");
        await File.WriteAllTextAsync(rule2, ":\n$z\n");
        var attack = new PreparedAttack { Description = "binary rules", Args = { "-a", "0", words, "-r", rule1, "-r", rule2 } };
        var tail = await DictionaryKernelPlanner.RuleLengthPassAsync(new AttackSpec { Kind = AttackKind.Dictionary }, attack,
            new HashModeInfo { Mode = 22000, PasswordLenMin = 8, PasswordLenMax = 63 }, tool, Path.Combine(_dir, "tail"), null, default);
        Assert.NotNull(tail);
        var psi = tool.StartInfo(["--stdout", "--quiet", "-a", "0", selected, "-r", rule1, "-r", rule2]);
        using var process = Process.Start(psi)!;
        var error = process.StandardError.ReadToEndAsync();
        using var bytes = new MemoryStream();
        await process.StandardOutput.BaseStream.CopyToAsync(bytes);
        await process.WaitForExitAsync();
        Assert.True(process.ExitCode == 0, await error);
        byte[] Decode(string line)
        {
            try { return line.StartsWith("$HEX[", StringComparison.Ordinal) && line.EndsWith(']')
                ? Convert.FromHexString(line.AsSpan(5, line.Length - 6)) : Encoding.Latin1.GetBytes(line); }
            catch (FormatException) { return Encoding.Latin1.GetBytes(line); }
        }
        var expected = Encoding.Latin1.GetString(bytes.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => Decode(l.TrimEnd('\r'))).Where(b => b.Length is >= 8 and <= 63).Select(Convert.ToHexString).Order().ToArray();
        var actual = File.ReadAllLines(tail.DictionaryKernel!.TailPath!).Select(l => Convert.ToHexString(PasswordConfirmation.PlainBytes(l))).Order().ToArray();
        Assert.NotEmpty(expected);
        Assert.Equal(expected, actual);
        output.WriteLine($"compressed={compressed}: all {actual.Length} valid outputs equal slow hashcat rule expansion, including duplicates");
    }

    [Fact]
    public async Task MultiNetworkTargetReportsBothPasswordsThroughHashcat()
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words");
        await File.WriteAllLinesAsync(words, ["hashcat!", "password"]);
        var spec = new AttackSpec { Kind = AttackKind.Dictionary };
        spec.Dictionaries[0] = words;
        string second = (string)WpaCpuTests.KnownAnswers.First(r => ((string)r[0]).Contains("49454545***"))[0];
        var target = new HashTarget { FormatId = "WPAH", FormatName = "WPA", Protection = "test", Modes = [22000],
            HashLines = NativeKernels.BenchmarkHashes[22000] + "\n" + second };
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = true, PerformanceStrategyExplicit = true, OptimizedKernels = false };
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        var messages = new List<string>();
        session.Log += (_, line) => messages.Add(line);
        var result = await session.RunAsync(target, "unused", [spec], null, default);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(new[] { "hashcat!", "password" }, result.Passwords.Order().ToArray());
        Assert.DoesNotContain(messages, m => m.Contains("Built-in CPU engine:"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MultiNetworkRulesKeepHitsFromInRangeAndShortWordsTogether(bool noCache)
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllLinesAsync(words, ["hashcat!", "passwor"]);
        await File.WriteAllTextAsync(rules, ":\n$d\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var first = WpaTarget("hashcat!", Guid.NewGuid().ToString("N"));
        var second = WpaTarget("password", Guid.NewGuid().ToString("N"));
        var target = new HashTarget { FormatId = "WPAH", FormatName = "WPA", Protection = "test", Modes = [22000],
            HashLines = first.HashLines + "\n" + second.HashLines };
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = noCache, OptimizedKernels = false };
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        int steps = 0;
        session.StepStarted += (_, count, _, _) => steps = count;
        var result = await session.RunAsync(target, "unused", [spec], null, default);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(new[] { "hashcat!", "password" }, result.Passwords.Order().ToArray());
        Assert.Equal(2, steps);
        Assert.Empty(Directory.GetFiles(_dir, SessionState.KeyFor(target) + ".dictionary-*"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WpaRuleLengthFixAlsoCoversManagedDictionaryInput(bool utf16)
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, utf16 ? "$HEX[68617368636174]\n" : "hashcat\n", utf16 ? Encoding.Unicode : new UTF8Encoding(false));
        await File.WriteAllTextAsync(rules, "$!\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules, SkipShorterThan = utf16 ? 0 : 1 };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "WPAH", FormatName = "WPA", Protection = "test", Modes = [22000], HashLines = NativeKernels.BenchmarkHashes[22000] };
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = true, HybridCpuGpu = false, OptimizedKernels = false };
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        session.Log += (_, line) => output.WriteLine(line);
        var result = await session.RunAsync(target, "unused", [spec], null, default);
        Assert.True(result.Outcome == SessionOutcome.Found, result.Error ?? result.Outcome.ToString());
        Assert.Contains("hashcat!", result.Passwords);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ManagedSavedPassRebuildsTheSameFilteredBytes(bool utf16)
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, "hashcat\npassword\nsmall\néééxxxx\n", utf16 ? Encoding.Unicode : new UTF8Encoding(false));
        await File.WriteAllTextAsync(rules, "$!\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules, SkipShorterThan = 7, SkipLongerThan = 7 };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "WPAH", FormatName = "WPA", Protection = "test", Modes = [22000], HashLines = NativeKernels.BenchmarkHashes[22000] };
        var settings = new Settings { SessionsDir = _dir, OptimizedKernels = false };
        var state = new SessionState { Key = SessionState.KeyFor(target), Modes = [22000], Steps = [spec], DictionaryPlanPending = true };
        await DictionaryKernelPlanner.PrepareSessionAsync(state, target, tool, settings, null, new(), null, default);
        var restored = SessionState.Load(settings, target)!;
        Assert.Equal(2, restored.Steps.Count);
        var pass = restored.Steps[1].DictionaryKernel!;
        Assert.True(pass.ManagedWords);
        byte[] expected = await File.ReadAllBytesAsync(pass.TailPath!);
        Assert.Equal(new[] { "hashcat!" }.Select(w => Convert.ToHexString(Encoding.UTF8.GetBytes(w))).Order(),
            File.ReadAllLines(pass.TailPath!).Select(w => Convert.ToHexString(PasswordConfirmation.PlainBytes(w))).Order());
        File.Delete(pass.TailPath!);
        await DictionaryKernelPlanner.PreparePassAsync(pass, null, default, tool: tool);
        Assert.Equal(expected, await File.ReadAllBytesAsync(pass.TailPath!));
        await File.AppendAllTextAsync(words, "changed\n");
        await Assert.ThrowsAsync<InvalidDataException>(() => DictionaryKernelPlanner.PreparePassAsync(pass, null, default, tool: tool));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PmkRulesRecoverFromBothSidesOfTheFixedHexLength(bool truncate)
    {
        var tool = Tool();
        string hash = NativeKernels.BenchmarkHashes[22000];
        byte[] essid = Convert.FromHexString(hash.Split('*')[5]);
        string pmk = Convert.ToHexStringLower(System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2("hashcat!"u8, essid, 4096,
            System.Security.Cryptography.HashAlgorithmName.SHA1, 32));
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, (truncate ? pmk + "0" : pmk[..^1]) + "\n");
        await File.WriteAllTextAsync(rules, truncate ? "]\n" : "$" + pmk[^1] + "\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "WPAH", FormatName = "WPA PMK", Protection = "test", Modes = [22001], HashLines = hash };
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = true, OptimizedKernels = false, HybridCpuGpu = false };
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        session.Log += (_, line) => output.WriteLine(line);
        var result = await session.RunAsync(target, "unused", [spec], null, default);
        Assert.True(result.Outcome == SessionOutcome.Found, result.Error ?? result.Outcome.ToString());
        Assert.Contains(pmk, result.Passwords);
    }

    [Fact]
    public async Task AnsiRescueKeepsOriginalStepAndOnlyExpandsOutOfRangeWords()
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "ansi-words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllBytesAsync(words, [0xe9, .. "abcd\nwrongword\n"u8]);
        await File.WriteAllTextAsync(rules, "$1$2\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "WPAH", FormatName = "WPA", Protection = "test", Modes = [22000], HashLines = WpaTarget("éabcd12").HashLines };
        var settings = new Settings { SessionsDir = _dir, OptimizedKernels = false, DontUsePasswordCache = true, HybridCpuGpu = false };
        var state = new SessionState { Key = SessionState.KeyFor(target), Modes = [22000], Steps = [spec], DictionaryPlanPending = true };
        await DictionaryKernelPlanner.PrepareSessionAsync(state, target, tool, settings, null, new(), null, default);
        Assert.Equal(2, state.Steps.Count);
        Assert.NotNull(AttackPlanner.Prepare(state.Steps[0], target, new()).Stdin);
        Assert.Equal(1, state.Steps[1].DictionaryKernel!.Words);
        Assert.Equal(1, state.Steps[1].DictionaryKernel!.SelectedWords);
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        session.Log += (_, line) => output.WriteLine(line);
        var result = await session.RunAsync(target, "unused", [spec], state, default);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Contains("éabcd12", result.Passwords);
        Assert.Empty(Directory.GetFiles(_dir, state.Key + ".dictionary-*"));
    }

    private static HashTarget WpaTarget(string password, string? ssid = null, byte[]? passwordBytes = null)
    {
        string[] fields = NativeKernels.BenchmarkHashes[22000].Split('*');
        if (ssid is not null) fields[5] = Convert.ToHexStringLower(Encoding.ASCII.GetBytes(ssid));
        byte[] key = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(passwordBytes ?? Encoding.UTF8.GetBytes(password), Convert.FromHexString(fields[5]),
            4096, System.Security.Cryptography.HashAlgorithmName.SHA1, 32);
        byte[] data = [.. "PMK Name"u8, .. Convert.FromHexString(fields[3] + fields[4])];
        fields[2] = Convert.ToHexStringLower(System.Security.Cryptography.HMACSHA1.HashData(key, data).AsSpan(0, 16));
        return new HashTarget { FormatId = "WPAH", FormatName = "WPA", Protection = "test", Modes = [22000], HashLines = string.Join('*', fields) };
    }

    [Fact]
    public async Task StreamedRescueRestartsAfterStopAndFindsTheLastWord()
    {
        RuleRescue.MaximumFileCandidates = 1;
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllLinesAsync(words, Enumerable.Range(0, 1999).Select(i => $"w{i:000000}").Append("hashcat"));
        await File.WriteAllLinesAsync(rules, Enumerable.Repeat("$!", 500));
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = WpaTarget("hashcat!");
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = true, HybridCpuGpu = false, OptimizedKernels = false };
        using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        bool rescue = false;
        session.StepStarted += (_, _, description, _) => rescue = description.Contains("expanded rules pass");
        session.Status += status =>
        {
            if (rescue && status.Status == 3 && status.ProgressDone > 0)
            {
                Assert.Equal(1_000_000, status.ProgressTotal);
                stop.Cancel();
            }
        };
        session.Log += (_, line) => output.WriteLine(line);
        var result = await session.RunAsync(target, "unused", [spec], null, stop.Token);
        Assert.Equal(SessionOutcome.Stopped, result.Outcome);
        var saved = SessionState.Load(settings, target)!;
        Assert.Equal(1, saved.StepIndex);
        Assert.False(saved.Restorable);
        var pass = saved.Steps[1].DictionaryKernel!;
        Assert.True(pass.StreamRules);
        Assert.Null(pass.TailPath);
        Assert.Equal(2000, pass.SelectedWords);
        Assert.Equal(2000, File.ReadAllLines(pass.RuleInputPath!).Length);
        Assert.Equal(1_000_000, AttackPlanner.Prepare(saved.Steps[1], target, new() { Hashcat = tool }).Keyspace);
        File.Delete(pass.RuleInputPath!);
        var messages = new List<string>();
        var resumed = new RecoverySession(tool, settings) { Devices = session.Devices };
        resumed.Log += (_, line) => { messages.Add(line); output.WriteLine(line); };
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        result = await resumed.RunAsync(target, "unused", [spec], saved, timeout.Token);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Contains("hashcat!", result.Passwords);
        Assert.Single(messages, m => m.Contains("restarts from the beginning"));
        Assert.DoesNotContain(messages, m => m.Contains("--restore-position"));
        Assert.DoesNotContain(messages, m => m.Contains("Candidate generator failed"));
        Assert.Empty(Directory.GetFiles(_dir, saved.Key + ".dictionary-*"));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task FinishedRescueHasCompleteProgressAndLeavesNoFiles(bool stream, bool noValidOutput)
    {
        if (stream) RuleRescue.MaximumFileCandidates = 0;
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, noValidOutput ? "cat\n" : "notpass\n");
        await File.WriteAllTextAsync(rules, ":\n$!\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = WpaTarget("hashcat!");
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = true, HybridCpuGpu = false, OptimizedKernels = false };
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        HashcatStatus? last = null;
        session.Status += status => last = status;
        var result = await session.RunAsync(target, "unused", [spec], null, default);
        Assert.Equal(SessionOutcome.NotFound, result.Outcome);
        Assert.NotNull(last);
        Assert.Equal(5, last.Status);
        Assert.Equal(1, last.Fraction);
        Assert.Empty(Directory.GetFiles(_dir, SessionState.KeyFor(target) + ".dictionary-*"));
    }

    [Fact]
    public async Task DeletingStoppedSessionRemovesSelectedAndExpandedWords()
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, "hashcat\n");
        await File.WriteAllTextAsync(rules, "$!\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = WpaTarget("hashcat!");
        var settings = new Settings { SessionsDir = _dir, OptimizedKernels = false };
        var state = new SessionState { Key = SessionState.KeyFor(target), Modes = [22000], Steps = [spec], DictionaryPlanPending = true };
        await DictionaryKernelPlanner.PrepareSessionAsync(state, target, tool, settings, null, new(), null, default);
        Assert.True(File.Exists(state.Steps[1].DictionaryKernel!.RuleInputPath));
        Assert.True(File.Exists(state.Steps[1].DictionaryKernel!.TailPath));
        SessionState.Delete(settings, state.Key);
        Assert.Empty(Directory.GetFiles(_dir, state.Key + ".dictionary-*"));
    }

    [Fact]
    public async Task FailedStreamGeneratorCannotReportNotFound()
    {
        RuleRescue.MaximumFileCandidates = 0;
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, "hashcat\n");
        await File.WriteAllTextAsync(rules, "$!\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = WpaTarget("hashcat!");
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = true, HybridCpuGpu = false, OptimizedKernels = false };
        var state = new SessionState { Key = SessionState.KeyFor(target), Modes = [22000], Steps = [spec], DictionaryPlanPending = true };
        await DictionaryKernelPlanner.PrepareSessionAsync(state, target, tool, settings, null, new(), null, default);
        bool rescue = false;
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        session.StepStarted += (_, _, description, _) => rescue = description.Contains("expanded rules pass");
        session.Log += (_, line) =>
        {
            if (rescue && line.StartsWith("hashcat ", StringComparison.Ordinal)) File.Delete(state.Steps[1].DictionaryKernel!.RuleInputPath!);
        };
        var result = await session.RunAsync(target, "unused", [spec], state, default);
        Assert.Equal(SessionOutcome.Error, result.Outcome);
        Assert.Contains("Candidate generator failed", result.Error);
        Assert.Empty(Directory.GetFiles(_dir, state.Key + ".dictionary-*"));
    }

    [Theory]
    [InlineData("wpa-utf8-best66", false, false)]
    [InlineData("pdf-ansi-advanced", true, true)]
    [InlineData("wpa-utf8-advanced", false, true)]
    public async Task RequestedPlanningExamples(string label, bool ansiPdf, bool advanced)
    {
        Assert.Equal(50_000_000, RuleRescue.MaximumFileCandidates);
        var tool = Tool();
        string words = Path.Combine(_dir, "example-words");
        HashTarget target;
        if (ansiPdf)
        {
            await File.WriteAllBytesAsync(words, Encoding.Latin1.GetBytes(string.Concat(Enumerable.Range(0, 200).Select(i => $"caféword{i}\n"))));
            string pdf = Path.Combine(_dir, "example.pdf");
            using var resource = typeof(RestrictedDictionaryRuleTests).Assembly.GetManifestResourceStream("RecoverKit.Tests.Fixtures.Pdf.AES-128-user.pdf")!;
            using (var file = File.Create(pdf)) await resource.CopyToAsync(file);
            target = FormatDetector.Detect(pdf).Target!;
            Assert.Contains(10500, target.Modes);
        }
        else
        {
            await File.WriteAllLinesAsync(words, Enumerable.Range(0, 200).Select(i => i < 50 ? $"s{i:000000}" : $"word{i:0000}"));
            target = WpaTarget("hashcat!");
        }
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = advanced ? RulesPreset.Advanced : RulesPreset.Simple };
        spec.Dictionaries[0] = words;
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = true, HybridCpuGpu = false, OptimizedKernels = false };
        var state = new SessionState { Key = SessionState.KeyFor(target), Modes = target.Modes.ToList(), Steps = [spec], DictionaryPlanPending = true };
        var messages = new List<string>();
        await DictionaryKernelPlanner.PrepareSessionAsync(state, target, tool, settings, null, new() { HashcatDir = tool.Directory }, messages.Add, default);
        var rescue = state.Steps.Select(s => s.DictionaryKernel).SingleOrDefault(p => p?.RuleExpanded == true);
        if (ansiPdf)
        {
            Assert.Null(rescue);
            Assert.Single(state.Steps);
        }
        else
        {
            Assert.NotNull(rescue);
            Assert.Equal(50, rescue.SelectedWords);
        }
        foreach (string message in messages) output.WriteLine(message);
        output.WriteLine($"DECISION {label}: selected={rescue?.SelectedWords ?? 0}, output={(rescue is null ? "none" : rescue.StreamRules ? "stream" : "file")}, candidates={rescue?.Words ?? 0}, bytes={(rescue?.TailPath is { } path ? new FileInfo(path).Length : 0)}");
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        var result = await session.RunAsync(target, "unused", [spec], state, timeout.Token);
        Assert.Equal(SessionOutcome.NotFound, result.Outcome);
        Assert.Empty(Directory.GetFiles(_dir, state.Key + ".dictionary-*"));
    }

    [Fact]
    public async Task PlainMultiNetworkAttackIncludesThePreviouslyCachedNetwork()
    {
        var tool = Tool();
        var first = WpaTarget("hashcat!", Guid.NewGuid().ToString("N"));
        var second = WpaTarget("password", Guid.NewGuid().ToString("N"));
        var target = new HashTarget { FormatId = "WPAH", FormatName = "WPA", Protection = "test", Modes = [22000],
            HashLines = first.HashLines + "\n" + second.HashLines };
        var settings = new Settings { SessionsDir = _dir, HybridCpuGpu = false, OptimizedKernels = false };
        var kernel = NativeKernels.TryCreate(22000, first.HashLines)!;
        byte[] password = "hashcat!"u8.ToArray();
        await NativeRunner.RecordFoundAsync(settings, NativeRunner.MatchedHashLine(kernel, first.HashLines, password), password);
        string words = Path.Combine(_dir, "words");
        await File.WriteAllTextAsync(words, "password\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary };
        spec.Dictionaries[0] = words;
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        var result = await session.RunAsync(target, "unused", [spec], null, default);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(new[] { "hashcat!", "password" }, result.Passwords.Order().ToArray());
    }

    [Theory]
    [InlineData("changed", false, false)]
    [InlineData("changed", true, false)]
    [InlineData("changed", true, true)]
    [InlineData("found", false, true)]
    [InlineData("rebuild", false, false)]
    [InlineData("stdout", false, false)]
    [InlineData("stop", false, false)]
    public async Task RescueFailureReportsNetworksAlreadyRecovered(string failure, bool potfileOnly, bool binary)
    {
        var tool = Tool();
        if (failure == "stdout") RuleRescue.MaximumFileCandidates = 0;
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        byte[] firstPassword = binary ? [0xff, .. "aaaaaaa!"u8] : "password!"u8.ToArray();
        string expected = HybridRunner.DictionaryPlain(firstPassword);
        await File.WriteAllTextAsync(words, (binary ? PasswordConfirmation.HexPlain(firstPassword.AsSpan(0, 8)) : "password") + "\nhashcat\n");
        await File.WriteAllTextAsync(rules, "$!\n");
        var first = WpaTarget("password!", Guid.NewGuid().ToString("N"), firstPassword);
        var second = WpaTarget("hashcat!", Guid.NewGuid().ToString("N"));
        var target = new HashTarget { FormatId = "WPAH", FormatName = "WPA", Protection = "test", Modes = [22000],
            HashLines = first.HashLines + "\n" + second.HashLines };
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = true, HybridCpuGpu = false, OptimizedKernels = false };
        var state = new SessionState { Key = SessionState.KeyFor(target), Modes = [22000], Steps = [spec], DictionaryPlanPending = true };
        await DictionaryKernelPlanner.PrepareSessionAsync(state, target, tool, settings, null, new(), null, default);
        var rescue = state.Steps[1].DictionaryKernel!;
        using var stop = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        bool inRescue = false;
        session.StepStarted += (_, _, description, _) => inRescue = description.Contains("expanded rules pass");
        session.Log += (_, line) =>
        {
            output.WriteLine(line);
            if (line.StartsWith("Step 1 finished", StringComparison.Ordinal))
            {
                Assert.Contains(expected, state.WpaPasswords);
                if (potfileOnly) state.WpaPasswords.Clear();
                if (failure == "changed") File.AppendAllText(words, "changed\n");
                if (failure == "rebuild") { File.Delete(rescue.TailPath!); rescue.TailHash = "mismatch"; }
                if (failure == "stop") stop.Cancel();
            }
            if (failure == "stdout" && inRescue && line.StartsWith("hashcat ", StringComparison.Ordinal)) File.Delete(rescue.RuleInputPath!);
        };
        var result = await session.RunAsync(target, "unused", [spec], state, stop.Token);
        Assert.Equal(failure == "found" ? SessionOutcome.Found : failure == "stop" ? SessionOutcome.Stopped : SessionOutcome.Error, result.Outcome);
        if (failure == "found") Assert.Equal(new[] { expected, "hashcat!" }.Order(), result.Passwords.Order());
        else Assert.Equal(expected, Assert.Single(result.Passwords));
        if (failure == "stop") SessionState.Delete(settings, state.Key);
        Assert.Empty(Directory.GetFiles(_dir, state.Key + ".dictionary-*"));
    }

    [Fact]
    public async Task FinalStreamValidationFailureReturnsError()
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules"), hash = Path.Combine(_dir, "hash");
        await File.WriteAllTextAsync(words, "wrongwd\n");
        await File.WriteAllTextAsync(rules, "$!\n");
        await File.WriteAllTextAsync(hash, WpaTarget("hashcat!").HashLines);
        var attack = new PreparedAttack { Description = "rules", Args = { "-a", "0", words, "-r", rules } };
        RuleRescue.MaximumFileCandidates = 0;
        var spec = await DictionaryKernelPlanner.RuleLengthPassAsync(new AttackSpec { Kind = AttackKind.Dictionary }, attack,
            new HashModeInfo { Mode = 22000, PasswordLenMin = 8, PasswordLenMax = 63 }, tool, Path.Combine(_dir, "rescue"), null, default);
        IEnumerable<string> ChangedDuringExport()
        {
            foreach (string candidate in RuleRescue.Candidates(spec!.DictionaryKernel!, tool, default))
            {
                yield return candidate;
                File.AppendAllText(words, "changed\n");
            }
        }
        var prepared = new PreparedAttack { Description = "stream", Stdin = ChangedDuringExport, StdinTotalIsUpperBound = true, Args = { "-a", "0" } };
        var runner = new HashcatRunner(tool) { KnownDevices = await tool.DevicesAsync() };
        var result = await runner.RunAsync(new RunRequest { Mode = 22000, HashFile = hash, Attack = prepared,
            SessionName = "changed-stream", SessionDir = _dir, Settings = new Settings { DontUsePasswordCache = true } }, default);
        Assert.Equal(RunOutcome.Error, result.Outcome);
        Assert.Contains("changed", result.Error);
    }

    [Theory]
    [InlineData(15, false)]
    [InlineData(16, true)]
    public async Task SelectedWordsRequireTwiceTheirExactSize(long free, bool fits)
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules"), path = Path.Combine(_dir, "rescue");
        await File.WriteAllTextAsync(words, "hashcat\n");
        await File.WriteAllTextAsync(rules, "$!\n");
        RuleRescue.AvailableBytes = _ => free;
        var attack = new PreparedAttack { Description = "rules", Args = { "-a", "0", words, "-r", rules } };
        Task<AttackSpec?> Plan() => DictionaryKernelPlanner.RuleLengthPassAsync(new AttackSpec { Kind = AttackKind.Dictionary }, attack,
            new HashModeInfo { Mode = 22000, PasswordLenMin = 8, PasswordLenMax = 63 }, tool, path, null, default);
        if (fits)
        {
            var pass = (await Plan())!.DictionaryKernel!;
            Assert.Equal("hashcat\n", await File.ReadAllTextAsync(pass.RuleInputPath!));
            Assert.True(pass.StreamRules);
        }
        else
        {
            var error = await Assert.ThrowsAsync<IOException>(Plan);
            Assert.Contains("Not enough free space", error.Message);
            Assert.Empty(Directory.GetFiles(_dir, "rescue*"));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CachedLengthsSkipOnlyWhenDecodedWordsAreInRange(bool autohex)
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, autohex ? "$HEX[68617368636174]\n" : "password\n");
        await File.WriteAllTextAsync(rules, "$!\n");
        var stats = await WordlistLengthCache.AnalyzeAsync(words);
        Assert.Equal(autohex, stats!.HasAutohexWords);
        var attack = new PreparedAttack { Description = "rules", Args = { "-a", "0", words, "-r", rules } };
        var messages = new List<string>();
        var spec = await DictionaryKernelPlanner.RuleLengthPassAsync(new AttackSpec { Kind = AttackKind.Dictionary }, attack,
            new HashModeInfo { Mode = 22000, PasswordLenMin = 8, PasswordLenMax = 63 }, tool, Path.Combine(_dir, "rescue"), messages.Add, default);
        if (autohex) Assert.Equal(1, spec!.DictionaryKernel!.SelectedWords);
        else
        {
            Assert.Null(spec);
            Assert.Contains(messages, m => m.StartsWith("Cached word lengths:"));
            Assert.DoesNotContain(messages, m => m.StartsWith("Selecting dictionary words"));
        }
    }

    [Fact]
    public async Task SelectionStopsAndRemovesItsPartialFileWhenFreeSpaceFalls()
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllLinesAsync(words, Enumerable.Repeat("hashcat", 200_000));
        await File.WriteAllTextAsync(rules, "$!\n");
        int queries = 0;
        RuleRescue.AvailableBytes = _ => ++queries == 1 ? 4 * 1024 * 1024 : 0;
        var attack = new PreparedAttack { Description = "rules", Args = { "-a", "0", words, "-r", rules } };
        var error = await Assert.ThrowsAsync<IOException>(() => DictionaryKernelPlanner.RuleLengthPassAsync(
            new AttackSpec { Kind = AttackKind.Dictionary }, attack,
            new HashModeInfo { Mode = 22000, PasswordLenMin = 8, PasswordLenMax = 63 }, tool, Path.Combine(_dir, "rescue"), null, default));
        Assert.Contains("Free space ran low", error.Message);
        Assert.Equal(2, queries);
        Assert.Empty(Directory.GetFiles(_dir, "rescue*"));
    }

    [Fact]
    public async Task ManagedWordsOverTheStdoutLimitAreNotAddedToTheRescue()
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, "hashcat!" + new string('x', 249) + "\n", Encoding.Unicode);
        await File.WriteAllTextAsync(rules, "'8\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = WpaTarget("hashcat!");
        var settings = new Settings { SessionsDir = _dir, OptimizedKernels = false };
        var state = new SessionState { Key = SessionState.KeyFor(target), Modes = [22000], Steps = [spec], DictionaryPlanPending = true };
        await DictionaryKernelPlanner.PrepareSessionAsync(state, target, tool, settings, null, new(), null, default);
        Assert.Single(state.Steps);
        Assert.Empty(Directory.GetFiles(_dir, state.Key + ".dictionary-*"));
    }

    [Fact]
    public async Task PmkTableRulesDoNotCreateARescuePass()
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "table"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, PmkTable.Header + "74657374\n" + new string('a', 64) + ":password\n");
        await File.WriteAllTextAsync(rules, "'8\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = WpaTarget("password");
        var settings = new Settings { SessionsDir = _dir, OptimizedKernels = false };
        var state = new SessionState { Key = SessionState.KeyFor(target), Modes = [22000], Steps = [spec], DictionaryPlanPending = true };
        await DictionaryKernelPlanner.PrepareSessionAsync(state, target, tool, settings, null, new(), null, default);
        Assert.Single(state.Steps);
        Assert.Empty(Directory.GetFiles(_dir, state.Key + ".dictionary-*"));
    }

    [Fact]
    public async Task CachedLongAutohexWordStillNeedsItsDecodedLengthRescued()
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, PasswordConfirmation.HexPlain(Enumerable.Repeat((byte)'a', 128).ToArray()) + "\n");
        await File.WriteAllTextAsync(rules, "'8\n");
        var stats = await WordlistLengthCache.AnalyzeAsync(words);
        Assert.Equal(262, stats!.Maximum);
        Assert.True(stats.HasAutohexWords);
        var attack = new PreparedAttack { Description = "rules", Args = { "-a", "0", words, "-r", rules } };
        var spec = await DictionaryKernelPlanner.RuleLengthPassAsync(new AttackSpec { Kind = AttackKind.Dictionary }, attack,
            new HashModeInfo { Mode = 9700, PasswordLenMin = 0, PasswordLenMax = 15 }, tool, Path.Combine(_dir, "rescue"), null, default);
        Assert.Equal(1, spec!.DictionaryKernel!.SelectedWords);
        Assert.Equal("aaaaaaaa", HashcatTool.DecodePlain(Assert.Single(File.ReadAllLines(spec.DictionaryKernel.TailPath!))));
    }

    [Fact]
    public async Task EqualModeBoundsShareSelectionAndRescuesAreGroupedByDistinctBounds()
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, new string('a', 129) + "\n");
        await File.WriteAllTextAsync(rules, "'8\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "TEST", FormatName = "all KDF", Protection = "test", Modes = [29411, 29421, 29431, 29451, 29471], HashLines = "unused" };
        var settings = new Settings { SessionsDir = _dir, OptimizedKernels = false };
        var state = new SessionState { Key = SessionState.KeyFor(target), Modes = target.Modes.ToList(), Steps = [spec], DictionaryPlanPending = true };
        var messages = new List<string>();
        await DictionaryKernelPlanner.PrepareSessionAsync(state, target, tool, settings, null, new(), messages.Add, default);
        Assert.Equal(3, state.Steps.Count);
        Assert.Equal(new[] { 29411 }, state.Steps[1].DictionaryKernel!.Modes);
        Assert.Equal(new[] { 29421, 29431, 29451, 29471 }, state.Steps[2].DictionaryKernel!.Modes);
        Assert.Equal(2, messages.Count(m => m.StartsWith("Selecting dictionary words")));
        Assert.Null(state.Steps[0].DictionaryKernel!.Optimized);
    }

    [Fact]
    public async Task RescueRunsOnlyUnderItsOwnModes()
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, "hashcat!" + new string('x', 60) + "\n");
        await File.WriteAllTextAsync(rules, "'8\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "WPAH", FormatName = "test", Protection = "test", Modes = [13600, 22000], HashLines = WpaTarget("hashcat!").HashLines };
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = true, HybridCpuGpu = false, OptimizedKernels = false };
        var state = new SessionState { Key = SessionState.KeyFor(target), Modes = target.Modes.ToList(), Steps = [spec], DictionaryPlanPending = true };
        await DictionaryKernelPlanner.PrepareSessionAsync(state, target, tool, settings, null, new(), null, default);
        Assert.Equal(new[] { 22000 }, state.Steps[1].DictionaryKernel!.Modes);
        state.StepIndex = 1;
        var messages = new List<string>();
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        session.Log += (_, line) => messages.Add(line);
        var result = await session.RunAsync(target, "unused", [spec], state, default);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Contains("hashcat!", result.Passwords);
        Assert.DoesNotContain(messages, m => m.StartsWith("hashcat -m 13600 "));
        Assert.Contains(messages, m => m.StartsWith("hashcat -m 22000 "));
    }

    [Fact]
    public async Task RescueMetadataPreservesTheOriginalRuntimeOptimizedChoice()
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, new string('a', 16) + "\n");
        await File.WriteAllTextAsync(rules, "'7\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = new HashTarget { FormatId = "TEST", FormatName = "test", Protection = "test", Modes = [9700, 10400], HashLines = "unused" };
        var settings = new Settings { SessionsDir = _dir, OptimizedKernels = true };
        var original = AttackPlanner.Prepare(spec, target, new());
        bool before = await RecoverySession.SelectOptimizedKernelAsync(tool, 10400, original, true, false, null);
        Assert.True(before);
        var state = new SessionState { Key = SessionState.KeyFor(target), Modes = target.Modes.ToList(), Steps = [spec], DictionaryPlanPending = true };
        await DictionaryKernelPlanner.PrepareSessionAsync(state, target, tool, settings, null, new(), null, default);
        Assert.Equal(2, state.Steps.Count);
        Assert.Null(state.Steps[0].DictionaryKernel!.Optimized);
        bool after = await RecoverySession.SelectOptimizedKernelAsync(tool, 10400, AttackPlanner.Prepare(state.Steps[0], target, new()),
            true, false, null, plannedChoice: state.Steps[0].DictionaryKernel!.Optimized);
        Assert.Equal(before, after);
    }

    [Fact]
    public async Task SavedFileCanBecomeAStreamWithoutReusingItsRestoreOffset()
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, "hashcat\n");
        await File.WriteAllTextAsync(rules, "$!\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary, Rules = RulesPreset.CustomFile, RulesFile = rules };
        spec.Dictionaries[0] = words;
        var target = WpaTarget("hashcat!");
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = true, OptimizedKernels = false, HybridCpuGpu = false };
        var state = new SessionState { Key = SessionState.KeyFor(target), Modes = [22000], Steps = [spec], DictionaryPlanPending = true };
        await DictionaryKernelPlanner.PrepareSessionAsync(state, target, tool, settings, null, new(), null, default);
        File.Delete(state.Steps[1].DictionaryKernel!.TailPath!);
        state.StepIndex = 1;
        state.Restorable = true;
        state.HashcatSession = "file-to-stream";
        await File.WriteAllTextAsync(HashcatRunner.RestoreFile(_dir, state.HashcatSession), "must not be used");
        RuleRescue.MaximumFileCandidates = 0;
        var messages = new List<string>();
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        session.Log += (_, line) => messages.Add(line);
        var result = await session.RunAsync(target, "unused", [spec], state, default);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Contains("hashcat!", result.Passwords);
        Assert.True(state.Steps[1].DictionaryKernel!.StreamRules);
        Assert.DoesNotContain(messages, m => m.Contains("--restore-position"));
        Assert.Empty(Directory.GetFiles(_dir, state.Key + ".dictionary-*"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task MultiNetworkAttackKeepsPartialPmkTablePasswords(bool finishOtherNetwork)
    {
        var tool = Tool();
        string ssid = Guid.NewGuid().ToString("N");
        var first = WpaTarget("hashcat!", ssid);
        var second = WpaTarget("password", Guid.NewGuid().ToString("N"));
        var target = new HashTarget { FormatId = "WPAH", FormatName = "WPA", Protection = "test", Modes = [22000],
            HashLines = first.HashLines + "\n" + second.HashLines };
        string table = Path.Combine(_dir, "table"), words = Path.Combine(_dir, "words");
        string pmk = Convert.ToHexStringLower(System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(
            "hashcat!"u8, Encoding.UTF8.GetBytes(ssid), 4096, System.Security.Cryptography.HashAlgorithmName.SHA1, 32));
        await File.WriteAllTextAsync(table, PmkTable.Header + Convert.ToHexString(Encoding.UTF8.GetBytes(ssid)) + "\n" + pmk + ":hashcat!\n");
        await File.WriteAllTextAsync(words, finishOtherNetwork ? "password\n" : "wrongword\n");
        var tableStep = new AttackSpec { Kind = AttackKind.Dictionary };
        tableStep.Dictionaries[0] = table;
        var nextStep = new AttackSpec { Kind = AttackKind.Dictionary };
        nextStep.Dictionaries[0] = words;
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = true, HybridCpuGpu = false, OptimizedKernels = false };
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        session.Log += (_, line) => output.WriteLine(line);
        var result = await session.RunAsync(target, "unused", [tableStep, nextStep], null, default);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(finishOtherNetwork ? new[] { "hashcat!", "password" } : new[] { "hashcat!" }, result.Passwords.Order().ToArray());
    }

    [Fact]
    public async Task MultiNetworkPmkTargetKeepsItsPartialResult()
    {
        var tool = Tool();
        string ssid = Guid.NewGuid().ToString("N");
        var first = WpaTarget("hashcat!", ssid);
        var second = WpaTarget("password", Guid.NewGuid().ToString("N"));
        var target = new HashTarget { FormatId = "WPAH", FormatName = "WPA PMK", Protection = "test", Modes = [22001],
            HashLines = first.HashLines + "\n" + second.HashLines };
        string pmk = Convert.ToHexStringLower(System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(
            "hashcat!"u8, Encoding.UTF8.GetBytes(ssid), 4096, System.Security.Cryptography.HashAlgorithmName.SHA1, 32));
        string words = Path.Combine(_dir, "words");
        await File.WriteAllTextAsync(words, pmk + "\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary };
        spec.Dictionaries[0] = words;
        var settings = new Settings { SessionsDir = _dir, DontUsePasswordCache = true, HybridCpuGpu = false, OptimizedKernels = false };
        var session = new RecoverySession(tool, settings) { Devices = await tool.DevicesAsync() };
        session.Log += (_, line) => output.WriteLine(line);
        var result = await session.RunAsync(target, "unused", [spec], null, default);
        Assert.Equal(SessionOutcome.Found, result.Outcome);
        Assert.Equal(pmk, Assert.Single(result.Passwords), ignoreCase: true);
    }

    [Theory]
    [InlineData(22000, 8, 63)]
    [InlineData(22001, 64, 64)]
    [InlineData(9700, 0, 15)]
    [InlineData(10400, 0, 32)]
    [InlineData(10600, 0, 127)]
    [InlineData(12500, 0, 128)]
    [InlineData(18600, 0, 51)]
    [InlineData(26600, 8, 256)]
    [InlineData(29311, 0, 64)]
    public async Task SavedPassPreservesValidRuleOutputAndRefusesChangedInputs(int mode, int min, int max)
    {
        var tool = Tool();
        string words = Path.Combine(_dir, "words"), rules = Path.Combine(_dir, "rules");
        await File.WriteAllTextAsync(words, new string('a', Math.Max(0, min - 1)) + "\n" + new string('x', Math.Min(255, max + 1)) + "\n");
        await File.WriteAllTextAsync(rules, "$!\n'8\n'5\n");
        var spec = new AttackSpec { Kind = AttackKind.Dictionary };
        spec.Dictionaries[0] = words;
        var attack = new PreparedAttack { Description = "test", Args = { "-a", "0", words, "-r", rules } };
        var info = await tool.ModeInfoAsync(mode);
        Assert.Equal(min, info!.PasswordLenMin);
        Assert.Equal(max, info.PasswordLenMax);
        var tail = await DictionaryKernelPlanner.RuleLengthPassAsync(spec, attack, info, tool, Path.Combine(_dir, "expanded"), null, default);
        Assert.NotNull(tail);
        var pass = tail.DictionaryKernel!;
        Assert.True(pass.RuleExpanded);
        Assert.Equal(1, pass.RuleCount);
        var expected = await File.ReadAllBytesAsync(pass.TailPath!);
        Assert.NotEmpty(expected);
        File.Delete(pass.TailPath!);
        await DictionaryKernelPlanner.PreparePassAsync(pass, null, default, tool: tool);
        Assert.Equal(expected, await File.ReadAllBytesAsync(pass.TailPath!));
        Assert.Equal(pass.Words, File.ReadAllLines(pass.TailPath!).Length);
        var prepared = AttackPlanner.Prepare(tail, new HashTarget { FormatId = "TEST", FormatName = "test", Protection = "test", Modes = [mode], HashLines = "unused" }, new());
        Assert.Null(prepared.Stdin);
        Assert.DoesNotContain("-r", prepared.Args);
        foreach (string line in File.ReadLines(pass.TailPath!))
            Assert.InRange(PasswordConfirmation.PlainBytes(line).Length, min, max);
        await File.AppendAllTextAsync(rules, ":\n");
        await Assert.ThrowsAsync<InvalidDataException>(() => DictionaryKernelPlanner.PreparePassAsync(pass, null, default, tool: tool));
        output.WriteLine($"mode {mode}: {pass.Words} valid expanded candidates, identical rebuild");
    }
}
