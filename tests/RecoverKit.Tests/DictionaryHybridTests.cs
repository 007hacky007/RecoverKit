using System.Collections.Concurrent;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public class DictionaryHybridTests
{
    [Theory]
    [InlineData(13000)]
    [InlineData(12500)]
    [InlineData(10700)]
    [InlineData(29331)]
    public void PlansOnlyFileDictionariesOnSlowBuiltInFormats(int mode)
    {
        var attack = new PreparedAttack { Description = "dictionary", Args = { "-a", "0", "words", "-r", "rules", "-r", "more-rules" } };
        var settings = new Settings();
        BackendDevice[] devices = [new() { Id = 1, Type = "GPU" }];
        if (NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]) is null) return;
        var plan = HybridRunner.Plan(mode, NativeKernels.BenchmarkHashes[mode], attack, settings, devices);
        Assert.NotNull(plan);
        Assert.NotNull(plan.Dictionary);
        settings.UseNativeCpuEngine = false;
        Assert.Null(HybridRunner.Plan(mode, NativeKernels.BenchmarkHashes[mode], attack, settings, devices));
    }

    [Theory]
    [InlineData(12500)]
    [InlineData(13000)]
    [InlineData(10700)]
    [InlineData(29331)]
    public void UnrelatedPasswordBatchMatchesReference(int mode)
    {
        NativeKernel kernel = mode switch
        {
            12500 => Rar3Kernel.TryParse(NativeKernels.BenchmarkHashes[mode])!,
            13000 => Rar5Kernel.TryParse(NativeKernels.BenchmarkHashes[mode])!,
            10700 => PdfR6Kernel.TryParse(NativeKernels.BenchmarkHashes[mode])!,
            _ => TrueCryptWhirlpoolKernel.TryParse(NativeKernels.BenchmarkHashes[mode])!,
        };
        string target = mode == 10700 ? "Qz7#Kp2" : "hashcat";
        var passwords = Enumerable.Range(0, 19).Select(i => Encoding.ASCII.GetBytes($"x{i:000000}")).ToArray();
        passwords[17] = Encoding.ASCII.GetBytes(target);
        var packed = passwords.SelectMany(p => p).ToArray();
        Assert.Equal(17, Array.FindIndex(passwords, p => kernel.Verify(p)));
        Assert.Equal(17, kernel.CreateWorker().SearchPasswords(packed, 7, passwords.Length));
        Assert.Equal(-1, kernel.CreateWorker().SearchPasswords(packed.AsSpan(18 * 7), 7, 1));
        bool disabled = RkNative.Disabled;
        try
        {
            RkNative.Disabled = true;
            Assert.Equal(1, kernel.CreateWorker().SearchPasswords(packed.AsSpan(16 * 7, 3 * 7), 7, 3));
        }
        finally { RkNative.Disabled = disabled; }
    }

    [Fact]
    public void IntegratedGpuKeepsSmallCpuContributionOffExceptForPendingResume()
    {
        var attack = new PreparedAttack { Description = "dictionary", Args = { "-a", "0", "words" } };
        var settings = new Settings();
        settings.CpuSpeedByMode[13000] = 1000;
        settings.GpuSpeedByMode[13000] = 10000;
        BackendDevice[] devices = [new() { Id = 1, Type = "GPU", Unified = true }];
        string hash = NativeKernels.BenchmarkHashes[13000];
        Assert.True(HybridRunner.CpuAddsTooLittle(settings, devices, 13000));
        Assert.Null(HybridRunner.Plan(13000, hash, attack, settings, devices));
        Assert.NotNull(HybridRunner.Plan(13000, hash, attack, settings, devices, resumeDictionary: true));
    }

    [Theory]
    [InlineData(1, 1, 1000)]
    [InlineData(97, 1, 1000)]
    [InlineData(400, 4, 1000)]
    [InlineData(800, 3, 100000000)]
    public async Task DictionaryPartitionsCoverEveryCandidate(int words, int rules, double gpuGuess)
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-hybrid").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            var dictionary = new DictionaryAttack(["-a", "0", "unused"])
            {
                BaseCount = words, AmplifierCount = rules,
                ReadCandidates = (lo, count, ct) => Task.FromResult(Enumerable.Range((int)lo, (int)count)
                    .SelectMany(w => Enumerable.Range(0, rules).Select(a => Encoding.ASCII.GetBytes($"{w:0000}:{a}"))).ToList()),
            };
            var gpu = new Gpu(seen);
            var runner = new HybridRunner
            {
                ForceGpu = true, HashcatStartupSeconds = 0.001, BatchSeconds = 0.01,
                Tick = TimeSpan.FromMilliseconds(2), InitialGpuSpeed = gpuGuess, InitialCpuSpeed = 1000, ThreadsOverride = 2,
            };
            var request = new RunRequest
            {
                Mode = 13000, HashFile = "unused", Attack = new PreparedAttack { Description = "test" },
                SessionName = "test", SessionDir = dir, Settings = new Settings { DontUsePasswordCache = true },
            };
            var result = await runner.RunAsync(new HybridPlan(new RecordingKernel(seen), null) { Dictionary = dictionary }, "hash", request, gpu, CancellationToken.None);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(words * rules, seen.Count);
            Assert.All(seen.Values, n => Assert.True(n >= 1));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StopAndResumeDoNotReplayCompletedCpuGroups(bool stopDuringExport)
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-resume").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            using var stop = new CancellationTokenSource();
            int cpuTested = 0;
            var kernel = new RecordingKernel(seen) { OnTest = () => { if (Interlocked.Increment(ref cpuTested) == 70) stop.Cancel(); } };
            var dictionary = TestDictionary(2000, 3);
            if (stopDuringExport)
            {
                var read = dictionary.ReadCandidates;
                dictionary.ReadCandidates = (lo, count, ct) =>
                {
                    stop.Cancel();
                    ct.ThrowIfCancellationRequested();
                    return read(lo, count, ct);
                };
            }
            var request = Request(dir);
            var result = await Runner().RunAsync(new HybridPlan(kernel, null) { Dictionary = dictionary }, "hash", request, new Gpu(seen), stop.Token);
            Assert.Equal(RunOutcome.Aborted, result.Outcome);
            if (!stopDuringExport)
            {
                using var again = new CancellationTokenSource();
                var pending = TestDictionary(2000, 3);
                pending.ReadCandidates = (lo, count, ct) =>
                {
                    again.Cancel();
                    ct.ThrowIfCancellationRequested();
                    return Task.FromResult(new List<byte[]>());
                };
                result = await Runner().RunAsync(new HybridPlan(new RecordingKernel(seen), null) { Dictionary = pending },
                    "hash", request with { Restore = true }, new Gpu(seen), again.Token);
                Assert.Equal(RunOutcome.Aborted, result.Outcome);
            }
            dictionary = TestDictionary(2000, 3);
            result = await Runner().RunAsync(new HybridPlan(new RecordingKernel(seen), null) { Dictionary = dictionary }, "hash", request with { Restore = true }, new Gpu(seen), CancellationToken.None);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(6000, seen.Count);
            Assert.All(seen.Values, n => Assert.True(n >= 1));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task IncompatibleCandidatesAreDeferredWithoutRetiringTheCpu()
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-incompatible").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            var warnings = new List<string>();
            var runner = Runner();
            runner.Warning += warnings.Add;
            var result = await runner.RunAsync(new HybridPlan(new RecordingKernel(seen) { MaxLength = 2 }, null)
                { Dictionary = TestDictionary(300, 4) }, "hash", Request(dir), new Gpu(seen), CancellationToken.None);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(1200, seen.Count);
            Assert.All(seen.Values, n => Assert.True(n >= 1));
            Assert.Empty(warnings);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("-a", "1", "left", "right")]
    [InlineData("-a", "6", "words", "?d")]
    [InlineData("-a", "7", "?d", "words")]
    [InlineData("-a", "0", "words", "--hex-wordlist")]
    [InlineData("-a", "0", "words", "--skip", "3")]
    public void OtherCandidateInterpretationsStayOnHashcat(params string[] args)
        => Assert.Null(DictionaryAttack.Parse(args));

    [Theory]
    [InlineData("0000:0", false)]
    [InlineData("1000:1", null)]
    [InlineData("1999:0", true)]
    public async Task APasswordFromEitherShareStopsBoth(string target, bool? cpu)
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-find").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            var output = new List<string>();
            var runner = Runner();
            runner.OutputLine += output.Add;
            var result = await runner.RunAsync(new HybridPlan(new RecordingKernel(seen) { Target = target }, null)
                { Dictionary = TestDictionary(2000, 3) }, "hash", Request(dir), new Gpu(seen) { Target = target }, CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal(target, Assert.Single(result.Passwords));
            if (cpu is bool byCpu) Assert.Contains(byCpu ? "Found by the built-in CPU engine." : "Found by hashcat.", output);
            else Assert.Contains(output, line => line.StartsWith("Found by "));
            Assert.False(File.Exists(HybridRunner.RestoreFile(dir, "test")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task GpuFailureHandsItsRemainingIntervalToCpu()
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-failure").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            var result = await Runner().RunAsync(new HybridPlan(new RecordingKernel(seen), null)
                { Dictionary = TestDictionary(2000, 3) }, "hash", Request(dir), new Gpu(seen) { FailAfter = 10 }, CancellationToken.None);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(6000, seen.Count);
            Assert.All(seen.Values, n => Assert.True(n >= 1));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("{invalid")]
    [InlineData("null")]
    [InlineData("{\"Length\":1,\"BaseCount\":300,\"BatchLo\":300,\"BatchHi\":300}")]
    [InlineData("{\"BaseCount\":300,\"Lo\":200,\"BatchLo\":100,\"BatchHi\":300}")]
    [InlineData("{\"BaseCount\":300,\"BatchLo\":299,\"BatchHi\":300,\"Box\":0,\"BoxPrefix\":5}")]
    [InlineData("{\"DictionaryFingerprint\":\"changed\"}")]
    public async Task InvalidOrChangedCheckpointIsRefusedWithoutTestingCandidates(string checkpoint)
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-checkpoint").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            string path = HybridRunner.RestoreFile(dir, "test");
            await File.WriteAllTextAsync(path, checkpoint);
            var result = await Runner().RunAsync(new HybridPlan(new RecordingKernel(seen), null)
                { Dictionary = TestDictionary(300, 4) }, "hash", Request(dir) with { Restore = true }, new Gpu(seen), CancellationToken.None);
            Assert.Equal(RunOutcome.Error, result.Outcome);
            Assert.Empty(seen);
            Assert.Equal(checkpoint, await File.ReadAllTextAsync(path));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task NonAsciiRar3BatchIsLeftToHashcat()
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-rar3-bytes").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            var dictionary = TestDictionary(3, 1);
            dictionary.ReadCandidates = (lo, count, ct) => Task.FromResult(Enumerable.Range((int)lo, (int)count)
                .Select(w => new byte[] { 195, 169, (byte)('0' + w) }).ToList());
            var kernel = Rar3Kernel.TryParse(NativeKernels.BenchmarkHashes[12500])!;
            var result = await Runner().RunAsync(new HybridPlan(kernel, null) { Dictionary = dictionary }, "hash", Request(dir),
                new Gpu(seen) { Candidate = (w, a) => Encoding.Latin1.GetString(new byte[] { 195, 169, (byte)('0' + w) }) }, CancellationToken.None);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(3, seen.Count);
            Assert.All(seen.Values, n => Assert.True(n >= 1));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task SessionResumesOnlyCompatibleEngineCheckpoints(bool gpuResume, bool disableHybrid)
    {
        if (OperatingSystem.IsWindows() || NativeKernels.TryCreate(13000, NativeKernels.BenchmarkHashes[13000]) is null) return;
        string dir = Directory.CreateTempSubdirectory("rk-dict-session").FullName;
        try
        {
            string exe = Path.Combine(dir, "hashcat"), words = Path.Combine(dir, "words");
            await File.WriteAllTextAsync(words, "word\n");
            await File.WriteAllTextAsync(exe, """
                #!/bin/sh
                case " $* " in
                  *" --version "*) echo v8.0.0; exit 0;;
                  *" --keyspace "*) echo 1; exit 0;;
                  *" --total-candidates "*) echo 65537; exit 0;;
                esac
                printf '%s\n' "$@" > run.args
                exit 2
                """);
            File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var tool = HashcatTool.Locate(exe, dir, dir)!;
            var settings = new Settings { SessionsDir = dir, DontUsePasswordCache = true, AutomaticPerformanceCalibration = false,
                PerformanceStrategyExplicit = true, OptimizedKernels = false, HybridCpuGpu = !disableHybrid };
            if (!gpuResume) { settings.CpuSpeedByMode[13000] = 100; settings.GpuSpeedByMode[13000] = 10000; }
            var target = new HashTarget { FormatId = "RAR5", FormatName = "test", Protection = "test", Modes = [13000], HashLines = NativeKernels.BenchmarkHashes[13000] };
            var spec = new AttackSpec { Kind = AttackKind.Dictionary, Dictionaries = [words, null, null, null] };
            var state = new SessionState { Key = SessionState.KeyFor(target), Modes = [13000], Steps = [spec], HashcatSession = "test", Restorable = true };
            state.Save(settings);
            string checkpoint = gpuResume ? HashcatRunner.RestoreFile(dir, "test") : HybridRunner.RestoreFile(dir, "test");
            await File.WriteAllTextAsync(checkpoint, "saved checkpoint");
            if (disableHybrid)
            {
                await File.WriteAllTextAsync(HashcatRunner.RestoreFile(dir, "test"), "deferred wordlist checkpoint");
                await File.WriteAllTextAsync(HybridRunner.LeftoverFile(dir, "test"), "$HEX[ff]\n");
            }
            var session = new RecoverySession(tool, settings) { Devices = [new BackendDevice { Id = 1, Type = "GPU", Unified = !gpuResume }] };
            var result = await session.RunAsync(target, "fixture", [spec], state, CancellationToken.None);
            Assert.Equal(gpuResume || disableHybrid ? SessionOutcome.Stopped : SessionOutcome.Error, result.Outcome);
            Assert.NotNull(SessionState.Load(settings, target));
            if (disableHybrid)
            {
                Assert.False(File.Exists(checkpoint));
                Assert.False(File.Exists(HybridRunner.LeftoverFile(dir, "test")));
            }
            else Assert.Equal("saved checkpoint", await File.ReadAllTextAsync(checkpoint));
            if (gpuResume || disableHybrid)
            {
                string[] arguments = await File.ReadAllLinesAsync(Path.Combine(dir, "run.args"));
                if (gpuResume) Assert.Contains("--restore-position", arguments);
                else Assert.DoesNotContain("--restore-position", arguments);
                Assert.DoesNotContain("--limit", arguments);
            }
            else Assert.False(File.Exists(Path.Combine(dir, "run.args")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task ARejectedCpuHitDoesNotHideTheNextPasswordInItsBatch()
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-confirm").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            var confirmed = new ConcurrentBag<string>();
            var request = Request(dir) with { ConfirmPassword = pw =>
            {
                string text = Encoding.ASCII.GetString(pw);
                confirmed.Add(text);
                return text == "1999:1";
            } };
            var result = await Runner().RunAsync(new HybridPlan(new RecordingKernel(seen) { Target = "1999:1", RejectedTarget = "1999:0" }, null)
                { Dictionary = TestDictionary(2000, 3) }, "hash", request, new Gpu(seen), CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal("1999:1", Assert.Single(result.Passwords));
            Assert.Contains("1999:0", confirmed);
            Assert.Contains("1999:1", confirmed);
            Assert.Equal(1, seen["1999:0"]);
            Assert.Equal(1, seen["1999:1"]);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task MixedLengthsAndEmptyCandidatesCoverBothSharesOnce()
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-lengths").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            string Candidate(long word, int rule) => (word == 299 ? "" : word.ToString()) + (rule == 0 ? "" : "!");
            var dictionary = TestDictionary(300, 2);
            dictionary.ReadCandidates = (lo, count, ct) => Task.FromResult(Enumerable.Range((int)lo, (int)count)
                .SelectMany(w => Enumerable.Range(0, 2).Select(a => Encoding.ASCII.GetBytes(Candidate(w, a)))).ToList());
            var result = await Runner().RunAsync(new HybridPlan(new RecordingKernel(seen), null) { Dictionary = dictionary },
                "hash", Request(dir), new Gpu(seen) { Candidate = Candidate }, CancellationToken.None);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(600, seen.Count);
            Assert.All(seen.Values, n => Assert.True(n >= 1));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(2, false)]
    [InlineData(128, false)]
    [InlineData(256, false)]
    [InlineData(8, true)]
    public async Task Rar5DictionaryCandidatesKeepExactBytesAndCache(int length, bool literal)
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-rar5-long").FullName;
        try
        {
            byte[] password = literal ? Encoding.ASCII.GetBytes("$HEX[41]") : Enumerable.Range(0, length).Select(i => (byte)(128 + i % 127)).ToArray();
            byte[] salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
            string hash = $"$rar5$16${Convert.ToHexString(salt)}$01${new string('0', 32)}$8${Convert.ToHexString(Rar5Kernel.CheckValue(password, salt, 1))}";
            var kernel = Rar5Kernel.TryParse(hash)!;
            var dictionary = TestDictionary(300, 1);
            dictionary.ReadCandidates = (lo, count, ct) => Task.FromResult(new List<byte[]> { password });
            string cache = Path.Combine(dir, "cache");
            var request = Request(dir) with { Settings = new Settings { DontUsePasswordCache = false }, PasswordCachePath = cache };
            var result = await Runner().RunAsync(new HybridPlan(kernel, null) { Dictionary = dictionary }, "hash", request, new Gpu(new()), CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal(password, PasswordConfirmation.PlainBytes(Assert.Single(result.Passwords)));
            Assert.Equal("hash:" + PasswordConfirmation.HexPlain(password) + "\n", await File.ReadAllTextAsync(cache));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task BinaryGpuPasswordRetainsItsRawBytes()
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-binary-hit").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            var result = await Runner().RunAsync(new HybridPlan(new RecordingKernel(seen), null) { Dictionary = TestDictionary(300, 1) },
                "hash", Request(dir), new Gpu(seen) { Target = "0000:0", RawPassword = "$HEX[ff80]" }, CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal(new byte[] { 255, 128 }, PasswordConfirmation.PlainBytes(Assert.Single(result.Passwords)));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(13000, "ff80", false)]
    [InlineData(13000, "ff80", true)]
    [InlineData(13000, "244845585b34315d", false)]
    [InlineData(13000, "244845585b34315d", true)]
    [InlineData(13000, "efbbbf61", false)]
    [InlineData(13000, "efbbbf61", true)]
    [InlineData(13600, "ff80", false)]
    [InlineData(13600, "ff80", true)]
    [InlineData(13600, "244845585b34315d", false)]
    [InlineData(13600, "244845585b34315d", true)]
    [InlineData(13600, "efbbbf61", false)]
    [InlineData(13600, "efbbbf61", true)]
    [InlineData(22000, "ff80616263646566", false)]
    [InlineData(22000, "ff80616263646566", true)]
    [InlineData(22000, "244845585b34315d", false)]
    [InlineData(22000, "244845585b34315d", true)]
    [InlineData(22000, "efbbbf6162636465", false)]
    [InlineData(22000, "efbbbf6162636465", true)]
    public async Task CachedDictionaryPasswordsRetainBytes(int mode, string hex, bool confirm)
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-dict-cache").FullName;
        try
        {
            var tool = OutputTool(dir, hex);
            var settings = new Settings { SessionsDir = dir };
            string format = mode switch { 13600 => "WZAE", 22000 => "WPAH", _ => "RAR5" };
            var target = new HashTarget { FormatId = format, FormatName = "test", Protection = "test", Modes = [mode], HashLines = NativeKernels.BenchmarkHashes[mode] };
            byte[] password = Convert.FromHexString(hex);
            if (confirm) target.ConfirmPassword = bytes => bytes.AsSpan().SequenceEqual(password);
            var result = await new RecoverySession(tool, settings).RunAsync(target, "fixture", [new AttackSpec { Kind = AttackKind.Dictionary }], null, CancellationToken.None);
            Assert.Equal(SessionOutcome.FoundInCache, result.Outcome);
            Assert.Equal(password, PasswordConfirmation.PlainBytes(Assert.Single(result.Passwords)));
            string[] args = await File.ReadAllLinesAsync(Path.Combine(dir, "show.args"));
            Assert.Equal("2", args[Array.IndexOf(args, "--outfile-format") + 1]);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task FirstGpuOutfilePasswordDoesNotLoseItsBom()
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-dict-gpu-bom").FullName;
        try
        {
            var tool = OutputTool(dir, "");
            await File.WriteAllBytesAsync(Path.Combine(dir, "gpu.output"), [239, 187, 191, 97, 10]);
            string words = Path.Combine(dir, "words");
            await File.WriteAllTextAsync(words, "wrong\n");
            var kernel = Rar5Kernel.TryParse(NativeKernels.BenchmarkHashes[13000])!;
            var request = Request(dir) with { UseOptimizedKernel = true, Attack = new PreparedAttack { Description = "test", Args = { "-a", "0", words } } };
            var output = new List<string>();
            var runner = Runner();
            runner.OutputLine += output.Add;
            var result = await runner.RunAsync(new HybridPlan(kernel, null) { Dictionary = DictionaryAttack.Parse(request.Attack.Args) },
                "hash", request, tool, CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal(new byte[] { 239, 187, 191, 97 }, PasswordConfirmation.PlainBytes(Assert.Single(result.Passwords)));
            Assert.Contains("Found by hashcat.", output);
            Assert.DoesNotContain("-O", await File.ReadAllLinesAsync(Path.Combine(dir, "gpu.args")));
        }
        finally { Directory.Delete(dir, true); }
    }

    private static HashcatTool OutputTool(string dir, string showHex)
    {
        string exe = Path.Combine(dir, "hashcat");
        File.WriteAllBytes(Path.Combine(dir, "show.raw"), showHex.StartsWith("efbbbf", StringComparison.Ordinal)
            ? [.. Convert.FromHexString(showHex), 10] : Encoding.UTF8.GetBytes("$HEX[" + showHex + "]\n"));
        File.WriteAllText(exe, """
            #!/bin/sh
            case " $* " in
              *" --version "*) echo v8.0.0; exit 0;;
              *" --show "*) printf '%s\n' "$@" > show.args; cat show.raw; exit 0;;
              *" --keyspace "*) echo 300; exit 0;;
              *" --total-candidates "*) echo 300; exit 0;;
              *" --stdout "*) exit 0;;
            esac
            printf '%s\n' "$@" > gpu.args
            while [ "$#" -gt 0 ]; do
              if [ "$1" = "-o" ]; then shift; cp gpu.output "$1"; fi
              shift
            done
            exit 0
            """);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return HashcatTool.Locate(exe, dir, dir)!;
    }

    [Fact]
    public async Task InvalidHexLookingWordStaysLiteralInCandidateExport()
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-dict-literal").FullName;
        try
        {
            var tool = OutputTool(dir, "");
            string exe = Path.Combine(dir, "hashcat");
            await File.WriteAllTextAsync(exe, (await File.ReadAllTextAsync(exe))
                .Replace("*\" --stdout \"*) exit 0;;", "*\" --stdout \"*) cat show.raw; exit 0;;"));
            await File.WriteAllTextAsync(Path.Combine(dir, "show.raw"), "$HEX[no]\n");
            string words = Path.Combine(dir, "words");
            await File.WriteAllTextAsync(words, "$HEX[no]\n");
            var dictionary = new DictionaryAttack(["-a", "0", words]);
            Assert.True(await dictionary.PrepareAsync(tool, 13000, CancellationToken.None));
            Assert.Equal("$HEX[no]"u8.ToArray(), Assert.Single(await dictionary.ReadCandidates(0, 1, CancellationToken.None)));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task DuplicateEmptyCandidatesKeepTheirMultiplicity()
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-empty").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            var dictionary = TestDictionary(300, 2);
            dictionary.ReadCandidates = (lo, count, ct) => Task.FromResult(Enumerable.Range(0, (int)count * 2).Select(_ => Array.Empty<byte>()).ToList());
            var result = await Runner().RunAsync(new HybridPlan(new RecordingKernel(seen), null) { Dictionary = dictionary },
                "hash", Request(dir), new Gpu(seen) { Candidate = (_, _) => "" }, CancellationToken.None);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.True(seen[""] >= 600);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(400, false)]
    [InlineData(799, false)]
    [InlineData(799, true)]
    public async Task UnsuitableWordsKeepCoverageAndSurviveResume(int badWord, bool resume)
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-deferred").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            byte[] Candidate(long word, int rule)
            {
                var bytes = Encoding.ASCII.GetBytes($"{word:0000}:{rule}");
                if (word == badWord) { bytes[0] = 1; bytes[1] = 255; }
                return bytes;
            }
            DictionaryAttack Dictionary() => new(["-a", "0", "unused"])
            {
                BaseCount = 800, AmplifierCount = 2,
                ReadCandidates = (lo, count, ct) => Task.FromResult(Enumerable.Range((int)lo, (int)count)
                    .SelectMany(w => Enumerable.Range(0, 2).Select(a => Candidate(w, a))).ToList()),
            };
            Gpu Gpu() => new(seen) { Candidate = (w, a) => Encoding.Latin1.GetString(Candidate(w, a)) };
            using var stop = new CancellationTokenSource();
            int cpu = 0;
            var kernel = new RecordingKernel(seen) { AsciiOnly = true, OnTest = () => { if (resume && Interlocked.Increment(ref cpu) == 70) stop.Cancel(); } };
            var request = Request(dir);
            var result = await Runner().RunAsync(new HybridPlan(kernel, null) { Dictionary = Dictionary() }, "hash", request, Gpu(), stop.Token);
            if (resume)
            {
                Assert.Equal(RunOutcome.Aborted, result.Outcome);
                var point = System.Text.Json.JsonSerializer.Deserialize<HybridResumePoint>(await File.ReadAllTextAsync(HybridRunner.RestoreFile(dir, "test")))!;
                Assert.True(point.LeftoverCount > 0);
                result = await Runner().RunAsync(new HybridPlan(new RecordingKernel(seen) { AsciiOnly = true }, null) { Dictionary = Dictionary() },
                    "hash", request with { Restore = true }, Gpu(), CancellationToken.None);
            }
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(1600, seen.Count);
            for (int w = 0; w < 800; w++)
                for (int a = 0; a < 2; a++) Assert.True(seen.ContainsKey(Encoding.Latin1.GetString(Candidate(w, a))));
            Assert.True(seen.Values.Sum() > 0);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task DeferredGpuResumeKeepsItsCursorAndTruncatesUncommittedSuffix()
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-tail-resume").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            using var stop = new CancellationTokenSource();
            var request = Request(dir);
            var gpu = new Gpu(seen) { DeferredProgress = _ => stop.Cancel() };
            var result = await Runner().RunAsync(new HybridPlan(new RecordingKernel(seen) { MaxLength = 2 }, null)
                { Dictionary = TestDictionary(200, 3) }, "hash", request, gpu, stop.Token);
            Assert.Equal(RunOutcome.Aborted, result.Outcome);
            var point = System.Text.Json.JsonSerializer.Deserialize<HybridResumePoint>(await File.ReadAllTextAsync(HybridRunner.RestoreFile(dir, "test")))!;
            Assert.InRange(point.LeftoverLo, 1, point.LeftoverCount - 1);
            string path = HybridRunner.LeftoverFile(dir, "test");
            await File.AppendAllTextAsync(path, "$HEX[756e636f6d6d6974746564]\n");
            gpu = new Gpu(seen);
            result = await Runner().RunAsync(new HybridPlan(new RecordingKernel(seen) { MaxLength = 2 }, null)
                { Dictionary = TestDictionary(200, 3) }, "hash", request with { Restore = true }, gpu, CancellationToken.None);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(point.LeftoverCount, gpu.DeferredLineCount);
            Assert.Equal(point.LeftoverLo, gpu.DeferredSkip);
            Assert.Equal(600, seen.Count);
            Assert.False(File.Exists(path));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PrefetchStartsBeforeHashingAndIsJoinedOnStop(bool stopDuringPrefetch)
    {
        string dir = Directory.CreateTempSubdirectory("rk-dict-prefetch").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            using var stop = new CancellationTokenSource();
            var dictionary = TestDictionary(100000, 1);
            var read = dictionary.ReadCandidates;
            int reads = 0, cpu = 0;
            bool exportFinished = false;
            dictionary.ReadCandidates = async (lo, count, ct) =>
            {
                if (Interlocked.Increment(ref reads) == 2 && stopDuringPrefetch)
                    try { await Task.Delay(Timeout.Infinite, ct); }
                    finally { exportFinished = true; }
                return await read(lo, count, ct);
            };
            var kernel = new RecordingKernel(seen) { OnTest = () =>
            {
                Assert.True(Volatile.Read(ref reads) >= 2);
                if (Interlocked.Increment(ref cpu) == 70) stop.Cancel();
            } };
            var request = Request(dir);
            var result = await Runner().RunAsync(new HybridPlan(kernel, null) { Dictionary = dictionary }, "hash", request, new Gpu(seen), stop.Token);
            Assert.Equal(RunOutcome.Aborted, result.Outcome);
            if (stopDuringPrefetch) Assert.True(exportFinished);
            result = await Runner().RunAsync(new HybridPlan(new RecordingKernel(seen), null) { Dictionary = TestDictionary(100000, 1) },
                "hash", request with { Restore = true }, new Gpu(seen), CancellationToken.None);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(100000, seen.Count);
        }
        finally { Directory.Delete(dir, true); }
    }

    private static HybridRunner Runner() => new()
    {
        ForceGpu = true, HashcatStartupSeconds = .001, BatchSeconds = 1,
        Tick = TimeSpan.FromMilliseconds(2), InitialGpuSpeed = 20000, InitialCpuSpeed = 10000, ThreadsOverride = 2,
    };

    private static RunRequest Request(string dir) => new()
    {
        Mode = 13000, HashFile = "unused", Attack = new PreparedAttack { Description = "test" },
        SessionName = "test", SessionDir = dir, Settings = new Settings { DontUsePasswordCache = true },
    };

    private static DictionaryAttack TestDictionary(int words, int rules) => new(["-a", "0", "unused"])
    {
        BaseCount = words, AmplifierCount = rules,
        ReadCandidates = (lo, count, ct) => Task.FromResult(Enumerable.Range((int)lo, (int)count)
            .SelectMany(w => Enumerable.Range(0, rules).Select(a => Encoding.ASCII.GetBytes($"{w:0000}:{a}"))).ToList()),
    };

    private sealed class RecordingKernel(ConcurrentDictionary<string, int> seen) : NativeKernel
    {
        public string? Target { get; init; }
        public string? RejectedTarget { get; init; }
        public Action? OnTest { get; init; }
        public int MaxLength { get; init; } = 64;
        public bool AsciiOnly { get; init; }
        public override bool SupportsDictionaryPassword(ReadOnlySpan<byte> password)
            => base.SupportsDictionaryPassword(password) && (!AsciiOnly || password.IndexOfAnyInRange((byte)128, byte.MaxValue) < 0);
        public override int MaxPasswordLength => MaxLength;
        public override string Name => "recording";
        public override double SpeedHint => 1000;
        public override bool Verify(ReadOnlySpan<byte> pw)
        {
            if (pw.Length == 0) seen.AddOrUpdate("", 1, (_, n) => n + 1);
            return Encoding.ASCII.GetString(pw) == Target || Encoding.ASCII.GetString(pw) == RejectedTarget;
        }
        public override KernelWorker CreateWorker() => new Worker(seen, OnTest, Target, RejectedTarget);
        private sealed class Worker(ConcurrentDictionary<string, int> seen, Action? onTest, string? target, string? rejectedTarget) : KernelWorker
        {
            public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last) => throw new NotSupportedException();
            public override int SearchPasswords(ReadOnlySpan<byte> packed, int length, int count)
            {
                for (int i = 0; i < count; i++)
                {
                    seen.AddOrUpdate(Encoding.Latin1.GetString(packed.Slice(i * length, length)), 1, (_, n) => n + 1);
                    string text = Encoding.Latin1.GetString(packed.Slice(i * length, length));
                    if (text == target || text == rejectedTarget) return i;
                    onTest?.Invoke();
                    Thread.SpinWait(1000);
                }
                return -1;
            }
        }
    }

    private sealed class Gpu(ConcurrentDictionary<string, int> seen) : IGpuRange
    {
        public string? Target { get; init; }
        public long FailAfter { get; init; }
        public Func<long, int, string>? Candidate { get; init; }
        public string? RawPassword { get; init; }
        public Action<long>? DeferredProgress { get; init; }
        public int DeferredLineCount { get; private set; }
        public long DeferredSkip { get; private set; }
        public Task<long?> KeyspaceAsync(IReadOnlyList<string> args, CancellationToken ct) => throw new NotSupportedException();
        public async Task<GpuRangeResult> RunAsync(HashcatOrder order, long skip, long count, IReadOnlyCollection<int> exclude,
            Action<HashcatStatus> onStatus, CancellationToken stop)
        {
            string[]? deferred = order.Dictionary is { } dictionary && File.Exists(dictionary.Args[2])
                ? File.ReadAllLines(dictionary.Args[2]) : null;
            if (deferred is not null) { DeferredLineCount = deferred.Length; DeferredSkip = skip; }
            long w = skip;
            while (w < skip + count && !stop.IsCancellationRequested)
            {
                if (FailAfter > 0 && w - skip >= FailAfter) return new GpuRangeResult { Outcome = RunOutcome.Error, DoneUpTo = w };
                for (int a = 0; a < order.AmplifierCount; a++)
                {
                    string pw = deferred is not null ? Encoding.Latin1.GetString(PasswordConfirmation.PlainBytes(deferred[w]))
                        : Candidate?.Invoke(w, a) ?? $"{w:0000}:{a}";
                    seen.AddOrUpdate(pw, 1, (_, n) => n + 1);
                    if (pw == Target) return new GpuRangeResult { Outcome = RunOutcome.Cracked, DoneUpTo = w, Passwords = [pw], RawPasswords = RawPassword is not null ? [RawPassword] : [] };
                }
                w++;
                onStatus(new HashcatStatus
                {
                    Status = 3, RestorePoint = w, ProgressDone = (w - skip) * order.AmplifierCount,
                    Devices = [new() { Id = 1, Type = "GPU", Speed = 1000 }],
                });
                if (deferred is not null) DeferredProgress?.Invoke(w);
                await Task.Delay(1, CancellationToken.None);
            }
            return new GpuRangeResult { Outcome = w == skip + count ? RunOutcome.Exhausted : RunOutcome.Aborted, DoneUpTo = w };
        }
    }
}
