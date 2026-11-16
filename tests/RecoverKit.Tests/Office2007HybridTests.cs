using System.Collections.Concurrent;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using RecoverKit.Core.Formats;
using RecoverKit.App.Ui;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class Office2007HybridTests
{
    [Theory]
    [InlineData(9400)]
    public void DefaultsUseHybridWithAnyActiveDiscreteGpu(int mode)
    {
        string hash = NativeKernels.BenchmarkHashes[mode];
        foreach (var (devices, expected) in new (BackendDevice[], bool)[]
        {
            ([new() { Id = 1, Type = "GPU" }], true),
            ([new() { Id = 1, Type = "GPU", Unified = true }], false),
            ([new() { Id = 1, Type = "GPU", Unified = true }, new() { Id = 2, Type = "GPU", Unified = true }], false),
            ([new() { Id = 1, Type = "GPU", Unified = true }, new() { Id = 2, Type = "GPU" }], true),
        })
        {
            foreach (var args in new string[][] { ["-a", "3", "ABCDEFG?d"], ["-a", "0", "words", "-r", "rules"] })
            {
                var attack = new PreparedAttack { Description = "test" };
                attack.Args.AddRange(args);
                var settings = new Settings();
                AssertEligibility(expected, mode, hash, attack, settings, devices);
                settings.PerformanceChoice = new PerformanceDecision { Engine = "hybrid" };
                AssertEligibility(true, mode, hash, attack, settings, devices);
                settings.PerformanceChoice = null;
                settings.PerformanceStrategyExplicit = true;
                AssertEligibility(true, mode, hash, attack, settings, devices);
                settings.HybridCpuGpu = false;
                AssertEligibility(false, mode, hash, attack, settings, devices);
            }
        }
    }

    [Theory]
    [InlineData(9400)]
    public void UserOptOutsKeepHashcatAlone(int mode)
    {
        BackendDevice[] devices = [new() { Id = 1, Type = "GPU" }];
        foreach (var settings in new Settings[]
        {
            new() { HybridCpuGpu = false },
            new() { Strategy = DeviceStrategy.FastGpu },
            new() { Strategy = DeviceStrategy.CpuOnly },
            new() { UseNativeCpuEngine = false },
            new() { PerformanceChoice = new PerformanceDecision { Engine = "gpu" } },
            new() { PerformanceChoice = new PerformanceDecision { Engine = "cpu" } },
            new() { ExtraArguments = "--force" },
        })
        foreach (var args in new string[][] { ["-a", "3", "ABCDEFG?d"], ["-a", "0", "words", "-r", "rules"] })
        {
            var attack = new PreparedAttack { Description = "test" };
            attack.Args.AddRange(args);
            AssertEligibility(false, mode, NativeKernels.BenchmarkHashes[mode], attack, settings, devices);
        }
    }

    [Theory]
    [InlineData(9400)]
    public void MeasuredGpuChoiceKeepsTinyJobsOnHashcat(int mode)
    {
        string hash = NativeKernels.BenchmarkHashes[mode];
        BackendDevice[] devices = [new() { Id = 1, Key = "gpu", Type = "GPU" }];
        var profile = new PerformanceProfile
        {
            Decisions = [new() { Domain = "execution", Mode = mode, Length = 8, Engine = "gpu", DeviceKeys = ["gpu"] }],
        };
        var settings = ProfileSettings.ForAttack(new Settings(), profile, devices, mode, 8, hash, candidates: 1);
        Assert.Equal("gpu", settings.PerformanceChoice?.Engine);
        var attack = new PreparedAttack { Description = "test", Args = { "-a", "3", "ABCDEFGH" } };
        AssertEligibility(false, mode, hash, attack, settings, devices);
    }

    [Theory]
    [InlineData(9400)]
    public void OnlyActiveGpusDecideTheDefaultAndQuarterSpeedRule(int mode)
    {
        BackendDevice[] devices =
        [
            new() { Id = 1, Key = "integrated", Type = "GPU", Unified = true },
            new() { Id = 2, Key = "discrete", Type = "GPU" },
        ];
        string hash = NativeKernels.BenchmarkHashes[mode];
        foreach (var args in new string[][] { ["-a", "3", "ABCDEFG?d"], ["-a", "0", "words", "-r", "rules"] })
        {
            var attack = new PreparedAttack { Description = "test" };
            attack.Args.AddRange(args);
            var settings = new Settings();
            settings.CpuSpeedByMode[mode] = 100;
            settings.GpuSpeedByMode[mode] = 1000;
            AssertEligibility(true, mode, hash, attack, settings, devices);
            settings.DisabledDeviceKeys.Add("discrete");
            AssertEligibility(false, mode, hash, attack, settings, devices);
            settings.PerformanceStrategyExplicit = true;
            AssertEligibility(true, mode, hash, attack, settings, devices);
            settings.CpuSpeedByMode[mode] = 250;
            AssertEligibility(true, mode, hash, attack, settings, devices);
            settings.CpuSpeedByMode[mode] = 100;
            settings.PerformanceChoice = new PerformanceDecision { Engine = "hybrid" };
            AssertEligibility(true, mode, hash, attack, settings, devices);
            settings.PerformanceChoice = null;
            settings.PerformanceStrategyExplicit = false;
            settings.DisabledDeviceKeys.Clear();
            settings.GpuPerformanceChoice = new PerformanceDecision { DeviceKeys = ["integrated"] };
            // An old integrated-only profile cannot bypass automatic dedicated-GPU selection.
            AssertEligibility(true, mode, hash, attack, settings, devices);
            settings.DeviceSelectionExplicit = true;
            AssertEligibility(false, mode, hash, attack, settings, devices);
            settings.DeviceSelectionExplicit = false;
            settings.GpuPerformanceChoice = new PerformanceDecision { DeviceKeys = ["discrete"] };
            AssertEligibility(true, mode, hash, attack, settings, devices);
            settings.DisabledDeviceKeys.Add("discrete");
            AssertEligibility(false, mode, hash, attack, settings, devices);
        }
    }

    [Fact]
    public void OfficeDiagnosticsRegisterIndependentPaths()
    {
        Assert.Equal(["default", "scalar", "avx2", "avx512", "sha-ni", "neon", "arm-sha1"],
            KernelVariants.ForMode(9400).Select(v => v.Name));
        Assert.Contains(9400, DetailedBenchmarkRunner.HybridModes);
        Assert.Equal(7, MatchedSpeedProbe.LengthFor(9400));
    }

    [Fact]
    public void ExplicitOfficePathOverridesMeasuredSelectionWithoutReadingPbkdf2Selector()
    {
        if (!RkNative.Available) return;
        string? savedOffice = Environment.GetEnvironmentVariable("RECOVERKIT_OFFICE2007_PATH");
        string? savedPbkdf = Environment.GetEnvironmentVariable("RECOVERKIT_PBKDF2_SHA1_PATH");
        try
        {
            var settings = new Settings { CpuPerformanceChoice = new() { Variant = "scalar" } };
            Environment.SetEnvironmentVariable("RECOVERKIT_OFFICE2007_PATH", "arm-sha1");
            Assert.Null(ProfileSettings.CpuSelection(settings, 9400));
            Environment.SetEnvironmentVariable("RECOVERKIT_OFFICE2007_PATH", null);
            Environment.SetEnvironmentVariable("RECOVERKIT_PBKDF2_SHA1_PATH", "arm-sha1");
            using var selection = ProfileSettings.CpuSelection(settings, 9400);
            Assert.NotNull(selection);
            const RkNative.Feature paths = RkNative.Feature.Avx2 | RkNative.Feature.Avx512 | RkNative.Feature.ShaNi | RkNative.Feature.Neon | RkNative.Feature.ArmSha1;
            Assert.Equal((RkNative.Feature)0, RkNative.Features & paths);
        }
        finally
        {
            Environment.SetEnvironmentVariable("RECOVERKIT_OFFICE2007_PATH", savedOffice);
            Environment.SetEnvironmentVariable("RECOVERKIT_PBKDF2_SHA1_PATH", savedPbkdf);
        }
    }

    [Theory]
    [InlineData("native scalar", "passed", false)]
    [InlineData("native SHA-NI + scalar fallback", "passed", false)]
    [InlineData("native SHA-NI", "passed", true)]
    public void RequestedShaNiNeedsTheExactPath(string actual, string state, bool passed)
    {
        var result = CpuDiagnosticWorker.EnforcePath(new(new(true, 19), 100, 1, actual, SelfTestState: state), "sha-ni");
        Assert.Equal(passed, result.Check.Passed);
        Assert.Equal(passed ? 100 : 0, result.Speed);
    }

    [Fact]
    public void WideReportRequiresOfficeGuardAndExactPath()
    {
        var report = new DiagnosticReport { System = new() { ["AVX-512 available"] = "True", ["Logical threads"] = "1" } };
        report.Measurements = [new() { Section = "cpu", Mode = 9400, Variant = "avx512", Threads = 1,
            Correct = true, Speed = 100, Length = 7, Target = "synthetic",
            Details = new() { ["actual path"] = "native AVX-512", ["self-test state"] = "passed" } }];
        Assert.Equal(100d, report.WideVectorPaths.Rows.Single(r => r.Mode == 9400).SingleThread.Avx512.Median);
        report.Measurements[0].Details["self-test state"] = "not run";
        Assert.Equal("FAIL", report.WideVectorPaths.Rows.Single(r => r.Mode == 9400).Correctness);
        report.Measurements[0].Details["self-test state"] = "passed";
        report.Measurements[0].Details["actual path"] = "native scalar";
        Assert.Equal("FAIL", report.WideVectorPaths.Rows.Single(r => r.Mode == 9400).Correctness);
    }

    [Fact]
    public void OfficeVariantsMatchIndependentReferenceAndRestoreFeatureMask()
    {
        if (!RkNative.Available) return;
        var saved = RkNative.Features;
        foreach (var variant in KernelVariants.ForMode(9400).Where(v => v.Supported))
        {
            using (KernelVariants.Select(9400, variant.Name))
            {
                NativeKernels.ResetCpuPath(9400);
                var check = CpuDiagnostics.CheckKernel(9400, variant.Name);
                Assert.True(check.Passed, $"{variant.Name}: {check.Error}");
                if (variant.Name != "default")
                {
                    var result = CpuDiagnosticWorker.EnforcePath(new(check, 0, 0, NativeKernels.CpuPath(9400, actualOnly: true),
                        SelfTestState: NativeKernels.WideSelfTestState(9400)), variant.Name);
                    Assert.True(result.Check.Passed, $"{variant.Name}: {result.Error}");
                }
            }
            Assert.Equal(saved, RkNative.Features);
        }
    }

    [Fact]
    public void ResumeRetainsTheSavedHybridEngineOnIntegratedGpu()
    {
        string dir = Directory.CreateTempSubdirectory("rk-office-resume-engine-").FullName;
        try
        {
            File.WriteAllText(HybridRunner.RestoreFile(dir, "test"), "{}");
            var settings = ProfileSettings.PreserveResumeEngine(new Settings(), 9400, dir, "test");
            Assert.Equal("hybrid", settings.PerformanceChoice?.Engine);
            BackendDevice[] devices = [new() { Id = 1, Type = "GPU", Unified = true }];
            var attack = new PreparedAttack { Description = "dictionary", Args = { "-a", "0", "words" } };
            Assert.Equal(RkNative.Available, HybridRunner.Plan(9400, NativeKernels.BenchmarkHashes[9400], attack, settings, devices, resumeDictionary: true) is not null);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void MissingNativeLibraryLeavesHybridOffAndMeasuredCpuFallbackAvailable()
    {
        bool saved = RkNative.Disabled;
        try
        {
            RkNative.Disabled = true;
            var settings = new Settings { PerformanceChoice = new() { Engine = "hybrid" } };
            BackendDevice[] devices = [new() { Id = 1, Type = "GPU" }];
            var attack = new PreparedAttack { Description = "mask", Args = { "-a", "3", "ABC?d" } };
            string hash = NativeKernels.BenchmarkHashes[9400];
            Assert.Null(HybridRunner.Plan(9400, hash, attack, settings, devices));
            Assert.False(SpeedProbe.HybridEligible(settings, devices, 9400));
            settings.PerformanceChoice = new() { Engine = "cpu" };
            Assert.NotNull(NativeRunner.Plan(9400, hash, attack, settings, devices));
        }
        finally { RkNative.Disabled = saved; }
    }

    private static void AssertEligibility(bool expected, int mode, string hash, PreparedAttack attack,
        Settings settings, IReadOnlyList<BackendDevice> devices)
    {
        expected &= RkNative.Available;
        Assert.Equal(expected, HybridRunner.Plan(mode, hash, attack, settings, devices) is not null);
        Assert.Equal(expected, SpeedProbe.HybridEligible(settings, devices, mode));
    }

    [Theory]
    [InlineData(9400)]
    public void CpuOnlyRequiresAMeasuredExecutionWinner(int mode)
    {
        string hash = NativeKernels.BenchmarkHashes[mode];
        var attack = new PreparedAttack { Description = "test", Args = { "-a", "3", "ABCDEFG?d" } };
        foreach (var strategy in new[] { DeviceStrategy.CpuOnly, DeviceStrategy.GpuOnly })
        {
            var settings = new Settings { Strategy = strategy };
            BackendDevice[] devices = [new() { Id = 1, Type = "CPU" }];
            Assert.Null(NativeRunner.Plan(mode, hash, attack, settings, devices));
            var args = HashcatRunner.DeviceArguments(settings, devices);
            Assert.Equal("1", args[args.IndexOf("-D") + 1]);
            settings.PerformanceChoice = new PerformanceDecision { Engine = "cpu", Speed = 1000 };
            Assert.NotNull(NativeRunner.Plan(mode, hash, attack, settings, devices));
        }
    }

    [Theory]
    [InlineData(9400)]
    public async Task HybridWithRealKernelChecksEveryCandidateOnce(int mode)
    {
        if (!RkNative.Available) return;
        string dir = Directory.CreateTempSubdirectory("rk-office2007-partition-").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            var kernel = new RecordingKernel(NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode])!, seen);
            var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "ABCD", "?1?1?1?1WXYZ"])!;
            var runner = new HybridRunner
            {
                ForceGpu = true, ThreadsOverride = 1, HashcatStartupSeconds = .001,
                InitialCpuSpeed = 1000, InitialGpuSpeed = 1000, BatchSeconds = .01, Tick = TimeSpan.FromMilliseconds(2),
            };
            var request = new RunRequest
            {
                Mode = mode, HashFile = "unused", SessionName = "partition", SessionDir = dir,
                Settings = new Settings { DontUsePasswordCache = true }, Attack = new PreparedAttack { Description = "partition" },
            };
            var result = await runner.RunAsync(new HybridPlan(kernel, space), NativeKernels.BenchmarkHashes[mode], request, new RecordingGpu(seen), CancellationToken.None);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(256, seen.Count);
            Assert.All(seen.Values, count => Assert.Equal(1, count));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task RealOfficeDictionaryResumesWithoutLosingExpandedCandidates()
    {
        if (!RkNative.Available) return;
        string dir = Directory.CreateTempSubdirectory("rk-office-dictionary-").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            using var stop = new CancellationTokenSource();
            int cpuTested = 0;
            var kernel = new RecordingKernel(NativeKernels.TryCreate(9400, NativeKernels.BenchmarkHashes[9400])!, seen)
            {
                OnTest = () => { if (Interlocked.Increment(ref cpuTested) == 9) stop.Cancel(); },
            };
            var dictionary = new DictionaryAttack(["-a", "0", "unused", "-r", "rules"])
            {
                BaseCount = 80, AmplifierCount = 2,
                ReadCandidates = (lo, count, _) => Task.FromResult(Enumerable.Range((int)lo, (int)count)
                    .SelectMany(w => Enumerable.Range(0, 2).Select(a => Encoding.UTF8.GetBytes($"{w:0000}:é{a}"))).ToList()),
            };
            HybridRunner Runner() => new()
            {
                ForceGpu = true, ThreadsOverride = 1, HashcatStartupSeconds = .001,
                InitialCpuSpeed = 1000, InitialGpuSpeed = 1000, BatchSeconds = .01, Tick = TimeSpan.FromMilliseconds(2),
            };
            var request = new RunRequest
            {
                Mode = 9400, HashFile = "unused", SessionName = "dictionary", SessionDir = dir,
                Settings = new Settings { DontUsePasswordCache = true }, Attack = new PreparedAttack { Description = "dictionary resume" },
            };
            var result = await Runner().RunAsync(new HybridPlan(kernel, null) { Dictionary = dictionary }, NativeKernels.BenchmarkHashes[9400],
                request, new DictionaryGpu(seen), stop.Token);
            Assert.Equal(RunOutcome.Aborted, result.Outcome);
            Assert.True(File.Exists(HybridRunner.RestoreFile(dir, request.SessionName)));
            result = await Runner().RunAsync(new HybridPlan(kernel, null) { Dictionary = dictionary }, NativeKernels.BenchmarkHashes[9400],
                request with { Restore = true }, new DictionaryGpu(seen), CancellationToken.None);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(160, seen.Count);
            Assert.All(seen.Values, count => Assert.True(count >= 1));
            Assert.False(File.Exists(HybridRunner.RestoreFile(dir, request.SessionName)));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OfficeMaskHitsPreserveLiteralHexPasswords(bool hybrid)
    {
        const string literal = "$HEX[4141]";
        string dir = Directory.CreateTempSubdirectory("rk-office-literal-mask-").FullName;
        try
        {
            string hash = StandardTarget(literal).HashLines;
            var kernel = Office2007Kernel.TryParse(hash)!;
            var attack = new PreparedAttack { Description = "literal mask", Args = { "-a", "3", literal } };
            var request = new RunRequest { Mode = 9400, HashFile = "unused", SessionName = "literal", SessionDir = dir,
                Attack = attack, Settings = new Settings { DontUsePasswordCache = true, MaxCpuThreads = 1 }, PasswordCachePath = Path.Combine(dir, "cache") };
            var space = MaskSpace.FromHashcatArgs(attack.Args)!;
            var result = hybrid
                ? await new HybridRunner { ThreadsOverride = 1 }.RunAsync(new HybridPlan(kernel, space), hash, request, new RecordingGpu(new()), CancellationToken.None)
                : await new NativeRunner().RunAsync(kernel, space, hash, request, CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal(Encoding.ASCII.GetBytes(literal), PasswordConfirmation.PlainBytes(Assert.Single(result.Passwords)));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("244845585b343134315d")]
    [InlineData("f4908080")]
    public async Task OfficeRecordedHitsPreserveExactBytesAndUseConfirmedCache(string hex)
    {
        string dir = Directory.CreateTempSubdirectory("rk-office-hit-cache-").FullName;
        try
        {
            byte[] password = Convert.FromHexString(hex);
            string cache = Path.Combine(dir, "requested-cache");
            string plain = await NativeRunner.RecordFoundAsync(new Settings(), Office2007CpuTests.HashcatExample, password, cache);
            Assert.Equal(password, PasswordConfirmation.PlainBytes(plain));
            Assert.Equal(Office2007CpuTests.HashcatExample + ":" + PasswordConfirmation.HexPlain(password) + "\n", await File.ReadAllTextAsync(cache));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void ExtractedStandardOfficeTargetIndependentlyConfirmsPasswordBytes()
    {
        var target = StandardTarget("$HEX[4141]");
        Assert.NotNull(target.ConfirmPassword);
        Assert.True(target.ConfirmPassword!("$HEX[4141]"u8.ToArray()));
        Assert.False(target.ConfirmPassword("AA"u8.ToArray()));
    }

    [Theory]
    [InlineData("244845585b343134315d")]
    [InlineData("f4908080")]
    public async Task OfficeMaskCacheRetainsExactBytes(string hex)
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-office-mask-cache-").FullName;
        try
        {
            byte[] password = Convert.FromHexString(hex);
            var tool = OfficeOutputTool(dir, PasswordConfirmation.HexPlain(password));
            string hash = hex == "f4908080" ? (string)Office2007CpuTests.RawUtf8KnownAnswers.First()[2] : StandardTarget("$HEX[4141]").HashLines;
            var target = new HashTarget { FormatId = "OF07", FormatName = "test", Protection = "test", Modes = [9400], HashLines = hash };
            var result = await new RecoverySession(tool, new Settings { SessionsDir = dir }).RunAsync(target, "fixture",
                [new AttackSpec { Kind = AttackKind.BruteForce, MinLength = 1, MaxLength = 1 }], null, CancellationToken.None);
            Assert.Equal(SessionOutcome.FoundInCache, result.Outcome);
            Assert.Equal(password, PasswordConfirmation.PlainBytes(Assert.Single(result.Passwords)));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("hashcat", true, true)]
    [InlineData("hashcat", false, false)]
    [InlineData("wrong", true, false)]
    public async Task DirectOfficeGpuRequestsRequireIndependentAndCallerConfirmation(string password, bool callerAccepts, bool accepted)
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-office-gpu-confirm-").FullName;
        try
        {
            var tool = OfficeOutputTool(dir, password);
            string hashFile = Path.Combine(dir, "target.hash");
            await File.WriteAllTextAsync(hashFile, Office2007CpuTests.HashcatExample);
            var request = new RunRequest { Mode = 9400, HashFile = hashFile, SessionName = "confirm", SessionDir = dir,
                Attack = new PreparedAttack { Description = "test", Args = { "-a", "3", "?l?l?l?l?l?l?l" } },
                Settings = new Settings { DontUsePasswordCache = true }, ConfirmPassword = _ => callerAccepts };
            var result = await new HashcatRunner(tool) { HashcatMajorVersion = 8 }.RunAsync(request, CancellationToken.None);
            Assert.Equal(accepted ? RunOutcome.Cracked : RunOutcome.Exhausted, result.Outcome);
            var args = await File.ReadAllLinesAsync(Path.Combine(dir, "gpu.args"));
            Assert.Contains("--keep-guessing", args);
            Assert.Contains("--potfile-disable", args);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("244845585b343134315d")]
    [InlineData("f4908080")]
    public async Task DirectOfficeGpuHitsPreserveRawBytesAndRequestedCache(string hex)
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-office-gpu-bytes-").FullName;
        try
        {
            byte[] password = Convert.FromHexString(hex);
            string hash = hex == "f4908080" ? (string)Office2007CpuTests.RawUtf8KnownAnswers.First()[2] : StandardTarget("$HEX[4141]").HashLines;
            var tool = OfficeOutputTool(dir, PasswordConfirmation.HexPlain(password));
            string hashFile = Path.Combine(dir, "target.hash"), cache = Path.Combine(dir, "requested-cache");
            await File.WriteAllTextAsync(hashFile, hash);
            var request = new RunRequest { Mode = 9400, HashFile = hashFile, SessionName = "bytes", SessionDir = dir,
                Attack = new PreparedAttack { Description = "test", Args = { "-a", "3", "?a?a?a?a" } },
                Settings = new Settings(), PasswordCachePath = cache };
            var result = await new HashcatRunner(tool) { HashcatMajorVersion = 8 }.RunAsync(request, CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal(password, PasswordConfirmation.PlainBytes(Assert.Single(result.Passwords)));
            Assert.Equal(hash + ":" + PasswordConfirmation.HexPlain(password) + "\n", await File.ReadAllTextAsync(cache));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task DirectOfficeGpuRequestsConfirmAnyTargetAndCacheTheMatchingHash()
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-office-gpu-multiple-").FullName;
        try
        {
            string secondHash = (string)Office2007CpuTests.KnownAnswers.Single(row => (string)row[0] == "128-ascii")[1];
            var tool = OfficeOutputTool(dir, "office-test");
            string hashFile = Path.Combine(dir, "target.hash"), cache = Path.Combine(dir, "requested-cache");
            await File.WriteAllTextAsync(hashFile, Office2007CpuTests.HashcatExample + "\n" + secondHash);
            var request = new RunRequest { Mode = 9400, HashFile = hashFile, SessionName = "multiple", SessionDir = dir,
                Attack = new PreparedAttack { Description = "test", Args = { "-a", "3", "?l?l?l?l?l?l?l" } },
                Settings = new Settings(), PasswordCachePath = cache };
            var result = await new HashcatRunner(tool) { HashcatMajorVersion = 8 }.RunAsync(request, CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal("office-test", Assert.Single(result.Passwords));
            Assert.Equal(secondHash + ":" + PasswordConfirmation.HexPlain("office-test"u8) + "\n", await File.ReadAllTextAsync(cache));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-office-hash")]
    public async Task DirectOfficeGpuRequestsCannotRunWithoutAnIndependentVerificationTarget(string? hash)
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-office-gpu-no-verifier-").FullName;
        try
        {
            var tool = OfficeOutputTool(dir, "hashcat");
            string hashFile = Path.Combine(dir, "target.hash");
            if (hash is not null) await File.WriteAllTextAsync(hashFile, hash);
            var request = new RunRequest { Mode = 9400, HashFile = hashFile, SessionName = "unverified", SessionDir = dir,
                Attack = new PreparedAttack { Description = "test", Args = { "-a", "3", "?l?l?l?l?l?l?l" } },
                Settings = new Settings { DontUsePasswordCache = true } };
            var result = await new HashcatRunner(tool) { HashcatMajorVersion = 8 }.RunAsync(request, CancellationToken.None);
            Assert.Equal(RunOutcome.Error, result.Outcome);
            Assert.Contains("independent verification", result.Error);
            Assert.False(File.Exists(Path.Combine(dir, "gpu.args")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task UsernamePrefixedOfficeTargetsStillUseIndependentVerificationAndUnprefixedCacheKeys()
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-office-gpu-username-").FullName;
        try
        {
            var tool = OfficeOutputTool(dir, "hashcat");
            string hashFile = Path.Combine(dir, "target.hash"), cache = Path.Combine(dir, "requested-cache");
            await File.WriteAllTextAsync(hashFile, "test-user:" + Office2007CpuTests.HashcatExample);
            var request = new RunRequest { Mode = 9400, HashFile = hashFile, SessionName = "username", SessionDir = dir,
                Attack = new PreparedAttack { Description = "test", Args = { "-a", "3", "?l?l?l?l?l?l?l" } },
                Settings = new Settings { ExtraArguments = "--username" }, PasswordCachePath = cache };
            var result = await new HashcatRunner(tool) { HashcatMajorVersion = 8 }.RunAsync(request, CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal("hashcat", Assert.Single(result.Passwords));
            Assert.Contains("--keep-guessing", await File.ReadAllLinesAsync(Path.Combine(dir, "gpu.args")));
            Assert.Equal(Office2007CpuTests.HashcatExample + ":" + PasswordConfirmation.HexPlain("hashcat"u8) + "\n", await File.ReadAllTextAsync(cache));
        }
        finally { Directory.Delete(dir, true); }
    }

    private static HashTarget StandardTarget(string password)
    {
        using var stream = new MemoryStream(DiagnosticOfficeSample.Create(false, password));
        var detection = new Detection { FilePath = "fixture" };
        OfficeExtractor.Extract(new CompoundFile(stream), detection);
        return detection.Target!;
    }

    private static HashcatTool OfficeOutputTool(string dir, string rawPassword)
    {
        string exe = Path.Combine(dir, "hashcat");
        File.WriteAllText(Path.Combine(dir, "show.raw"), rawPassword + "\n", new UTF8Encoding(false));
        File.WriteAllText(exe, """
            #!/bin/sh
            case " $* " in
              *" --version "*) echo v8.0.0; exit 0;;
              *" --show "*) cat show.raw; exit 0;;
            esac
            printf '%s\n' "$@" > gpu.args
            while [ "$#" -gt 0 ]; do
              if [ "$1" = "-o" ]; then shift; cp show.raw "$1"; fi
              shift
            done
            exit 0
            """);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        return HashcatTool.Locate(exe, dir, dir)!;
    }

    private sealed class DictionaryGpu(ConcurrentDictionary<string, int> seen) : IGpuRange
    {
        public Task<long?> KeyspaceAsync(IReadOnlyList<string> args, CancellationToken ct) => throw new NotSupportedException();
        public async Task<GpuRangeResult> RunAsync(HashcatOrder order, long skip, long count, IReadOnlyCollection<int> exclude,
            Action<HashcatStatus> onStatus, CancellationToken stop)
        {
            long word = skip;
            for (; word < skip + count && !stop.IsCancellationRequested; word++)
            {
                foreach (byte[] candidate in await order.Dictionary!.ReadCandidates(word, 1, stop))
                    seen.AddOrUpdate(Encoding.Latin1.GetString(candidate), 1, (_, n) => n + 1);
                onStatus(new HashcatStatus { Status = 3, RestorePoint = word + 1,
                    ProgressDone = (word + 1 - skip) * order.AmplifierCount, Devices = [new() { Id = 1, Type = "GPU", Speed = 1000 }] });
                await Task.Delay(1, CancellationToken.None);
            }
            return new GpuRangeResult { Outcome = word == skip + count ? RunOutcome.Exhausted : RunOutcome.Aborted, DoneUpTo = word };
        }
    }

    private sealed class RecordingKernel(NativeKernel inner, ConcurrentDictionary<string, int> seen) : NativeKernel
    {
        public Action? OnTest { get; init; }
        public override string Name => inner.Name;
        public override double SpeedHint => inner.SpeedHint;
        public override int MaxPasswordLength => inner.MaxPasswordLength;
        public override int PrefixBatch(int lastCount) => inner.PrefixBatch(lastCount);
        public override bool Verify(ReadOnlySpan<byte> password) => inner.Verify(password);
        public override KernelWorker CreateWorker() => new Worker(inner.CreateWorker(), seen, OnTest);
        private sealed class Worker(KernelWorker worker, ConcurrentDictionary<string, int> seen, Action? onTest) : KernelWorker
        {
            public override int SearchPasswords(ReadOnlySpan<byte> packed, int length, int count)
            {
                for (int i = 0; i < count; i++)
                {
                    seen.AddOrUpdate(Encoding.Latin1.GetString(packed.Slice(i * length, length)), 1, (_, n) => n + 1);
                    onTest?.Invoke();
                }
                return worker.SearchPasswords(packed, length, count);
            }
            public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last) => SearchBatch(prefix, 1, last);
            public override int SearchBatch(ReadOnlySpan<byte> prefixes, int count, ReadOnlySpan<byte> last)
            {
                int length = prefixes.Length / count;
                for (int k = 0; k < count; k++)
                    foreach (byte b in last)
                    {
                        byte[] candidate = [.. prefixes.Slice(k * length, length), b];
                        seen.AddOrUpdate(Encoding.Latin1.GetString(candidate), 1, (_, n) => n + 1);
                    }
                return worker.SearchBatch(prefixes, count, last);
            }
        }
    }

    private sealed class RecordingGpu(ConcurrentDictionary<string, int> seen) : IGpuRange
    {
        public Task<long?> KeyspaceAsync(IReadOnlyList<string> args, CancellationToken ct)
        {
            var space = MaskSpace.FromHashcatArgs(args)!;
            return Task.FromResult<long?>((long)space.TotalKeyspace / space.Positions[0].Length);
        }
        public async Task<GpuRangeResult> RunAsync(HashcatOrder order, long skip, long count, IReadOnlyCollection<int> exclude,
            Action<HashcatStatus> onStatus, CancellationToken stop)
        {
            long word = skip;
            for (; word < skip + count && !stop.IsCancellationRequested; word++)
            {
                for (long a = 0; a < order.AmplifierCount; a++)
                    seen.AddOrUpdate(Encoding.Latin1.GetString(order.Candidate(a, word)), 1, (_, n) => n + 1);
                await Task.Delay(1, CancellationToken.None);
            }
            return new GpuRangeResult { Outcome = word == skip + count ? RunOutcome.Exhausted : RunOutcome.Aborted, DoneUpTo = word };
        }
    }
}
