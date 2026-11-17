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

using RecordingKernel = RecoverKit.Tests.Office2007HybridTests.RecordingKernel;
using RecordingGpu = RecoverKit.Tests.Office2007HybridTests.RecordingGpu;
using DictionaryGpu = RecoverKit.Tests.Office2007HybridTests.DictionaryGpu;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class OfficeAgileHybridTests
{
    [Theory]
    [InlineData(9500)]
    [InlineData(9600)]
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
    [InlineData(9500)]
    [InlineData(9600)]
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
    [InlineData(9500)]
    [InlineData(9600)]
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
    [InlineData(9500)]
    [InlineData(9600)]
    public async Task HybridWithRealKernelChecksEveryCandidateOnce(int mode)
    {
        if (!RkNative.Available) return;
        string dir = Directory.CreateTempSubdirectory("rk-office-agile-partition-").FullName;
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

    [Theory]
    [InlineData(9500)]
    [InlineData(9600)]
    public void ResumeRetainsTheSavedHybridEngineOnIntegratedGpu(int mode)
    {
        string dir = Directory.CreateTempSubdirectory("rk-office-resume-engine-").FullName;
        try
        {
            File.WriteAllText(HybridRunner.RestoreFile(dir, "test"), "{}");
            var settings = ProfileSettings.PreserveResumeEngine(new Settings(), mode, dir, "test");
            Assert.Equal("hybrid", settings.PerformanceChoice?.Engine);
            BackendDevice[] devices = [new() { Id = 1, Type = "GPU", Unified = true }];
            var attack = new PreparedAttack { Description = "dictionary", Args = { "-a", "0", "words" } };
            Assert.Equal(RkNative.Available, HybridRunner.Plan(mode, NativeKernels.BenchmarkHashes[mode], attack, settings, devices, resumeDictionary: true) is not null);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(9500)]
    [InlineData(9600)]
    public void MissingNativeLibraryLeavesHybridOffAndMeasuredCpuFallbackAvailable(int mode)
    {
        bool saved = RkNative.Disabled;
        try
        {
            RkNative.Disabled = true;
            var settings = new Settings { PerformanceChoice = new() { Engine = "hybrid" } };
            BackendDevice[] devices = [new() { Id = 1, Type = "GPU" }];
            var attack = new PreparedAttack { Description = "mask", Args = { "-a", "3", "ABC?d" } };
            string hash = NativeKernels.BenchmarkHashes[mode];
            Assert.Null(HybridRunner.Plan(mode, hash, attack, settings, devices));
            Assert.False(SpeedProbe.HybridEligible(settings, devices, mode));
            settings.PerformanceChoice = new() { Engine = "cpu" };
            Assert.NotNull(NativeRunner.Plan(mode, hash, attack, settings, devices));
        }
        finally { RkNative.Disabled = saved; }
    }

    [Theory]
    [InlineData(9500)]
    [InlineData(9600)]
    public async Task RealOfficeDictionaryResumesWithoutLosingExpandedCandidates(int mode)
    {
        if (!RkNative.Available) return;
        string dir = Directory.CreateTempSubdirectory("rk-office-dictionary-").FullName;
        try
        {
            var seen = new ConcurrentDictionary<string, int>();
            using var stop = new CancellationTokenSource();
            int cpuTested = 0;
            var kernel = new RecordingKernel(NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode])!, seen)
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
                Mode = mode, HashFile = "unused", SessionName = "dictionary", SessionDir = dir,
                Settings = new Settings { DontUsePasswordCache = true }, Attack = new PreparedAttack { Description = "dictionary resume" },
            };
            var result = await Runner().RunAsync(new HybridPlan(kernel, null) { Dictionary = dictionary }, NativeKernels.BenchmarkHashes[mode],
                request, new DictionaryGpu(seen), stop.Token);
            Assert.Equal(RunOutcome.Aborted, result.Outcome);
            Assert.True(File.Exists(HybridRunner.RestoreFile(dir, request.SessionName)));
            result = await Runner().RunAsync(new HybridPlan(kernel, null) { Dictionary = dictionary }, NativeKernels.BenchmarkHashes[mode],
                request with { Restore = true }, new DictionaryGpu(seen), CancellationToken.None);
            Assert.Equal(RunOutcome.Exhausted, result.Outcome);
            Assert.Equal(160, seen.Count);
            Assert.All(seen.Values, count => Assert.True(count >= 1));
            Assert.False(File.Exists(HybridRunner.RestoreFile(dir, request.SessionName)));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(9500)]
    [InlineData(9600)]
    public async Task GpuAndPotfileHitsPreserveRawUtf8Bytes(int mode)
    {
        if (OperatingSystem.IsWindows()) return;
        using var fixture = System.Text.Json.JsonDocument.Parse(typeof(OfficeAgileHybridTests).Assembly
            .GetManifestResourceStream("RecoverKit.Tests.Fixtures.Office.agile-vectors.json")!);
        string hash = fixture.RootElement.EnumerateArray().Single(v => v.GetProperty("name").GetString() == $"{mode}-raw-f4908080")
            .GetProperty("hash").GetString()!;
        byte[] password = Convert.FromHexString("f4908080");
        string dir = Directory.CreateTempSubdirectory("rk-agile-raw-hit-").FullName;
        try
        {
            var tool = Office2007HybridTests.OfficeOutputTool(dir, PasswordConfirmation.HexPlain(password));
            string hashFile = Path.Combine(dir, "target.hash"), cache = Path.Combine(dir, "cache");
            await File.WriteAllTextAsync(hashFile, hash);
            var request = new RunRequest { Mode = mode, HashFile = hashFile, SessionName = "bytes", SessionDir = dir,
                Attack = new PreparedAttack { Description = "test", Args = { "-a", "3", "?a?a?a?a" } },
                Settings = new Settings(), PasswordCachePath = cache };
            var result = await new HashcatRunner(tool) { HashcatMajorVersion = 8 }.RunAsync(request, CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, result.Outcome);
            Assert.Equal(password, PasswordConfirmation.PlainBytes(Assert.Single(result.Passwords)));
            Assert.Equal(hash + ":" + PasswordConfirmation.HexPlain(password) + "\n", await File.ReadAllTextAsync(cache));
            var target = new HashTarget { FormatId = mode == 9500 ? "OF10" : "OF13", FormatName = "test", Protection = "test", Modes = [mode], HashLines = hash };
            var cached = await new RecoverySession(tool, new Settings { SessionsDir = dir }).RunAsync(target, "fixture",
                [new AttackSpec { Kind = AttackKind.BruteForce, MinLength = 1, MaxLength = 1 }], null, CancellationToken.None);
            Assert.Equal(SessionOutcome.FoundInCache, cached.Outcome);
            Assert.Equal(password, PasswordConfirmation.PlainBytes(Assert.Single(cached.Passwords)));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(9500, "hashcat", true, true)]
    [InlineData(9500, "hashcat", false, false)]
    [InlineData(9500, "wrong", true, false)]
    [InlineData(9600, "hashcat", true, true)]
    [InlineData(9600, "hashcat", false, false)]
    [InlineData(9600, "wrong", true, false)]
    public async Task GpuRequestsRequireIndependentAndCallerConfirmation(int mode, string password, bool callerAccepts, bool accepted)
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-agile-gpu-confirm-").FullName;
        try
        {
            var tool = Office2007HybridTests.OfficeOutputTool(dir, password);
            string hashFile = Path.Combine(dir, "target.hash");
            await File.WriteAllTextAsync(hashFile, NativeKernels.BenchmarkHashes[mode]);
            var request = new RunRequest { Mode = mode, HashFile = hashFile, SessionName = "confirm", SessionDir = dir,
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
    [InlineData(9500, "agile-sha1-default.xlsx")]
    [InlineData(9600, "agile-default.xlsx")]
    public void ExtractedAgileTargetsConfirmPasswordBytes(int mode, string fixture)
    {
        using var stream = typeof(OfficeAgileHybridTests).Assembly.GetManifestResourceStream("RecoverKit.Tests.Fixtures.Office." + fixture)!;
        var detection = new Detection { FilePath = "fixture" };
        OfficeExtractor.Extract(new CompoundFile(stream), detection);
        Assert.Equal([mode], detection.Target!.Modes);
        Assert.NotNull(detection.Target.ConfirmPassword);
        Assert.True(detection.Target.ConfirmPassword!("VelvetSweatshop"u8.ToArray()));
        Assert.False(detection.Target.ConfirmPassword("wrong"u8.ToArray()));
    }

    [Theory]
    [InlineData(9500, false)]
    [InlineData(9500, true)]
    [InlineData(9600, false)]
    [InlineData(9600, true)]
    public async Task MaskHitsPreserveLiteralHexPasswords(int mode, bool hybrid)
    {
        const string literal = "$HEX[4141]";
        byte[] salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        byte[] verifier = Enumerable.Range(16, 16).Select(i => (byte)i).ToArray();
        string algorithm = mode == 9500 ? "SHA1" : "SHA512";
        int keyBytes = mode == 9500 ? 16 : 32;
        byte[] spin = OfficeDecryptor.PasswordHash(algorithm, salt, literal, 100000);
        byte[] Encrypt(byte[] value, byte[] block) => OfficeDecryptor.AesCbcNoPad(value,
            OfficeDecryptor.Hash(algorithm, spin, block)[..keyBytes], salt, decrypt: false);
        byte[] digest = OfficeDecryptor.Hash(algorithm, verifier);
        Array.Resize(ref digest, (digest.Length + 15) / 16 * 16);
        byte[] encryptedVerifier = Encrypt(verifier, [0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79]);
        byte[] encryptedHash = Encrypt(digest, [0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e]);
        string hash = $"$office$*{(mode == 9500 ? 2010 : 2013)}*100000*{keyBytes * 8}*16*{Convert.ToHexString(salt)}*{Convert.ToHexString(encryptedVerifier)}*{Convert.ToHexString(encryptedHash[..32])}";
        string dir = Directory.CreateTempSubdirectory("rk-agile-literal-").FullName;
        try
        {
            var kernel = NativeKernels.TryCreate(mode, hash)!;
            var attack = new PreparedAttack { Description = "literal mask", Args = { "-a", "3", literal } };
            var request = new RunRequest { Mode = mode, HashFile = "unused", SessionName = "literal", SessionDir = dir,
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
    [InlineData(9500, false)]
    [InlineData(9500, true)]
    [InlineData(9600, false)]
    [InlineData(9600, true)]
    public async Task UnsupportedVariantsStayOnHashcatAndMixedTargetsFailExplicitly(int mode, bool mixed)
    {
        if (OperatingSystem.IsWindows()) return;
        string dir = Directory.CreateTempSubdirectory("rk-agile-unsupported-").FullName;
        try
        {
            string supported = NativeKernels.BenchmarkHashes[mode];
            string unsupported = supported.Replace("*100000*", "*99999*", StringComparison.Ordinal);
            var attack = new PreparedAttack { Description = "test", Args = { "-a", "3", "?l?l?l?l?l?l?l" } };
            BackendDevice[] devices = [new() { Id = 1, Type = "GPU" }];
            var settings = new Settings { DontUsePasswordCache = true };
            Assert.Null(HybridRunner.Plan(mode, unsupported, attack, settings, devices));
            settings.PerformanceChoice = new() { Engine = "cpu" };
            Assert.Null(NativeRunner.Plan(mode, unsupported, attack, settings, devices));
            var tool = Office2007HybridTests.OfficeOutputTool(dir, "hashcat");
            string hashFile = Path.Combine(dir, "target.hash");
            await File.WriteAllTextAsync(hashFile, mixed ? supported + "\n" + unsupported : unsupported);
            var request = new RunRequest { Mode = mode, HashFile = hashFile, SessionName = "variants", SessionDir = dir,
                Attack = attack, Settings = new Settings { DontUsePasswordCache = true } };
            var result = await new HashcatRunner(tool) { HashcatMajorVersion = 8 }.RunAsync(request, CancellationToken.None);
            Assert.Equal(mixed ? RunOutcome.Error : RunOutcome.Cracked, result.Outcome);
            if (mixed)
            {
                Assert.Contains("does not support all Office target rows", result.Error);
                Assert.False(File.Exists(Path.Combine(dir, "gpu.args")));
            }
            else Assert.DoesNotContain("--keep-guessing", await File.ReadAllLinesAsync(Path.Combine(dir, "gpu.args")));
        }
        finally { Directory.Delete(dir, true); }
    }

    private static void AssertEligibility(bool expected, int mode, string hash, PreparedAttack attack,
        Settings settings, IReadOnlyList<BackendDevice> devices)
    {
        expected &= RkNative.Available;
        Assert.Equal(expected, HybridRunner.Plan(mode, hash, attack, settings, devices) is not null);
        Assert.Equal(expected, SpeedProbe.HybridEligible(settings, devices, mode));
    }
}
