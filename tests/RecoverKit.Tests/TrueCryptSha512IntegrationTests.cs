using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using RecoverKit.App.Ui;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class TrueCryptSha512IntegrationTests
{
    public static IEnumerable<object[]> Modes => new[] { 29321, 29322, 29323, 29421, 29422, 29423 }.Select(mode => new object[] { mode });

    [Theory]
    [MemberData(nameof(Modes))]
    public void EveryEmittedModeRegistersTheKernelAndBenchmark(int mode)
    {
        Assert.True(NativeKernels.Supports(mode));
        Assert.IsType<TrueCryptSha512Kernel>(NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]));
        Assert.Equal(["default", "managed", "scalar", "avx2", "avx512", "neon", "arm-sha512"], KernelVariants.ForMode(mode).Select(v => v.Name));
        Assert.Equal(7, MatchedSpeedProbe.LengthFor(mode));
        Assert.Equal(NativeKernels.BenchmarkHashes[mode], MatchedSpeedProbe.HashLine(mode));
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public void HiddenHeadersEmitTheSameSha512ModeAndBytes(int mode)
    {
        string dir = Directory.CreateTempSubdirectory("rk-sha512-hidden-").FullName;
        try
        {
            string hash = NativeKernels.BenchmarkHashes[mode];
            string[] fields = hash.Split('$');
            byte[] header = [.. Convert.FromHexString(fields[2]), .. Convert.FromHexString(fields[3])];
            string file = Path.Combine(dir, "volume");
            using (var stream = File.Create(file))
            {
                stream.Position = VolumeOptions.HiddenOffset;
                stream.Write(header);
            }
            var options = new VolumeOptions
            {
                Kind = mode < 29400 ? VolumeKind.TrueCrypt : VolumeKind.VeraCrypt,
                HeaderOffset = VolumeOptions.HiddenOffset, Kdfs = VolumeKdf.Sha512,
                Ciphers = (mode % 10) switch { 1 => VolumeCipher.Single, 2 => VolumeCipher.Double, _ => VolumeCipher.Triple },
            };
            var target = CryptVolume.Open(file, options).Target!;
            Assert.Equal([mode], target.Modes);
            Assert.Equal(hash.ToLowerInvariant(), target.HashLines.ToLowerInvariant());
            Assert.NotNull(NativeKernels.TryCreate(mode, target.HashLines));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public void DefaultHybridRequiresAnActiveDiscreteGpuAndHonorsAnExplicitChoice(int mode)
    {
        foreach (bool dictionary in new[] { false, true })
        foreach (bool integrated in new[] { false, true })
        {
            BackendDevice[] devices = [new() { Id = 1, Key = "gpu", Type = "GPU", Unified = integrated }];
            var attack = Attack(dictionary);
            var settings = new Settings();
            AssertHybrid(!integrated, settings);
            settings.PerformanceChoice = new() { Engine = "hybrid" };
            AssertHybrid(true, settings);
            settings.PerformanceChoice = new() { Engine = "gpu" };
            AssertHybrid(false, settings);
            settings.PerformanceChoice = null;
            settings.PerformanceStrategyExplicit = true;
            AssertHybrid(true, settings);
            settings.UseNativeCpuEngine = false;
            AssertHybrid(false, settings);

            void AssertHybrid(bool expected, Settings preferences)
            {
                Assert.Equal(expected, HybridRunner.Plan(mode, NativeKernels.BenchmarkHashes[mode], attack, preferences, devices) is not null);
                Assert.Equal(expected, SpeedProbe.HybridEligible(preferences, devices, mode));
            }
        }
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public void CpuOnlyNeedsAMeasuredExecutionWin(int mode)
    {
        BackendDevice[] devices = [new() { Id = 1, Type = "CPU" }];
        var settings = new Settings { Strategy = DeviceStrategy.CpuOnly };
        string hash = NativeKernels.BenchmarkHashes[mode];
        Assert.Null(NativeRunner.Plan(mode, hash, Attack(false), settings, devices));
        settings.PerformanceChoice = new() { Engine = "cpu", Speed = 1000 };
        Assert.NotNull(NativeRunner.Plan(mode, hash, Attack(false), settings, devices));
        settings.ExtraArguments = "--keyboard-layout-mapping layout.hc";
        Assert.Null(NativeRunner.Plan(mode, hash, Attack(false), settings, devices));
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public void KeyfilesAndFixedPimRemainEntirelyWithHashcat(int mode)
    {
        string dir = Directory.CreateTempSubdirectory("rk-sha512-credentials-").FullName;
        try
        {
            string keyfile = Path.Combine(dir, "keyfile");
            File.WriteAllBytes(keyfile, [1, 2, 3]);
            var credentials = new List<VolumeCredentials>
            {
                new(new VolumeOptions { Kind = mode < 29400 ? VolumeKind.TrueCrypt : VolumeKind.VeraCrypt, Keyfiles = [keyfile] }),
            };
            if (mode >= 29400) credentials.Add(new(new VolumeOptions { Pim = 7 }));
            foreach (var credential in credentials)
            foreach (bool dictionary in new[] { false, true })
            {
                string hash = NativeKernels.BenchmarkHashes[mode];
                var settings = new Settings { PerformanceChoice = new() { Engine = "hybrid" } };
                BackendDevice[] devices = [new() { Id = 1, Type = "GPU" }];
                Assert.Null(HybridRunner.Plan(mode, hash, Attack(dictionary), settings, devices, credential));
                Assert.Null(NativeRunner.Plan(mode, hash, Attack(dictionary), settings, devices, ignoreGpu: true, credentials: credential));
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData(29321)]
    [InlineData(29322)]
    [InlineData(29323)]
    public async Task RealKernelHybridPartitionCoversEveryCandidateOnce(int mode)
    {
        using var rig = new Rig(mode);
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "ABC", "?1?1?1XYZ"])!;
        var gpu = new RecordingGpu(rig.Seen);
        var kernel = new RecordingKernel(NativeKernels.TryCreate(mode, rig.Hash)!, rig.Seen);
        var result = await Runner().RunAsync(new(kernel, space), rig.Hash, rig.Request(), gpu, CancellationToken.None);
        Assert.Equal(RunOutcome.Exhausted, result.Outcome);
        Assert.Equal(27, rig.Seen.Count);
        Assert.All(rig.Seen.Values, n => Assert.Equal(1, n));
        Assert.True(kernel.Candidates > 0);
        Assert.True(gpu.Candidates > 0);
    }

    [Fact]
    public async Task RuleExpandedDictionaryWithRealKernelCoversEveryCandidate()
    {
        using var rig = new Rig(29321);
        const int words = 13, rules = 2;
        var dictionary = new DictionaryAttack(["-a", "0", "unused", "-r", "unused-rules"])
        {
            BaseCount = words, AmplifierCount = rules,
            ReadCandidates = (lo, count, ct) => Task.FromResult(Enumerable.Range((int)lo, (int)count)
                .SelectMany(word => Enumerable.Range(0, rules).Select(rule => Encoding.ASCII.GetBytes($"x{word:00000}{rule}"))).ToList()),
        };
        var kernel = new RecordingKernel(NativeKernels.TryCreate(29321, rig.Hash)!, rig.Seen);
        var gpu = new RecordingGpu(rig.Seen);
        var result = await Runner().RunAsync(new(kernel, null) { Dictionary = dictionary }, rig.Hash, rig.Request(), gpu, CancellationToken.None);
        Assert.Equal(RunOutcome.Exhausted, result.Outcome);
        Assert.Equal(words * rules, rig.Seen.Count);
        Assert.All(rig.Seen.Values, n => Assert.True(n >= 1));
        Assert.True(kernel.Candidates > 0);
        Assert.True(gpu.Candidates > 0);
    }

    [Fact]
    public async Task RealKernelResumesAPartialCpuBatchWithoutDroppingCandidates()
    {
        using var rig = new Rig(29321);
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "AB", "?1?1?1XYZ"])!;
        // The first two words were done by hashcat. The last two form an unfinished CPU box.
        // Use no amplifier so the checkpoint maps one word to one candidate.
        var order = HashcatOrder.WithAmplifier(HashcatOrder.SortedPositions(space, 6), 0);
        for (long word = 0; word < 2; word++) rig.Seen[Encoding.Latin1.GetString(order.Candidate(0, word))] = 1;
        var pendingBox = order.Boxes(6, 8).Single();
        var firstPending = pendingBox.Positions.Select(position => position[0]).ToArray();
        rig.Seen[Encoding.Latin1.GetString(firstPending)] = 1;
        var resume = new HybridResumePoint { Length = 6, BaseCount = 8, Lo = 2, BatchLo = 6, BatchHi = 8, Box = 0, BoxPrefix = 1 };
        File.WriteAllText(HybridRunner.RestoreFile(rig.Dir, "sha512"), JsonSerializer.Serialize(resume));
        var kernel = new RecordingKernel(NativeKernels.TryCreate(29321, rig.Hash)!, rig.Seen);
        var result = await Runner().RunAsync(new(kernel, space), rig.Hash, rig.Request(restore: true), new RecordingGpu(rig.Seen), CancellationToken.None);
        Assert.Equal(RunOutcome.Exhausted, result.Outcome);
        Assert.Equal(8, rig.Seen.Count);
        Assert.All(rig.Seen.Values, n => Assert.Equal(1, n));
        Assert.Equal(8, result.LastStatus!.ProgressDone);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RealKernelReportsPasswordsFromEitherEngine(bool gpuHit)
    {
        using var rig = new Rig(29321);
        string password = gpuHit ? "aaaaa" : "aabbb";
        string hash = TrueCryptSha512Tests.MakeHeader(29321, "AES", Encoding.ASCII.GetBytes(password));
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "ab", "aa?1?1?1"])!;
        var kernel = new RecordingKernel(TrueCryptSha512Kernel.TryParse(29321, hash)!, rig.Seen);
        var gpu = new RecordingGpu(rig.Seen, gpuHit ? password : null);
        var result = await Runner().RunAsync(new(kernel, space), hash, rig.Request(), gpu, CancellationToken.None);
        Assert.Equal(RunOutcome.Cracked, result.Outcome);
        Assert.Contains(password, result.Passwords);
        Assert.True(TrueCryptSha512Kernel.TryParse(29321, hash)!.Verify(Encoding.ASCII.GetBytes(password)));
        Assert.Equal(gpuHit, gpu.Found);
        Assert.Equal(!gpuHit, kernel.Found);
    }

    private static PreparedAttack Attack(bool dictionary) => dictionary
        ? new() { Description = "dictionary", Args = { "-a", "0", "words", "-r", "rules" } }
        : new() { Description = "mask", Args = { "-a", "3", "hashca?l" } };

    private static HybridRunner Runner() => new()
    {
        ForceGpu = true, ThreadsOverride = 1, HashcatStartupSeconds = .001,
        InitialCpuSpeed = 1000, InitialGpuSpeed = 1000, BatchSeconds = .01, Tick = TimeSpan.FromMilliseconds(2),
    };

    private sealed class Rig(int mode) : IDisposable
    {
        public string Dir { get; } = Directory.CreateTempSubdirectory("rk-sha512-hybrid-").FullName;
        public string Hash { get; } = NativeKernels.BenchmarkHashes[mode];
        public ConcurrentDictionary<string, int> Seen { get; } = new();
        public RunRequest Request(bool restore = false) => new()
        {
            Mode = mode, HashFile = "unused", SessionName = "sha512", SessionDir = Dir, Restore = restore,
            Settings = new() { DontUsePasswordCache = true, SessionsDir = Dir }, Attack = new() { Description = "SHA512 partition" },
        };
        public void Dispose() => Directory.Delete(Dir, true);
    }

    private sealed class RecordingKernel(NativeKernel inner, ConcurrentDictionary<string, int> seen) : NativeKernel
    {
        public int Candidates;
        public bool Found;
        public override string Name => inner.Name;
        public override double SpeedHint => inner.SpeedHint;
        public override int MaxPasswordLength => inner.MaxPasswordLength;
        public override int PrefixBatch(int lastCount) => inner.PrefixBatch(lastCount);
        public override bool Verify(ReadOnlySpan<byte> password) => inner.Verify(password);
        public override KernelWorker CreateWorker() => new Worker(this, inner.CreateWorker(), seen);
        private sealed class Worker(RecordingKernel kernel, KernelWorker worker, ConcurrentDictionary<string, int> seen) : KernelWorker
        {
            public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last) => SearchBatch(prefix, 1, last);
            public override int SearchBatch(ReadOnlySpan<byte> prefixes, int count, ReadOnlySpan<byte> last)
            {
                int length = prefixes.Length / count;
                for (int k = 0; k < count; k++)
                foreach (byte b in last)
                {
                    byte[] candidate = [.. prefixes.Slice(k * length, length), b];
                    seen.AddOrUpdate(Encoding.Latin1.GetString(candidate), 1, (_, n) => n + 1);
                    Interlocked.Increment(ref kernel.Candidates);
                }
                int hit = worker.SearchBatch(prefixes, count, last);
                if (hit >= 0) kernel.Found = true;
                return hit;
            }
            public override int SearchPasswords(ReadOnlySpan<byte> passwords, int length, int count)
            {
                for (int i = 0; i < count; i++)
                {
                    seen.AddOrUpdate(Encoding.Latin1.GetString(passwords.Slice(i * length, length)), 1, (_, n) => n + 1);
                    Interlocked.Increment(ref kernel.Candidates);
                }
                int hit = worker.SearchPasswords(passwords, length, count);
                if (hit >= 0) kernel.Found = true;
                return hit;
            }
        }
    }

    private sealed class RecordingGpu(ConcurrentDictionary<string, int> seen, string? target = null) : IGpuRange
    {
        public int Candidates;
        public bool Found;
        public Task<long?> KeyspaceAsync(IReadOnlyList<string> args, CancellationToken ct)
            => Task.FromResult<long?>((long)MaskSpace.FromHashcatArgs(args)!.TotalKeyspace);
        public async Task<GpuRangeResult> RunAsync(HashcatOrder order, long skip, long count, IReadOnlyCollection<int> exclude,
            Action<HashcatStatus> onStatus, CancellationToken stop)
        {
            long word = skip;
            for (; word < skip + count && !stop.IsCancellationRequested; word++)
            {
                var candidates = order.Dictionary is { } dictionary
                    ? await dictionary.ReadCandidates(word, 1, stop)
                    : Enumerable.Range(0, (int)order.AmplifierCount).Select(a => order.Candidate(a, word)).ToList();
                foreach (byte[] bytes in candidates)
                {
                    string candidate = Encoding.Latin1.GetString(bytes);
                    seen.AddOrUpdate(candidate, 1, (_, n) => n + 1);
                    Interlocked.Increment(ref Candidates);
                    if (candidate == target)
                    {
                        Found = true;
                        return new() { Outcome = RunOutcome.Cracked, DoneUpTo = word + 1, Passwords = [candidate] };
                    }
                }
                await Task.Delay(1, CancellationToken.None);
            }
            return new() { Outcome = word == skip + count ? RunOutcome.Exhausted : RunOutcome.Aborted, DoneUpTo = word };
        }
    }
}
