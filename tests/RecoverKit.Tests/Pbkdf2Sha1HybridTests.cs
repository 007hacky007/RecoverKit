using System.Collections.Concurrent;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Native;
using RecoverKit.App.Ui;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class Pbkdf2Sha1HybridTests
{
    [Theory]
    [InlineData(13600)]
    [InlineData(22000)]
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
    [InlineData(13600)]
    [InlineData(22000)]
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
    [InlineData(13600)]
    [InlineData(22000)]
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
    [InlineData(13600)]
    [InlineData(22000)]
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

    private static void AssertEligibility(bool expected, int mode, string hash, PreparedAttack attack,
        Settings settings, IReadOnlyList<BackendDevice> devices)
    {
        Assert.Equal(expected, HybridRunner.Plan(mode, hash, attack, settings, devices) is not null);
        Assert.Equal(expected, SpeedProbe.HybridEligible(settings, devices, mode));
    }

    [Theory]
    [InlineData(13600)]
    [InlineData(22000)]
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

    [Fact]
    public void MultiLineWpaKeepsHashcatsAllNetworkSearch()
    {
        string hash = NativeKernels.BenchmarkHashes[22000];
        var settings = new Settings { PerformanceChoice = new PerformanceDecision { Engine = "hybrid" } };
        BackendDevice[] devices = [new() { Id = 1, Type = "GPU" }];
        foreach (var args in new string[][] { ["-a", "3", "ABCDEFG?d"], ["-a", "0", "words", "-r", "rules"] })
        {
            var attack = new PreparedAttack { Description = "test" };
            attack.Args.AddRange(args);
            Assert.Null(HybridRunner.Plan(22000, hash + "\n" + hash, attack, settings, devices));
            Assert.Null(NativeRunner.Plan(22000, hash + "\n" + hash, attack, settings, devices, ignoreGpu: true));
        }
    }

    [Theory]
    [InlineData(13600)]
    [InlineData(22000)]
    public async Task HybridWithRealKernelChecksEveryCandidateOnce(int mode)
    {
        if (!RkNative.Available) return;
        string dir = Directory.CreateTempSubdirectory("rk-sha1-partition-").FullName;
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

    private sealed class RecordingKernel(NativeKernel inner, ConcurrentDictionary<string, int> seen) : NativeKernel
    {
        public override string Name => inner.Name;
        public override double SpeedHint => inner.SpeedHint;
        public override int MaxPasswordLength => inner.MaxPasswordLength;
        public override int PrefixBatch(int lastCount) => inner.PrefixBatch(lastCount);
        public override bool Verify(ReadOnlySpan<byte> password) => inner.Verify(password);
        public override KernelWorker CreateWorker() => new Worker(inner.CreateWorker(), seen);
        private sealed class Worker(KernelWorker worker, ConcurrentDictionary<string, int> seen) : KernelWorker
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
