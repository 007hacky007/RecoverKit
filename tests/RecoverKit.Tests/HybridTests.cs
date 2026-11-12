using System.Collections.Concurrent;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

/// <summary>
/// Hybrid CPU + GPU attacks: hashcat's base word numbering, the boxes the built-in engine runs for a
/// range of it, and the scheduler with a simulated hashcat, checking that every candidate is tested
/// exactly once whatever the split, the rebalancing, failures and stop/resume do.
/// </summary>
public class HybridTests
{
    private static byte[] Set(string s) => Encoding.ASCII.GetBytes(s).Distinct().OrderBy(b => b).ToArray();

    private static IEnumerable<byte[]> Enumerate(MaskSpace box)
    {
        int len = box.MaxLength;
        var idx = new int[len];
        while (true)
        {
            var pw = new byte[len];
            for (int i = 0; i < len; i++) pw[i] = box.Positions[i][idx[i]];
            yield return pw;
            int k = len - 1;
            while (k >= 0 && ++idx[k] == box.Positions[k].Length) idx[k--] = 0;
            if (k < 0) yield break;
        }
    }

    private static string S(byte[] b) => Encoding.Latin1.GetString(b);

    [Fact]
    public void CandidateNumberingCoversTheLengthOnce()
    {
        var pos = new[] { Set("ab7"), Set("xyz"), Set("01"), Set("Q"), Set("mn") };
        for (int r = 0; r <= pos.Length; r++)
        {
            var o = HashcatOrder.WithAmplifier(pos, r);
            Assert.Equal(3 * 3 * 2 * 1 * 2, o.Candidates);
            var seen = new HashSet<string>();
            for (long b = 0; b < o.BaseCount; b++)
                for (long a = 0; a < o.AmplifierCount; a++)
                {
                    var c = o.Candidate(a, b);
                    Assert.True(seen.Add(S(c)));
                    Assert.Equal(b, o.BaseWordOf(c));
                }
            Assert.Equal(o.Candidates, seen.Count);
        }
    }

    [Fact]
    public void BoxesHoldExactlyTheBaseWordRange()
    {
        var pos = new[] { Set("ab"), Set("cdef"), Set("012"), Set("X"), Set("uvwxy"), Set("78") };
        var rnd = new Random(5);
        foreach (int r in new[] { 0, 1, 2, 3, 6 })
        {
            var o = HashcatOrder.WithAmplifier(pos, r);
            var ranges = new List<(long, long)> { (0, o.BaseCount), (0, 0), (o.BaseCount - 1, o.BaseCount) };
            for (int i = 0; i < 60; i++)
            {
                long a = rnd.NextInt64(o.BaseCount + 1), b = rnd.NextInt64(o.BaseCount + 1);
                ranges.Add((Math.Min(a, b), Math.Max(a, b)));
            }
            foreach (var (lo, hi) in ranges)
            {
                var expected = new HashSet<string>();
                for (long w = lo; w < hi; w++)
                    for (long a = 0; a < o.AmplifierCount; a++) expected.Add(S(o.Candidate(a, w)));
                var got = new List<string>();
                foreach (var box in o.Boxes(lo, hi)) got.AddRange(Enumerate(box).Select(S));
                Assert.Equal(expected.Count, got.Count);              // no candidate twice
                Assert.True(expected.SetEquals(got), $"r={r} [{lo},{hi})");
            }
        }
    }

    [Fact]
    public void AdjacentRangesSplitTheLengthWithoutGapsOrOverlap()
    {
        var pos = new[] { Set("abc"), Set("0123456789"), Set("xy"), Set("klmnop") };
        var o = HashcatOrder.WithAmplifier(pos, 1);
        var cuts = new long[] { 0, 1, 7, 10, 59, 60, 61, 100, 119, 120 };
        var counts = new Dictionary<string, int>();
        for (int i = 0; i + 1 < cuts.Length; i++)
            foreach (var box in o.Boxes(cuts[i], cuts[i + 1]))
                foreach (var c in Enumerate(box)) counts[S(c)] = counts.GetValueOrDefault(S(c)) + 1;
        Assert.Equal(o.Candidates, counts.Count);
        Assert.All(counts.Values, v => Assert.Equal(1, v));
    }

    [Fact]
    public void KeyspaceFromHashcatSelectsTheAmplifier()
    {
        var pos = new[] { Set("abc"), Set("0123456789"), Set("xy"), Set("Q"), Set("klmnop") };
        Assert.Equal(1, HashcatOrder.FromKeyspace(pos, 10 * 2 * 6)!.AmplifierPositions);
        Assert.Equal(2, HashcatOrder.FromKeyspace(pos, 2 * 6)!.AmplifierPositions);
        Assert.Equal(0, HashcatOrder.FromKeyspace(pos, 3 * 10 * 2 * 6)!.AmplifierPositions);
        Assert.Null(HashcatOrder.FromKeyspace(pos, 7));
    }

    [Fact]
    public void MaskArgumentsDescribeTheSamePositions()
    {
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "?d?u", "-2", "zyx", "?1?l?2?2a?b?1"])!;
        var sorted = HashcatOrder.SortedPositions(space, 7);
        var args = HashcatOrder.MaskArgs(sorted)!;
        Assert.Contains("--hex-charset", args);
        var back = MaskSpace.FromHashcatArgs(args)!;
        Assert.Equal(7, back.MinLength);
        for (int i = 0; i < 7; i++) Assert.Equal(sorted[i], back.Positions[i].OrderBy(b => b).ToArray());
        // ?b has 256 bytes; nine different sets do not fit hashcat's -1..-8.
        var many = Enumerable.Range(0, 9).Select(i => Set("ab" + (char)('c' + i))).ToList();
        Assert.Null(HashcatOrder.MaskArgs(many));
    }

    [Fact]
    public void BatchStartsAlignToCoarseDigits()
    {
        var o = HashcatOrder.WithAmplifier([Set("ab"), Set("0123456789"), Set("0123456789"), Set("0123456789")], 1);
        Assert.Equal(700, o.AlignDown(745, 100, 0));
        Assert.Equal(740, o.AlignDown(745, 50, 0));
        Assert.Equal(745, o.AlignDown(745, 5, 0));
        Assert.Equal(720, o.AlignDown(745, 100, 720));
    }

    // ------------------------------------------------------------------ scheduler

    /// <summary>A kernel that records every candidate it tests and "finds" one password.</summary>
    private sealed class RecordingKernel(ConcurrentDictionary<string, int> seen, string? target, int failAfter = 0) : NativeKernel
    {
        public int Calls;
        private readonly ConcurrentDictionary<string, int> _seen = seen;
        private readonly string? _target = target;
        private readonly int _failAfter = failAfter;
        public override string Name => "recording";
        public override double SpeedHint => 20000;
        public override KernelWorker CreateWorker() => new Worker(this);
        public override bool Verify(ReadOnlySpan<byte> password) => _target is not null && Encoding.Latin1.GetString(password) == _target;

        private sealed class Worker(RecordingKernel k) : KernelWorker
        {
            public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
            {
                if (k._failAfter > 0 && Interlocked.Increment(ref k.Calls) > k._failAfter) throw new InvalidOperationException("simulated CPU failure");
                var buf = new byte[prefix.Length + 1];
                prefix.CopyTo(buf);
                int hit = -1;
                for (int i = 0; i < last.Length; i++)
                {
                    buf[^1] = last[i];
                    string c = Encoding.Latin1.GetString(buf);
                    k._seen.AddOrUpdate(c, 1, (_, v) => v + 1);
                    if (hit < 0 && c == k._target) hit = i;
                    Thread.SpinWait(200);
                }
                return hit;
            }
        }
    }

    /// <summary>
    /// hashcat simulated with the same numbering: amplifier size from a fixed rule, words processed
    /// in steps, a status per step, graceful stop at the current word, optional failure.
    /// </summary>
    private sealed class FakeGpu(ConcurrentDictionary<string, int> seen, string? target, long wordsPerStep) : IGpuRange
    {
        public List<(int Len, long Skip, long Count, RunOutcome Outcome, long Done)> Runs { get; } = new();
        public long FailAfterWords { get; init; }
        public Func<int, int> Amplifier { get; init; } = len => len < 3 ? 1 : 2;
        private long _words;

        public Task<long?> KeyspaceAsync(IReadOnlyList<string> maskArgs, CancellationToken ct)
        {
            var sp = MaskSpace.FromHashcatArgs(maskArgs)!;
            long b = 1;
            for (int i = Amplifier(sp.MaxLength); i < sp.MaxLength; i++) b *= sp.Positions[i].Length;
            return Task.FromResult<long?>(b);
        }

        public async Task<GpuRangeResult> RunAsync(HashcatOrder order, long skip, long count, IReadOnlyCollection<int> exclude,
            Action<HashcatStatus> onStatus, CancellationToken stop)
        {
            Assert.Equal(Amplifier(order.Length), order.AmplifierPositions);
            long w = skip, end = skip + count;
            await Task.Delay(5, CancellationToken.None);    // start-up
            while (w < end)
            {
                if (stop.IsCancellationRequested) return Done(RunOutcome.Aborted, w);
                if (FailAfterWords > 0 && Interlocked.Read(ref _words) >= FailAfterWords) return Done(RunOutcome.Error, w);
                long stepEnd = Math.Min(end, w + wordsPerStep);
                for (; w < stepEnd; w++)
                {
                    Interlocked.Increment(ref _words);
                    for (long a = 0; a < order.AmplifierCount; a++)
                    {
                        string c = Encoding.Latin1.GetString(order.Candidate(a, w));
                        seen.AddOrUpdate(c, 1, (_, v) => v + 1);
                        if (c == target)
                        {
                            lock (Runs) Runs.Add((order.Length, skip, count, RunOutcome.Cracked, w + 1));
                            return new GpuRangeResult { Outcome = RunOutcome.Cracked, DoneUpTo = w, Passwords = [c] };
                        }
                    }
                }
                onStatus(new HashcatStatus
                {
                    Status = 3, RestorePoint = w, ProgressDone = (w - skip) * order.AmplifierCount, ProgressTotal = count * order.AmplifierCount,
                    Devices = [new DeviceSpeed { Id = 1, Name = "Fake GPU", Type = "GPU", Speed = wordsPerStep * order.AmplifierCount / 0.002 }],
                });
                await Task.Delay(2, CancellationToken.None);
            }
            return Done(RunOutcome.Exhausted, end);

            GpuRangeResult Done(RunOutcome o, long upTo)
            {
                lock (Runs) Runs.Add((order.Length, skip, count, o, upTo));
                return new GpuRangeResult { Outcome = o, DoneUpTo = upTo, Error = o == RunOutcome.Error ? "simulated" : null };
            }
        }
    }

    private sealed class Rig : IDisposable
    {
        public readonly string Dir = Directory.CreateTempSubdirectory("rk-hybrid").FullName;
        public readonly ConcurrentDictionary<string, int> Seen = new();
        public void Dispose() { try { Directory.Delete(Dir, true); } catch (IOException) { } }

        public RunRequest Request(bool restore = false) => new()
        {
            Mode = 10700, HashFile = "unused", Attack = new PreparedAttack { Description = "test" },
            SessionName = "rk_test", SessionDir = Dir, Restore = restore,
            Settings = new Settings { DontUsePasswordCache = true, SessionsDir = Dir },
        };

        public static HybridRunner Runner(double gpuGuess, double cpuGuess = 50_000) => new()
        {
            HashcatStartupSeconds = 0.02, BatchSeconds = 0.03, Tick = TimeSpan.FromMilliseconds(20),
            InitialGpuSpeed = gpuGuess, InitialCpuSpeed = cpuGuess, ThreadsOverride = 3,
        };
    }

    private static readonly MaskSpace Space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "abcdefgh", "-i", "--increment-min", "2", "--increment-max", "5", "?1?d?1?1?d"])!;

    private static void AssertExactlyOnce(ConcurrentDictionary<string, int> seen, MaskSpace space)
    {
        Assert.Equal((long)space.TotalKeyspace, seen.Count);
        var twice = seen.Where(kv => kv.Value != 1).Select(kv => kv.Key).Take(5).ToList();
        Assert.True(twice.Count == 0, "tested more than once: " + string.Join(", ", twice));
    }

    [Theory]
    [InlineData(50_000.0, 20)]       // GPU guess about right
    [InlineData(1_000.0, 40)]        // GPU guessed far too slow: it finishes early and comes back for more
    [InlineData(50_000_000.0, 1)]    // GPU guessed far too fast: the CPU runs out, hashcat is stopped and the rest split again
    public async Task EveryCandidateIsTestedExactlyOnce(double gpuGuess, long wordsPerStep)
    {
        using var rig = new Rig();
        var kernel = new RecordingKernel(rig.Seen, null);
        var gpu = new FakeGpu(rig.Seen, null, wordsPerStep);
        var res = await Rig.Runner(gpuGuess).RunAsync(new HybridPlan(kernel, Space), "hash", rig.Request(), gpu, CancellationToken.None);
        Assert.Equal(RunOutcome.Exhausted, res.Outcome);
        AssertExactlyOnce(rig.Seen, Space);
        Assert.Contains(gpu.Runs, r => r.Outcome == RunOutcome.Exhausted);
        Assert.False(File.Exists(HybridRunner.RestoreFile(rig.Dir, "rk_test")));
    }

    [Fact]
    public async Task RebalancingStopsHashcatWhenTheCpuRunsOut()
    {
        using var rig = new Rig();
        var gpu = new FakeGpu(rig.Seen, null, 1);
        var runner = Rig.Runner(500_000_000);
        var res = await runner.RunAsync(new HybridPlan(new RecordingKernel(rig.Seen, null), Space), "hash", rig.Request(), gpu, CancellationToken.None);
        Assert.Equal(RunOutcome.Exhausted, res.Outcome);
        Assert.Contains(gpu.Runs, r => r.Outcome == RunOutcome.Aborted);   // stopped to rebalance, then restarted
        AssertExactlyOnce(rig.Seen, Space);
    }

    [Fact]
    public async Task PasswordFoundInEitherShareOrAtTheBoundary()
    {
        // One length, so the first split depends only on the initial estimates: find it with a dry run.
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "abcdefgh", "?1?d?1?1?d"])!;
        var order = HashcatOrder.WithAmplifier(HashcatOrder.SortedPositions(space, 5), 2);
        long first;
        {
            using var rig = new Rig();
            var gpu = new FakeGpu(rig.Seen, null, 20);
            await Rig.Runner(50_000).RunAsync(new HybridPlan(new RecordingKernel(rig.Seen, null), space), "hash", rig.Request(), gpu, CancellationToken.None);
            Assert.Equal(0, gpu.Runs[0].Skip);
            first = gpu.Runs[0].Count;
            AssertExactlyOnce(rig.Seen, space);
        }
        Assert.InRange(first, 2, order.BaseCount - 2);

        // Bottom: hashcat's share. Top: the CPU's. Both sides of the first boundary: either may get
        // there first after rebalancing, but the password must be found exactly once.
        foreach (var (word, gpuSide) in new (long, bool?)[] { (0L, true), (order.BaseCount - 1, false), (first - 1, null), (first, null) })
        {
            using var rig = new Rig();
            string target = S(order.Candidate(1, word));
            var kernel = new RecordingKernel(rig.Seen, target);
            var gpu = new FakeGpu(rig.Seen, target, 20);
            var res = await Rig.Runner(50_000).RunAsync(new HybridPlan(kernel, space), "hash", rig.Request(), gpu, CancellationToken.None);
            Assert.Equal(RunOutcome.Cracked, res.Outcome);
            Assert.Equal([target], res.Passwords);
            Assert.Equal(1, rig.Seen[target]);
            if (gpuSide is bool g) Assert.Equal(g, gpu.Runs.Any(r => r.Outcome == RunOutcome.Cracked));
        }
    }

    [Fact]
    public async Task StopAndResumeLosesNothing()
    {
        using var rig = new Rig();
        var plan = new HybridPlan(new RecordingKernel(rig.Seen, null), Space);
        int stops = 0;
        RunResult res;
        bool restore = false;
        do
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(30 + 10 * stops));
            res = await Rig.Runner(50_000).RunAsync(plan, "hash", rig.Request(restore), new FakeGpu(rig.Seen, null, 2), cts.Token);
            restore = true;
            if (res.Outcome == RunOutcome.Aborted) Assert.True(File.Exists(HybridRunner.RestoreFile(rig.Dir, "rk_test")));
        } while (res.Outcome == RunOutcome.Aborted && ++stops < 200);
        Assert.Equal(RunOutcome.Exhausted, res.Outcome);
        Assert.True(stops >= 2, "the attack should have been stopped at least twice");
        // Nothing skipped. The CPU engine redoes the work its threads had in hand at the stop (as it
        // always has on resume); the simulated hashcat stops exactly at its restore point.
        Assert.Equal((long)Space.TotalKeyspace, rig.Seen.Count);
        long repeats = rig.Seen.Values.Sum(v => v - 1L);
        Assert.True(repeats < (long)Space.TotalKeyspace / 4, $"{repeats} repeats");
    }

    [Fact]
    public async Task CpuTakesOverWhenHashcatFails()
    {
        using var rig = new Rig();
        var gpu = new FakeGpu(rig.Seen, null, 10) { FailAfterWords = 30 };
        var warnings = new List<string>();
        var runner = Rig.Runner(50_000);
        runner.Warning += warnings.Add;
        var res = await runner.RunAsync(new HybridPlan(new RecordingKernel(rig.Seen, null), Space), "hash", rig.Request(), gpu, CancellationToken.None);
        Assert.Equal(RunOutcome.Exhausted, res.Outcome);
        Assert.Contains(gpu.Runs, r => r.Outcome == RunOutcome.Error);
        Assert.Single(warnings, w => w.Contains("hashcat stopped with an error"));   // later lengths do not retry hashcat
        AssertExactlyOnce(rig.Seen, Space);
    }

    [Fact]
    public async Task HashcatTakesOverWhenTheCpuFails()
    {
        using var rig = new Rig();
        var kernel = new RecordingKernel(rig.Seen, null, failAfter: 300);
        var res = await Rig.Runner(50_000).RunAsync(new HybridPlan(kernel, Space), "hash", rig.Request(), new FakeGpu(rig.Seen, null, 20), CancellationToken.None);
        Assert.Equal(RunOutcome.Exhausted, res.Outcome);
        // The failed batch goes back to hashcat in full, so part of it may be tested twice; nothing is missed.
        Assert.Equal((long)Space.TotalKeyspace, rig.Seen.Count);
    }

    [Fact]
    public async Task CombinedStatusAddsTheCpuEngine()
    {
        using var rig = new Rig();
        var statuses = new ConcurrentQueue<HashcatStatus>();
        var runner = Rig.Runner(50_000);
        runner.StatusReceived += statuses.Enqueue;
        await runner.RunAsync(new HybridPlan(new RecordingKernel(rig.Seen, null), Space), "hash", rig.Request(), new FakeGpu(rig.Seen, null, 5), CancellationToken.None);
        Assert.NotEmpty(statuses);
        Assert.All(statuses, s => Assert.Contains(s.Devices, d => d.Name == "CPU (built-in engine)"));
        Assert.Contains(statuses, s => s.Devices.Any(d => d.Name == "Fake GPU") && s.Devices.Count == 2);
        foreach (var s in statuses) Assert.InRange(s.ProgressDone, 0, s.ProgressTotal);
        var last5 = statuses.Where(s => s.MaskLength == 5).ToList();
        Assert.Equal(last5[^1].ProgressTotal, last5[^1].ProgressDone);
    }

    [Fact]
    public void BuiltInEngineResumeSkipsNothing()
    {
        // Regression: a worker that left its chunk early on a stop cleared its in-flight mark, so the
        // resume point could pass the rest of that chunk.
        var seen = new ConcurrentDictionary<string, int>();
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "abcdefgh", "?1?1?d?1?d"])!;
        NativeResumePoint? at = null;
        for (int round = 0; round < 500; round++)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(15));
            var r = new NativeEngine(new RecordingKernel(seen, null), space) { Threads = 4, Priority = ThreadPriority.Normal }.Run(at, cts.Token);
            if (r.Outcome == NativeOutcome.Exhausted) break;
            at = r.ResumeAt;
        }
        Assert.Equal((long)space.TotalKeyspace, seen.Count);
    }

    // ------------------------------------------------------------------ planning

    [Fact]
    public void HybridOnlyWhereTheCpuEngineCanWorkNextToGpus()
    {
        var gpu = new BackendDevice { Id = 1, Type = "GPU", Name = "Test GPU", Key = "OpenCL|Test GPU|0" };
        var attack = new PreparedAttack { Description = "mask" };
        attack.Args.AddRange(["-a", "3", "?l?l?l?l"]);
        string hash = NativeKernels.BenchmarkHashes[17210];
        Assert.NotNull(HybridRunner.Plan(17210, hash, attack, new Settings(), [gpu]));
        Assert.NotNull(HybridRunner.Plan(17210, hash, attack, new Settings { Strategy = DeviceStrategy.GpuAndCpu }, [gpu]));
        Assert.Null(HybridRunner.Plan(17210, hash, attack, new Settings { HybridCpuGpu = false }, [gpu]));
        Assert.Null(HybridRunner.Plan(17210, hash, attack, new Settings { Strategy = DeviceStrategy.FastGpu }, [gpu]));
        Assert.Null(HybridRunner.Plan(17210, hash, attack, new Settings { UseNativeCpuEngine = false }, [gpu]));
        Assert.Null(HybridRunner.Plan(17210, hash, attack, new Settings(), [new BackendDevice { Id = 1, Type = "CPU" }]));
        // Every GPU unchecked: no hybrid, and the CPU-only built-in engine applies instead.
        var off = new Settings { DisabledDeviceKeys = [gpu.Key] };
        Assert.Null(HybridRunner.Plan(17210, hash, attack, off, [gpu]));
        Assert.NotNull(NativeRunner.Plan(17210, hash, attack, off, [gpu]));
        var dict = new PreparedAttack { Description = "dict" };
        dict.Args.AddRange(["-a", "0", "words.txt"]);
        Assert.Null(HybridRunner.Plan(17210, hash, dict, new Settings(), [gpu]));
    }

    [Fact]
    public void CpuThreadsLeaveOneThreadPerGpu()
    {
        var devs = new List<BackendDevice>
        {
            new() { Id = 1, Type = "GPU", Name = "dGPU" }, new() { Id = 2, Type = "GPU", Name = "iGPU", Unified = true },
            new() { Id = 3, Type = "CPU", Name = "CPU" },
        };
        int n = Environment.ProcessorCount;
        Assert.Equal(Math.Max(1, n - 2), HybridRunner.CpuThreads(new Settings(), devs, hashcatRunning: true));
        Assert.Equal(Math.Max(1, n - 1), HybridRunner.CpuThreads(new Settings(), devs, true, excluded: [2]));
        Assert.Equal(n, HybridRunner.CpuThreads(new Settings(), devs, hashcatRunning: false));
        Assert.Equal(n, HybridRunner.CpuThreads(new Settings { Strategy = DeviceStrategy.GpuAndCpu }, devs, true));
        Assert.Equal(1, HybridRunner.CpuThreads(new Settings { MaxCpuThreads = 2 }, devs, true));
        Assert.Equal(Math.Min(3, n), HybridRunner.CpuThreads(new Settings { MaxCpuThreads = 3 }, devs, false));
    }

    [Fact]
    public void RestorePointIsReadFromHashcatsRestoreFile()
    {
        var f = Path.GetTempFileName();
        try
        {
            var b = new byte[300];
            BitConverter.GetBytes(7u).CopyTo(b, 0);
            BitConverter.GetBytes(123456789L).CopyTo(b, 272);
            File.WriteAllBytes(f, b);
            Assert.Equal(123456789L, HybridRunner.ReadRestorePoint(f));
            File.WriteAllBytes(f, new byte[100]);
            Assert.Null(HybridRunner.ReadRestorePoint(f));
        }
        finally { File.Delete(f); }
        Assert.Null(HybridRunner.ReadRestorePoint(f));
    }

    [Fact]
    public void OrderedMarkovTableIsWritten()
    {
        var dir = Directory.CreateTempSubdirectory("rk-markov").FullName;
        try
        {
            var p = OrderedMarkov.Ensure(dir);
            Assert.True(new FileInfo(p).Length > 1000);
            Assert.Equal(p, OrderedMarkov.Ensure(dir));
        }
        finally { Directory.Delete(dir, true); }
    }
}
