using System.Collections.Concurrent;
using System.Diagnostics;
using RecoverKit.Core.Native;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public class NativeSchedulingTests(ITestOutputHelper output)
{
    // CPU only. Slow-format boxes use 69 trailing characters; Word 97 is the fast control.
    [Theory]
    [Trait("Category", "Slow")]
    [InlineData(12500, 113, 69)]
    [InlineData(13000, 224, 69)]
    [InlineData(10700, 1024, 69)]
    [InlineData(9700, 40_000_000, 1)]
    public void CpuBoxTailMeasurements(int mode, int prefixes, int lastCount)
    {
        Assert.True(RkNative.Available, "Build the native library before measuring.");
        var kernel = NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]);
        Assert.NotNull(kernel);
        byte[] chars = Enumerable.Range(32, 69).Select(i => (byte)i).ToArray();
        var space = new MaskSpace { Positions = [chars, chars, chars, chars.Take(lastCount).ToArray()], MinLength = 4, MaxLength = 4 };
        long totalPrefixes = 69L * 69 * 69;
        if (prefixes > totalPrefixes)
        {
            byte[] wide = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
            space = new MaskSpace { Positions = [wide, wide, wide, wide, chars.Take(lastCount).ToArray()], MinLength = 5, MaxLength = 5 };
            totalPrefixes = 256L * 256 * 256 * 256;
        }
        int threads = int.TryParse(Environment.GetEnvironmentVariable("RECOVERKIT_TAIL_THREADS"), out int requested)
            ? Math.Clamp(requested, 1, Environment.ProcessorCount) : Math.Min(8, Environment.ProcessorCount);
        NativeKernels.ResetCpuPath(mode);
        for (int repeat = 0; repeat < 4; repeat++)
        {
            var probe = new TimedKernel(kernel!);
            var watch = Stopwatch.StartNew();
            var result = new NativeEngine(probe, space) { Threads = threads, Priority = ThreadPriority.Normal }
                .Run(new NativeResumePoint { Length = space.MaxLength, PrefixIndex = totalPrefixes - prefixes }, CancellationToken.None);
            double seconds = watch.Elapsed.TotalSeconds;
            Assert.Equal(NativeOutcome.Exhausted, result.Outcome);
            Assert.Equal((long)prefixes * lastCount, result.Tested);
            long end = probe.Finished.Max(t => t.Last);
            double idle = probe.Finished.Sum(t => (double)(end - t.Last)) / Stopwatch.Frequency / threads;
            // Repeat zero warms the JIT and the kernel. Idle is mean worker tail time / box wall time.
            output.WriteLine($"mode={mode} repeat={repeat} threads={threads} prefixes={prefixes} batch={kernel!.PrefixBatch(lastCount)} seconds={seconds:F4} rate={result.Tested / seconds:F0}/s tail={idle:F4}s idle={100 * idle / seconds:F2}% path={NativeKernels.CpuPath(mode)}");
        }
        output.WriteLine(NativeKernels.CpuFeatures());
    }

    [Theory]
    [Trait("Category", "Slow")]
    [InlineData(12500, 8192)]
    [InlineData(13000, 16384)]
    [InlineData(10700, 65536)]
    [InlineData(9700, 40_000_000)]
    public void CpuFixedSuffixTailMeasurements(int mode, int prefixes) => CpuBoxTailMeasurements(mode, prefixes, 1);

    [Theory]
    [InlineData(1, 1, false)]
    [InlineData(3, 1, false)]
    [InlineData(3, 137, false)]
    [InlineData(4, 989, false)]
    [InlineData(1, 9991, false)]
    [InlineData(1, 10000, false)]
    [InlineData(4, 1, true)]
    [InlineData(4, 989, true)]
    public void StopDrainsClaimsAndResumeTestsEachCandidateOnce(int threads, int stopAt, bool fixedSuffix)
    {
        var seen = new ConcurrentDictionary<string, int>();
        var space = MaskSpace.FromHashcatArgs(["-a", "3", fixedSuffix ? "?d?d?dX" : "?d?d?d?d"])!;
        int lastCount = fixedSuffix ? 1 : 10;
        int total = fixedSuffix ? 1000 : 10_000;
        using var stop = new CancellationTokenSource();
        int count = 0;
        var kernel = new CoverageKernel(seen, () =>
        {
            if (Interlocked.Increment(ref count) == stopAt) stop.Cancel();
        });
        var engine = new NativeEngine(kernel, space) { Threads = threads, Priority = ThreadPriority.Normal };
        var first = engine.Run(null, stop.Token);
        Assert.Equal(NativeOutcome.Stopped, first.Outcome);
        Assert.Equal(seen.Count, first.Tested);
        Assert.Equal(seen.Count, first.ResumeAt!.PrefixIndex * lastCount);
        // Serialize the checkpoint exactly as a session does, then use a new engine.
        var restored = System.Text.Json.JsonSerializer.Deserialize<NativeResumePoint>(
            System.Text.Json.JsonSerializer.Serialize(first.ResumeAt));
        var next = new NativeEngine(kernel, space) { Threads = threads, Priority = ThreadPriority.Normal };
        next.Progress += p => Assert.Equal(first.Tested, p.ResumedFrom);
        var second = next.Run(restored, CancellationToken.None);
        Assert.Equal(NativeOutcome.Exhausted, second.Outcome);
        Assert.Equal(total, first.Tested + second.Tested);
        Assert.Equal(total, seen.Count);
        Assert.All(seen.Values, n => Assert.Equal(1, n));
    }

    [Fact]
    public async Task StopWaitsForAnEarlierClaimBeforeSavingTheCheckpoint()
    {
        var seen = new ConcurrentDictionary<string, int>();
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "?d?d?d?d"])!;
        using var stop = new CancellationTokenSource();
        using var releaseFirst = new ManualResetEventSlim();
        using var laterCanceled = new ManualResetEventSlim();
        int calls = 0;
        var kernel = new CoverageKernel(seen, () =>
        {
            int call = Interlocked.Increment(ref calls);
            if (call == 1)
            {
                if (!releaseFirst.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("Earlier claim was not released.");
            }
            if (call == 2) { stop.Cancel(); laterCanceled.Set(); }
        });
        var running = Task.Run(() => new NativeEngine(kernel, space) { Threads = 2 }.Run(null, stop.Token));
        try
        {
            Assert.True(laterCanceled.Wait(TimeSpan.FromSeconds(10)));
            Assert.False(running.IsCompleted);
        }
        finally { releaseFirst.Set(); }
        var first = await running.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(NativeOutcome.Stopped, first.Outcome);
        Assert.Equal(seen.Count, first.Tested);
        Assert.Equal(seen.Count, first.ResumeAt!.PrefixIndex * 10);
        var second = new NativeEngine(kernel, space) { Threads = 2 }.Run(first.ResumeAt, CancellationToken.None);
        Assert.Equal(NativeOutcome.Exhausted, second.Outcome);
        Assert.Equal(10_000, first.Tested + second.Tested);
        Assert.Equal(10_000, seen.Count);
        Assert.All(seen.Values, n => Assert.Equal(1, n));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(32)]
    public void IncrementalMasksMatchSerialEnumerationAcrossRepeatedStops(int threads)
    {
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "abc", "-i", "--increment-min", "1", "?1?1?1"])!;
        var serial = new ConcurrentDictionary<string, int>();
        var reference = new NativeEngine(new CoverageKernel(serial, () => { }), space) { Threads = 1 }.Run(null, CancellationToken.None);
        Assert.Equal(39, reference.Tested);
        var seen = new ConcurrentDictionary<string, int>();
        NativeResumePoint? resume = null;
        long tested = 0;
        int stops = 0;
        bool exhausted = false;
        for (int round = 0; round < 64; round++)
        {
            using var stop = new CancellationTokenSource();
            int nextStop = seen.Count + 2;
            int count = seen.Count;
            var kernel = new CoverageKernel(seen, () =>
            {
                if (Interlocked.Increment(ref count) == nextStop) stop.Cancel();
            });
            var result = new NativeEngine(kernel, space) { Threads = threads }.Run(resume, stop.Token);
            tested += result.Tested;
            if (result.Outcome == NativeOutcome.Exhausted) { exhausted = true; break; }
            Assert.Equal(NativeOutcome.Stopped, result.Outcome);
            stops++;
            resume = result.ResumeAt;
        }
        Assert.True(exhausted);
        Assert.True(stops >= 2);
        Assert.Equal(39, tested);
        Assert.Equal(serial.Keys.Order(), seen.Keys.Order());
        Assert.All(seen.Values, n => Assert.Equal(1, n));
    }

    [Theory]
    [InlineData(12500)]
    [InlineData(13000)]
    [InlineData(10700)]
    [InlineData(9700)]
    public void ScheduledKernelAgreesWithReferenceOnSmallWholeKeyspace(int mode)
    {
        var kernel = NativeKernels.TryCreate(mode, NativeKernels.BenchmarkHashes[mode]);
        if (kernel is null) return;
        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", "ABC", "-2", "123", "?1?2"])!;
        foreach (byte first in "ABC"u8)
            foreach (byte last in "123"u8) Assert.False(kernel.Verify([first, last]));
        var result = new NativeEngine(kernel, space) { Threads = 4 }.Run(null, CancellationToken.None);
        Assert.Equal(NativeOutcome.Exhausted, result.Outcome);
        Assert.Equal(9, result.Tested);
    }

    private sealed class CoverageKernel(ConcurrentDictionary<string, int> seen, Action onCandidate) : NativeKernel
    {
        public override string Name => "coverage";
        public override double SpeedHint => 200_000;
        public override int PrefixBatch(int lastCount) => 19;
        public override bool Verify(ReadOnlySpan<byte> password) => false;
        public override KernelWorker CreateWorker() => new Worker(seen, onCandidate);

        private sealed class Worker(ConcurrentDictionary<string, int> seen, Action onCandidate) : KernelWorker
        {
            public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
            {
                foreach (byte c in last)
                {
                    seen.AddOrUpdate(Convert.ToHexString([.. prefix, c]), 1, (_, n) => n + 1);
                    onCandidate();
                }
                return -1;
            }
        }
    }

    private sealed class TimedKernel(NativeKernel kernel) : NativeKernel
    {
        public sealed class Timing { public long Last = Stopwatch.GetTimestamp(); }
        public ConcurrentBag<Timing> Finished { get; } = [];
        public override string Name => kernel.Name;
        public override double SpeedHint => kernel.SpeedHint;
        public override int PrefixBatch(int lastCount) => kernel.PrefixBatch(lastCount);
        public override bool Verify(ReadOnlySpan<byte> password) => kernel.Verify(password);
        public override KernelWorker CreateWorker()
        {
            var timing = new Timing();
            Finished.Add(timing);
            return new Worker(timing, kernel.CreateWorker());
        }

        private sealed class Worker(Timing timing, KernelWorker worker) : KernelWorker
        {
            public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last) => SearchBatch(prefix, 1, last);
            public override int SearchBatch(ReadOnlySpan<byte> prefixes, int count, ReadOnlySpan<byte> last)
            {
                // Replace this thread's timestamp without contending with the other workers.
                int hit = worker.SearchBatch(prefixes, count, last);
                timing.Last = Stopwatch.GetTimestamp();
                return hit;
            }
        }
    }
}
