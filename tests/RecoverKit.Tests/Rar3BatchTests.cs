using System.Text;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public class Rar3BatchTests
{
    private const string Hash = "$RAR3$*0*3a94df521d0214a7*16445717853d420c627bc11af1e2b1b1";
    private const string PrefixCharacters = "ACDEFGHIJKLMNOPQRSTUVWXYZacdefghijklmnopqrstuvwxyz023456789";

    [Fact]
    public void NativeBatchesFillTheLaneGroupForEveryLastCharsetSize()
    {
        if (!Rar3Kernel.NativeFast) return;
        var kernel = Rar3Kernel.TryParse(Hash)!;
        int lanes = RkNative.Rar3Lanes();
        for (int last = 1; last <= 256; last++)
        {
            int batch = kernel.PrefixBatch(last);
            int candidates = batch * last;
            int capacity = (candidates + lanes - 1) / lanes * lanes;
            Assert.InRange(batch, 1, lanes);
            Assert.True(candidates >= 0.98 * capacity, $"last={last}, batch={batch}, fill={candidates}/{capacity}");
        }
    }

    [Fact]
    public void ManagedBatchingStaysAtOnePrefix()
    {
        bool saved = RkNative.Disabled;
        try
        {
            RkNative.Disabled = true;
            var kernel = Rar3Kernel.TryParse(Hash)!;
            foreach (int last in new[] { 1, 3, 10, 26, 95, 256 })
                Assert.Equal(1, kernel.PrefixBatch(last));
        }
        finally { RkNative.Disabled = saved; }
    }

    [Fact]
    public void NativeLaneCountFollowsTheSelectedPath()
    {
        if (!RkNative.Available) return;
        try
        {
            foreach (var path in new[] { RkNative.Feature.Avx2, RkNative.Feature.Neon, (RkNative.Feature)0 })
            {
                RkNative.LimitFeatures(path);
                Assert.Equal(RkNative.HasVectorPath ? 16 : 1, RkNative.Rar3Lanes());
            }
        }
        finally { RkNative.LimitFeatures((RkNative.Feature)~0); }
    }

    [Theory]
    [Trait("Category", "Slow")]
    [InlineData("1")]
    [InlineData("12x")]
    public void FindsEveryBatchPositionAndTheLastPartialPrefixWithAndWithoutNative(string last)
    {
        var kernel = Rar3Kernel.TryParse(Hash)!;
        int batch = kernel.PrefixBatch(last.Length);
        // One full native batch followed by three prefixes; the known password is "ab1".
        string others = PrefixCharacters[..(batch + 2)];
        bool saved = RkNative.Disabled;
        try
        {
            foreach (bool disabled in new[] { false, true })
            {
                RkNative.Disabled = saved || disabled;
                for (int prefixIndex = 0; prefixIndex <= others.Length; prefixIndex++)
                    for (int lastIndex = 0; lastIndex < last.Length; lastIndex++)
                    {
                        string prefixes = others.Insert(prefixIndex, "b");
                        string suffixes = last.Replace("1", "").Insert(lastIndex, "1");
                        string mask = last.Length == 1 ? "a?11" : "a?1?2";
                        var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", prefixes, "-2", suffixes, mask])!;
                        var result = new NativeEngine(kernel, space) { Threads = 1 }.Run(null, CancellationToken.None);
                        Assert.Equal(NativeOutcome.Found, result.Outcome);
                        Assert.Equal("ab1", Encoding.ASCII.GetString(result.Password!));
                    }
            }
        }
        finally { RkNative.Disabled = saved; }
    }

    [Theory]
    [Trait("Category", "Slow")]
    [InlineData("2")]
    [InlineData("23x")]
    public void ExhaustionVisitsEveryCandidateExactlyOnceWithAndWithoutNative(string last)
    {
        var kernel = Rar3Kernel.TryParse(Hash)!;
        int batch = kernel.PrefixBatch(last.Length);
        string prefixes = PrefixCharacters[..(batch + 3)];
        bool saved = RkNative.Disabled;
        try
        {
            foreach (bool disabled in new[] { false, true })
            {
                RkNative.Disabled = saved || disabled;
                var recording = new RecordingKernel(kernel);
                string mask = last.Length == 1 ? "a?12" : "a?1?2";
                var space = MaskSpace.FromHashcatArgs(["-a", "3", "-1", prefixes, "-2", last, mask])!;
                var result = new NativeEngine(recording, space) { Threads = 1 }.Run(null, CancellationToken.None);
                var expected = prefixes.SelectMany(p => last.Select(c => $"a{p}{c}")).ToArray();
                Assert.Equal(NativeOutcome.Exhausted, result.Outcome);
                Assert.Equal(expected.Length, result.Tested);
                Assert.Equal(expected, recording.Candidates);
            }
        }
        finally { RkNative.Disabled = saved; }
    }

    private sealed class RecordingKernel(NativeKernel kernel) : NativeKernel
    {
        public List<string> Candidates { get; } = [];
        public override string Name => kernel.Name;
        public override double SpeedHint => kernel.SpeedHint;
        public override int PrefixBatch(int lastCount) => kernel.PrefixBatch(lastCount);
        public override bool Verify(ReadOnlySpan<byte> password) => kernel.Verify(password);
        public override KernelWorker CreateWorker() => new Worker(this, kernel.CreateWorker());

        private sealed class Worker(RecordingKernel owner, KernelWorker worker) : KernelWorker
        {
            public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last) => SearchBatch(prefix, 1, last);

            public override int SearchBatch(ReadOnlySpan<byte> prefixes, int count, ReadOnlySpan<byte> last)
            {
                int length = prefixes.Length / count;
                for (int k = 0; k < count; k++)
                    foreach (byte c in last)
                        owner.Candidates.Add(Encoding.ASCII.GetString(prefixes.Slice(k * length, length)) + (char)c);
                return worker.SearchBatch(prefixes, count, last);
            }
        }
    }
}
