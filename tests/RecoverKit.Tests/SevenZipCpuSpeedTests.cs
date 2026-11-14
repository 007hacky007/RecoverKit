using System.Diagnostics;
using System.Text;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

public sealed class SevenZipCpuSpeedTests(ITestOutputHelper output)
{
    [Fact]
    [Trait("Category", "Slow")]
    public void MeasureKdfImplementations()
    {
        foreach (int bytes in new[] { 4096, 65536, 262144 })
        for (int repeat = 0; repeat < 3; repeat++)
        {
            var buffer = new byte[bytes];
            SevenZipKernel.DeriveKey("password"u8, [], 19, scratch: buffer);
            var watch = Stopwatch.StartNew();
            for (int i = 0; i < 20; i++) SevenZipKernel.DeriveKey("password"u8, [], 19, scratch: buffer);
            output.WriteLine($"managed block={bytes}, repeat={repeat + 1}, ms={watch.Elapsed.TotalMilliseconds / 20:F3}, rate={20 / watch.Elapsed.TotalSeconds:F1}/s");
        }

    }

    [SevenZipFact]
    [Trait("Category", "Slow")]
    public void MeasureCpuRateAndFilterRejection()
    {
        string dir = SevenZipGeneratedTests.Scratch();
        try
        {
            string input = Path.Combine(dir, "media.bin");
            using (var file = File.Create(input))
            {
                var random = new Random(71600);
                var buffer = new byte[65536];
                for (int i = 0; i < 145; i++) { random.NextBytes(buffer); file.Write(buffer); }
            }
            string archive = Path.Combine(dir, "large.7z");
            SevenZipGeneratedTests.Create(dir, archive, "LZMA2", input);
            var target = RecoverKit.Core.Formats.FormatDetector.Detect(archive).Target!.SevenZipCpu!;
            Assert.True(target.PackedSize > 8 * 1024 * 1024);
            var kernel = new SevenZipKernel(target);
            Assert.True(kernel.Verify("kit7"u8));
            output.WriteLine($"Managed IncrementalHash SHA-256, processor threads {Environment.ProcessorCount}");
            var space = MaskSpace.FromHashcatArgs(["-a", "3", "w?d?d?d?d?d?d"])!;
            foreach (int threads in new[] { 1, Environment.ProcessorCount }.Distinct())
            for (int repeat = 0; repeat < 3; repeat++)
            {
                var measured = new MeasuredKernel(target);
                using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                var watch = Stopwatch.StartNew();
                var result = new NativeEngine(measured, space) { Threads = threads, Priority = ThreadPriority.Normal,
                    ProgressInterval = TimeSpan.FromMilliseconds(100) }.Run(null, stop.Token);
                Assert.Equal(NativeOutcome.Stopped, result.Outcome);
                output.WriteLine($"threads={threads}, repeat={repeat + 1}, tested={result.Tested}, seconds={watch.Elapsed.TotalSeconds:F3}, rate={result.Tested / watch.Elapsed.TotalSeconds:F1}/s, KDF={100.0 * measured.KdfTicks / measured.AllTicks:F2}%");
            }
            const int count = 16384;
            var keys = new byte[count][];
            Parallel.For(0, count, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                i => keys[i] = SevenZipKernel.DeriveKey(Encoding.ASCII.GetBytes($"wrong{i}"), [], 19));
            foreach (string fixture in new[] { "7zz-copy-off", "7zz-LZMA-off", "7zz-LZMA2-off", "7zz-Deflate-off" })
            {
                var t = SevenZipCpuTests.CpuTarget(fixture);
                var k = new SevenZipKernel(t);
                var counts = new int[5];
                foreach (byte[] key in keys) counts[(int)k.CheckKey(key)]++;
                Assert.Equal(0, counts[(int)SevenZipKernel.CheckResult.Match]);
                output.WriteLine($"{fixture}: n={count}, padding={t.PackedSize - t.AesOutputSize}, header={counts[0]}, padding={counts[1]}, trial={counts[2]}, CRC={counts[3]}");
            }
            foreach (string method in new[] { "LZMA", "LZMA2", "Deflate" })
            {
                RecoverKit.Core.Formats.SevenZipCpuTarget? unpadded = null;
                var random = new Random(711);
                for (int size = 4096; size < 4224 && unpadded is null; size++)
                {
                    var data = new byte[size]; random.NextBytes(data); File.WriteAllBytes(input, data);
                    string path = Path.Combine(dir, $"aligned-{method}-{size}.7z");
                    SevenZipGeneratedTests.Create(dir, path, method, input);
                    var candidate = SevenZipGeneratedTests.Extract(path);
                    if (candidate.PackedSize == candidate.AesOutputSize) unpadded = candidate;
                }
                Assert.NotNull(unpadded);
                var k = new SevenZipKernel(unpadded);
                Assert.True(k.Verify("kit7"u8));
                var counts = new int[5];
                foreach (byte[] key in keys) counts[(int)k.CheckKey(key)]++;
                Assert.Equal(0, counts[4]);
                output.WriteLine($"{method}, no padding: n={count}, header={counts[0]}, trial={counts[2]}, CRC={counts[3]}");
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    private sealed class MeasuredKernel(RecoverKit.Core.Formats.SevenZipCpuTarget target) : NativeKernel
    {
        private readonly SevenZipKernel kernel = new(target);
        internal long KdfTicks, AllTicks;
        public override string Name => kernel.Name;
        public override double SpeedHint => kernel.SpeedHint;
        public override bool Verify(ReadOnlySpan<byte> password) => kernel.Verify(password);
        public override KernelWorker CreateWorker() => new Worker(this, target);
        private sealed class Worker(MeasuredKernel owner, RecoverKit.Core.Formats.SevenZipCpuTarget target) : KernelWorker
        {
            private readonly byte[] kdfBuffer = new byte[65536];
            private readonly RecoverKit.Core.Formats.SevenZipLzma.Buffers trialBuffers = new();
            public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last)
            {
                Span<byte> password = stackalloc byte[prefix.Length + 1]; prefix.CopyTo(password);
                foreach (byte b in last)
                {
                    password[^1] = b;
                    long before = Stopwatch.GetTimestamp();
                    byte[] key = SevenZipKernel.DeriveKey(password, target.Salt, target.Power, scratch: kdfBuffer);
                    long derived = Stopwatch.GetTimestamp();
                    Assert.NotEqual(SevenZipKernel.CheckResult.Match, owner.kernel.CheckKey(key, trialBuffers: trialBuffers));
                    Interlocked.Add(ref owner.KdfTicks, derived - before);
                    Interlocked.Add(ref owner.AllTicks, Stopwatch.GetTimestamp() - before);
                }
                return -1;
            }
        }
    }
}
