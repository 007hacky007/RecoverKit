using System.Diagnostics;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

public sealed class SevenZipGeneratedTests
{
    [SevenZipTheory]
    [InlineData("-mx=5")]
    [InlineData("-mx=9")]
    [InlineData("-md=64k")]
    [InlineData("-m0=LZMA2:lc=0:lp=4:pb=4")]
    [InlineData("-mmt=4 -md=64k -mx=1")]
    public void Lzma2KeepsStateAcrossUncompressedChunks(string options)
    {
        string dir = Scratch();
        try
        {
            byte[] data = MixedData(1 << 20, 1 << 20);
            string input = Path.Combine(dir, "input.bin"); File.WriteAllBytes(input, data);
            string archive = Path.Combine(dir, "mixed.7z");
            CreateWithOptions(dir, archive, ["-m0=LZMA2", "-mmt=1", .. options.Split(' ')], input);
            var target = Extract(archive);
            Assert.True(new SevenZipKernel(target).Verify("kit7"u8), options);
            Assert.False(new SevenZipKernel(target).Verify("wrong"u8));
        }
        finally { Directory.Delete(dir, true); }
    }

    [SevenZipTheory]
    [InlineData("Copy")]
    [InlineData("LZMA")]
    [InlineData("LZMA2")]
    public void TinyFileChecksMatchHashcatCrcLayout(string method)
    {
        string dir = Scratch();
        try
        {
            byte[] largeData = new byte[65536]; new Random(1168).NextBytes(largeData);
            string first = Path.Combine(dir, "00.bin"), large = Path.Combine(dir, "01.bin");
            File.WriteAllBytes(large, largeData);
            byte[] key = SevenZipKernel.DeriveKey("kit7"u8, [], 19);
            foreach (int firstSize in new[] { 1, 2, 7, 8, 9 })
            {
                byte[] tiny = Enumerable.Range(1, firstSize).Select(i => (byte)i).ToArray();
                File.WriteAllBytes(first, tiny);
                string path = Path.Combine(dir, $"{method}-{firstSize}.7z");
                Create(dir, path, method, first, large);
                HashTarget target;
                try { SevenZipExtractor.TestDataLimit = 128; target = FormatDetector.Detect(path).Target!; }
                finally { SevenZipExtractor.TestDataLimit = 0; }
                if (firstSize < 8)
                {
                    Assert.Empty(target.Modes);
                    // 7zz writes Copy files in separate blocks even with solid mode requested.
                    Assert.Equal(method == "Copy" ? firstSize : firstSize + largeData.Length, target.SevenZipCpu!.CrcLength);
                    Assert.True(new SevenZipKernel(target.SevenZipCpu).Verify("kit7"u8));
                    continue;
                }
                Assert.Equal([11600], target.Modes);
                Assert.True(target.ConfirmPassword!("kit7"u8.ToArray()));
                Assert.False(target.ConfirmPassword("wrong"u8.ToArray()));
                var fields = target.HashLines.Split('$');
                int crcLength = int.Parse(fields[method == "Copy" ? 10 : 12]);
                Assert.Equal(firstSize, crcLength);
                // The hashcat LZMA hook requests exactly crc_len output bytes from this decrypted prefix.
                using var aes = System.Security.Cryptography.Aes.Create(); aes.Key = key;
                byte[] decrypted = aes.DecryptCbc(Convert.FromHexString(fields[11]), Convert.FromHexString(fields[7]),
                    System.Security.Cryptography.PaddingMode.None);
                byte[] decoded;
                if (method == "Copy") decoded = decrypted[..crcLength];
                else
                {
                    using var decoder = SevenZipLzma.Open(new MemoryStream(decrypted), Convert.FromHexString(fields[13]),
                        firstSize + largeData.Length, method == "LZMA2");
                    decoded = new byte[crcLength]; decoder.ReadExactly(decoded);
                }
                Assert.Equal(tiny, decoded);
                Assert.Equal(uint.Parse(fields[8]), ZipCryptoSample.Crc32(decoded));
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    [SevenZipFact]
    [Trait("Category", "Slow")]
    public void DefaultSettingsOversizedMixedLzma2ArchiveVerifies()
    {
        string dir = Scratch();
        try
        {
            string input = Path.Combine(dir, "disk.img"); File.WriteAllBytes(input, MixedData(4 << 20, 6 << 20));
            string archive = Path.Combine(dir, "big.7z");
            CreateWithOptions(dir, archive, [], input);
            var detection = FormatDetector.Detect(archive);
            var target = Assert.IsType<SevenZipCpuTarget>(detection.Target?.SevenZipCpu);
            Assert.True(target.PackedSize > 8 * 1024 * 1024);
            Assert.True(new SevenZipKernel(target).Verify("kit7"u8));
            Assert.False(new SevenZipKernel(target).Verify("wrong"u8));
        }
        finally { Directory.Delete(dir, true); }
    }

    internal static byte[] MixedData(int textSize, int randomSize)
    {
        var random = new Random(3);
        var data = new byte[2 * textSize + randomSize];
        random.NextBytes(data.AsSpan(textSize, randomSize));
        foreach (int start in new[] { 0, textSize + randomSize })
            for (int i = 0; i < textSize; i++)
                data[start + i] = (byte)"abcdefgh \n"[random.Next(10) < 7 ? i / 7 % 10 : random.Next(10)];
        return data;
    }

    [SevenZipFact]
    public void WorkerReusesHistoryForLargeDictionaryChecks()
    {
        string dir = Scratch();
        try
        {
            var data = new byte[2 * 1024 * 1024]; new Random(716).NextBytes(data);
            string input = Path.Combine(dir, "input.bin"); File.WriteAllBytes(input, data);
            string archive = Path.Combine(dir, "history.7z"); Create(dir, archive, "LZMA2", input);
            // A larger advertised dictionary is valid for this stream, without a large encoder allocation.
            var target = Extract(archive) with { Properties = [34] };
            var kernel = new SevenZipKernel(target);
            var worker = kernel.CreateWorker();
            Assert.Equal(0, worker.Search("kit"u8, "7"u8));
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 3; i++) Assert.Equal(0, worker.Search("kit"u8, "7"u8));
            Assert.True(GC.GetAllocatedBytesForCurrentThread() - before < 1024 * 1024,
                "The worker must reuse the full-check history across candidates.");
            // Different workers share only the gated full-check history, never trial state.
            Parallel.For(0, 12, new ParallelOptions { MaxDegreeOfParallelism = 4 }, _ =>
                Assert.Equal(0, kernel.CreateWorker().Search("kit"u8, "7"u8)));
            using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
            Assert.False(new SevenZipKernel(target, cancelled.Token).Verify("kit7"u8));
            Assert.Equal(0, worker.Search("kit"u8, "7"u8));
        }
        finally { Directory.Delete(dir, true); }
    }

    [SevenZipFact]
    public void TinyFirstFileInSolidDeflateUsesTheCombinedStreamCrc()
    {
        string dir = Scratch();
        try
        {
            string tiny = Path.Combine(dir, "00.bin"), large = Path.Combine(dir, "01.bin");
            File.WriteAllBytes(tiny, [42]);
            var data = new byte[100000]; new Random(717).NextBytes(data); File.WriteAllBytes(large, data);
            string archive = Path.Combine(dir, "solid.7z"); Create(dir, archive, "Deflate", tiny, large);
            var target = Extract(archive);
            Assert.Equal(100001, target.OutputSize);
            Assert.Equal(target.OutputSize, target.CrcLength);
            Assert.True(new SevenZipKernel(target).Verify("kit7"u8));
            Assert.False(new SevenZipKernel(target).Verify("wrong"u8));
        }
        finally { Directory.Delete(dir, true); }
    }

    [SevenZipFact]
    public void FiltersNeverRejectValidGeneratedStreams()
    {
        string dir = Scratch();
        try
        {
            var random = new Random(719);
            byte[] key = SevenZipKernel.DeriveKey("kit7"u8, [], 19);
            foreach (string method in new[] { "Copy", "LZMA", "LZMA2", "Deflate" })
            foreach (int size in new[] { 8, 9, 15, 16, 17, 255, 4095, 4096, 4097, 65535, 65536, 65537, 140000 })
            {
                var data = new byte[size]; random.NextBytes(data);
                if (size % 2 == 1)
                    for (int i = 40; i < data.Length; i++) data[i] = data[i % 40];
                string input = Path.Combine(dir, "input.bin"); File.WriteAllBytes(input, data);
                string archive = Path.Combine(dir, $"{method}-{size}.7z");
                Create(dir, archive, method, input);
                SevenZipCpuTarget target = Extract(archive);
                Assert.True(new SevenZipKernel(target).CheckKey(key) == SevenZipKernel.CheckResult.Match,
                    $"Right key rejected for {method}, size {size}, AES padding {target.PackedSize - target.AesOutputSize}.");
                // Prefixes cut inside literal or match symbols must remain inconclusive or valid.
                for (int length = 1; length < 40 && length <= size; length++)
                    Assert.Equal(SevenZipKernel.CheckResult.Match, new SevenZipKernel(target with
                    { CrcLength = length, Crc = ZipCryptoSample.Crc32(data.AsSpan(0, length)) }).CheckKey(key));
                Assert.False(new SevenZipKernel(target).Verify("wrong"u8));
            }
        }
        finally { Directory.Delete(dir, true); }
    }

    [SevenZipFact]
    public void Lzma2StreamsAcrossChunksDictionaryWrapAndResets()
    {
        string dir = Scratch();
        try
        {
            var data = new byte[6 * 1024 * 1024 + 19];
            new Random(718).NextBytes(data);
            for (int i = 1024 * 1024; i < 3 * 1024 * 1024; i++) data[i] = (byte)(i % 31);
            string input = Path.Combine(dir, "input.bin"); File.WriteAllBytes(input, data);
            string archive = Path.Combine(dir, "chunks.7z"); Create(dir, archive, "LZMA2", input);
            var target = Extract(archive);
            byte[] key = SevenZipKernel.DeriveKey("kit7"u8, [], 19);
            long before = GC.GetAllocatedBytesForCurrentThread();
            Assert.Equal(SevenZipKernel.CheckResult.Match, new SevenZipKernel(target).CheckKey(key));
            Assert.True(GC.GetAllocatedBytesForCurrentThread() - before < 2 * 1024 * 1024);
            // Corruption beyond the trial and all first-block checks cannot be reported as a hit.
            using (var file = File.Open(archive, FileMode.Open, FileAccess.ReadWrite))
            {
                file.Position = target.DataOffset + target.PackedSize / 2;
                int b = file.ReadByte(); file.Position--; file.WriteByte((byte)(b ^ 0x80));
            }
            Assert.NotEqual(SevenZipKernel.CheckResult.Match, new SevenZipKernel(target).CheckKey(key));
        }
        finally { Directory.Delete(dir, true); }
    }

    [SevenZipFact]
    public void RealOversizedCopyArchiveAndSplitVolumesVerify()
    {
        string dir = Scratch();
        try
        {
            string input = Path.Combine(dir, "input.bin");
            using (var file = File.Create(input))
            {
                var buffer = new byte[65536]; new Random(7191).NextBytes(buffer);
                for (int i = 0; i < 130; i++) file.Write(buffer);
                file.WriteByte(19);
            }
            string archive = Path.Combine(dir, "large.7z"); Create(dir, archive, "Copy", input);
            var detection = FormatDetector.Detect(archive);
            var target = Assert.IsType<SevenZipCpuTarget>(detection.Target?.SevenZipCpu);
            long before = GC.GetAllocatedBytesForCurrentThread();
            Assert.True(new SevenZipKernel(target).Verify("kit7"u8));
            Assert.True(GC.GetAllocatedBytesForCurrentThread() - before < 1024 * 1024);
            using (var file = File.OpenRead(archive))
            {
                var buffer = new byte[700001];
                for (int part = 1, n; (n = file.Read(buffer)) > 0; part++)
                    File.WriteAllBytes(Path.Combine(dir, $"split.7z.{part:000}"), buffer.AsSpan(0, n).ToArray());
            }
            var split = FormatDetector.Detect(Path.Combine(dir, "split.7z.002"));
            Assert.True(new SevenZipKernel(Assert.IsType<SevenZipCpuTarget>(split.Target?.SevenZipCpu)).Verify("kit7"u8));
            Assert.False(new SevenZipKernel(target).Verify("wrong"u8));
        }
        finally { Directory.Delete(dir, true); }
    }

    internal static SevenZipCpuTarget Extract(string archive)
    {
        try
        {
            SevenZipExtractor.TestDataLimit = 1;
            var d = FormatDetector.Detect(archive);
            Assert.Null(d.Message);
            return Assert.IsType<SevenZipCpuTarget>(d.Target?.SevenZipCpu);
        }
        finally { SevenZipExtractor.TestDataLimit = 0; }
    }

    internal static string Scratch()
    {
        string dir = Path.Combine(Environment.GetEnvironmentVariable("RECOVERKIT_HOME") ?? Path.GetTempPath(), "7z-generated-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir); return dir;
    }

    internal static void Create(string dir, string archive, string method, params string[] inputs)
    {
        CreateWithOptions(dir, archive, ["-mmt=1", "-m0=" + method,
            .. method is "LZMA" or "LZMA2" ? new[] { "-md=64k" } : Array.Empty<string>()], inputs);
    }

    internal static void CreateWithOptions(string dir, string archive, string[] options, params string[] inputs)
    {
        var start = new ProcessStartInfo("7zz") { WorkingDirectory = dir, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (string arg in new[] { "a", "-t7z", "-pkit7", "-mhe=off", "-y", archive }.Concat(options)) start.ArgumentList.Add(arg);
        foreach (string input in inputs) start.ArgumentList.Add(input);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        Assert.True(process.WaitForExit(30000), "7zz did not finish within 30 seconds.");
        Assert.True(process.ExitCode == 0, output.GetAwaiter().GetResult() + error.GetAwaiter().GetResult());
    }
}

public sealed class SevenZipFactAttribute : FactAttribute
{
    public SevenZipFactAttribute()
    {
        string name = OperatingSystem.IsWindows() ? "7zz.exe" : "7zz";
        if (!(Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator).Any(p => File.Exists(Path.Combine(p, name))))
            Skip = "7zz is not available on PATH; generated 7z fixtures require the installed 7-Zip command line tool.";
    }
}

public sealed class SevenZipTheoryAttribute : TheoryAttribute
{
    public SevenZipTheoryAttribute() => Skip = new SevenZipFactAttribute().Skip;
}
