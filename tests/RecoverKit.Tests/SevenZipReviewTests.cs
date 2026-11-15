using System.Buffers.Binary;
using System.Security.Cryptography;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

public sealed class SevenZipReviewTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    public void SolidPrefixNeverUsesFewerThanEightBytes(int firstSize)
    {
        WithArchive([[], new byte[firstSize], new byte[256]], path =>
        {
            foreach (ulong limit in new ulong[] { 128, 1024 })
            {
                HashTarget target = Detect(path, limit).Target!;
                if (target.Modes.Contains(11600))
                {
                    var fields = target.HashLines.Split('$');
                    Assert.True(int.Parse(fields[10]) >= 8);
                    Assert.NotNull(target.ConfirmPassword);
                    Assert.True(target.ConfirmPassword("kit7"u8.ToArray()));
                    Assert.False(target.ConfirmPassword("wrong"u8.ToArray()));
                }
                else
                {
                    Assert.True(target.SevenZipCpu!.CrcLength >= 8);
                    Assert.True(new SevenZipKernel(target.SevenZipCpu).Verify("kit7"u8));
                }
            }
        });
    }

    [Fact]
    public void SolidPrefixCombinesEmptyAndTinyFilesBeforeHashcatCheck()
    {
        byte[][] files = [[], [1], [2, 3], [4, 5, 6, 7, 8], new byte[256]];
        WithArchive(files, path =>
        {
            var target = Detect(path, 128).Target!;
            Assert.Equal([11600], target.Modes);
            var fields = target.HashLines.Split('$');
            Assert.Equal("8", fields[10]);
            Assert.Equal(ZipCryptoSample.Crc32([1, 2, 3, 4, 5, 6, 7, 8]).ToString(), fields[8]);
            Assert.True(target.ConfirmPassword!("kit7"u8.ToArray()));
            // Emulate module 11600's Copy hook: CRC of the first unpack_size bytes, no padding check.
            byte[] ciphertext = Convert.FromHexString(fields[11]);
            byte[] iv = Convert.FromHexString(fields[7]);
            uint expected = uint.Parse(fields[8]);
            int length = int.Parse(fields[10]);
            var random = new Random(11600);
            using var aes = Aes.Create();
            var key = new byte[32];
            for (int i = 0; i < 100000; i++)
            {
                random.NextBytes(key); aes.Key = key;
                byte[] plain = aes.DecryptCbc(ciphertext, iv, PaddingMode.None);
                Assert.NotEqual(expected, ZipCryptoSample.Crc32(plain.AsSpan(0, length)));
            }
        });
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(7)]
    public void SingleTinyCopyFileUsesCpuPaddingAndCrc(int length)
    {
        WithArchive([Enumerable.Range(1, length).Select(i => (byte)i).ToArray()], path =>
        {
            var detection = Detect(path, 1024);
            var target = Assert.IsType<HashTarget>(detection.Target);
            Assert.Empty(target.Modes);
            var cpu = Assert.IsType<SevenZipCpuTarget>(target.SevenZipCpu);
            Assert.True(new SevenZipKernel(cpu).Verify("kit7"u8));
            Assert.False(new SevenZipKernel(cpu).Verify("wrong"u8));
            // Keep the CRC intact while damaging only zero padding.
            byte[] archive = File.ReadAllBytes(path);
            byte[] key = SevenZipKernel.DeriveKey("kit7"u8, [], 8);
            using var aes = Aes.Create(); aes.Key = key;
            byte[] plain = aes.DecryptCbc(archive.AsSpan(32, 16), cpu.Iv, PaddingMode.None);
            plain[^1] = 1;
            aes.EncryptCbc(plain, cpu.Iv, PaddingMode.None).CopyTo(archive, 32);
            File.WriteAllBytes(path, archive);
            Assert.False(new SevenZipKernel(cpu).Verify("kit7"u8));
        });
    }

    [Fact]
    public void FullWorkerHitDoesNotRepeatIndependentVerification()
    {
        using var staleStop = new CancellationTokenSource(); staleStop.Cancel();
        var kernel = new SevenZipKernel(SevenZipCpuTests.CpuTarget("7zz-copy-off"), staleStop.Token);
        // NativeEngine supplies a fresh worker token. Rechecking with the stale token would lose this full hit.
        Assert.False(kernel.Verify("kit7"u8));
        var result = new NativeEngine(kernel, MaskSpace.FromHashcatArgs(["-a", "3", "kit?d"])!)
        { Threads = 1 }.Run(null, default);
        Assert.Equal(NativeOutcome.Found, result.Outcome);
        Assert.Equal("kit7"u8.ToArray(), result.Password);
    }

    [Fact]
    public void FullWorkerHitStillRunsAdditionalConfirmationAndContinuesOnRejection()
    {
        var kernel = new SevenZipKernel(SevenZipCpuTests.CpuTarget("7zz-copy-off"));
        int confirmed = 0;
        var result = new NativeEngine(kernel, MaskSpace.FromHashcatArgs(["-a", "3", "kit?d"])!)
        { Threads = 1, Confirm = _ => { confirmed++; return false; } }.Run(null, default);
        Assert.Equal(NativeOutcome.Exhausted, result.Outcome);
        Assert.Equal(1, confirmed);
    }

    [Fact]
    public void SpeedHintAccountsForUnpaddedCopyLength()
    {
        var target = SevenZipCpuTests.CpuTarget("7zz-copy-off") with
        { PackedSize = 14 << 20, AesOutputSize = 14 << 20, CrcLength = 14 << 20 };
        double large = new SevenZipKernel(target).SpeedHint;
        Assert.True(large < new SevenZipKernel(target with { CrcLength = 1 << 20 }).SpeedHint);
        Assert.True(large < new SevenZipKernel(target with { AesOutputSize = target.PackedSize - 1 }).SpeedHint);
    }

    [Fact]
    public void StreamingCrcMatchesIeeeKnownAnswerAndBytewiseReference()
    {
        Assert.Equal(0xcbf43926u, ~SevenZipKernel.UpdateCrc(uint.MaxValue, "123456789"u8));
        Assert.Equal(0xcbf43926u, ~SevenZipKernel.UpdateCrcSoftware(uint.MaxValue, "123456789"u8));
        var data = new byte[65553]; new Random(116).NextBytes(data);
        foreach (int offset in new[] { 0, 1, 7 })
        foreach (int length in new[] { 0, 1, 7, 8, 9, 15, 16, 17, 4095, 65536 })
        {
            var bytes = data.AsSpan(offset, length);
            uint expected = ZipCryptoSample.Crc32(bytes);
            Assert.Equal(expected, ~SevenZipKernel.UpdateCrc(uint.MaxValue, bytes));
            Assert.Equal(expected, ~SevenZipKernel.UpdateCrcSoftware(uint.MaxValue, bytes));
            uint crc = uint.MaxValue, software = uint.MaxValue;
            for (int i = 0; i < length; i += 13)
            {
                var chunk = bytes.Slice(i, Math.Min(13, length - i));
                crc = SevenZipKernel.UpdateCrc(crc, chunk);
                software = SevenZipKernel.UpdateCrcSoftware(software, chunk);
            }
            Assert.Equal(expected, ~crc);
            Assert.Equal(expected, ~software);
        }
    }

    [Fact]
    public void OnlyTheSameSevenZipKernelCanTrustAFullWorkerHit()
    {
        var target = SevenZipCpuTests.CpuTarget("7zz-copy-off");
        var kernel = new SevenZipKernel(target);
        var worker = Assert.IsType<SevenZipKernel.Worker>(kernel.CreateWorker());
        Assert.Equal(0, worker.Search("kit"u8, "7"u8));
        Assert.True(worker.VerifiedBy(kernel));
        Assert.False(worker.VerifiedBy(new SevenZipKernel(target)));
    }

    private static Detection Detect(string path, ulong limit)
    {
        try { SevenZipExtractor.TestDataLimit = limit; return FormatDetector.Detect(path); }
        finally { SevenZipExtractor.TestDataLimit = 0; }
    }

    private static void WithArchive(byte[][] files, Action<string> check)
    {
        string dir = SevenZipGeneratedTests.Scratch();
        try
        {
            string path = Path.Combine(dir, "solid.7z");
            File.WriteAllBytes(path, CopyArchive(files));
            check(path);
        }
        finally { Directory.Delete(dir, true); }
    }

    // A real encrypted Copy stream with explicit substream sizes, including zero-length substreams.
    private static byte[] CopyArchive(byte[][] files)
    {
        byte[] data = files.SelectMany(f => f).ToArray();
        var padded = new byte[(data.Length + 15) / 16 * 16]; data.CopyTo(padded, 0);
        using var aes = Aes.Create(); aes.Key = SevenZipKernel.DeriveKey("kit7"u8, [], 8);
        byte[] encrypted = aes.EncryptCbc(padded, new byte[16], PaddingMode.None);
        var header = new List<byte> { 1, 4, 6, 0, 1, 9 };
        Number((ulong)encrypted.Length);
        header.AddRange([0, 7, 11, 1, 0, 2, 0x24, 6, 0xf1, 7, 1, 1, 8, 1, 0, 1, 0, 12]);
        Number((ulong)data.Length); Number((ulong)data.Length);
        header.AddRange([0, 8, 13]); Number((ulong)files.Length);
        header.Add(9);
        foreach (byte[] file in files[..^1]) Number((ulong)file.Length);
        header.AddRange([10, 1]);
        foreach (byte[] file in files)
        {
            var crc = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(crc, ZipCryptoSample.Crc32(file));
            header.AddRange(crc);
        }
        header.AddRange([0, 0, 0]);
        byte[] archive = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4, .. new byte[24], .. encrypted, .. header];
        BinaryPrimitives.WriteUInt64LittleEndian(archive.AsSpan(12), (ulong)encrypted.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(archive.AsSpan(20), (ulong)header.Count);
        BinaryPrimitives.WriteUInt32LittleEndian(archive.AsSpan(28), ZipCryptoSample.Crc32(header.ToArray()));
        BinaryPrimitives.WriteUInt32LittleEndian(archive.AsSpan(8), ZipCryptoSample.Crc32(archive.AsSpan(12, 20)));
        return archive;

        void Number(ulong n)
        {
            int extra = 0;
            while (extra < 8 && n >= (1UL << (7 + 7 * extra))) extra++;
            header.Add(extra == 8 ? (byte)255 : (byte)((0xffUL << (8 - extra)) | (n >> (8 * extra))));
            for (int i = 0; i < extra; i++) header.Add((byte)(n >> (8 * i)));
        }
    }
}
