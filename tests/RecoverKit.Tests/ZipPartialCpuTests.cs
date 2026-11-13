using System.Buffers.Binary;
using System.IO.Compression;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

public class ZipPartialCpuTests
{
    [Theory]
    [InlineData(false, 1, false)]
    [InlineData(false, 1, true)]
    [InlineData(false, 2, false)]
    [InlineData(false, 2, true)]
    [InlineData(true, 1, false)]
    [InlineData(true, 1, true)]
    [InlineData(true, 2, false)]
    [InlineData(true, 2, true)]
    public void PartialHashVerifiesWholeEntryAndRejectsHeaderSurvivor(bool deflate, int checkBytes, bool descriptor)
    {
        using var sample = new Sample(deflate, checkBytes: checkBytes, descriptor: descriptor);
        var kernel = Parse(sample);
        Assert.True(kernel.Verify("secret"u8));
        var worker = kernel.CreateWorker();
        Assert.Equal(0, worker.Search("secre"u8, "tux"u8));
        Assert.Equal(3, worker.SearchBatch("xxxxxsecre"u8, 2, "tux"u8));
        byte check = ZipCryptoKernel.HeaderCheckByte("secret"u8, sample.Header);
        byte[] wrong = Enumerable.Range(0, 100000).Select(i => System.Text.Encoding.ASCII.GetBytes($"wrong{i}"))
            .First(p => ZipCryptoKernel.HeaderCheckByte(p, sample.Header) == check);
        Assert.False(kernel.Verify(wrong));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PartialHashRejectsCorruptionAfterPrefixAndMissingArchive(bool deflate)
    {
        using var sample = new Sample(deflate);
        var kernel = Parse(sample);
        using (var file = File.Open(sample.Target.ArchivePath, FileMode.Open, FileAccess.ReadWrite))
        {
            file.Position = sample.Target.DataOffset + sample.Target.CompressedLength - 2;
            int b = file.ReadByte();
            file.Position--;
            file.WriteByte((byte)(b ^ 0xff));
        }
        Assert.False(kernel.Verify("secret"u8));
        File.Delete(sample.Target.ArchivePath);
        Assert.False(kernel.Verify("secret"u8));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PartialHashRejectsTruncatedEntryAndWrongLength(bool deflate)
    {
        using var sample = new Sample(deflate);
        var wrongLength = Parse(sample, sample.Target with { UncompressedLength = sample.Target.UncompressedLength + 1 });
        Assert.False(wrongLength.Verify("secret"u8));
        var kernel = Parse(sample);
        using (var file = File.OpenWrite(sample.Target.ArchivePath))
            file.SetLength(sample.Target.DataOffset + sample.Target.CompressedLength - 1);
        Assert.False(kernel.Verify("secret"u8));
    }

    [Fact]
    public void PartialHashNeedsMatchingMetadataAndArchivePrefix()
    {
        using var sample = new Sample(false);
        Assert.Null(ZipCryptoKernel.TryParse(sample.Hash));
        Assert.Null(ParseOrNull(sample, sample.Target with { Method = 8 }));
        Assert.Null(ParseOrNull(sample, sample.Target with { DataOffset = -1 }));
        Assert.Null(ParseOrNull(sample, sample.Target with { CompressedLength = 11 }));
        Assert.Null(ParseOrNull(sample, sample.Target with { DataOffset = long.MaxValue }));
        Assert.Null(ParseOrNull(sample, sample.Target with { CompressedLength = long.MaxValue }));
        Assert.Null(ParseOrNull(sample, sample.Target with { UncompressedLength = -1 }));
        using (var file = File.OpenWrite(sample.Target.ArchivePath))
        {
            file.Position = sample.Target.DataOffset;
            file.WriteByte((byte)(sample.Header[0] ^ 1));
        }
        Assert.Null(ParseOrNull(sample, sample.Target));
    }

    [Fact]
    public void PartialHashChecksBothHeaderBytesWhenRequested()
    {
        using var sample = new Sample(false, checkBytes: 2);
        var fields = sample.Hash.Split('*');
        fields[6] = ((sample.Target.Crc >> 16) ^ 1).ToString("x4");
        var kernel = ZipCryptoKernel.TryParse(string.Join('*', fields), sample.Target);
        Assert.NotNull(kernel);
        Assert.False(kernel.Verify("secret"u8));
    }

    [Fact]
    public void PartialDeflateRequiresTheFinalBlockEvenAfterAllOutput()
    {
        byte[] content = new byte[100];
        new Random(51).NextBytes(content);
        // A nonfinal stored block, then a final empty fixed-Huffman block.
        byte[] deflated = new byte[5 + content.Length + 2];
        BinaryPrimitives.WriteUInt16LittleEndian(deflated.AsSpan(1), (ushort)content.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(deflated.AsSpan(3), (ushort)~content.Length);
        content.CopyTo(deflated, 5);
        deflated[^2] = 3;
        using (var compressed = new MemoryStream(deflated, 0, deflated.Length - 2))
        using (var inflater = new DeflateStream(compressed, CompressionMode.Decompress))
        using (var output = new MemoryStream())
        {
            inflater.CopyTo(output);
            Assert.Equal(content, output.ToArray());
        }
        using var sample = new Sample(false, deflated);
        var target = sample.Target with { Method = 8, Crc = ZipCryptoSample.Crc32(content), UncompressedLength = content.Length };
        string hash = sample.Hash.Replace("*1*0*0*", "*1*0*8*");
        var complete = Assert.IsType<ZipCryptoKernel>(ZipCryptoKernel.TryParse(hash, target));
        Assert.True(complete.Verify("secret"u8));
        var truncated = Assert.IsType<ZipCryptoKernel>(ZipCryptoKernel.TryParse(hash,
            target with { CompressedLength = target.CompressedLength - 2 }));
        Assert.False(truncated.Verify("secret"u8));
    }

    [Fact]
    public void PartialHashRejectsChangedArchiveHeaderAndWrongCrc()
    {
        using var sample = new Sample(false);
        var wrongCrc = Parse(sample, sample.Target with { Crc = sample.Target.Crc ^ 1 });
        Assert.False(wrongCrc.Verify("secret"u8));
        var kernel = Parse(sample);
        using (var file = File.OpenWrite(sample.Target.ArchivePath))
        {
            file.Position = sample.Target.DataOffset;
            file.WriteByte((byte)(sample.Header[0] ^ 1));
        }
        Assert.False(kernel.Verify("secret"u8));
    }

    [Fact]
    public void PartialHashRequiresTheEntirePrefixToMatch()
    {
        using var sample = new Sample(false);
        using (var file = File.Open(sample.Target.ArchivePath, FileMode.Open, FileAccess.ReadWrite))
        {
            file.Position = sample.Target.DataOffset + 63;
            int b = file.ReadByte();
            file.Position--;
            file.WriteByte((byte)(b ^ 1));
        }
        Assert.Null(ParseOrNull(sample, sample.Target));
    }

    [Fact]
    public void CpuAndHybridPlanningCarryTheArchiveTarget()
    {
        using var sample = new Sample(true);
        var attack = new PreparedAttack { Description = "mask" };
        attack.Args.AddRange(["-a", "3", "?l?l?l?l?l?l"]);
        var cpu = NativeRunner.Plan(17200, sample.Hash, attack,
            new Settings { Strategy = DeviceStrategy.CpuOnly }, [], partial: sample.Target);
        Assert.NotNull(cpu);
        Assert.True(cpu.Value.Kernel.Verify("secret"u8));
        var gpu = new BackendDevice { Id = 1, Type = "GPU", Name = "Test GPU" };
        var hybrid = HybridRunner.Plan(17200, sample.Hash, attack, new Settings(), [gpu], partial: sample.Target);
        Assert.NotNull(hybrid);
        Assert.True(hybrid.Kernel.Verify("secret"u8));
        Assert.Null(NativeRunner.Plan(17200, sample.Hash, attack, new Settings(), []));
    }

    [Fact]
    public void PartialHashStreamsOutputBeyond64MiB()
    {
        using var sample = new Sample(true, new byte[64 * 1024 * 1024 + 1]);
        var kernel = Parse(sample);
        long before = GC.GetAllocatedBytesForCurrentThread();
        Assert.True(kernel.Verify("secret"u8));
        Assert.True(GC.GetAllocatedBytesForCurrentThread() - before < 1024 * 1024);
    }

    private static ZipCryptoKernel Parse(Sample sample, ZipPartialTarget? target = null) =>
        Assert.IsType<ZipCryptoKernel>(ParseOrNull(sample, target ?? sample.Target));

    private static NativeKernel? ParseOrNull(Sample sample, ZipPartialTarget target) =>
        NativeKernels.TryCreate(sample.Target.Method == 8 ? 17200 : 17210, sample.Hash, target);

    private sealed class Sample : IDisposable
    {
        public ZipPartialTarget Target { get; }
        public byte[] Header { get; }
        public string Hash { get; }

        public Sample(bool deflate, byte[]? data = null, int checkBytes = 1, bool descriptor = false)
        {
            var rng = new Random(144);
            byte[] content = data ?? new byte[32768];
            if (data is null) rng.NextBytes(content);
            byte[] archive = ZipCryptoSample.Archive([new("data", content, deflate, descriptor)], "secret"u8, rng);
            string path = Path.Combine(Path.GetTempPath(), "rk-partial-" + Guid.NewGuid().ToString("N") + ".zip");
            File.WriteAllBytes(path, archive);
            int central = (int)BinaryPrimitives.ReadUInt32LittleEndian(archive.AsSpan(archive.Length - 6));
            uint comp = BinaryPrimitives.ReadUInt32LittleEndian(archive.AsSpan(central + 20));
            uint crc = BinaryPrimitives.ReadUInt32LittleEndian(archive.AsSpan(central + 16));
            Target = new(path, 34, comp, content.Length, crc, deflate ? 8 : 0);
            Header = archive.AsSpan(34, 12).ToArray();
            byte[] prefix = archive.AsSpan(34, 64).ToArray();
            uint checksum = descriptor && checkBytes == 2 ? 0x6d2b : Target.Crc >> 16;
            uint timeChecksum = descriptor ? 0x6d2b : Target.Crc >> 16;
            Hash = $"$pkzip2$1*{checkBytes}*1*0*{Target.Method}*{prefix.Length:x}*{checksum:x4}*{timeChecksum:x4}*{Convert.ToHexString(prefix)}*$/pkzip2$";
        }

        public void Dispose() => File.Delete(Target.ArchivePath);
    }
}
