using RecoverKit.Core.Formats;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using System.Buffers.Binary;
using Xunit;

namespace RecoverKit.Tests;

public class SevenZipExtractorTests
{
    [Theory]
    [InlineData("7zz-copy-on", 0)]
    [InlineData("7zz-copy-off", 0)]
    [InlineData("7zz-LZMA-on", 0)]
    [InlineData("7zz-LZMA-off", 1)]
    [InlineData("7zz-LZMA2-off", 2)]
    [InlineData("7zz-Deflate-off", 7)]
    [InlineData("7z-LZMA2-on", 0)]
    [InlineData("solid", 2)]
    [InlineData("nonsolid", 2)]
    [InlineData("plainmeta", 2)]
    [InlineData("many-on", 1)]
    [InlineData("many-off", 2)]
    [InlineData("mixed", 0)]
    public void DetectsAndExtractsRealArchives(string fixture, int type)
    {
        var d = FormatDetector.Detect(Fixture(fixture));
        Assert.Null(d.Message);
        var t = Assert.IsType<HashTarget>(d.Target);
        Assert.Equal("7ZIP", t.FormatId);
        Assert.Equal([11600], t.Modes);
        Assert.StartsWith($"$7z${type}$19$0$$16$", t.HashLines);
        Assert.Equal(SpeedClass.VerySlow, t.Speed);
        Assert.True(t.Utf16Password);
        Assert.Contains("slow", t.Notes!, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("7zz-PPMd-off")]
    [InlineData("7zz-BZip2-off")]
    [InlineData("filter")]
    public void ExplainsUnsupportedCompression(string fixture)
    {
        var d = FormatDetector.Detect(Fixture(fixture));
        Assert.Null(d.Target);
        Assert.Contains("hashcat", d.Message!);
    }

    [Theory]
    [InlineData("empty")]
    [InlineData("unprotected")]
    public void DoesNotInventEncryptionForEmptyOrUnprotectedArchive(string fixture)
    {
        var d = FormatDetector.Detect(Fixture(fixture));
        Assert.Equal("7-Zip archive", d.TypeName);
        Assert.Null(d.Target);
        Assert.Contains("not password protected", d.Message!);
    }

    [Fact]
    public void SelectsSmallestNonSolidStream()
    {
        var t = FormatDetector.Detect(Fixture("nonsolid")).Target!;
        Assert.Equal("16", t.HashLines.Split('$')[9]);
        Assert.Equal("11", t.HashLines.Split('$')[12]);
    }

    [Fact]
    public void CombinesSolidSubstreamsForFullHashcatInput()
    {
        var t = FormatDetector.Detect(Fixture("many-off")).Target!;
        byte[] prefix = System.Text.Encoding.UTF8.GetBytes(string.Concat(
            Enumerable.Range(0, 13).Select(i => $"data for file {i}\n")));
        var fields = t.HashLines.Split('$');
        Assert.Equal(prefix.Length.ToString(), fields[12]);
        Assert.Equal(Crc(prefix).ToString(), fields[8]);
    }

    [Fact]
    public void DetectsContentAndSelfExtractingPrefix()
    {
        byte[] archive = File.ReadAllBytes(Fixture("7zz-copy-on"));
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, archive);
            var expected = FormatDetector.Detect(path).Target!.HashLines;
            byte[] prefix = new byte[65537]; prefix[0] = (byte)'M'; prefix[1] = (byte)'Z';
            File.WriteAllBytes(path, [.. prefix, .. archive]);
            var d = FormatDetector.Detect(path);
            Assert.Equal(expected, d.Target!.HashLines);
            Assert.Contains(d.Info, pair => pair.Key == "Self-extracting prefix");
            // SFX stubs can contain the signature constant before the actual archive.
            archive.AsSpan(0, 6).CopyTo(prefix.AsSpan(128));
            File.WriteAllBytes(path, [.. prefix, .. archive]);
            Assert.Equal(expected, FormatDetector.Detect(path).Target!.HashLines);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void ExplainsSplitVolumes()
    {
        var d = new Detection { FilePath = "archive.7z.001" };
        using var s = File.OpenRead(Fixture("7zz-copy-on"));
        var e = Assert.Throws<UnsupportedFormatException>(() => SevenZipExtractor.Extract(s, d));
        Assert.Contains("Join all", e.Message);
    }

    [Fact]
    public void RejectsEveryTruncationOfRealArchive()
    {
        var bytes = File.ReadAllBytes(Fixture("7zz-LZMA-on"));
        for (int n = 0; n < bytes.Length; n++)
            Assert.Throws<FormatException>(() => Extract(bytes[..n]));
    }

    [Fact]
    public void RejectsHeaderCrcDamage()
    {
        var bytes = File.ReadAllBytes(Fixture("7zz-LZMA-on"));
        bytes[8] ^= 1;
        Assert.Throws<FormatException>(() => Extract(bytes));
        bytes[8] ^= 1; bytes[^1] ^= 1;
        Assert.Throws<FormatException>(() => Extract(bytes));
    }

    [Theory]
    [InlineData(8 * 1024 * 1024, true)]
    [InlineData(8 * 1024 * 1024 + 16, false)]
    public void EnforcesEncryptedDataLimit(int packed, bool supported)
    {
        var d = Extract(Archive((packed, (ulong)packed, "00", [], null)));
        Assert.Equal(supported, d.Target != null);
        if (!supported) Assert.Contains("8 MiB", d.Message!);
    }

    [Fact]
    public void TriesSmallerStreamAfterOversizedOne()
    {
        var d = Extract(Archive((8 * 1024 * 1024 + 16, 8 * 1024 * 1024 + 16, "00", [], null),
            (16, 11, "00", [], null)));
        Assert.Equal("16", d.Target!.HashLines.Split('$')[9]);
    }

    [Theory]
    [InlineData(9_999_999, true)]
    [InlineData(10_000_000, false)]
    public void EnforcesDecompressedCrcLimit(ulong crcSize, bool supported)
    {
        var d = Extract(Archive((16, crcSize, "21", [0], null)));
        Assert.Equal(supported, d.Target != null);
    }

    [Fact]
    public void ExplainsRealLargeCompressedFileLimit()
    {
        var d = FormatDetector.Detect(Fixture("large-lzma2"));
        Assert.Null(d.Target);
        Assert.Contains("9,999,999", d.Message!);
    }

    [Theory]
    [InlineData(8 * 1024 * 1024 - 16, true)]
    [InlineData(8 * 1024 * 1024, false)]
    public void ReservesHashcatTokenSpaceForCompressionSuffix(int packed, bool supported)
    {
        var d = Extract(Archive((packed, 100, "21", [0], null)));
        Assert.Equal(supported, d.Target != null);
    }

    [Fact]
    public void ExplainsSaltAndDirectKeyLimitations()
    {
        var salted = Extract(Archive((16, 11, "00", [], new byte[] { 0x93, 0, 0x42 })));
        Assert.Null(salted.Target);
        Assert.Contains("salted AES", salted.Message!);
        var direct = Extract(Archive((16, 11, "00", [], new byte[] { 63 })));
        Assert.Null(direct.Target);
        Assert.Contains("NumCyclesPower", direct.Message!);
    }

    [Fact]
    public void PadsShortIvAndPreservesIterationExponent()
    {
        var d = Extract(Archive((16, 11, "00", [], new byte[] { 0x4e, 0, 0x42 })));
        Assert.StartsWith("$7z$0$14$0$$1$42000000000000000000000000000000$", d.Target!.HashLines);
    }

    [Theory]
    [InlineData(20, true)]
    [InlineData(21, false)]
    public void RespectsOptimizedKernelPasswordLimit(int length, bool optimized)
    {
        Assert.Equal(optimized, RecoverySession.CanUseOptimizedKernel(
            new RecoverKit.Core.Hashcat.HashModeInfo { Mode = 11600, HasOptimizedKernel = true, OptimizedPasswordLenMax = 20 },
            new PreparedAttack { Description = "test", Args = { "-a", "3", new string('a', length) } }));
    }

    [Fact]
    public void RejectsMalformedMetadataAndLzmaWithoutCrashing()
    {
        byte[] archive = File.ReadAllBytes(Fixture("plainmeta"));
        int start = 32 + (int)BinaryPrimitives.ReadUInt64LittleEndian(archive.AsSpan(12));
        for (int i = start; i < archive.Length; i++)
        {
            var changed = archive.ToArray(); changed[i] ^= 0xff;
            RepairCrcs(changed);
            try { Extract(changed); }
            catch (FormatException) { }
            catch (UnsupportedFormatException) { }
        }
        var random = new Random(7);
        for (int i = 0; i < 100; i++)
        {
            byte[] data = new byte[50]; random.NextBytes(data); data[0] = 0;
            try { SevenZipLzma.Decode(data, [0x5d, 0, 0x10, 0, 0], 4096); }
            catch (FormatException) { }
        }
    }

    private static Detection Extract(byte[] data)
    {
        var d = new Detection { FilePath = "test.7z" };
        using var s = new MemoryStream(data);
        SevenZipExtractor.Extract(s, d);
        return d;
    }

    // Synthetic folder metadata surrounds placeholder ciphertext for size/property boundary tests.
    private static byte[] Archive(params (int Packed, ulong Size, string Method, byte[] Props, byte[]? Aes)[] folders)
    {
        var header = new List<byte> { 1, 4, 6, 0 };
        Number((ulong)folders.Length);
        header.Add(9);
        foreach (var f in folders) Number((ulong)f.Packed);
        header.AddRange([0, 7, 11]); Number((ulong)folders.Length); header.Add(0);
        foreach (var f in folders)
        {
            header.AddRange([2, 0x24, 6, 0xf1, 7, 1]);
            byte[] aes = f.Aes ?? [19]; Number((ulong)aes.Length); header.AddRange(aes);
            byte[] method = Convert.FromHexString(f.Method);
            header.Add((byte)(method.Length | (f.Props.Length > 0 ? 32 : 0))); header.AddRange(method);
            if (f.Props.Length > 0) { Number((ulong)f.Props.Length); header.AddRange(f.Props); }
            header.AddRange([1, 0]);
        }
        header.Add(12);
        foreach (var f in folders) { Number(f.Method == "00" ? f.Size : (ulong)f.Packed); Number(f.Size); }
        header.AddRange([10, 1]);
        foreach (var _ in folders) header.AddRange([1, 2, 3, 4]);
        header.AddRange([0, 0, 0]);
        int dataLength = folders.Sum(f => f.Packed);
        var archive = new byte[32 + dataLength + header.Count];
        new byte[] { 0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4 }.CopyTo(archive, 0);
        BinaryPrimitives.WriteUInt64LittleEndian(archive.AsSpan(12), (ulong)dataLength);
        BinaryPrimitives.WriteUInt64LittleEndian(archive.AsSpan(20), (ulong)header.Count);
        header.CopyTo(archive, 32 + dataLength); RepairCrcs(archive); return archive;

        void Number(ulong n)
        {
            int extra = 0;
            while (extra < 8 && n >= (1UL << (7 + 7 * extra))) extra++;
            header.Add(extra == 8 ? (byte)255 : (byte)((0xffUL << (8 - extra)) | (n >> (8 * extra))));
            for (int i = 0; i < extra; i++) header.Add((byte)(n >> (8 * i)));
        }
    }

    private static void RepairCrcs(byte[] archive)
    {
        int start = 32 + (int)BinaryPrimitives.ReadUInt64LittleEndian(archive.AsSpan(12));
        BinaryPrimitives.WriteUInt32LittleEndian(archive.AsSpan(28), Crc(archive.AsSpan(start)));
        BinaryPrimitives.WriteUInt32LittleEndian(archive.AsSpan(8), Crc(archive.AsSpan(12, 20)));
    }

    private static uint Crc(ReadOnlySpan<byte> bytes)
    {
        uint c = uint.MaxValue;
        foreach (byte b in bytes)
        {
            c ^= b;
            for (int bit = 0; bit < 8; bit++) c = (c >> 1) ^ ((c & 1) != 0 ? 0xedb88320u : 0);
        }
        return ~c;
    }

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", "SevenZip", name + ".7z");
}
