using System.Buffers.Binary;
using System.IO.Compression;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native.Kernels;
using RecoverKit.Core.Attacks.Stay;
using Xunit;

namespace RecoverKit.Tests;

public sealed class ZipSplitTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-zip-split").FullName;
    public void Dispose() => Directory.Delete(_dir, true);
    private string PathFor(string name) => Path.Combine(_dir, name);
    private static ushort U16(byte[] b, int p) => BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(p));
    private static uint U32(byte[] b, int p) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(p));
    private static void W16(byte[] b, int p, int v) => BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(p), checked((ushort)v));
    private static void W32(byte[] b, int p, long v) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(p), checked((uint)v));

    private static byte[] Archive(int size = 800, bool deflate = false)
    {
        var data = new byte[size];
        new Random(42).NextBytes(data);
        return ZipCryptoSample.Archive([new("data.bin", data, deflate), new("other.txt", "other content"u8.ToArray(), true)], "7"u8, new Random(7));
    }

    // A PKZIP writer independent of the production parser. Fixed-size cuts deliberately split
    // local data, central records and the ZIP64 end record across volumes.
    private List<string> Spanned(byte[] archive, int partSize, bool zip64)
    {
        int end = archive.Length - 22, central = (int)U32(archive, end + 16);
        ushort entryCount = U16(archive, end + 10);
        using var cd = new MemoryStream();
        using var w = new BinaryWriter(cd, System.Text.Encoding.UTF8, true);
        for (int p = central; p < end;)
        {
            int nl = U16(archive, p + 28), el = U16(archive, p + 30), cl = U16(archive, p + 32);
            var rec = archive[p..(p + 46 + nl + el + cl)];
            long offset = U32(rec, 42) + 4;
            int disk = (int)(offset / partSize);
            if (zip64)
            {
                uint compressed = U32(rec, 20), uncompressed = U32(rec, 24);
                W16(rec, 34, 0xffff); W32(rec, 42, uint.MaxValue);
                W16(rec, 30, el + 32);
                W32(rec, 20, uint.MaxValue); W32(rec, 24, uint.MaxValue);
                w.Write(rec[..(46 + nl + el)]);
                w.Write((ushort)1); w.Write((ushort)28); w.Write((ulong)uncompressed); w.Write((ulong)compressed); w.Write((ulong)(offset % partSize)); w.Write((uint)disk);
                w.Write(rec[(46 + nl + el)..]);
            }
            else
            {
                W16(rec, 34, disk); W32(rec, 42, offset % partSize); w.Write(rec);
            }
            p += rec.Length;
        }
        using var joined = new MemoryStream();
        using var output = new BinaryWriter(joined, System.Text.Encoding.UTF8, true);
        output.Write(0x08074b50u); output.Write(archive[..central]); output.Write(cd.ToArray());
        long cdStart = central + 4;
        if (zip64)
        {
            long z = joined.Position;
            output.Write(0x06064b50u); output.Write(44ul); output.Write((ushort)45); output.Write((ushort)45);
            output.Write((uint)(z / partSize)); output.Write((uint)(cdStart / partSize));
            output.Write((ulong)entryCount); output.Write((ulong)entryCount); output.Write((ulong)cd.Length); output.Write((ulong)(cdStart % partSize));
            output.Write(0x07064b50u); output.Write((uint)(z / partSize)); output.Write((ulong)(z % partSize));
            output.Write((uint)((joined.Position + 4 + 22 + partSize - 1) / partSize));
        }
        long eocd = joined.Position;
        output.Write(0x06054b50u); output.Write((ushort)(zip64 ? 0xffff : eocd / partSize));
        output.Write((ushort)(zip64 ? 0xffff : cdStart / partSize));
        output.Write((ushort)(zip64 ? 0xffff : entryCount)); output.Write((ushort)(zip64 ? 0xffff : entryCount));
        output.Write(zip64 ? uint.MaxValue : (uint)cd.Length);
        output.Write(zip64 ? uint.MaxValue : (uint)(cdStart % partSize)); output.Write((ushort)0);
        return Parts(joined.ToArray(), partSize, false);
    }

    private List<string> Parts(byte[] bytes, int size, bool plain)
    {
        int count = (bytes.Length + size - 1) / size;
        var paths = new List<string>();
        for (int i = 0; i < count; i++)
        {
            string name = plain ? $"sample.zip.{i + 1:D3}" : i == count - 1 ? "sample.zip" : $"sample.z{i + 1:D2}";
            string path = PathFor(name);
            File.WriteAllBytes(path, bytes[(i * size)..Math.Min(bytes.Length, (i + 1) * size)]);
            paths.Add(path);
        }
        return paths;
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void EveryPartProducesTheSameHash(bool plain, bool zip64)
    {
        var original = Archive();
        var paths = plain ? Parts(original, 109, true) : Spanned(original, 109, zip64);
        var expected = ZipCryptoSample.Extract(original);
        foreach (var path in paths)
        {
            var d = FormatDetector.Detect(path);
            Assert.True(d.Target is not null, d.Message);
            Assert.Equal(expected.HashLines, d.Target.HashLines);
            Assert.True(d.Target.ConfirmPassword!("7"u8.ToArray()));
            Assert.False(d.Target.ConfirmPassword("wrong"u8.ToArray()));
            Assert.Null(d.Target.StayZip);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingMiddlePartIsNamedFromEitherEnd(bool plain)
    {
        var paths = plain ? Parts(Archive(), 109, true) : Spanned(Archive(), 109, true);
        File.Delete(paths[1]);
        foreach (var path in new[] { paths[0], paths[^1] })
        {
            var d = FormatDetector.Detect(path);
            Assert.Null(d.Target);
            Assert.Contains(Path.GetFileName(paths[1]), d.Message);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingLastPartIsNamed(bool plain)
    {
        var paths = plain ? Parts(Archive(), 109, true) : Spanned(Archive(), 109, false);
        File.Delete(paths[^1]);
        var d = FormatDetector.Detect(paths[0]);
        Assert.Null(d.Target);
        Assert.Contains(Path.GetFileName(paths[^1]), d.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LargeEntryConfirmationReopensAllParts(bool deflate)
    {
        var original = Archive(400_000, deflate);
        // Remove the small sibling so that the large entry is attacked.
        int end = original.Length - 22, central = (int)U32(original, end + 16);
        int firstLength = 46 + U16(original, central + 28);
        int secondLocal = (int)U32(original, central + firstLength + 42);
        var single = original[..secondLocal].Concat(original[central..(central + firstLength)]).Concat(original[end..]).ToArray();
        int newEnd = single.Length - 22;
        W16(single, newEnd + 8, 1); W16(single, newEnd + 10, 1);
        W32(single, newEnd + 12, firstLength); W32(single, newEnd + 16, secondLocal);
        var paths = Parts(single, 65536, true);
        var d = FormatDetector.Detect(paths[2]);
        Assert.True(d.Target is not null, d.Message);
        Assert.NotNull(d.Target.ZipPartial);
        Assert.True(d.Target.ConfirmPassword!("7"u8.ToArray()));
        Assert.False(d.Target.ConfirmPassword("wrong"u8.ToArray()));
    }

    [Fact]
    public void WrongLocalNameFailsBeforeProducingHash()
    {
        var paths = Spanned(Archive(), 109, true);
        var first = File.ReadAllBytes(paths[0]);
        first[34] ^= 1;
        File.WriteAllBytes(paths[0], first);
        var d = FormatDetector.Detect(paths[^1]);
        Assert.Null(d.Target);
        Assert.Contains("local", d.Message, StringComparison.OrdinalIgnoreCase);
    }
    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", "ZipSplit", name);

    [Theory]
    [InlineData("infozip")]
    [InlineData("infozip64")]
    public void InfoZipMatchesTheHashFromZipS0(string name)
    {
        string expected = File.ReadAllText(Fixture(name + ".hash")).Trim();
        foreach (var ext in new[] { ".z01", ".zip" })
        {
            var d = FormatDetector.Detect(Fixture(name + ext));
            Assert.True(d.Target is not null, d.Message);
            Assert.Equal(expected, d.Target.HashLines);
            var kernel = Assert.IsType<ZipCryptoKernel>(ZipCryptoKernel.TryParse(d.Target.HashLines));
            Assert.True(kernel.Verify("7"u8));
            Assert.False(kernel.Verify("wrong"u8));
            Assert.True(d.Target.ConfirmPassword!("7"u8.ToArray()));
        }
    }

    [Theory]
    [InlineData("7zip-crypto", false)]
    [InlineData("7zip-aes", true)]
    [InlineData("7zip-aes-store", true)]
    public void SevenZipVolumesMatchPlainConcatenation(string name, bool aes)
    {
        var paths = Directory.GetFiles(Path.GetDirectoryName(Fixture(name))!, name + ".zip.*").Order().ToArray();
        var joined = paths.SelectMany(File.ReadAllBytes).ToArray();
        var expected = ZipCryptoSample.Extract(joined);
        foreach (string path in paths)
        {
            var d = FormatDetector.Detect(path);
            Assert.True(d.Target is not null, d.Message);
            Assert.Equal(expected.HashLines, d.Target.HashLines);
            Assert.True(aes ? WinZipAesKernel.TryParse(d.Target.HashLines)!.Verify("7"u8)
                : ZipCryptoKernel.TryParse(d.Target.HashLines)!.Verify("7"u8));
        }
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void AesSpannedAndZip64SupportAe1AndAe2(bool zip64, bool ae1)
    {
        byte[] archive = Directory.GetFiles(Path.GetDirectoryName(Fixture("7zip-aes"))!, "7zip-aes.zip.*")
            .Order().SelectMany(File.ReadAllBytes).ToArray();
        if (ae1)
        {
            for (int i = 0; i < archive.Length - 10; i++)
                if (U16(archive, i) == 0x9901 && U16(archive, i + 2) == 7) W16(archive, i + 4, 1);
            uint crc = ZipCryptoSample.Crc32(System.Text.Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("Split ZIP password recovery fixture.\n", 30))));
            W32(archive, 14, crc);
            int central = (int)U32(archive, archive.Length - 6);
            W32(archive, central + 16, crc);
        }
        // Spanned() also works for a one-entry archive when its EOCD counts are preserved.
        var paths = Spanned(archive, 109, zip64);
        var d = FormatDetector.Detect(paths[1]);
        Assert.True(d.Target is not null, d.Message);
        Assert.Equal(ZipCryptoSample.Extract(archive).HashLines, d.Target.HashLines);
        var kernel = WinZipAesKernel.TryParse(d.Target.HashLines)!;
        Assert.True(kernel.Verify("7"u8));
        Assert.False(kernel.Verify("wrong"u8));
    }

    [Theory]
    [InlineData(6)] // flags
    [InlineData(8)] // compression method
    [InlineData(10)] // time supplies the encryption check byte for data descriptors
    [InlineData(14)] // CRC
    [InlineData(18)] // compressed size
    [InlineData(22)] // uncompressed size
    public void MismatchedLocalMetadataCannotProduceAHash(int field)
    {
        var paths = Spanned(Archive(), 109, true);
        byte[] first = File.ReadAllBytes(paths[0]);
        first[4 + field] ^= 1;
        File.WriteAllBytes(paths[0], first);
        var d = FormatDetector.Detect(paths[^1]);
        Assert.Null(d.Target);
        Assert.Contains("local", d.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void MissingFirstPartAndBadDiskOffsetFailLoudly()
    {
        var paths = Spanned(Archive(), 109, false);
        File.Delete(paths[0]);
        Assert.Contains("sample.z01", FormatDetector.Detect(paths[^1]).Message);
        paths = Spanned(Archive(), 109, false);
        using var stream = new MultiVolumeStream(paths);
        var bytes = new byte[stream.Length]; stream.ReadExactly(bytes);
        int central = -1;
        for (int i = 0; i < bytes.Length - 4; i++)
            if (U32(bytes, i) == 0x02014b50) { central = i; break; }
        W16(bytes, central + 34, 32000);
        Parts(bytes, 109, false);
        var d = FormatDetector.Detect(paths[^1]);
        Assert.Null(d.Target);
        Assert.Contains("disk", d.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DecryptedCopyRefusesSplitInputBeforeCreatingOutput()
    {
        var paths = Spanned(Archive(), 109, true);
        string output = PathFor("clear.zip");
        var ex = Assert.Throws<UnsupportedFormatException>(() => ZipStayDecryptor.WriteDecryptedCopy(
            paths[0], new ZipStayTarget { Entries = [] }, default(ZipStayKeys), output));
        Assert.Contains("split ZIP", ex.Message);
        Assert.False(File.Exists(output));
    }

    [Fact]
    public void Zip64LocalOffsetsAboveFourGiBAreReadWithoutJoining()
    {
        byte[] original = Archive();
        var paths = Spanned(original, 109, true);
        byte[] joined = paths.SelectMany(File.ReadAllBytes).ToArray();
        int central = -1;
        for (int i = 0; i < joined.Length - 4; i++)
            if (U32(joined, i) == 0x02014b50) { central = i; break; }
        const long gap = 1L << 32;
        int offsetField = central + 46 + U16(joined, central + 28) + 4 + 16;
        BinaryPrimitives.WriteUInt64LittleEndian(joined.AsSpan(offsetField), (ulong)(gap + 4));
        paths = Parts(joined, 109, false);
        byte[] first = File.ReadAllBytes(paths[0]);
        using (var file = File.Create(paths[0]))
        {
            file.Write(first.AsSpan(0, 4));
            file.Position = gap + 4;
            file.Write(first.AsSpan(4));
        }
        var d = FormatDetector.Detect(paths[^1]);
        Assert.True(d.Target is not null, d.Message);
        Assert.Equal(ZipCryptoSample.Extract(original).HashLines, d.Target.HashLines);
        Assert.True(d.Target.ConfirmPassword!("7"u8.ToArray()));
    }

    [Fact]
    public void Zip64CentralDirectoryAndLocatorOffsetsAboveFourGiBAreReadInPlace()
    {
        byte[] original = Archive();
        int end = original.Length - 22, central = (int)U32(original, end + 16);
        byte[] cd = original[central..end];
        for (int p = 0; p < cd.Length;)
        {
            W32(cd, p + 42, U32(cd, p + 42) + 4);
            p += 46 + U16(cd, p + 28) + U16(cd, p + 30) + U16(cd, p + 32);
        }
        string first = PathFor("sparse.z01"), last = PathFor("sparse.zip");
        using (var file = File.Create(first))
        using (var w = new BinaryWriter(file)) { w.Write(0x08074b50u); w.Write(original[..central]); }
        const long offset = (1L << 32) + 123;
        using (var file = File.Create(last))
        using (var w = new BinaryWriter(file))
        {
            file.Position = offset;
            w.Write(cd);
            ulong z64 = (ulong)file.Position;
            w.Write(0x06064b50u); w.Write(44ul); w.Write((ushort)45); w.Write((ushort)45);
            w.Write(1u); w.Write(1u); w.Write(2ul); w.Write(2ul); w.Write((ulong)cd.Length); w.Write((ulong)offset);
            w.Write(0x07064b50u); w.Write(1u); w.Write(z64); w.Write(2u);
            w.Write(0x06054b50u); w.Write((ushort)1); w.Write((ushort)1);
            w.Write((ushort)0xffff); w.Write((ushort)0xffff); w.Write(uint.MaxValue); w.Write(uint.MaxValue); w.Write((ushort)0);
        }
        foreach (string path in new[] { first, last })
        {
            var d = FormatDetector.Detect(path);
            Assert.True(d.Target is not null, d.Message);
            Assert.Equal(ZipCryptoSample.Extract(original).HashLines, d.Target.HashLines);
            Assert.True(d.Target.ConfirmPassword!("7"u8.ToArray()));
        }
    }

    [Fact]
    public void SingleZipWithTrailingBytesKeepsItsExistingHash()
    {
        byte[] original = Archive();
        string path = PathFor("single.zip");
        File.WriteAllBytes(path, original.Concat("trailing bytes"u8.ToArray()).ToArray());
        var d = FormatDetector.Detect(path);
        Assert.True(d.Target is not null, d.Message);
        Assert.Equal(ZipCryptoSample.Extract(original).HashLines, d.Target.HashLines);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    public void SingleZip64AcceptsZeroOrOneTotalDisks(uint totalDisks)
    {
        byte[] original = Archive();
        int end = original.Length - 22;
        ushort entries = U16(original, end + 10);
        uint cdSize = U32(original, end + 12), cdOffset = U32(original, end + 16);
        using var bytes = new MemoryStream();
        using (var w = new BinaryWriter(bytes, System.Text.Encoding.UTF8, true))
        {
            w.Write(original[..end]);
            long z64 = bytes.Position;
            w.Write(0x06064b50u); w.Write(44ul); w.Write((ushort)45); w.Write((ushort)45);
            w.Write(0u); w.Write(0u);
            w.Write((ulong)entries); w.Write((ulong)entries); w.Write((ulong)cdSize); w.Write((ulong)cdOffset);
            // Some writers store 0 here; a single file must still open.
            w.Write(0x07064b50u); w.Write(0u); w.Write((ulong)z64); w.Write(totalDisks);
            w.Write(0x06054b50u); w.Write((ushort)0); w.Write((ushort)0);
            w.Write((ushort)0xffff); w.Write((ushort)0xffff); w.Write(uint.MaxValue); w.Write(uint.MaxValue); w.Write((ushort)0);
        }
        string path = PathFor("single64.zip");
        File.WriteAllBytes(path, bytes.ToArray());
        var d = FormatDetector.Detect(path);
        Assert.True(d.Target is not null, d.Message);
        Assert.Equal(ZipCryptoSample.Extract(original).HashLines, d.Target.HashLines);
    }

    [Fact]
    public void DescriptorTimeMismatchCannotProduceAHashThatRejectsThePassword()
    {
        string first = PathFor("infozip.z01"), last = PathFor("infozip.zip");
        File.Copy(Fixture("infozip.z01"), first);
        byte[] bytes = File.ReadAllBytes(Fixture("infozip.zip"));
        int end = bytes.Length - 22, p = (int)U32(bytes, end + 16);
        while (p + 46 <= bytes.Length && U32(bytes, p) == 0x02014b50)
        {
            bytes[p + 13] ^= 1; // high DOS-time byte in central directory only
            p += 46 + U16(bytes, p + 28) + U16(bytes, p + 30) + U16(bytes, p + 32);
        }
        File.WriteAllBytes(last, bytes);
        var d = FormatDetector.Detect(first);
        Assert.Null(d.Target);
        Assert.Contains("local", d.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void HugeInvalidZip64DirectoryFieldsReturnADamagedDetection()
    {
        byte[] archive = Archive();
        var paths = Spanned(archive, 109, true);
        byte[] joined = paths.SelectMany(File.ReadAllBytes).ToArray();
        int z64 = -1;
        for (int p = 0; p < joined.Length - 4; p++)
        {
            if (U32(joined, p) == 0x06064b50) z64 = p;
        }
        W32(joined, z64 + 16, 0); W32(joined, z64 + 20, 0);
        int locator = joined.Length - 42;
        W32(joined, locator + 4, 0);
        BinaryPrimitives.WriteUInt64LittleEndian(joined.AsSpan(locator + 8), (ulong)z64);
        BinaryPrimitives.WriteUInt64LittleEndian(joined.AsSpan(z64 + 40), long.MaxValue);
        BinaryPrimitives.WriteUInt64LittleEndian(joined.AsSpan(z64 + 48), long.MaxValue);
        var plain = Parts(joined, 109, true);
        var d = FormatDetector.Detect(plain[0]);
        Assert.Null(d.Target);
        Assert.Contains("damaged", d.Message);
    }

    [Fact]
    public void Zip64LocatorCanCrossDiskBoundariesWithSentinelDiskNumbers()
    {
        byte[] original = Archive();
        var paths = Spanned(original, 97, true);
        Assert.True(new FileInfo(paths[^1]).Length < 42); // locator begins on the preceding disk
        foreach (string path in new[] { paths[0], paths[paths.Count / 2], paths[^1] })
        {
            var d = FormatDetector.Detect(path);
            Assert.True(d.Target is not null, d.Message);
            Assert.Equal(ZipCryptoSample.Extract(original).HashLines, d.Target.HashLines);
        }
    }

    [Fact]
    public void SingleZipAtTheClassicEntryCountLimitDoesNotRequireZip64()
    {
        using var bytes = new MemoryStream();
        using (var archive = new ZipArchive(bytes, ZipArchiveMode.Create, leaveOpen: true))
            for (int i = 0; i < ushort.MaxValue; i++) archive.CreateEntry($"{i}.txt");
        byte[] data = bytes.ToArray();
        int end = data.Length - 22;
        if (U32(data, end - 20) == 0x07064b50)
        {
            int z64 = checked((int)BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(end - 12)));
            byte[] footer = data[end..];
            W32(footer, 12, (long)BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(z64 + 40)));
            W32(footer, 16, (long)BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(z64 + 48)));
            data = data[..z64].Concat(footer).ToArray();
        }
        using var classic = new MemoryStream(data);
        Assert.NotEqual(0x07064b50u, U32(data, data.Length - 42));
        var entries = ZipExtractor.ReadCentralDirectory(classic, out _, out _, out _);
        Assert.Equal(ushort.MaxValue, entries.Count);
    }

}
