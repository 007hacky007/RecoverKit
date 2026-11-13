using System.Text;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public sealed class ZipLargeEntryTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-largezip").FullName;
    public void Dispose() => Directory.Delete(_dir, true);

    private Detection Detect(params ZipCryptoSample.Entry[] entries)
    {
        string path = Path.Combine(_dir, "sample.zip");
        File.WriteAllBytes(path, ZipCryptoSample.Archive(entries, "ab1"u8.ToArray(), new Random(7)));
        using var stream = File.OpenRead(path);
        var detection = new Detection { FilePath = path };
        ZipExtractor.Extract(stream, detection);
        return detection;
    }

    private static byte[] RandomData(int size)
    {
        var data = new byte[size];
        new Random(42).NextBytes(data);
        return data;
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void LargeEntriesProduceAModuleCompatiblePrefix(bool deflate, bool descriptor)
    {
        var d = Detect(new ZipCryptoSample.Entry("large.bin", RandomData(400_000), deflate, descriptor));
        var t = Assert.IsType<HashTarget>(d.Target);
        var fields = t.HashLines["$pkzip2$".Length..^"*$/pkzip2$".Length].Split('*');
        // module_17200/17210 skip the five full-data fields for data_type 1.
        Assert.Equal(9, fields.Length);
        Assert.Equal("1", fields[0]);
        Assert.Contains(fields[1], new[] { "1", "2" });
        Assert.Equal("1", fields[2]);
        Assert.Equal(deflate ? "8" : "0", fields[4]);
        int length = Convert.ToInt32(fields[5], 16);
        Assert.InRange(length, 12, 320 * 1024);
        Assert.Equal(256 * 1024, length);
        Assert.Equal(length * 2, fields[8].Length);
        Assert.All(fields[8], c => Assert.True(Uri.IsHexDigit(c)));
        Assert.Contains("Only the beginning", t.Notes);
        Assert.NotNull(t.ConfirmPassword);
        Assert.True(t.ConfirmPassword!("ab1"u8.ToArray()));
        Assert.False(t.ConfirmPassword("wrong"u8.ToArray()));
    }

    [Fact]
    public void ACompleteEntryIsChosenBeforeALargeDeflatedOne()
    {
        var d = Detect(new("large.bin", RandomData(400_000), true), new("small.txt", "small"u8.ToArray(), false));
        Assert.Contains(d.Info, p => p.Key == "Attacked entry" && p.Value.StartsWith("small.txt"));
        Assert.StartsWith("$pkzip2$1*1*2*", d.Target!.HashLines);
    }

    [Fact]
    public void PartialConfirmationReadsDataBeyondTheGpuPrefix()
    {
        var d = Detect(new ZipCryptoSample.Entry("large.bin", RandomData(400_000), false));
        Assert.NotNull(d.Target!.ConfirmPassword);
        Assert.True(d.Target.ConfirmPassword!("ab1"u8.ToArray()));
        using (var file = new FileStream(d.FilePath, FileMode.Open, FileAccess.ReadWrite))
        {
            file.Position = 300_000;
            int b = file.ReadByte();
            file.Position--;
            file.WriteByte((byte)(b ^ 1));
        }
        Assert.False(d.Target.ConfirmPassword("ab1"u8.ToArray()));
    }

    [Theory]
    [InlineData(320 * 1024, false)]
    [InlineData(320 * 1024 + 1, true)]
    public void FullEntryLimitIncludesTheEncryptionHeader(int encryptedLength, bool partial)
    {
        var target = Detect(new ZipCryptoSample.Entry("data.bin", RandomData(encryptedLength - 12), false)).Target!;
        Assert.Equal(partial, target.ZipPartial is not null);
        AssertModuleAccepts(target.HashLines, 0);
    }

    [Theory]
    [InlineData(65L * 1024 * 1024, false)]
    [InlineData(65L * 1024 * 1024, true)]
    [InlineData(3_000_000_000L, true)]
    public void LargeSparseEntriesPreserveExtractionAndStaySizeLimits(long encryptedLength, bool withSmallEntry)
    {
        // A sparse synthetic payload tests size limits without allocating or encrypting the large body.
        ZipCryptoSample.Entry large = new("large.bin", RandomData(400_000), false);
        byte[] original = ZipCryptoSample.Archive(withSmallEntry
            ? [new("small.txt", "small"u8.ToArray(), false), large] : [large], "ab1"u8, new Random(7));
        int directory = (int)BitConverter.ToUInt32(original, original.Length - 6);
        byte[] tail = original[directory..];
        int largeRecord = withSmallEntry ? 46 + "small.txt".Length : 0;
        BitConverter.TryWriteBytes(tail.AsSpan(largeRecord + 20), (uint)encryptedLength);
        BitConverter.TryWriteBytes(tail.AsSpan(largeRecord + 24), (uint)(encryptedLength - 12));
        int dataOffset = (int)BitConverter.ToUInt32(tail, largeRecord + 42) + 30 + "large.bin".Length;
        long newDirectory = dataOffset + encryptedLength;
        BitConverter.TryWriteBytes(tail.AsSpan(tail.Length - 6), (uint)newDirectory);
        string path = Path.Combine(_dir, "sparse.zip");
        using (var file = File.Create(path))
        {
            file.Write(original.AsSpan(0, directory));
            file.Position = newDirectory;
            file.Write(tail);
        }
        var detection = new Detection { FilePath = path };
        using (var file = File.OpenRead(path)) ZipExtractor.Extract(file, detection);
        if (withSmallEntry)
        {
            if (encryptedLength > int.MaxValue) Assert.Null(detection.Target!.StayZip);
            else
            {
                var payload = detection.Target!.StayZip!;
                Assert.Equal(2, payload.Entries.Count);
                Assert.Equal(encryptedLength, payload.Entries.Single(e => e.Name == "large.bin").CompSize);
            }
            Assert.Null(detection.Target.ZipPartial); // the small entry remains the normal password target
        }
        else Assert.Equal(encryptedLength, detection.Target!.ZipPartial!.CompressedLength);
        AssertModuleAccepts(detection.Target.HashLines, 0);
    }

    private static void AssertModuleAccepts(string line, int method)
    {
        // module_17200/17210 pkzip_decode_input: only full types carry lengths/CRC/offsets.
        Assert.StartsWith("$pkzip2$1*", line);
        Assert.EndsWith("*$/pkzip2$", line);
        var f = line["$pkzip2$".Length..^"*$/pkzip2$".Length].Split('*');
        Assert.Equal(1, int.Parse(f[0]));
        Assert.Contains(int.Parse(f[1]), new[] { 1, 2 });
        int type = int.Parse(f[2]);
        Assert.InRange(type, 0, 3);
        _ = int.Parse(f[3]); // magic type, accepted unchanged by the module
        int i = 4;
        if (type > 1)
        {
            Assert.InRange(Convert.ToUInt32(f[i++], 16), 12u, 320u * 1024);
            _ = Convert.ToUInt32(f[i++], 16); // uncompressed length
            _ = Convert.ToUInt32(f[i++], 16); // CRC-32
            _ = Convert.ToUInt32(f[i++], 16); // offset
            _ = Convert.ToUInt32(f[i++], 16); // additional offset
        }
        Assert.Equal(method, int.Parse(f[i++]));
        int length = Convert.ToInt32(f[i++], 16);
        Assert.InRange(length, 12, 320 * 1024);
        _ = Convert.ToUInt16(f[i++], 16);
        _ = Convert.ToUInt16(f[i++], 16);
        Assert.Equal(length * 2, f[i].Length);
        Assert.True(f[i].Length <= 320 * 1024 * 2 && f[i].Length % 2 == 0);
        Assert.Equal(length, Convert.FromHexString(f[i]).Length);
        Assert.Equal(i + 1, f.Length);
    }
}
