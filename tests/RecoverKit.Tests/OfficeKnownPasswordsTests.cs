using System.IO.Compression;
using System.Buffers.Binary;
using System.Text;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

public class OfficeKnownPasswordsTests
{
    [Theory]
    [InlineData("agile-default.xlsx", "VelvetSweatshop", 9600, true)]
    [InlineData("agile-empty.xlsx", "", 9600, true)]
    [InlineData("agile-sha1-default.xlsx", "VelvetSweatshop", 9500, true)]
    [InlineData("agile-sha1-empty.xlsx", "", 9500, true)]
    [InlineData("standard-default.xlsx", "VelvetSweatshop", 9400, true)]
    [InlineData("standard-empty.xlsx", "", 9400, true)]
    [InlineData("lo-default.xls", "VelvetSweatshop", 9700, false)]
    [InlineData("rc4-default.xls", "VelvetSweatshop", 9700, false)]
    [InlineData("rc4-empty.xls", "", 9700, false)]
    [InlineData("cryptoapi-default.xls", "VelvetSweatshop", 9800, false)]
    [InlineData("cryptoapi-empty.xls", "", 9800, false)]
    [InlineData("cryptoapi40-default.xls", "VelvetSweatshop", 9800, false)]
    [InlineData("cryptoapi40-empty.xls", "", 9800, false)]
    [InlineData("cryptoapi-empty.doc", "", 9800, false)]
    public void FindsPasswordFromContent(string name, string password, int mode, bool canSave)
    {
        using var stream = new MemoryStream(Fixture(name));
        var d = new Detection { FilePath = "unrelated.bin" };
        OfficeExtractor.Extract(new CompoundFile(stream), d);
        Assert.Equal([mode], d.Target!.Modes);
        var unlock = Assert.Single(d.Unlocks);
        Assert.Equal(password, unlock.Password);
        Assert.Contains(password.Length == 0 ? "empty" : "built-in default", unlock.Description);
        Assert.Equal(canSave, unlock.SaveCopyAsync is not null);
        Assert.Equal(canSave, unlock.SaveLabel is not null);
        if (!canSave) Assert.Contains("not supported", unlock.Description);
    }

    [Theory]
    [InlineData("agile-other.xlsx")]
    [InlineData("standard-other.xlsx")]
    public void DoesNotOfferUnlockForAnotherPassword(string name)
    {
        using var stream = new MemoryStream(Fixture(name));
        var d = new Detection { FilePath = "test.bin" };
        OfficeExtractor.Extract(new CompoundFile(stream), d);
        Assert.NotNull(d.Target);
        Assert.Empty(d.Unlocks);
    }

    [Theory]
    [InlineData("agile-default.xlsx")]
    [InlineData("agile-empty.xlsx")]
    [InlineData("agile-sha1-default.xlsx")]
    [InlineData("agile-sha1-empty.xlsx")]
    [InlineData("standard-default.xlsx")]
    [InlineData("standard-empty.xlsx")]
    public async Task SavesOriginalPackageAtomically(string name)
    {
        var dir = Directory.CreateTempSubdirectory("rk-office-").FullName;
        try
        {
            var source = Path.Combine(dir, "source.bin");
            var output = Path.Combine(dir, "copy.xlsx");
            var original = Fixture(name);
            File.WriteAllBytes(source, original);
            var unlock = Assert.Single(FormatDetector.Detect(source).Unlocks);
            await Assert.ThrowsAsync<IOException>(() => unlock.SaveAsync(source, source));
            File.WriteAllText(output, "previous output");
            using (var cts = new CancellationTokenSource())
            {
                cts.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => unlock.SaveAsync(source, output, cts.Token));
                Assert.Equal("previous output", File.ReadAllText(output));
            }
            await unlock.SaveAsync(source, output);
            using var zip = ZipFile.OpenRead(output);
            Assert.NotNull(zip.GetEntry("xl/workbook.xml"));
            using var reader = new StreamReader(zip.GetEntry("xl/worksheets/sheet1.xml")!.Open());
            Assert.Contains("RecoverKit default password test", reader.ReadToEnd());
            Assert.Equal(original, File.ReadAllBytes(source));
            Assert.Equal(2, Directory.GetFiles(dir).Length);
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void CryptoApi128UsesHashcatType4AndFallsBackFrom40BitCpuKernel()
    {
        var d = Extract(Fixture("cryptoapi-default.xls"));
        Assert.StartsWith("$oldoffice$4*", d.Target!.HashLines);
        Assert.Null(Office2003Kernel.TryParse(d.Target.HashLines));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void RejectsMalformedAgileVerifiers(int kind)
    {
        string from = kind switch { 0 => "keyBits=\"256\"", 1 => "spinCount=\"100000\"", 2 => "blockSize=\"16\"", 3 => "saltSize=\"16\"", _ => "hashSize=\"64\"" };
        string to = kind switch { 0 => "keyBits=\"257\"", 1 => "spinCount=\"-00001\"", 2 => "blockSize=\"17\"", 3 => "saltSize=\"15\"", _ => "hashSize=\"63\"" };
        var bytes = ReplaceInfo("agile-default.xlsx", info => Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(info).Replace(from, to)));
        Assert.Throws<FormatException>(() => Extract(bytes));
    }

    [Theory]
    [InlineData(28, 257)]
    [InlineData(44, 15)]
    [InlineData(80, 19)]
    public void RejectsMalformedStandardVerifiers(int offset, int value)
    {
        var bytes = ReplaceInfo("standard-default.xlsx", info =>
        {
            BinaryPrimitives.WriteInt32LittleEndian(info.AsSpan(offset), value);
            return info;
        });
        Assert.Throws<FormatException>(() => Extract(bytes));
    }

    [Fact]
    public void BoundsUntrustedSpinCountWithoutLosingTarget()
    {
        var bytes = ReplaceInfo("agile-default.xlsx", info =>
        {
            var text = Encoding.UTF8.GetString(info).Replace("spinCount=\"100000\"", "spinCount=\"2147483647\"")
                .Replace("\n    ", "\n");
            return Encoding.UTF8.GetBytes(text.PadRight(info.Length, '\0'));
        });
        var d = Extract(bytes);
        Assert.NotNull(d.Target);
        Assert.Empty(d.Unlocks);
        Assert.Contains(d.Info, pair => pair.Key == "Instant unlock" && pair.Value.Contains("skipped"));
    }

    [Fact]
    public void DoesNotReadEncryptedPackageDuringDetection()
    {
        var bytes = Fixture("agile-default.xlsx");
        int entry = bytes.AsSpan().IndexOf(Encoding.Unicode.GetBytes("EncryptedPackage\0"));
        Assert.True(entry >= 0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(entry + 120), 128 * 1024 * 1024);
        using var stream = new CountingStream(bytes);
        var d = new Detection { FilePath = "large.bin" };
        OfficeExtractor.Extract(new CompoundFile(stream), d);
        Assert.Single(d.Unlocks);
        Assert.True(stream.BytesRead < 32 * 1024);
    }

    [Fact]
    public async Task FailedSaveKeepsDestinationAndCleansTemporaryFile()
    {
        string dir = Directory.CreateTempSubdirectory("rk-office-").FullName;
        try
        {
            string source = Path.Combine(dir, "source.xlsx"), output = Path.Combine(dir, "out.xlsx");
            File.WriteAllBytes(source, Fixture("agile-default.xlsx"));
            var unlock = Assert.Single(FormatDetector.Detect(source).Unlocks);
            File.WriteAllBytes(source, Fixture("agile-other.xlsx"));
            File.WriteAllText(output, "previous copy");
            await Assert.ThrowsAsync<UnsupportedFormatException>(() => unlock.SaveAsync(source, output));
            Assert.Equal("previous copy", File.ReadAllText(output));
            Assert.Equal(2, Directory.GetFiles(dir).Length);
        }
        finally { Directory.Delete(dir, true); }
    }

    private sealed class CountingStream(byte[] bytes) : MemoryStream(bytes)
    {
        public long BytesRead { get; private set; }
        public override int Read(Span<byte> buffer)
        {
            int n = base.Read(buffer);
            BytesRead += n;
            return n;
        }
    }

    private static Detection Extract(byte[] bytes)
    {
        using var stream = new MemoryStream(bytes);
        var d = new Detection { FilePath = "test.bin" };
        OfficeExtractor.Extract(new CompoundFile(stream), d);
        return d;
    }

    private static byte[] ReplaceInfo(string name, Func<byte[], byte[]> change)
    {
        byte[] bytes = Fixture(name);
        using var stream = new MemoryStream(bytes);
        byte[] info = new CompoundFile(stream).ReadStream("EncryptionInfo")!;
        int offset = bytes.AsSpan().IndexOf(info);
        Assert.True(offset >= 0);
        byte[] changed = change(info);
        Assert.Equal(info.Length, changed.Length);
        changed.CopyTo(bytes, offset);
        return bytes;
    }

    private static byte[] Fixture(string name)
    {
        using var stream = typeof(OfficeKnownPasswordsTests).Assembly.GetManifestResourceStream(
            "RecoverKit.Tests.Fixtures.Office." + name)!;
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }
}
