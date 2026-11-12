using System.Buffers.Binary;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public sealed class BinaryWordRestrictionsTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-doc").FullName;

    [Theory]
    [InlineData("forms.doc", null)]
    [InlineData("write-reservation.doc", "kit42")]
    public async Task SavesSameSizeCompoundFileAndPreservesDocumentContents(string fixture, string? password)
    {
        string source = Fixture(fixture);
        byte[] original = File.ReadAllBytes(source);
        var detection = FormatDetector.Detect(source);
        Assert.Null(detection.Target);
        var unlock = Assert.Single(detection.Unlocks);
        Assert.Equal(password, unlock.Password);
        string output = Path.Combine(_dir, "unrestricted.doc");
        await unlock.SaveAsync(source, output);
        Assert.Empty(FormatDetector.Detect(output).Unlocks);
        Assert.Equal(original, File.ReadAllBytes(source));
        Assert.Equal(original.Length, new FileInfo(output).Length);
        using var a = File.OpenRead(source);
        using var b = File.OpenRead(output);
        var before = new CompoundFile(a);
        var after = new CompoundFile(b);
        Assert.Equal(before.Entries, after.Entries);
        foreach (var entry in before.Entries.Where(e => e.Type == 2 && e.Name is not ("WordDocument" or "1Table")))
            Assert.Equal(before.ReadStream(entry.Name), after.ReadStream(entry.Name));
        var wd = after.ReadStream("WordDocument")!;
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(wd.AsSpan(10)) & 0x0c00);
        Assert.Equal(before.ReadStream("WordDocument")!.AsSpan(512).ToArray(), wd.AsSpan(512).ToArray());
        var table = after.ReadStream("1Table")!;
        int dop = (int)BinaryPrimitives.ReadUInt32LittleEndian(wd.AsSpan(0x192));
        Assert.Equal(0, table[dop + 6] & 0x10);
        Assert.Equal(0, table[dop + 7] & 0x42);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(table.AsSpan(dop + 78)));
    }

    [Fact]
    public void TruncatedFibIsReportedWithoutUnlock()
    {
        string path = Fixture("forms.doc");
        byte[] bytes = File.ReadAllBytes(path);
        int start = bytes.AsSpan().IndexOf(new byte[] { 0xec, 0xa5, 0x01, 0x01 });
        Assert.True(start > 0);
        bytes[start + 32] = 0xff;
        bytes[start + 33] = 0xff;
        File.WriteAllBytes(path, bytes);
        var detection = FormatDetector.Detect(path);
        Assert.Empty(detection.Unlocks);
        Assert.Contains("damaged", detection.Message);
    }

    [Theory]
    [InlineData(0x10, 0, false)]
    [InlineData(0, 0x40, false)]
    [InlineData(0, 0, true)]
    public async Task ClearsCommentsRevisionsAndWord2003Enforcement(int comments, int revisions, bool modern)
    {
        string source = Fixture("forms.doc");
        byte[] bytes = File.ReadAllBytes(source);
        using (var input = File.OpenRead(source))
        {
            var cf = new CompoundFile(input);
            var wd = cf.ReadStream("WordDocument")!;
            var table = cf.ReadStream("1Table")!;
            int dop = (int)BinaryPrimitives.ReadUInt32LittleEndian(wd.AsSpan(0x192));
            // The fixture's contiguous mini sectors let us locate properties independently of the writer.
            int physical = bytes.AsSpan().IndexOf(table.AsSpan(dop, 84));
            Assert.True(physical > 0);
            bytes[physical + 5] |= 0x20;
            bytes[physical + 6] = (byte)((bytes[physical + 6] & ~0x10) | comments);
            bytes[physical + 7] = (byte)((bytes[physical + 7] & ~0x42) | revisions | 0x20); // preserve VBA flag
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(physical + 78), 0x64ceed7e);
            if (modern)
            {
                bytes[physical + 594] |= 0x23;
                bytes[physical + 598] |= 0x38;
            }
        }
        File.WriteAllBytes(source, bytes);
        var unlock = Assert.Single(FormatDetector.Detect(source).Unlocks);
        Assert.Null(unlock.Password);
        string output = Path.Combine(_dir, "unrestricted.doc");
        await unlock.SaveAsync(source, output);
        using var saved = File.OpenRead(output);
        var result = new CompoundFile(saved);
        var doc = result.ReadStream("WordDocument")!;
        var data = result.ReadStream("1Table")!;
        int offset = (int)BinaryPrimitives.ReadUInt32LittleEndian(doc.AsSpan(0x192));
        Assert.Equal(0x20, data[offset + 7] & 0x20);
        Assert.Equal(0, data[offset + 5] & 0x20);
        Assert.Equal(0, data[offset + 6] & 0x10);
        Assert.Equal(0, data[offset + 7] & 0x42);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 78)));
        if (modern)
        {
            Assert.Equal(0, data[offset + 594] & 0x23);
            Assert.Equal(0x70, data[offset + 598] & 0x78);
        }
        Assert.Empty(FormatDetector.Detect(output).Unlocks);
    }

    private string Fixture(string name)
    {
        string path = Path.Combine(_dir, name);
        using var input = typeof(BinaryWordRestrictionsTests).Assembly.GetManifestResourceStream("RecoverKit.Tests.Fixtures.Word." + name)!;
        using var output = File.Create(path);
        input.CopyTo(output);
        return path;
    }

    public void Dispose() => Directory.Delete(_dir, true);
}
