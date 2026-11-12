using System.Buffers.Binary;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class OfficeXorTests
{
    [Theory]
    [InlineData("poi-xor-abc.xls", "abc", "MS Excel 97-2003 workbook")]
    [InlineData("excel95-kit95.xls", "kit95", "MS Excel 5/95 workbook")]
    [InlineData("excel95-long-user.xls", "beccffbe", "MS Excel 5/95 workbook")]
    [InlineData("word6-kit6.doc", "kit6", "MS Word 6/95 document")]
    [InlineData("word95-word95.doc.gz", "word95", "MS Word 6/95 document")]
    [InlineData("word97-long.doc", "OfficeXor2026!a", "MS Word 97-2003 document")]
    public void RecoversPasswordFromRealFileData(string fixture, string password, string type)
    {
        using var stream = Fixture(fixture);
        var detection = new Detection { FilePath = "renamed.bin" };
        OfficeExtractor.Extract(new CompoundFile(stream), detection);
        var unlock = Assert.Single(detection.Unlocks);
        Assert.Equal(password, unlock.Password);
        Assert.Equal(type, detection.TypeName);
        Assert.Null(unlock.SaveCopyAsync);
        Assert.Null(detection.Target);
    }

    [Theory]
    [InlineData("abc", 0x514a, 0xcc1a)] // Apache POI TestXorEncryption
    [InlineData("Example", 0x64ce, 0xed7e)] // MS-OFFCRYPTO Method 2 example
    public void MatchesPublishedKeyAndVerifier(string password, ushort key, ushort verifier)
    {
        var bytes = System.Text.Encoding.ASCII.GetBytes(password);
        Assert.Equal(key, OfficeXor.Key(bytes));
        Assert.Equal(verifier, OfficeXor.Verifier(bytes));
    }

    [Fact]
    public void DetectsByContentAfterRenaming()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".bin");
        try
        {
            using (var source = Fixture("poi-xor-abc.xls"))
            using (var output = File.Create(path)) source.CopyTo(output);
            Assert.Equal("abc", Assert.Single(FormatDetector.Detect(path).Unlocks).Password);
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(0x65)]
    [InlineData(0x66)]
    [InlineData(0x67)]
    [InlineData(0x68)]
    [InlineData(0x69)]
    public void RecognizesWord6And95FibVersions(ushort version)
    {
        using var source = Fixture("word6-kit6.doc");
        var word = new CompoundFile(source).ReadStream("WordDocument")!;
        Set16(word, 2, version);
        var d = Extract("WordDocument", word);
        Assert.Equal("MS Word 6/95 document", d.TypeName);
        Assert.Equal("kit6", Assert.Single(d.Unlocks).Password);
    }

    [Fact]
    public void UnprotectedWord6DoesNotRequireTableStream()
    {
        var word = new byte[68]; Set16(word, 0, 0xa5dc); Set16(word, 2, 0x65);
        var d = Extract("WordDocument", word);
        Assert.Empty(d.Unlocks);
        Assert.Contains("not password protected", d.Message);
        Assert.Contains("6/95", d.TypeName);
    }

    [Fact]
    public void UnprotectedBiff5UsesBookStream()
    {
        var d = Extract("Book", [.. Bof(0x500), .. Record(0xa, [])]);
        Assert.Equal("MS Excel 5/95 workbook", d.TypeName);
        Assert.Empty(d.Unlocks);
        Assert.Contains("not password protected", d.Message);
    }

    [Theory]
    [InlineData(0x500)]
    [InlineData(0x600)]
    public void HeaderVerifierAloneDoesNotProduceAnUnlock(ushort version)
    {
        byte[] filepass = version == 0x500 ? [0x4a, 0x51, 0x1a, 0xcc] : [0, 0, 0x4a, 0x51, 0x1a, 0xcc];
        var d = Extract("Book", [.. Bof(version), .. Record(0x2f, filepass), .. Record(0xa, [])]);
        Assert.Empty(d.Unlocks);
        Assert.Null(d.Target);
        Assert.Contains("collision", d.Message);
    }

    [Theory]
    [InlineData("a", 0x500)]
    [InlineData("ab", 0x500)]
    [InlineData("0123456789abcde", 0x500)]
    [InlineData("Spaces & !", 0x500)]
    [InlineData("qzh1llaw", 0x500)]
    [InlineData("kspv94yc", 0x500)]
    [InlineData("a", 0x600)]
    [InlineData("0123456789abcde", 0x600)]
    public void RecoversOneThroughFifteenCharacterPasswordsFromWriteAccess(string password, ushort version)
    {
        // The last sixteen padding spaces expose all sixteen XOR array bytes
        // (independent fixture encoder, with a valid empty user name).
        var bytes = System.Text.Encoding.ASCII.GetBytes(password);
        ushort key = ReferenceKey(bytes), verifier = ReferenceVerifier(bytes);
        bool old = version == 0x500;
        var access = new byte[old ? 32 : 112];
        int end = 12 + (old ? 8 : 10) + 4 + access.Length;
        byte[] pad = Convert.FromHexString("bbffffbaffffb98000be0f00bf0f0000");
        for (int i = 0; i < access.Length; i++)
        {
            int index = (end + i) & 15;
            int value = index < bytes.Length ? bytes[index] : pad[index - bytes.Length];
            value ^= (key >> ((index & 1) * 8)) & 255;
            int xor = ((value << 2) | (value >> 6)) & 255;
            value = (i < (old ? 1 : 3) ? 0 : 0x20) ^ xor;
            access[i] = (byte)((value >> 3) | (value << 5));
        }
        byte[] pass = new byte[4]; Set16(pass, 0, key); Set16(pass, 2, verifier);
        var d = Extract("Book", [.. Bof(version), .. Record(0x2f, old ? pass : [0, 0, .. pass]),
            .. Record(0x5c, access), .. Record(0xa, [])]);
        Assert.Equal(password, Assert.Single(d.Unlocks).Password);
    }

    [Fact]
    public void DifferentPasswordsCanHaveTheSameKeyAndVerifier()
    {
        // These collide in both stored fields but require different XOR arrays.
        Assert.Equal(OfficeXor.Key("qzh1llaw"u8), OfficeXor.Key("kspv94yc"u8));
        Assert.Equal(OfficeXor.Verifier("qzh1llaw"u8), OfficeXor.Verifier("kspv94yc"u8));
    }

    [Theory]
    [InlineData(0x500, 0)]
    [InlineData(0x500, 2)]
    [InlineData(0x500, 6)]
    [InlineData(0x600, 0)]
    [InlineData(0x600, 1)]
    [InlineData(0x600, 4)]
    [InlineData(0x600, 8)]
    public void RejectsInvalidFilepassLengths(ushort version, int length)
        => Assert.Throws<FormatException>(() => Extract("Book", [.. Bof(version), .. Record(0x2f, new byte[length])]));

    [Fact]
    public void RejectsTruncatedBiffRecord()
        => Assert.Throws<FormatException>(() => Extract("Book", [.. Bof(0x500), 0x2f, 0, 4, 0, 0, 0]));

    [Fact]
    public void RejectsTruncatedRecordAfterFilepass()
        => Assert.Throws<FormatException>(() => Extract("Book", [.. Bof(0x500),
            .. Record(0x2f, [0x4a, 0x51, 0x1a, 0xcc]), 0x31, 0, 16, 0, 0]));

    [Fact]
    public void RejectsTruncatedFib()
        => Assert.Throws<FormatException>(() => Extract("WordDocument", [0xdc, 0xa5, 0x65, 0]));

    [Fact]
    public void PreservesBiff8Rc4Extraction()
    {
        byte[] header = [1, 0, 1, 0, 1, 0, .. new byte[48]];
        var d = Extract("Workbook", [.. Bof(0x600), .. Record(0x2f, header)]);
        Assert.Empty(d.Unlocks);
        Assert.Equal([9700], d.Target!.Modes);
    }

    private static Detection Extract(string name, byte[] bytes)
    {
        using var stream = new MemoryStream(Compound(name, bytes));
        var d = new Detection { FilePath = "sample.bin" };
        OfficeExtractor.Extract(new CompoundFile(stream), d);
        return d;
    }

    private static byte[] Bof(ushort version)
    {
        var b = new byte[8]; Set16(b, 0, version); Set16(b, 2, 5);
        return Record(0x809, b);
    }

    private static byte[] Record(ushort type, byte[] data)
    {
        var b = new byte[4 + data.Length]; Set16(b, 0, type); Set16(b, 2, (ushort)data.Length);
        data.CopyTo(b, 4); return b;
    }

    private static ushort ReferenceKey(byte[] password)
    {
        // Standard CRC-16/CCITT, deliberately expressed as a polynomial remainder.
        uint value = 0xffff;
        foreach (byte c in password)
        {
            value = (value << 8) ^ ((uint)c << 16);
            for (int bit = 23; bit >= 16; bit--)
                if ((value & (1u << bit)) != 0) value ^= 0x11021u << (bit - 16);
        }
        return (ushort)value;
    }

    private static ushort ReferenceVerifier(byte[] password)
    {
        int hash = password.Length ^ 0xce4b;
        for (int i = 0; i < password.Length; i++)
        {
            int shift = (i + 1) % 15;
            hash ^= ((password[i] << shift) | (password[i] >> (15 - shift))) & 0x7fff;
        }
        return (ushort)hash;
    }

    private static byte[] Compound(string name, byte[] data)
    {
        // A single-stream CFB, using mini sectors for small parser edge cases.
        bool mini = data.Length < 4096;
        int sectors = Math.Max(1, (data.Length + 511) / 512), first = mini ? 3 : 2;
        var b = new byte[(first + sectors + 1) * 512];
        Convert.FromHexString("d0cf11e0a1b11ae1").CopyTo(b, 0);
        Set16(b, 24, 0x3e); Set16(b, 26, 3); Set16(b, 28, 0xfffe);
        Set16(b, 30, 9); Set16(b, 32, 6);
        Set32(b, 44, 1); Set32(b, 48, 1); Set32(b, 56, 4096);
        Set32(b, 60, mini ? 2u : 0xfffffffe); Set32(b, 64, mini ? 1u : 0);
        Set32(b, 68, 0xfffffffe);
        for (int i = 0; i < 109; i++) Set32(b, 76 + i * 4, i == 0 ? 0 : 0xffffffff);
        for (int i = 0; i < 128; i++) Set32(b, 512 + i * 4, 0xffffffff);
        Set32(b, 512, 0xfffffffd); Set32(b, 516, 0xfffffffe);
        if (mini) Set32(b, 520, 0xfffffffe);
        for (int i = 0; i < sectors; i++)
            Set32(b, 512 + (first + i) * 4, i + 1 < sectors ? (uint)(first + i + 1) : 0xfffffffe);
        Entry(1024, "Root Entry", 5, mini ? (uint)first : 0xfffffffe, mini ? sectors * 512 : 0);
        Entry(1152, name, 2, mini ? 0 : (uint)first, data.Length);
        if (mini)
            for (int i = 0; i < 128; i++)
                Set32(b, 1536 + i * 4, i + 1 < (data.Length + 63) / 64 ? (uint)(i + 1) : 0xfffffffe);
        data.CopyTo(b, (first + 1) * 512);
        return b;

        void Entry(int offset, string label, byte type, uint start, int size)
        {
            var text = System.Text.Encoding.Unicode.GetBytes(label + '\0'); text.CopyTo(b, offset);
            Set16(b, offset + 64, (ushort)text.Length); b[offset + 66] = type; b[offset + 67] = 1;
            Set32(b, offset + 68, 0xffffffff); Set32(b, offset + 72, 0xffffffff);
            Set32(b, offset + 76, type == 5 ? 1u : 0xffffffff);
            Set32(b, offset + 116, start); Set32(b, offset + 120, (uint)size);
        }
    }

    private static void Set16(byte[] b, int offset, ushort value)
        => BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(offset), value);
    private static void Set32(byte[] b, int offset, uint value)
        => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(offset), value);

    private static Stream Fixture(string name)
    {
        var resource = typeof(OfficeXorTests).Assembly.GetManifestResourceStream(
            "RecoverKit.Tests.Fixtures.OfficeXor." + name)!;
        if (!name.EndsWith(".gz")) return resource;
        using var compressed = new System.IO.Compression.GZipStream(resource, System.IO.Compression.CompressionMode.Decompress);
        var stream = new MemoryStream(); compressed.CopyTo(stream); stream.Position = 0;
        return stream;
    }
}
