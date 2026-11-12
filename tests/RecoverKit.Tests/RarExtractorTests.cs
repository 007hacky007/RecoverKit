using System.Buffers.Binary;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class RarExtractorTests
{
    private const string Stored = "$RAR3$*1*e54a73729887cb53*49b0a846*16*14*1*34620bcca8176642a210b1051901921e*30";
    private const string Compressed = "$RAR3$*1*ad56eb40219c9da2*834064ce*32*13*1*eb47b1abe17a1a75bce6c92ab1cef3f4126035ea95deaf08b3f32a0c7b8078e1*33";

    [Theory]
    [InlineData(Stored, 23700)]
    [InlineData(Compressed, 23800)]
    public void ProducesHashcatExampleHash(string hash, int mode)
    {
        var d = Extract(Archive(Entry(hash)));
        Assert.NotNull(d.Target);
        Assert.Equal(hash, d.Target.HashLines);
        Assert.Equal([mode], d.Target.Modes);
        Assert.Equal("RAR3", d.Target.FormatId);
        Assert.Equal(128, d.Target.MaxPasswordLength);
        Assert.Contains(new("Encrypted file names", "no"), d.Info);
    }

    [Theory]
    [InlineData(0x31)]
    [InlineData(0x32)]
    [InlineData(0x34)]
    [InlineData(0x35)]
    public void AllCompressionMethodsUseCompressedMode(byte method)
    {
        var entry = Entry(Compressed);
        entry[25] = method;
        Assert.Equal([23800], Extract(Archive(entry)).Target!.Modes);
    }

    [Fact]
    public void HandlesSfxLargeSizeFieldsAndExtendedTimes()
    {
        var d = Extract([0x4d, 0x5a, .. new byte[126], .. Archive(Entry(Stored, extraFlags: 0x1300))]);
        Assert.Equal(Stored, d.Target!.HashLines);
        Assert.Contains(new("Self-extracting prefix", "128 bytes"), d.Info);
    }

    [Fact]
    public void SkipsPlaintextDirectoriesSolidAndSplitEntries()
    {
        var plain = Entry(Stored); Set16(plain, 3, 0x8400);
        var d = Extract(Archive(plain, Entry(Stored, extraFlags: 0xe0),
            Entry(Stored, extraFlags: 0x10), Entry(Stored, extraFlags: 1),
            Entry(Stored, extraFlags: 2), Entry(Compressed)));
        Assert.Equal(Compressed, d.Target!.HashLines);
    }

    [Fact]
    public void PrefersStoredEntryEvenIfItIsLarger()
    {
        var stored = Entry(Stored, packed: 48, unpacked: 40);
        var d = Extract(Archive(Entry(Compressed), stored));
        Assert.Equal([23700], d.Target!.Modes);
        Assert.Contains("*48*40*1*", d.Target.HashLines);
    }

    [Fact]
    public void SelectsSmallestUsableEntry()
    {
        var d = Extract(Archive(Entry(Compressed, packed: 48), Entry(Compressed)));
        Assert.Equal(Compressed, d.Target!.HashLines);
    }

    [Theory]
    [InlineData(327536, 14)] // hashcat's hex token limit is stricter than its buffer limit
    [InlineData(16, 655361)]
    [InlineData(0, 14)]
    [InlineData(16, 0)]
    [InlineData(17, 14)]
    public void SkipsEntriesOutsideHashcatLimits(int packed, int unpacked)
    {
        var d = Extract(Archive(Entry(Compressed, packed: packed, unpacked: unpacked), Entry(Stored)));
        Assert.Equal(Stored, d.Target!.HashLines);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(0x10)]
    [InlineData(0xe0)]
    public void UnsupportedEncryptedEntriesAreNotReportedAsUnprotected(ushort flags)
    {
        var d = Extract(Archive(Entry(Stored, extraFlags: flags)));
        Assert.Null(d.Target);
        Assert.Contains("encrypted", d.Message!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("not password protected", d.Message!);
    }

    [Fact]
    public void SkipsUnsupportedEncryptionAndCompressionVersions()
    {
        var old = Entry(Stored); old[24] = 20;
        var method = Entry(Stored); method[25] = 0x36;
        var noSalt = Entry(Stored); Set16(noSalt, 3, 0x8004);
        Assert.Equal(Compressed, Extract(Archive(old, method, noSalt, Entry(Compressed))).Target!.HashLines);
    }

    [Fact]
    public void UnencryptedArchiveHasNoTarget()
    {
        var entry = Entry(Stored); Set16(entry, 3, 0x8400);
        var d = Extract(Archive(entry));
        Assert.Null(d.Target);
        Assert.Equal("Archive is not password protected.", d.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void RejectsMalformedHeadersAndData(int kind)
    {
        var entry = Entry(Stored);
        byte[] archive;
        switch (kind)
        {
            case 0: Set16(entry, 5, 6); archive = Archive(entry); break;
            case 1: Set16(entry, 26, 0xffff); archive = Archive(entry); break;
            case 2: archive = Archive(entry)[..^10]; break;
            case 3: Set16(entry, 5, 0xffff); archive = Archive(entry); break;
            default: archive = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00, 0, 0]; break;
        }
        Assert.Throws<FormatException>(() => Extract(archive));
    }

    [Fact]
    public void PreservesEncryptedHeaderMode()
    {
        byte[] main = new byte[13]; main[2] = 0x73; Set16(main, 3, 0x80); Set16(main, 5, 13);
        var d = Extract([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0, .. main,
            .. Convert.FromHexString("45109af8ab5f297aadbf6c5385d7a40373e8f77d7b89d317")]);
        Assert.Equal([12500], d.Target!.Modes);
        Assert.Equal("$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317", d.Target.HashLines);
    }

    [Fact]
    public void EncryptedHeadersUseEndOfArchiveBlock()
    {
        // WinRAR 6.24: rar a -ma4 -hpab1 hp.rar a.txt
        var d = Extract(Convert.FromHexString(
            "526172211a0700ce997380000d000000000000003a94df521d0214a7db167c1b7727e42ae95c6b1cc9b3367c55500f7634a03d4075f2d5479a79e2002efbd35ec85f87d13b77594bc34546fc08b2c05a5783fe8ba7390147422ed97bca9b8acec6faaf99bce7b8062809d7a8167366e88e92d89bdf350c3634acfa0cd7d702eac1ecdbdfcd32c3f6a0c0dae3c2adcc7deb71d1b9cd96fc1a8305e1953a94df521d0214a716445717853d420c627bc11af1e2b1b1"));
        Assert.Equal("$RAR3$*0*3a94df521d0214a7*16445717853d420c627bc11af1e2b1b1", d.Target!.HashLines);
        var k = RecoverKit.Core.Native.Kernels.Rar3Kernel.TryParse(d.Target.HashLines)!;
        Assert.True(k.Verify("ab1"u8));
        Assert.False(k.Verify("ab2"u8));
    }

    [Theory]
    [InlineData(23700, 20, true)]
    [InlineData(23700, 21, false)]
    [InlineData(23800, 20, true)]
    [InlineData(23800, 21, false)]
    [InlineData(12500, 27, true)]
    [InlineData(12500, 28, false)]
    public void UsesPureKernelForPasswordsBeyondOptimizedLimit(int mode, int length, bool expected)
    {
        var attack = new AttackSpec { MaxLength = length };
        Assert.Equal(expected, RecoverySession.CanUseOptimizedKernel(mode, attack));
        attack.Kind = AttackKind.Mask;
        attack.HashcatMask = new string('a', length);
        Assert.Equal(expected, RecoverySession.CanUseOptimizedKernel(mode, attack));
        attack.Kind = AttackKind.Dictionary;
        Assert.False(RecoverySession.CanUseOptimizedKernel(mode, attack));
    }

    [Theory]
    [InlineData(327520, 655360, true)]
    [InlineData(327536, 655360, false)]
    [InlineData(327520, 655361, false)]
    public void EnforcesHashcatSizeBoundaries(int packed, int unpacked, bool usable)
    {
        var d = Extract(Archive(Entry(Compressed, packed: packed, unpacked: unpacked)));
        Assert.Equal(usable, d.Target is not null);
        if (!usable) Assert.Contains("encrypted", d.Message!);
    }

    [Theory]
    [InlineData(32)]
    [InlineData(36)]
    public void DoesNotIgnoreHighSizeWords(int highOffset)
    {
        var entry = Entry(Compressed, extraFlags: 0x100);
        BinaryPrimitives.WriteUInt32LittleEndian(entry.AsSpan(highOffset), 1);
        if (highOffset == 32)
            Assert.Throws<FormatException>(() => Extract(Archive(entry)));
        else
            Assert.Null(Extract(Archive(entry)).Target);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void PrefersReliableEntryOverTinyStoredFile(bool tinyFirst)
    {
        var tiny = Entry(Stored, unpacked: 1);
        var normal = Entry(Compressed);
        var d = Extract(tinyFirst ? Archive(tiny, normal) : Archive(normal, tiny));
        Assert.Equal(Compressed, d.Target!.HashLines);
    }

    [Fact]
    public void WarnsWhenOnlyTinyEntriesCanBeUsed()
    {
        var d = Extract(Archive(Entry(Stored, unpacked: 1)));
        Assert.NotNull(d.Target);
        Assert.Contains("false positive", d.Target.Notes!);
    }

    private static Detection Extract(byte[] bytes)
    {
        var d = new Detection { FilePath = "test.rar" };
        using var stream = new MemoryStream(bytes);
        RarExtractor.Extract(stream, d);
        return d;
    }

    private static byte[] Archive(params byte[][] entries)
    {
        byte[] main = new byte[13]; main[2] = 0x73; Set16(main, 5, 13);
        return [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0, .. main,
            .. entries.SelectMany(e => e), 0, 0, 0x7b, 0, 0, 7, 0];
    }

    // Reconstruct headers around hashcat's published ciphertext, CRC and salt.
    private static byte[] Entry(string hash, ushort extraFlags = 0, int? packed = null, int? unpacked = null)
    {
        var f = hash.Split('*');
        int pack = packed ?? int.Parse(f[4]), unp = unpacked ?? int.Parse(f[5]);
        int nameOffset = (extraFlags & 0x100) != 0 ? 40 : 32;
        int size = nameOffset + 8 + 8 + ((extraFlags & 0x1000) != 0 ? 6 : 0);
        var entry = new byte[size + pack];
        entry[2] = 0x74; Set16(entry, 3, (ushort)(0x8404 | extraFlags)); Set16(entry, 5, (ushort)size);
        BinaryPrimitives.WriteUInt32LittleEndian(entry.AsSpan(7), (uint)pack);
        BinaryPrimitives.WriteUInt32LittleEndian(entry.AsSpan(11), (uint)unp);
        entry[15] = 3; Convert.FromHexString(f[3]).CopyTo(entry, 16);
        entry[24] = 29; entry[25] = Convert.ToByte(f[8], 16); Set16(entry, 26, 8);
        "file.txt"u8.CopyTo(entry.AsSpan(nameOffset));
        Convert.FromHexString(f[2]).CopyTo(entry, nameOffset + 8);
        var data = Convert.FromHexString(f[7]);
        data.AsSpan(0, Math.Min(data.Length, pack)).CopyTo(entry.AsSpan(size));
        return entry;
    }

    private static void Set16(byte[] b, int offset, ushort value)
        => BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(offset), value);
}
