using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using RecoverKit.Core;
using RecoverKit.Core.Formats;
using Xunit;

namespace RecoverKit.Tests;

public class KeePassExtractorTests
{
    [Theory]
    [InlineData("v1.kdb", 13400)]
    [InlineData("v1-twofish.kdb", 13400)]
    [InlineData("v3.kdbx", 13400)]
    [InlineData("v4-argon2.kdbx", 34300)]
    [InlineData("v4-argon2id.kdbx", 34300)]
    [InlineData("v4-twofish.kdbx", 34300)]
    public void DetectsByContentWithoutExtension(string fixture, int mode)
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, Fixture(fixture));
            var d = FormatDetector.Detect(path);
            Assert.NotNull(d.Target);
            Assert.Equal(mode, Assert.Single(d.Target.Modes));
            Assert.StartsWith("$keepass$*", d.Target.HashLines);
            Assert.Equal(256, d.Target.MaxPasswordLength);
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("v1.kdb")]
    [InlineData("v1-key.kdb")]
    [InlineData("v1-twofish.kdb")]
    [InlineData("v3.kdbx")]
    [InlineData("v3-key.kdbx")]
    [InlineData("v4-argon2.kdbx")]
    [InlineData("v4-argon2-key.kdbx")]
    [InlineData("v4-argon2id.kdbx")]
    [InlineData("v4-argon2id-key.kdbx")]
    [InlineData("v4-twofish.kdbx")]
    public void MatchesReferenceHash(string fixture)
    {
        string keyfile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(keyfile, Enumerable.Range(0, 32).Select(x => (byte)x).ToArray());
            var d = Extract(Fixture(fixture), fixture.Contains("-key") ? keyfile : null);
            Assert.Equal(Encoding.ASCII.GetString(Fixture(fixture + ".hash")).Trim(), d.Target!.HashLines);
            Assert.Equal(SpeedClass.VerySlow, d.Target.Speed);
            Assert.False(d.Target.Utf16Password);
            Assert.Contains(fixture.StartsWith("v4") ? "memory-hard" : "keyfile", d.Target.Notes!);
        }
        finally { File.Delete(keyfile); }
    }

    [Theory]
    [InlineData("v1.kdb", 140)]
    [InlineData("v3.kdbx", 254)]
    [InlineData("v4-argon2.kdbx", 317)]
    public void EveryTruncationOfRequiredHeaderDataThrowsFormatException(string fixture, int required)
    {
        var data = Fixture(fixture);
        for (int n = 0; n < required; n++)
            Assert.Throws<FormatException>(() => Extract(data[..n]));
    }

    [Theory]
    [InlineData("v4-aeskdf.kdbx", "AES-KDF")]
    [InlineData("v4-chacha.kdbx", "249-byte header")]
    public void UnsupportedCombinationsHaveClearMessages(string fixture, string message)
        => Assert.Contains(message, Assert.Throws<UnsupportedFormatException>(() => Extract(Fixture(fixture))).Message);

    [Fact]
    public void TinyPasswordOnlyKdbReportsHashcatParserLimitation()
        => Assert.Contains("32 encrypted bytes", Assert.Throws<UnsupportedFormatException>(() => Extract(Fixture("v1.kdb")[..156])).Message);

    [Fact]
    public void TinyKdbRemainsRecognizedSoTheGuiCanOfferAKeyfile()
    {
        string database = Path.GetTempFileName(), keyfile = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(database, Fixture("v1-key.kdb")[..156]);
            File.WriteAllBytes(keyfile, new byte[32]);
            var first = FormatDetector.Detect(database);
            Assert.Null(first.Target);
            Assert.StartsWith("KeePass", first.TypeName);
            Assert.NotNull(FormatDetector.Detect(database, keyfile).Target);
        }
        finally { File.Delete(database); File.Delete(keyfile); }
    }

    [Fact]
    public void CorruptV4HeaderChecksumIsRejected()
    {
        var data = Fixture("v4-argon2.kdbx"); data[253] ^= 1;
        Assert.Contains("checksum", Assert.Throws<FormatException>(() => Extract(data)).Message);
    }

    [Fact]
    public void CustomV4HeaderLengthIsRejectedWithoutTruncatingIt()
    {
        var original = Fixture("v4-argon2.kdbx");
        int end = FieldOffset(original, 0) - 5;
        byte[] data = [.. original[..end], 1, 0, 0, 0, 0, .. original[end..]];
        SHA256.HashData(data.AsSpan(0, 258)).CopyTo(data, 258);
        Assert.Contains("258-byte header", Assert.Throws<UnsupportedFormatException>(() => Extract(data)).Message);
    }

    [Fact]
    public void AKeyfileCannotBeSilentlyIgnoredForAnotherFormat()
    {
        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, "%PDF-1.7\n");
            var d = FormatDetector.Detect(path, "unused-keyfile");
            Assert.Null(d.Target);
            Assert.Contains("only be used with a KeePass", d.Message);
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData("v3.kdbx", 3)]
    [InlineData("v4-argon2.kdbx", 5)]
    public void OversizedOrNegativeHeaderLengthsAreRejected(string fixture, int sizeBytes)
    {
        var data = Fixture(fixture);
        data.AsSpan(13, sizeBytes - 1).Fill(0xff);
        Assert.Throws<FormatException>(() => Extract(data));
    }

    [Theory]
    [InlineData("I", 0)]
    [InlineData("I", 100000)]
    [InlineData("P", 33)]
    [InlineData("V", 18)]
    [InlineData("M", 4294967296)]
    [InlineData("M", 8192)]
    public void UnsupportedArgonParametersAreRejected(string parameter, ulong value)
    {
        var data = Fixture("v4-argon2.kdbx");
        int p = ParameterOffset(data, parameter);
        if (parameter is "V" or "P") BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(p), (uint)value);
        else BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(p), value);
        Rehash(data);
        Assert.Throws<UnsupportedFormatException>(() => Extract(data));
    }

    [Fact]
    public void BadKdfDictionaryLengthIsRejected()
    {
        var data = Fixture("v4-argon2.kdbx");
        data.AsSpan(FieldOffset(data, 11) + 3, 4).Fill(0xff);
        Rehash(data);
        Assert.Throws<FormatException>(() => Extract(data));
    }

    [Fact]
    public void BadKdfParameterTypeIsRejected()
    {
        var data = Fixture("v4-argon2.kdbx");
        data[ParameterOffset(data, "I") - 10] = 4;
        Rehash(data);
        Assert.Throws<FormatException>(() => Extract(data));
    }

    [Fact]
    public void DuplicateHeaderFieldsAreRejected()
    {
        var data = Fixture("v4-argon2.kdbx");
        data[FieldOffset(data, 3) - 5] = 2;
        Assert.Throws<FormatException>(() => Extract(data));
    }

    [Fact]
    public void UnknownCipherIsRejected()
    {
        var data = Fixture("v3.kdbx"); data[FieldOffset(data, 2)] ^= 1;
        Assert.Throws<UnsupportedFormatException>(() => Extract(data));
    }

    [Fact]
    public void Kdbx3TwofishIsRejectedRatherThanProducingAnAesHash()
    {
        var data = Fixture("v3.kdbx");
        Convert.FromHexString("ad68f29f576f4bb9a36ad47af965346c").CopyTo(data, FieldOffset(data, 2));
        Assert.Contains("only AES", Assert.Throws<UnsupportedFormatException>(() => Extract(data)).Message);
    }

    [Fact]
    public void Kdbx2And4MinorVersionsAreRecognized()
    {
        var data = Fixture("v3.kdbx"); data[10] = 2;
        Assert.Equal(13400, Extract(data).Target!.Modes[0]);
        data = Fixture("v4-argon2.kdbx"); data[8] = 1; Rehash(data);
        Assert.Equal(34300, Extract(data).Target!.Modes[0]);
    }

    [Fact]
    public void LargeKdbIsRejectedBeforeReadingItsContents()
    {
        var data = Fixture("v1.kdb");
        using var stream = new MemoryStream();
        stream.Write(data); stream.SetLength(124 + 0x800010);
        Assert.Contains("8 MiB", Assert.Throws<UnsupportedFormatException>(() => KeePassExtractor.Extract(stream, new Detection { FilePath = "test" })).Message);
    }

    [Fact]
    public void KeyfilesSeparateSessionIdentities()
    {
        string path = Path.GetTempFileName();
        try
        {
            var data = Fixture("v3.kdbx");
            string noKey = SessionState.KeyFor(Extract(data).Target!);
            File.WriteAllBytes(path, new byte[32]);
            string first = SessionState.KeyFor(Extract(data, path).Target!);
            File.WriteAllBytes(path, Enumerable.Repeat((byte)1, 32).ToArray());
            string second = SessionState.KeyFor(Extract(data, path).Target!);
            Assert.NotEqual(noKey, first); Assert.NotEqual(first, second);
        }
        finally { File.Delete(path); }
    }

    private static Detection Extract(byte[] data, string? keyfile = null)
    {
        using var s = new MemoryStream(data);
        var d = new Detection { FilePath = "test" };
        KeePassExtractor.Extract(s, d, keyfile);
        return d;
    }

    private static int FieldOffset(byte[] data, int id)
    {
        int p = 12, width = data[10] == 4 ? 4 : 2;
        while (data[p] != id)
        {
            int size = width == 4 ? (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p + 1)) : BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(p + 1));
            p += 1 + width + size;
        }
        return p + 1 + width;
    }

    private static int ParameterOffset(byte[] data, string key)
    {
        int p = FieldOffset(data, 11) + 2;
        while (true)
        {
            p++;
            int n = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p)); p += 4;
            string name = Encoding.UTF8.GetString(data, p, n); p += n;
            int size = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(p)); p += 4;
            if (name == key) return p;
            p += size;
        }
    }

    private static void Rehash(byte[] data) => SHA256.HashData(data.AsSpan(0, 253)).CopyTo(data, 253);

    private static byte[] Fixture(string name)
    {
        using var s = typeof(KeePassExtractorTests).Assembly.GetManifestResourceStream("RecoverKit.Tests.Fixtures.KeePass." + name)!;
        using var b = new MemoryStream();
        s.CopyTo(b);
        return b.ToArray();
    }
}
