using System.IO.Compression;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

public class ZipSurvivorTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public void StagedCheckMatchesFullDecryptInflateAndCrc(bool descriptor, bool twoBytes)
    {
        Compare(descriptor, twoBytes, 12);
    }

    [Fact]
    [Trait("Category", "Slow")]
    public void RandomDeflateSurvivorsMatchFullVerification()
    {
        Compare(false, false, 256);
        Compare(true, true, 256);
    }

    private static void Compare(bool descriptor, bool twoBytes, int survivors)
    {
        var rng = new Random(600);
        foreach (var level in new[] { CompressionLevel.NoCompression, CompressionLevel.Fastest,
                     CompressionLevel.Optimal, CompressionLevel.SmallestSize })
        foreach (int size in new[] { 0, 1, 48, 4096, 16384 })
        foreach (bool random in new[] { false, true })
        {
            byte[] content = new byte[size];
            if (random) rng.NextBytes(content);
            else ZipCryptoSample.Text(size, rng).CopyTo(content, 0);
            using var compressed = new MemoryStream();
            using (var ds = new DeflateStream(compressed, level, leaveOpen: true)) ds.Write(content);
            uint crc = ZipCryptoSample.Crc32(content);
            ushort checksum = (ushort)(descriptor ? 0x6d2b : crc >> 16);
            byte[] plain = new byte[12 + compressed.Length];
            rng.NextBytes(plain.AsSpan(0, 10));
            plain[10] = (byte)checksum; plain[11] = (byte)(checksum >> 8);
            compressed.ToArray().CopyTo(plain, 12);
            byte[] data = Crypt(plain, "secret"u8, encrypt: true);
            string Hash(long length) => $"$pkzip2$1*{(twoBytes ? 2 : 1)}*2*0*{data.Length:x}*{length:x}*{crc:x8}*0*0*8*{data.Length:x}*{checksum:x4}*6d2b*{Convert.ToHexString(data)}*$/pkzip2$";
            var kernel = ZipCryptoKernel.TryParse(Hash(size))!;
            Assert.True(kernel.Verify("secret"u8));
            // Full hash lines have historically allowed zero as an unknown output length.
            Assert.True(ZipCryptoKernel.TryParse(Hash(0))!.Verify("secret"u8));
            int found = 0;
            for (int i = 0; found < survivors; i++)
            {
                byte[] password = System.Text.Encoding.ASCII.GetBytes($"wrong{i}");
                if (ZipCryptoKernel.HeaderCheckByte(password, data.AsSpan(0, 12)) != plain[11]) continue;
                found++;
                Assert.Equal(FullVerify(data, password, content.Length, crc, checksum, twoBytes), kernel.Verify(password));
            }
            // Correct header and plausible start, damaged later data: the prefix is never final proof.
            if (data.Length > 16)
            {
                data[^2] ^= 0x40;
                var damaged = ZipCryptoKernel.TryParse(Hash(size))!;
                Assert.Equal(FullVerify(data, "secret"u8, content.Length, crc, checksum, twoBytes), damaged.Verify("secret"u8));
            }
        }
    }

    private static bool FullVerify(byte[] data, ReadOnlySpan<byte> password, int length, uint crc, ushort checksum, bool twoBytes)
    {
        byte[] plain = Crypt(data, password, encrypt: false);
        if (twoBytes ? plain[11] != (byte)(checksum >> 8) || plain[10] != (byte)checksum
            : plain[11] != (byte)(checksum >> 8) && plain[11] != 0x6d) return false;
        try
        {
            using var source = new MemoryStream(plain, 12, plain.Length - 12);
            using var ds = new DeflateStream(source, CompressionMode.Decompress);
            using var output = new MemoryStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = ds.Read(buffer)) > 0)
            {
                if (output.Length + read > length) return false;
                output.Write(buffer, 0, read);
            }
            return output.Length == length && ZipCryptoSample.Crc32(output.ToArray()) == crc;
        }
        catch (InvalidDataException) { return false; }
    }

    private static byte[] Crypt(ReadOnlySpan<byte> data, ReadOnlySpan<byte> password, bool encrypt)
    {
        uint a = 0x12345678, b = 0x23456789, c = 0x34567890;
        foreach (byte p in password) Step(ref a, ref b, ref c, p);
        var result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            uint t = (c | 2) & 65535;
            result[i] = (byte)(data[i] ^ (byte)((t * (t ^ 1)) >> 8));
            Step(ref a, ref b, ref c, encrypt ? data[i] : result[i]);
        }
        return result;
    }

    private static void Step(ref uint a, ref uint b, ref uint c, byte plain)
    {
        a = Crc(a, plain);
        b = unchecked((b + (byte)a) * 134775813u + 1);
        c = Crc(c, (byte)(b >> 24));
    }

    private static uint Crc(uint x, byte b)
    {
        x ^= b;
        for (int i = 0; i < 8; i++) x = (x >> 1) ^ ((x & 1) == 0 ? 0u : 0xedb88320u);
        return x;
    }
}
