using System.Buffers.Binary;
using System.Diagnostics;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native.Kernels;
using Xunit;
using Xunit.Abstractions;

namespace RecoverKit.Tests;

/// <summary>
/// A large ZipCrypto entry is confirmed from the archive file. Candidates that pass the 12-byte
/// header check (1 in 256) must be rejected cheaply, without decrypting the whole entry, or the
/// built-in engine runs at a small fraction of its speed (seen: 16 M/s instead of 400 M/s).
/// </summary>
public sealed class ZipPartialSpeedTests(ITestOutputHelper output) : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("rk-zipspeed").FullName;
    public void Dispose() => Directory.Delete(_dir, true);

    private const int PrefixLength = 256 * 1024;

    private (ZipPartialTarget Target, byte[] Header, string Hash) Build(bool deflate, int size = 1_260_000)
    {
        var rng = new Random(144);
        byte[] content = new byte[size];
        rng.NextBytes(content);   // incompressible, like a photo
        byte[] archive = ZipCryptoSample.Archive([new("data", content, deflate, false)], "secret"u8, rng);
        string path = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".zip");
        File.WriteAllBytes(path, archive);
        int central = (int)BinaryPrimitives.ReadUInt32LittleEndian(archive.AsSpan(archive.Length - 6));
        uint comp = BinaryPrimitives.ReadUInt32LittleEndian(archive.AsSpan(central + 20));
        uint crc = BinaryPrimitives.ReadUInt32LittleEndian(archive.AsSpan(central + 16));
        var target = new ZipPartialTarget(path, 34, comp, content.Length, crc, deflate ? 8 : 0);
        byte[] prefix = archive.AsSpan(34, PrefixLength).ToArray();
        string hash = $"$pkzip2$1*1*1*0*{target.Method}*{prefix.Length:x}*{crc >> 16:x4}*{crc >> 16:x4}*{Convert.ToHexString(prefix)}*$/pkzip2$";
        return (target, archive.AsSpan(34, 12).ToArray(), hash);
    }

    private static byte[][] HeaderSurvivors(byte[] header, int count)
    {
        byte check = ZipCryptoKernel.HeaderCheckByte("secret"u8, header);
        return Enumerable.Range(0, 2_000_000).Select(i => System.Text.Encoding.ASCII.GetBytes($"w{i}"))
            .Where(p => ZipCryptoKernel.HeaderCheckByte(p, header) == check).Take(count).ToArray();
    }

    private static double MicrosecondsPerVerify(ZipCryptoKernel kernel, byte[][] passwords)
    {
        foreach (var p in passwords.Take(10)) Assert.False(kernel.Verify(p));
        var sw = Stopwatch.StartNew();
        foreach (var p in passwords) Assert.False(kernel.Verify(p));
        return sw.Elapsed.TotalMilliseconds * 1000 / passwords.Length;
    }

    [Fact]
    public void DeflatedEntryRejectsHeaderSurvivorsFromThePrefixInMemory()
    {
        var (target, header, hash) = Build(deflate: true);
        var kernel = Assert.IsType<ZipCryptoKernel>(ZipCryptoKernel.TryParse(hash, target));
        Assert.True(kernel.Verify("secret"u8));
        double us = MicrosecondsPerVerify(kernel, HeaderSurvivors(header, 300));
        output.WriteLine($"{us:F2} us per header survivor");
        // Was ~170 us (open the archive, decrypt and inflate 1.26 MB). The prefix in memory rejects
        // random deflate data within its first bytes.
        Assert.True(us < 4, $"{us:F1} us per header survivor");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SiblingHeadersRejectSurvivorsBeforeTheArchiveIsRead(bool deflate)
    {
        var (target, header, hash) = Build(deflate);
        // Sixteen other encrypted entries, each accepting only the check byte "secret" produces.
        var rng = new Random(9);
        var siblings = Enumerable.Range(0, 16).Select(_ =>
        {
            byte[] h = new byte[12];
            rng.NextBytes(h);
            byte c = ZipCryptoKernel.HeaderCheckByte("secret"u8, h);
            return new ZipHeaderCheck(h, c, c);
        }).ToArray();
        var kernel = Assert.IsType<ZipCryptoKernel>(ZipCryptoKernel.TryParse(hash, target with { Siblings = siblings }));
        Assert.True(kernel.Verify("secret"u8));
        double us = MicrosecondsPerVerify(kernel, HeaderSurvivors(header, 300));
        output.WriteLine($"{us:F2} us per header survivor");
        // Was ~170 us (deflate) and ~24 ms (stored) per survivor.
        Assert.True(us < 10, $"{us:F1} us per header survivor");
    }

    [Fact]
    public void SiblingHeaderThatRejectsThePasswordRejectsTheCandidate()
    {
        var (target, _, hash) = Build(deflate: true, size: 300_000);
        byte[] h = new byte[12];
        new Random(3).NextBytes(h);
        byte c = ZipCryptoKernel.HeaderCheckByte("secret"u8, h);
        var accepting = Assert.IsType<ZipCryptoKernel>(ZipCryptoKernel.TryParse(hash, target with { Siblings = [new ZipHeaderCheck(h, c, c)] }));
        Assert.True(accepting.Verify("secret"u8));
        var rejecting = Assert.IsType<ZipCryptoKernel>(ZipCryptoKernel.TryParse(hash, target with { Siblings = [new ZipHeaderCheck(h, (byte)(c ^ 1), (byte)(c ^ 2))] }));
        Assert.False(rejecting.Verify("secret"u8));
    }

    public static IEnumerable<object[]> RealDeflateStreams()
    {
        var rng = new Random(5);
        foreach (var level in new[] { System.IO.Compression.CompressionLevel.NoCompression, System.IO.Compression.CompressionLevel.Fastest,
                     System.IO.Compression.CompressionLevel.Optimal, System.IO.Compression.CompressionLevel.SmallestSize })
            foreach (int size in new[] { 1, 2, 7, 40, 300, 5000, 70_000, 400_000 })
                foreach (bool random in new[] { false, true })
                {
                    byte[] content = new byte[size];
                    if (random) rng.NextBytes(content);
                    else for (int i = 0; i < size; i++) content[i] = (byte)("the quick brown fox jumps over the lazy dog "[i % 44]);
                    yield return [level, size, random];
                }
    }

    [Theory]
    [MemberData(nameof(RealDeflateStreams))]
    public void RealDeflateStartsArePlausible(System.IO.Compression.CompressionLevel level, int size, bool random)
    {
        byte[] content = new byte[size];
        if (random) new Random(size).NextBytes(content);
        else for (int i = 0; i < size; i++) content[i] = (byte)("the quick brown fox jumps over the lazy dog "[i % 44]);
        using var ms = new MemoryStream();
        using (var ds = new System.IO.Compression.DeflateStream(ms, level, leaveOpen: true)) ds.Write(content);
        byte[] deflated = ms.ToArray();
        for (int head = 1; head <= Math.Min(deflated.Length, ZipCryptoKernel.DeflateHeadLength); head++)
            Assert.True(ZipCryptoKernel.DeflateStartIsPlausible(deflated.AsSpan(0, head), size), $"{level} {size} {random}: {head} bytes");
    }

    [Fact]
    public void ImpossibleDeflateStartsAreRejected()
    {
        Assert.False(ZipCryptoKernel.DeflateStartIsPlausible([0x07, 0, 0, 0, 0], 100));              // reserved block type
        Assert.False(ZipCryptoKernel.DeflateStartIsPlausible([0x01, 0x05, 0x00, 0xfa, 0xfe], 5));    // stored, length check fails
        Assert.False(ZipCryptoKernel.DeflateStartIsPlausible([0x01, 0x05, 0x00, 0xfa, 0xff], 6));    // final stored block of 5 bytes, 6 expected
        Assert.True(ZipCryptoKernel.DeflateStartIsPlausible([0x01, 0x05, 0x00, 0xfa, 0xff], 5));
        Assert.True(ZipCryptoKernel.DeflateStartIsPlausible([0x00, 0x05, 0x00, 0xfa, 0xff], 9));     // nonfinal stored block of 5 bytes
        // Fixed Huffman: a length/distance pair before any output (symbol 257 = code 0000001, distance code 0).
        Assert.False(ZipCryptoKernel.DeflateStartIsPlausible([0b0100_0011, 0b0000_0000], 100));
        Assert.True(ZipCryptoKernel.DeflateStartIsPlausible([0b0000_0011, 0b0000_0000], 0));          // final empty fixed block (256 = 0000000)
        Assert.False(ZipCryptoKernel.DeflateStartIsPlausible([0b0000_0011, 0b0000_0000], 1));
    }

    [Fact]
    public void RandomDeflateStartsAreRejectedNearlyAlways()
    {
        var rng = new Random(77);
        byte[] head = new byte[ZipCryptoKernel.DeflateHeadLength];
        int plausible = 0;
        for (int i = 0; i < 100_000; i++)
        {
            rng.NextBytes(head);
            if (ZipCryptoKernel.DeflateStartIsPlausible(head, 1_260_000)) plausible++;
        }
        // Dynamic blocks whose code-length code happens to be complete (about 0.6%) are left to the inflater.
        Assert.True(plausible < 2000, $"{plausible} of 100000 random starts passed");
    }

    [Fact]
    public void ExtractorPassesTheOtherEntriesHeadersToThePartialTarget()
    {
        // Every entry is larger than hashcat's 320 KB limit, like photos from a camera.
        var rng = new Random(42);
        var entries = new List<ZipCryptoSample.Entry>();
        for (int i = 0; i < 4; i++)
        {
            byte[] photo = new byte[340_000 + i * 1000];
            rng.NextBytes(photo);
            entries.Add(new($"photo{i}.jpg", photo, i % 2 == 0));
        }
        string path = Path.Combine(_dir, "sample.zip");
        File.WriteAllBytes(path, ZipCryptoSample.Archive(entries, "ab1"u8, new Random(7)));
        var detection = new Detection { FilePath = path };
        using (var stream = File.OpenRead(path)) ZipExtractor.Extract(stream, detection);
        var partial = Assert.IsType<ZipPartialTarget>(detection.Target!.ZipPartial);
        Assert.Equal(3, partial.Siblings.Count);
        var kernel = Assert.IsType<ZipCryptoKernel>(ZipCryptoKernel.TryParse(detection.Target.HashLines, partial));
        Assert.True(kernel.Verify("ab1"u8));
        foreach (var s in partial.Siblings)
            Assert.Contains(ZipCryptoKernel.HeaderCheckByte("ab1"u8, s.Header), new[] { s.CrcCheck, s.TimeCheck });
    }
}
