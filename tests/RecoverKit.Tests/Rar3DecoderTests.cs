using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO.Compression;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed unsafe class Rar3DecoderTests
{
    [Theory]
    [InlineData("ppm-lz-transition", 810UL, 0x34fc0041u, 65536u)]
    [InlineData("ppm-model-transition", 810UL, 0x34fc0041u, 65536u)]
    [InlineData("ppm-vm-record", 256UL, 0xf57459d7u, 65536u)]
    [InlineData("ppm-escape-commands", 254UL, 0xd31abadcu, 65536u)]
    [InlineData("small-ppm", 8192UL, 0x57021da4u, 131072u)]
    [InlineData("small-ppm-allbytes", 131072UL, 0x205fbff3u, 131072u)]
    [InlineData("small-delta", 8192UL, 0x8f9bf594u, 131072u)]
    [InlineData("small-audio", 8192UL, 0xf7dde6acu, 131072u)]
    [InlineData("small-x86", 8192UL, 0x7828eb44u, 131072u)]
    [InlineData("small-rgb", 8192UL, 0x66874833u, 131072u)]
    [InlineData("large-ppm", 5242917UL, 0xfa3f4c85u, 4194304u)]
    [InlineData("large-delta", 5242917UL, 0x1d472d69u, 4194304u)]
    [InlineData("large-x86", 5242917UL, 0x39aea390u, 4194304u)]
    [InlineData("large-rgb", 5242917UL, 0x9a644803u, 4194304u)]
    public void RealWinRarStreamsMatchTheSourceFileCrc(string name, ulong unpacked, uint crc, uint dictionary)
    {
        if (!RkNative.Available) return;
        using var resource = typeof(Rar3DecoderTests).Assembly.GetManifestResourceStream(
            $"RecoverKit.Tests.Fixtures.Rar3.{name}.packed.gz")!;
        using var gzip = new GZipStream(resource, CompressionMode.Decompress);
        using var packed = new MemoryStream();
        gzip.CopyTo(packed);
        var result = Decode(packed.ToArray(), unpacked, crc, dictionary);
        Assert.True(result.Result == 1, $"{name} rejected with result {result.Result}, stage {result.Stage}.");
    }

    [Fact]
    public void PpmHeaderCanOmitTheDefaultEscapeCharacter()
    {
        if (!RkNative.Available) return;
        using var resource = typeof(Rar3DecoderTests).Assembly.GetManifestResourceStream(
            "RecoverKit.Tests.Fixtures.Rar3.small-ppm-defaultesc.packed.gz")!;
        using var gzip = new GZipStream(resource, CompressionMode.Decompress);
        using var stream = new MemoryStream();
        gzip.CopyTo(stream);
        var packed = stream.ToArray();
        Assert.Equal(0, packed[0] & 0x40);
        Assert.Equal(1, Decode(packed, 33, 0x46755231, 65536).Result);
    }

    [Fact]
    public void ConcurrentPpmChecksWithEveryModelSizeKeepIndependentState()
    {
        if (!RkNative.Available) return;
        using var resource = typeof(Rar3DecoderTests).Assembly.GetManifestResourceStream(
            "RecoverKit.Tests.Fixtures.Rar3.small-ppm-defaultesc.packed.gz")!;
        using var gzip = new GZipStream(resource, CompressionMode.Decompress);
        using var stream = new MemoryStream();
        gzip.CopyTo(stream);
        byte[] packed = stream.ToArray();
        byte[] salt = Convert.FromHexString("ad56eb40219c9da2");
        var kdf = Rar3Kernel.TryParse("$RAR3$*0*ad56eb40219c9da2*00000000000000000000000000000000")!;
        var (digest, iv) = kdf.ReferenceHash("kit3"u8);
        var key = new byte[16];
        for (int i = 0; i < key.Length; i++) key[i] = digest[(i & ~3) + 3 - (i & 3)];
        string directory = Path.Combine(RecoverKit.Core.Settings.AppDataDir, "rar3-ppm-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            Parallel.For(0, 256, new ParallelOptions { MaxDegreeOfParallelism = 10 }, model =>
            {
                byte[] data = (byte[])packed.Clone();
                // This short stream never exhausts even the smallest PPM model.
                data[1] = (byte)model;
                using var aes = Aes.Create();
                aes.Key = key;
                string path = Path.Combine(directory, model + ".bin");
                File.WriteAllBytes(path, aes.EncryptCbc(data, iv, PaddingMode.None));
                var target = new Rar3FileTarget(path, 0, data.Length, 33, 0x35, 65536, salt, 0x46755231);
                Assert.True(Rar3FileDecoder.Check(target, digest, iv).Match, $"PPM model {model + 1} MiB rejected.");
                Assert.False(Rar3FileDecoder.Check(target with { Crc = 0x46755230 }, digest, iv).Match);
            });
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Fact]
    public void LzToPpmTableTransitionKeepsDecoding()
    {
        if (!RkNative.Available) return;
        using var resource = typeof(Rar3DecoderTests).Assembly.GetManifestResourceStream(
            "RecoverKit.Tests.Fixtures.Rar3.small-ppm.packed.gz")!;
        using var gzip = new GZipStream(resource, CompressionMode.Decompress);
        using var packed = new MemoryStream();
        gzip.CopyTo(packed);
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: false);
        main.Symbol(writer, 'A');
        main.Symbol(writer, 256);
        writer.Write(1, 1);
        writer.Align();
        foreach (byte b in packed.ToArray()) writer.Write(b, 8);
        // CRC32 of ASCII A followed by the independently verified small-ppm output.
        uint crc = CombinePrefixCrc((byte)'A', 0x57021da4, 8192);
        Assert.Equal(1, Decode(writer.ToArray(), 8193, crc, 131072).Result);
    }

    [Theory]
    [InlineData(false, 1)]
    [InlineData(true, 1)]
    [InlineData(false, 4096)]
    public void NewLzTablesResetLowDistanceAndRepeatState(bool repeat, int chunk)
    {
        if (!RkNative.Available) return;
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: true, lowRepeat: true);
        var expected = Enumerable.Range(0, 128).Select(i => (byte)i).ToList();
        foreach (byte b in expected) main.Symbol(writer, b);
        // Distance slot 10 starts at 33; its low distance is table-coded.
        var dist = new Codes(Enumerable.Range(0, 60).Select(i => i < 4 ? 5 : 6).ToArray());
        var low = new Codes([.. Enumerable.Repeat(4, 15), 5, 5]);
        void Match(int symbol, int distance)
        {
            main.Symbol(writer, 271);
            dist.Symbol(writer, 10);
            low.Symbol(writer, symbol);
            for (int i = 0; i < 3; i++) expected.Add(expected[expected.Count - distance]);
        }
        Match(7, 40);
        if (repeat) Match(16, 40);
        main.Symbol(writer, 256);
        writer.Write(1, 1); // Same file, new table.
        writer.Align();
        main = WriteTables(writer, 0, distances: true, lowRepeat: true);
        Match(16, 33); // PrevLowDist must be zero in the new block.
        main.Symbol(writer, 'Z');
        expected.Add((byte)'Z');
        Assert.Equal(1, Decode(writer.ToArray(), (ulong)expected.Count, Crc(expected.ToArray()), chunk: chunk).Result);
    }

    [Fact]
    public void IncompleteHuffmanCodesAreValidForUniformData()
    {
        if (!RkNative.Available) return;
        for (int value = 0; value < 256; value++)
        {
            var writer = new Bits();
            writer.Write(0, 2);
            // Pre-table only uses length symbols 0 and 1, with unused code space.
            for (int i = 0; i < 20; i++) writer.Write((uint)(i < 2 ? 2 : 0), 4);
            for (int i = 0; i < 404; i++) writer.Write((uint)(i == value ? 1 : 0), 2);
            for (int i = 0; i < 4096; i++) writer.Write(0, 1);
            var expected = Enumerable.Repeat((byte)value, 4096).ToArray();
            Assert.Equal(1, Decode(writer.ToArray(), 4096, Crc(expected), chunk: 1).Result);
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(0x5a)]
    public void OneMiBOfUniformDataAcceptsASingleSymbolTable(byte value)
    {
        if (!RkNative.Available) return;
        var writer = new Bits();
        writer.Write(0, 2);
        for (int i = 0; i < 20; i++) writer.Write((uint)(i < 2 ? 2 : 0), 4);
        for (int i = 0; i < 404; i++) writer.Write((uint)(i == value ? 1 : 0), 2);
        for (int i = 0; i < 1048576; i++) writer.Write(0, 1);
        var expected = Enumerable.Repeat(value, 1048576).ToArray();
        Assert.Equal(1, Decode(writer.ToArray(), 1048576, Crc(expected)).Result);
    }

    [Fact]
    public void SixteenByteStrideDataKeepsItsHistoryAcrossManyLzBlocks()
    {
        if (!RkNative.Available) return;
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: true);
        for (int i = 0; i < 16; i++) main.Symbol(writer, i * 17);
        main.Symbol(writer, 298);
        writer.Write(31, 5);
        WriteDistance(writer, 16);
        int done = 274;
        for (int block = 1; block <= 16; block++)
        {
            int end = block * 65536;
            while (done + 258 <= end) { main.Symbol(writer, 258); done += 258; }
            while (done < end) { main.Symbol(writer, done % 16 * 17); done++; }
            if (block == 16) break;
            main.Symbol(writer, 256);
            writer.Write(1, 1);
            writer.Align();
            main = WriteTables(writer, block, distances: true);
        }
        var expected = Enumerable.Range(0, done).Select(i => (byte)(i % 16 * 17)).ToArray();
        Assert.Equal(1, Decode(writer.ToArray(), (ulong)done, Crc(expected), 65536, chunk: 1).Result);
    }

    [Fact]
    public void PublishedHashcatCompressedVectorHasTheSameCrc()
    {
        if (!RkNative.Available) return;
        var kdf = Rar3Kernel.TryParse("$RAR3$*0*ad56eb40219c9da2*00000000000000000000000000000000")!;
        var (digest, iv) = kdf.ReferenceHash("hashcat"u8);
        var key = new byte[16];
        for (int i = 0; i < 16; i++) key[i] = digest[(i & ~3) + 3 - (i & 3)];
        using var aes = Aes.Create();
        aes.Key = key;
        var packed = aes.DecryptCbc(Convert.FromHexString(
            "eb47b1abe17a1a75bce6c92ab1cef3f4126035ea95deaf08b3f32a0c7b8078e1"), iv, PaddingMode.None);
        Assert.Equal(1, Decode(packed, 13, 0xce644083).Result);
    }

    [Fact]
    public void ManyValidStreamsSurviveTheFirstChunkAndFinishWithTheirCrc()
    {
        if (!RkNative.Available) return;
        var random = new Random(23800);
        for (int sample = 0; sample < 128; sample++)
        {
            var plain = new byte[random.Next(1, 14000)];
            random.NextBytes(plain);
            var stream = LiteralStream(plain, sample);
            var result = Decode(stream, (ulong)plain.Length, Crc(plain));
            Assert.True(result.Result == 1, $"Valid stream {sample} rejected at stage {result.Stage}.");
            Assert.Equal(3, result.Stage);
        }
    }

    [Fact]
    public void ManyEncryptedStreamsPassTheFilterWithTheRightPassword()
    {
        if (!RkNative.Available) return;
        byte[] salt = Convert.FromHexString("ad56eb40219c9da2");
        var kdf = Rar3Kernel.TryParse("$RAR3$*0*ad56eb40219c9da2*00000000000000000000000000000000")!;
        var (digest, iv) = kdf.ReferenceHash("hashcat"u8);
        var key = new byte[16];
        for (int i = 0; i < 16; i++) key[i] = digest[(i & ~3) + 3 - (i & 3)];
        string directory = Path.Combine(Environment.GetEnvironmentVariable("RECOVERKIT_HOME") ?? Path.GetTempPath(),
            "rar3-filters-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string path = Path.Combine(directory, "entry.bin");
            var random = new Random(23803);
            using var aes = Aes.Create();
            aes.Key = key;
            for (int sample = 0; sample < 128; sample++)
            {
                var plain = new byte[random.Next(1, 14000)];
                random.NextBytes(plain);
                var packed = LiteralStream(plain, sample);
                Array.Resize(ref packed, (packed.Length + 15) & ~15);
                var encrypted = aes.EncryptCbc(packed, iv, PaddingMode.None);
                File.WriteAllBytes(path, encrypted);
                var target = new Rar3FileTarget(path, 0, encrypted.Length, plain.Length, 0x33, 4194304, salt, Crc(plain));
                Assert.True(Rar3FileDecoder.Check(target, digest, iv).Match, $"Right password rejected for stream {sample}.");
            }
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Theory]
    [InlineData(65536)]
    [InlineData(1048576)]
    [InlineData(4194304)]
    public void MaximumDistanceMatchesReadTheWrappingDictionary(int window)
    {
        if (!RkNative.Available) return;
        int outputLength = window * 2 + 997;
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: true);
        for (int i = 0; i < window; i++) main.Symbol(writer, i % 251);
        int done = window;
        while (done + 258 <= outputLength)
        {
            main.Symbol(writer, 298);
            writer.Write((uint)(31 - (window >= 0x40000 ? 2 : window >= 0x2000 ? 1 : 0)), 5);
            WriteDistance(writer, window);
            done += 258;
        }
        for (; done < outputLength; done++) main.Symbol(writer, done % window % 251);
        uint crc = uint.MaxValue;
        for (int i = 0; i < outputLength; i++) crc = UpdateCrc(crc, (byte)(i % window % 251));
        Assert.Equal(1, Decode(writer.ToArray(), (ulong)outputLength, ~crc, (uint)window).Result);
    }

    [Theory]
    [InlineData(65536, false)]
    [InlineData(4194304, false)]
    [InlineData(65536, true)]
    public void StandardFiltersCollectTheirWholeBlockAcrossWindowWrap(int window, bool delta)
    {
        if (!RkNative.Available) return;
        int start = window - 20, blockLength = 128, outputLength = window + 512;
        var encoded = new byte[blockLength];
        new Random(23802).NextBytes(encoded);
        var expected = (byte[])encoded.Clone();
        if (delta)
        {
            byte previous = 0;
            for (int i = 0; i < expected.Length; i++) expected[i] = previous = (byte)(previous - encoded[i]);
        }
        else
        {
            Array.Fill(encoded, (byte)0x42);
            encoded[16] = 0xe8;
            encoded[17] = 0x45; encoded[18] = 0x23; encoded[19] = 1; encoded[20] = 0;
            encoded.CopyTo(expected, 0);
            uint address = unchecked(0x12345u - (uint)(start + 17));
            for (int i = 0; i < 4; i++) expected[17 + i] = (byte)(address >> (i * 8));
        }
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: false);
        main.Symbol(writer, 257);
        WriteFilterRecord(writer, start, blockLength, delta);
        uint crc = uint.MaxValue;
        for (int i = 0; i < outputLength; i++)
        {
            int offset = i - start;
            main.Symbol(writer, offset >= 0 && offset < blockLength ? encoded[offset] : 0x42);
            crc = UpdateCrc(crc, offset >= 0 && offset < blockLength ? expected[offset] : (byte)0x42);
        }
        Assert.Equal(1, Decode(writer.ToArray(), (ulong)outputLength, ~crc, (uint)window).Result);
    }

    [Theory]
    [InlineData(128)]
    [InlineData(129)]
    public void ChainedStandardFiltersAreAppliedBeforeTheCrcIncludingAtEof(int outputLength)
    {
        if (!RkNative.Available) return;
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: false);
        main.Symbol(writer, 257);
        WriteFilterRecord(writer, 0, 128, delta: true);
        main.Symbol(writer, 257);
        WriteFilterRecord(writer, 0, 128, delta: true, includeProgram: false);
        var expected = new byte[outputLength];
        for (int i = 0; i < outputLength; i++) { main.Symbol(writer, 1); expected[i] = 1; }
        for (int pass = 0; pass < 2; pass++)
        {
            byte previous = 0;
            for (int i = 0; i < 128; i++) expected[i] = previous = (byte)(previous - expected[i]);
        }
        Assert.Equal(1, Decode(writer.ToArray(), (ulong)outputLength, Crc(expected)).Result);
    }

    [Fact]
    public void AnUnimplementedOverlapAtEofRemainsPossibleRatherThanBeingDiscarded()
    {
        if (!RkNative.Available) return;
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: false);
        main.Symbol(writer, 257);
        WriteFilterRecord(writer, 0, 128, delta: true);
        main.Symbol(writer, 257);
        WriteFilterRecord(writer, 16, 112, delta: true, includeProgram: false);
        for (int i = 0; i < 128; i++) main.Symbol(writer, 1);
        Assert.Equal(-5, Decode(writer.ToArray(), 128, 0).Result);
    }

    [Fact]
    public void WindowWrappingFilterOffsetsRemainPossible()
    {
        if (!RkNative.Available) return;
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: false);
        main.Symbol(writer, 257);
        WriteFilterRecord(writer, 65536, 8, delta: false);
        for (int i = 0; i < 8; i++) main.Symbol(writer, 'A');
        Assert.Equal(-4, Decode(writer.ToArray(), 8, 0, 65536).Result);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(129)]
    public void UnusualStandardFilterParametersRemainPossible(int channels)
    {
        if (!RkNative.Available) return;
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: false);
        main.Symbol(writer, 257);
        WriteFilterRecord(writer, 0, 8, delta: true, channels: channels);
        for (int i = 0; i < 8; i++) main.Symbol(writer, 'A');
        Assert.Equal(-6, Decode(writer.ToArray(), 8, 0).Result);
    }

    [Fact]
    [Trait("Category", "Slow")]
    public void X86FilterUsesTheFullFileOffsetBeyondSixteenMiB()
    {
        if (!RkNative.Available) return;
        const int start = 0x2000000;
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: true);
        main.Symbol(writer, 'A');
        main.Symbol(writer, 298);
        writer.Write(31, 5);
        WriteDistance(writer, 1);
        int done = 259;
        while (done + 258 <= start) { main.Symbol(writer, 258); done += 258; }
        while (done < start) { main.Symbol(writer, 'A'); done++; }
        main.Symbol(writer, 257);
        WriteFilterRecord(writer, 0, 5, delta: false);
        foreach (byte b in new byte[] { 0xe8, 0, 0, 0x80, 0xfe }) main.Symbol(writer, b);
        // Independent zlib CRC32 of 32 MiB of A followed by E8 00 00 80 FF.
        Assert.Equal(1, Decode(writer.ToArray(), start + 5UL, 0x50f9e4fe).Result);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FilterResetClearsPendingRecordsOrRetainsTheCandidate(bool afterOutput)
    {
        if (!RkNative.Available) return;
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: false);
        if (afterOutput) main.Symbol(writer, 'A');
        main.Symbol(writer, 257);
        WriteFilterRecord(writer, 0, 8, delta: false);
        main.Symbol(writer, 257);
        WriteFilterRecord(writer, 0, 8, delta: false, filterNumber: 0);
        foreach (byte b in new byte[] { 0xe8, 5, 0, 0, 0, 0, 0, 0 }) main.Symbol(writer, b);
        // Only the replacement x86 filter remains: E8 04 00 00 00 00 00 00.
        Assert.Equal(afterOutput ? -7 : 1, Decode(writer.ToArray(), afterOutput ? 9UL : 8UL, 0xc158c5ae).Result);
    }

    [Fact]
    public void AFilterBeyondTheSupportedBlockSizeIsReportedAsUnsupported()
    {
        if (!RkNative.Available) return;
        Assert.Equal(-1, Decode(UnsupportedFilterStream(), 262145, 0).Result);
    }

    internal static byte[] UnsupportedFilterStream()
    {
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: false);
        main.Symbol(writer, 257);
        WriteFilterRecord(writer, 0, 262145, delta: false);
        return writer.ToArray();
    }

    [Fact]
    [Trait("Category", "Slow")]
    public void OutputLengthBeyondFourGiBDoesNotTruncateTheCounter()
    {
        if (!RkNative.Available) return;
        const ulong length = (1UL << 32) + 17;
        // Independent zlib CRC32 of 4 GiB + 17 ASCII 'A' bytes, computed in 1 MiB chunks.
        Assert.Equal(1, Decode(RepeatStream(length), length, 0xbf9bbb25).Result);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(17)]
    [InlineData(4096)]
    public void ShortInputReadsDoNotRejectAValidStream(int chunk)
    {
        if (!RkNative.Available) return;
        var plain = new byte[12000];
        new Random(42).NextBytes(plain);
        Assert.Equal(1, Decode(LiteralStream(plain), (ulong)plain.Length, Crc(plain), chunk: chunk).Result);
    }

    [Fact]
    public void AValidFirstChunkStillNeedsTheFullCrc()
    {
        if (!RkNative.Available) return;
        var plain = new byte[16000];
        new Random(912).NextBytes(plain);
        var packed = LiteralStream(plain);
        var rejected = Decode(packed, (ulong)plain.Length, Crc(plain) ^ 1);
        Assert.Equal(0, rejected.Result);
        Assert.Equal(2, rejected.Stage);
        Assert.NotEqual(1, Decode(packed[..^100], (ulong)plain.Length, Crc(plain)).Result);
    }

    [Fact]
    public void InputFailureIsAnErrorRatherThanAPasswordMiss()
    {
        if (!RkNative.Available) return;
        var plain = new byte[12000];
        new Random(913).NextBytes(plain);
        Assert.Equal(-2, Decode(LiteralStream(plain), (ulong)plain.Length, Crc(plain), failAfter: 4096).Result);
    }

    [Fact]
    public void CancellationIsPolledEvenWhenTheWholePackedStreamFitsInTheFirstRead()
    {
        if (!RkNative.Available) return;
        const ulong length = 262144;
        var packed = RepeatStream(length);
        Assert.True(packed.Length < 4096);
        Assert.Equal(-2, Decode(packed, length, 0x12345678, failPollAfter: 1).Result);
    }

    [Fact]
    public void NoiseAndMalformedTablesNeverProduceAHit()
    {
        if (!RkNative.Available) return;
        var random = new Random(23801);
        for (int sample = 0; sample < 128; sample++)
        {
            var noise = new byte[4096];
            random.NextBytes(noise);
            Assert.NotEqual(1, Decode(noise, 700000, 0x12345678).Result);
        }
    }

    private sealed class Reader(byte[] bytes, int chunk, int failAfter, int failPollAfter)
    {
        internal int Position;
        private int _polls;
        internal int Read(Span<byte> output)
        {
            if (output.Length == 0) return ++_polls > failPollAfter ? -1 : 0;
            if (Position >= failAfter) return -1;
            int n = Math.Min(Math.Min(output.Length, chunk), Math.Min(bytes.Length - Position, failAfter - Position));
            bytes.AsSpan(Position, n).CopyTo(output);
            Position += n;
            return n;
        }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static int Read(nint state, byte* output, int length)
        => ((Reader)GCHandle.FromIntPtr(state).Target!).Read(new Span<byte>(output, length));

    private static (int Result, int Stage) Decode(byte[] packed, ulong unpacked, uint crc,
        uint window = 4194304, int chunk = int.MaxValue, int failAfter = int.MaxValue, int failPollAfter = int.MaxValue)
    {
        var handle = GCHandle.Alloc(new Reader(packed, chunk, failAfter, failPollAfter));
        try
        {
            int stage = -1;
            int result = RkNative.Rar3DecodeStream(&Read, GCHandle.ToIntPtr(handle), (ulong)packed.Length,
                unpacked, window, crc, &stage);
            return (result, stage);
        }
        finally { handle.Free(); }
    }

    private static byte[] LiteralStream(byte[] plain, int tablePermutation = 0)
    {
        var writer = new Bits();
        var main = WriteTables(writer, tablePermutation, distances: false);
        foreach (byte b in plain) main.Symbol(writer, b);
        return writer.ToArray();
    }

    private static byte[] RepeatStream(ulong length)
    {
        var writer = new Bits();
        var main = WriteTables(writer, 0, distances: true);
        main.Symbol(writer, 'A');
        main.Symbol(writer, 298);
        writer.Write(31, 5);
        WriteDistance(writer, 1);
        ulong done = 259;
        for (; done + 258 <= length; done += 258) main.Symbol(writer, 258);
        for (; done < length; done++) main.Symbol(writer, 'A');
        return writer.ToArray();
    }

    private static Codes WriteTables(Bits writer, int permutation, bool distances, bool lowRepeat = false)
    {
        var preLengths = Enumerable.Range(0, 20).Select(i => i < 12 ? 4 : 5).ToArray();
        var mainLengths = Enumerable.Range(0, 299).Select(i => (i + permutation) % 299 < 213 ? 8 : 9).ToArray();
        var distLengths = distances ? Enumerable.Range(0, 60).Select(i => i < 4 ? 5 : 6).ToArray() : new int[60];
        var lowLengths = distances ? lowRepeat ? [.. Enumerable.Repeat(4, 15), 5, 5] : [.. Enumerable.Repeat(4, 16), 0] : new int[17];
        var lengths = mainLengths.Concat(distLengths).Concat(lowLengths).Concat(new int[28]);
        writer.Write(0, 2);
        foreach (int n in preLengths) writer.Write((uint)n, 4);
        var pre = new Codes(preLengths);
        foreach (int n in lengths) pre.Symbol(writer, n);
        return new Codes(mainLengths);
    }

    private static int DistExtra(int symbol) => symbol < 4 ? 0 : symbol >= 48 ? 18 : Math.Min(16, (symbol - 2) / 2);

    private static void WriteFilterRecord(Bits writer, int start, int length, bool delta, bool includeProgram = true, int channels = 1, int filterNumber = 1)
    {
        // Filter programs from hashcat 8.0.0, rar3/rar3_programs.c.
        // Author......: hashcat project contributors; see NOTICE
        // License.....: MIT (native/rar3/LICENSE.txt).
        byte[] program = Convert.FromHexString(delta
            ? "2f019a4180ec27482f09766dd3ea415b5944e8175ce16c914c4e3f7700"
            : "971b012807069808000000d13a101592ec50cb9920b925f0291915530312ae511035592b6004156d4066ab023449043602523e9700");
        var body = new Bits();
        Number(body, (uint)filterNumber);
        Number(body, (uint)start);
        Number(body, (uint)length);
        if (delta)
        {
            Number(body, 0);
            body.Write(1, 1);
            Number(body, (uint)channels);
        }
        if (includeProgram)
        {
            Number(body, (uint)program.Length);
            foreach (byte b in program) body.Write(b, 8);
        }
        var bytes = body.ToArray();
        uint flags = (uint)(0xa0 | (delta ? 0x10 : 0));
        if (bytes.Length <= 6) writer.Write(flags | (uint)(bytes.Length - 1), 8);
        else
        {
            writer.Write(flags | 6, 8);
            writer.Write((uint)bytes.Length - 7, 8);
        }
        foreach (byte b in bytes) writer.Write(b, 8);
    }

    private static void Number(Bits writer, uint value)
    {
        int selector = value < 16 ? 0 : value is >= 16 and < 256 ? 1 : value < 65536 ? 2 : 3;
        writer.Write((uint)selector, 2);
        writer.Write(value, new[] { 4, 8, 16, 32 }[selector]);
    }

    private static void WriteDistance(Bits writer, int distance)
    {
        int start = 1;
        var codes = new Codes(Enumerable.Range(0, 60).Select(i => i < 4 ? 5 : 6).ToArray());
        for (int symbol = 0; symbol < 60; symbol++)
        {
            int bits = DistExtra(symbol);
            int width = 1 << bits;
            if (distance < start + width)
            {
                int value = distance - start;
                codes.Symbol(writer, symbol);
                if (bits >= 4)
                {
                    writer.Write((uint)(value >> 4), bits - 4);
                    writer.Write((uint)(value & 15), 4);
                }
                else writer.Write((uint)value, bits);
                return;
            }
            start += width;
        }
        throw new ArgumentOutOfRangeException(nameof(distance));
    }

    private sealed class Codes(int[] lengths)
    {
        private readonly uint[] _values = Values(lengths);
        internal void Symbol(Bits writer, int symbol) => writer.Write(_values[symbol], lengths[symbol]);
        private static uint[] Values(int[] lengths)
        {
            var values = new uint[lengths.Length];
            uint code = 0;
            for (int length = 1; length <= 15; length++)
            {
                for (int symbol = 0; symbol < lengths.Length; symbol++)
                    if (lengths[symbol] == length) values[symbol] = code++;
                code <<= 1;
            }
            return values;
        }
    }

    private sealed class Bits
    {
        private readonly MemoryStream _bytes = new();
        private int _byte, _count;
        internal void Write(uint value, int count)
        {
            for (int bit = count - 1; bit >= 0; bit--)
            {
                _byte = (_byte << 1) | (int)((value >> bit) & 1);
                if (++_count != 8) continue;
                _bytes.WriteByte((byte)_byte);
                _byte = _count = 0;
            }
        }
        internal byte[] ToArray()
        {
            Align();
            return _bytes.ToArray();
        }
        internal void Align()
        {
            if (_count != 0) Write(0, 8 - _count);
        }
    }

    private static uint CombinePrefixCrc(byte prefix, uint suffixCrc, int suffixLength)
    {
        // CRC concatenation using the reflected polynomial, independent of the decoder.
        uint delta = Crc([prefix]);
        for (int i = 0; i < suffixLength; i++)
            for (int bit = 0; bit < 8; bit++) delta = (delta >> 1) ^ ((delta & 1) != 0 ? 0xedb88320u : 0);
        return delta ^ suffixCrc;
    }

    private static uint Crc(ReadOnlySpan<byte> bytes)
    {
        uint crc = uint.MaxValue;
        foreach (byte b in bytes) crc = UpdateCrc(crc, b);
        return ~crc;
    }

    private static uint UpdateCrc(uint crc, byte value)
    {
        crc ^= value;
        for (int bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xedb88320u : 0);
        return crc;
    }
}
