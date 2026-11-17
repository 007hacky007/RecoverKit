using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public sealed class OfficeAgileCpuTests
{
    public const string Example2010 = "$office$*2010*100000*128*16*34170046140146368675746031258762*de5bc114991bb3a5679a6e24320bdb09*1b72a4ddffba3dcd5395f6a5ff75b126cb832b733c298e86162028ca47a235a9";
    public const string Example2013 = "$office$*2013*100000*256*16*67805436882475302087847656644837*0c392d3b9ca889656d1e615c54f9f3c9*612b79e33b96322c3253fc8a0f314463cd76bc4efe1352f7efffca0f374f7e4b";
    public static IEnumerable<object[]> Examples => [[9500, Example2010], [9600, Example2013]];

    public static IEnumerable<object[]> Vectors
    {
        get
        {
            using var stream = Fixture("agile-vectors.json");
            using var json = JsonDocument.Parse(stream);
            foreach (var row in json.RootElement.EnumerateArray())
                yield return [row.GetProperty("name").GetString()!, row.GetProperty("mode").GetInt32(),
                    row.GetProperty("hash").GetString()!, row.GetProperty("raw").GetString()!,
                    row.GetProperty("utf16").GetString()!, row.GetProperty("spin").GetString()!,
                    row.GetProperty("spins").GetUInt32(), row.GetProperty("supported").GetBoolean()];
        }
    }

    public static IEnumerable<object[]> AcceptedVectors => Vectors.Where(row => (bool)row[7]);

    [Theory]
    [MemberData(nameof(Examples))]
    public void HashcatExamplesRegisterAndFindPasswords(int mode, string hash)
    {
        var kernel = Assert.IsType<OfficeAgileKernel>(NativeKernels.TryCreate(mode, hash));
        Assert.Equal(256, kernel.MaxPasswordLength);
        Assert.True(kernel.Verify("hashcat"u8));
        Assert.False(kernel.Verify("hashcau"u8));
        Assert.Equal(1, kernel.CreateWorker().Search("hashca"u8, "xtz"u8));
        Assert.Equal(4, kernel.CreateWorker().SearchBatch("wrong-hashca"u8, 2, "xtz"u8));
        Assert.Equal(1, kernel.CreateWorker().SearchPasswords("wrong!!hashcat"u8, 7, 2));
    }

    [Theory]
    [MemberData(nameof(Vectors))]
    public void IndependentPythonVectorsCoverSpinsAesAndEncoding(string name, int mode, string hash,
        string rawHex, string utf16Hex, string spinHex, uint spins, bool supported)
    {
        byte[] expected = Convert.FromHexString(spinHex);
        byte[] actual = new byte[expected.Length];
        byte[] salt = Convert.FromHexString(hash.Split('*')[5]);
        OfficeAgileKernel.SpinManaged(Convert.FromHexString(utf16Hex), salt, mode, spins, actual);
        Assert.Equal(expected, actual);
        if (!supported)
        {
            Assert.Null(OfficeAgileKernel.TryParse(hash));
            Assert.Null(NativeKernels.TryCreate(mode, hash));
            return;
        }
        var kernel = Assert.IsType<OfficeAgileKernel>(OfficeAgileKernel.TryParse(hash));
        byte[] password = Convert.FromHexString(rawHex);
        Assert.True(kernel.SupportsDictionaryPassword(password), name);
        Assert.True(kernel.Verify(password), name);
        Assert.False(kernel.Verify("wrong"u8), name);
        Assert.Equal(0, kernel.CreateWorker().SearchPasswords(password, password.Length, 1));
    }

    [Theory]
    [MemberData(nameof(Examples))]
    public void ManagedFallbackFindsPasswordsWithoutNativeLibrary(int mode, string hash)
    {
        bool disabled = RkNative.Disabled;
        try
        {
            RkNative.Disabled = true;
            var kernel = Assert.IsType<OfficeAgileKernel>(NativeKernels.TryCreate(mode, hash));
            Assert.True(kernel.Verify("hashcat"u8));
            Assert.Equal(1, kernel.CreateWorker().SearchPasswords("wrong!!hashcat"u8, 7, 2));
            Assert.Equal(-1, kernel.CreateWorker().SearchPasswords("wrong!!"u8, 7, 1));
            foreach (var row in AcceptedVectors.Where(row => ((int)row[1] == mode) && ((string)row[0]).Contains("raw-")))
            {
                var rawKernel = OfficeAgileKernel.TryParse((string)row[2])!;
                byte[] bytes = Convert.FromHexString((string)row[3]);
                Assert.True(rawKernel.Verify(bytes));
                Assert.Equal(0, rawKernel.CreateWorker().SearchPasswords(bytes, bytes.Length, 1));
                Assert.Equal(1, rawKernel.CreateWorker().Search(bytes.AsSpan(0, 3), [(byte)(bytes[3] ^ 1), bytes[3]]));
            }
        }
        finally { RkNative.Disabled = disabled; }
    }

    [Theory]
    [InlineData(9500, "sha1")]
    [InlineData(9600, "sha512")]
    public void IndependentMsoffcryptoDocumentExtractsAWorkingHash(int mode, string algorithm)
    {
        using var stream = Fixture($"agile-msoffcrypto-{algorithm}.bin");
        var detection = new Detection { FilePath = "unrelated.bin" };
        OfficeExtractor.Extract(new CompoundFile(stream), detection);
        Assert.Equal([mode], detection.Target!.Modes);
        var kernel = Assert.IsType<OfficeAgileKernel>(OfficeAgileKernel.TryParse(detection.Target.HashLines));
        byte[] password = Encoding.UTF8.GetBytes("independent-\u00e9-\U0001f510");
        Assert.True(kernel.Verify(password));
        Assert.False(kernel.Verify("wrong"u8));
        Assert.Equal(0, kernel.CreateWorker().SearchPasswords(password, password.Length, 1));
    }

    [Theory]
    [MemberData(nameof(Examples))]
    public void HashcatComparesOnlyTheFirstVerifierHashBlock(int mode, string hash)
    {
        foreach (var (field, offset, expected) in new[] { (6, 0, false), (7, 0, false), (7, 15, false), (7, 16, true), (7, 31, true) })
        {
            var fields = hash.Split('*');
            byte[] bytes = Convert.FromHexString(fields[field]);
            bytes[offset] ^= 1;
            fields[field] = Convert.ToHexString(bytes);
            var kernel = Assert.IsType<OfficeAgileKernel>(NativeKernels.TryCreate(mode, string.Join('*', fields)));
            Assert.Equal(expected, kernel.Verify("hashcat"u8));
            Assert.Equal(expected ? 0 : -1, kernel.CreateWorker().SearchPasswords("hashcat"u8, 7, 1));
        }
    }

    [Theory]
    [MemberData(nameof(Examples))]
    public void ParserRejectsUnsupportedOrMalformedHashcatVariants(int mode, string hash)
    {
        Assert.Null(OfficeAgileKernel.TryParse(""));
        Assert.Null(OfficeAgileKernel.TryParse(hash + "*extra"));
        foreach (var (field, value) in new (int, string)[]
        {
            (0, "$office"), (1, "2007"), (1, "2016"), (2, "0"), (2, "99999"), (2, "100001"),
            (2, "-100000"), (2, "4294967296"), (3, "0"), (3, "192"), (3, mode == 9500 ? "256" : "128"),
            (4, "15"), (4, "17"), (5, "00"), (5, new string('g', 32)), (6, "00"),
            (6, new string('0', 34)), (7, new string('0', 32)), (7, new string('0', 62)),
            (7, new string('0', 66)), (7, new string('g', 64)),
        })
        {
            var fields = hash.Split('*');
            fields[field] = value;
            string invalid = string.Join('*', fields);
            Assert.Null(OfficeAgileKernel.TryParse(invalid));
            Assert.Null(NativeKernels.TryCreate(mode, invalid));
        }
        Assert.Null(NativeKernels.TryCreate(mode == 9500 ? 9600 : 9500, hash));
    }

    [Theory]
    [MemberData(nameof(Examples))]
    public void MalformedUtf8AndOversizedPasswordsAreRejected(int mode, string hash)
    {
        var kernel = NativeKernels.TryCreate(mode, hash)!;
        foreach (byte[] password in new byte[][] { [0x80], [0xc0, 0xaf], [0xc3], [0xed, 0xa0, 0x80], [0xf5, 0x80, 0x80, 0x80], new byte[257] })
        {
            Assert.False(kernel.SupportsDictionaryPassword(password));
            Assert.False(kernel.Verify(password));
            Assert.Equal(-1, kernel.CreateWorker().SearchPasswords(password, password.Length, 1));
        }
    }

    [Fact]
    public void Utf8AndMaximumLengthMasksPreserveCandidateBytes()
    {
        foreach (var row in AcceptedVectors.Where(row => ((string)row[0]).EndsWith("-unicode") || ((string)row[0]).EndsWith("-ascii-256")))
        {
            byte[] password = Convert.FromHexString((string)row[3]);
            var kernel = OfficeAgileKernel.TryParse((string)row[2])!;
            string mask = Convert.ToHexString(password.AsSpan(0, password.Length - 1)) + "?1";
            string last = Convert.ToHexString(new byte[] { (byte)(password[^1] ^ 1), password[^1] });
            var space = MaskSpace.FromHashcatArgs(["-a", "3", "--hex-charset", "-1", last, mask])!;
            var result = new NativeEngine(kernel, space) { Threads = 1 }.Run(null, CancellationToken.None);
            Assert.Equal(NativeOutcome.Found, result.Outcome);
            Assert.Equal(password, result.Password);
        }
    }

    [Theory]
    [InlineData(9500)]
    [InlineData(9600)]
    public unsafe void EveryNativePathMatchesIndependentFullSpinAndRandomPartialBatches(int mode)
    {
        if (!RkNative.Available) return;
        var saved = RkNative.Features;
        string variable = mode == 9500 ? "RECOVERKIT_OFFICE2010_PATH" : "RECOVERKIT_OFFICE2013_PATH";
        string? previous = Environment.GetEnvironmentVariable(variable);
        int size = mode == 9500 ? 20 : 64;
        var rng = new Random(mode);
        try
        {
            Environment.SetEnvironmentVariable(variable, null);
            foreach (var (features, bit) in Paths(saved, mode))
            {
                RkNative.LimitFeatures(features);
                int lanes = RkNative.OfficeAgileLanes(mode);
                Assert.True(lanes > 0);
                Assert.Equal(bit, RkNative.OfficeAgileSelectedPath(mode));
                var kat = AcceptedVectors.First(row => (int)row[1] == mode && ((string)row[0]).EndsWith("-ascii"));
                byte[] password = Convert.FromHexString((string)kat[4]);
                byte[] salt = Convert.FromHexString(((string)kat[2]).Split('*')[5]);
                byte[] batch = Enumerable.Range(0, lanes + 1).SelectMany(_ => password).ToArray();
                byte[] actual = new byte[(lanes + 1) * size];
                RkNative.ResetExecutedPaths(mode);
                fixed (byte* p = batch, s = salt, h = actual)
                    Assert.Equal(0, RkNative.OfficeAgileSpin(mode, p, password.Length, null, lanes + 1, s, 100000, h));
                Assert.Equal(Enumerable.Range(0, lanes + 1).SelectMany(_ => Convert.FromHexString((string)kat[5])).ToArray(), actual);
                Assert.Equal(bit, RkNative.OfficeAgileExecutedPaths(mode));
                if (bit != 1) Assert.Equal(1, RkNative.OfficeAgileSelfTestState(mode));
                foreach (int count in new[] { 1, Math.Max(1, lanes - 1), lanes, lanes + 1, 2 * lanes + 3 }.Distinct())
                    foreach (uint spins in new uint[] { 0, 1, 7, 1001 })
                    {
                        const int stride = 512;
                        rng.NextBytes(salt);
                        batch = new byte[count * stride];
                        rng.NextBytes(batch);
                        int[] lengths = Enumerable.Range(0, count).Select(i =>
                            new[] { 0, 2, 38, 40, 54, 56, 110, 112, 126, 128, 254, 256, 258, 510, 512 }[i % 15]).ToArray();
                        byte[] expected = new byte[count * size];
                        for (int i = 0; i < count; i++)
                        {
                            byte[] reference = ReferenceSpin(batch.AsSpan(i * stride, lengths[i]), salt, mode, spins);
                            reference.CopyTo(expected, i * size);
                            byte[] managed = new byte[size];
                            OfficeAgileKernel.SpinManaged(batch.AsSpan(i * stride, lengths[i]), salt, mode, spins, managed);
                            Assert.Equal(reference, managed);
                        }
                        actual = Enumerable.Repeat((byte)0xcc, expected.Length + 16).ToArray();
                        fixed (byte* p = batch, s = salt, h = actual)
                        fixed (int* l = lengths)
                            Assert.Equal(0, RkNative.OfficeAgileSpin(mode, p, stride, l, count, s, spins, h));
                        Assert.Equal(expected, actual.AsSpan(0, expected.Length).ToArray());
                        Assert.All(actual.Skip(expected.Length), value => Assert.Equal((byte)0xcc, value));
                    }
            }
        }
        finally
        {
            RkNative.LimitFeatures(saved);
            Environment.SetEnvironmentVariable(variable, previous);
        }
    }

    [Theory]
    [MemberData(nameof(Examples))]
    public unsafe void NativeFilterAndWorkerFindOnlyPlantedPasswordsInPartialBatches(int mode, string hash)
    {
        if (!RkNative.Available) return;
        var saved = RkNative.Features;
        string variable = mode == 9500 ? "RECOVERKIT_OFFICE2010_PATH" : "RECOVERKIT_OFFICE2013_PATH";
        string? previous = Environment.GetEnvironmentVariable(variable);
        try
        {
            Environment.SetEnvironmentVariable(variable, null);
            int* hits = stackalloc int[2];
            foreach (var (features, _) in Paths(saved, mode))
            {
                RkNative.LimitFeatures(features);
                int count = 2 * RkNative.OfficeAgileLanes(mode) + 3;
                var kernel = OfficeAgileKernel.TryParse(hash)!;
                byte[] passwords = Enumerable.Repeat((byte)'x', count * 7).ToArray();
                "hashcat"u8.CopyTo(passwords.AsSpan((count - 1) * 7));
                fixed (byte* p = passwords)
                {
                    Assert.Equal(1, ((INativeFilter)kernel).Filter(p, 7, count, hits, 2));
                    Assert.Equal(count - 1, hits[0]);
                }
                Assert.Equal(count - 1, kernel.CreateWorker().SearchPasswords(passwords, 7, count));
            }
        }
        finally
        {
            RkNative.LimitFeatures(saved);
            Environment.SetEnvironmentVariable(variable, previous);
        }
    }

    [Theory]
    [InlineData(9500)]
    [InlineData(9600)]
    public unsafe void NativeSpinRejectsInvalidArgumentsBeforeWriting(int mode)
    {
        if (!RkNative.Available) return;
        byte* password = stackalloc byte[32];
        byte* salt = stackalloc byte[16];
        byte* hash = stackalloc byte[64];
        new Span<byte>(hash, 64).Fill(0xcc);
        foreach (int invalid in new[] { -2, 3, 34 })
        {
            int length = invalid;
            Assert.Equal(-1, RkNative.OfficeAgileSpin(mode, password, 32, &length, 1, salt, 1, hash));
        }
        Assert.Equal(-1, RkNative.OfficeAgileSpin(mode, password, 31, null, 1, salt, 1, hash));
        Assert.Equal(-1, RkNative.OfficeAgileSpin(mode, password, 32, null, -1, salt, 1, hash));
        Assert.Equal(-1, RkNative.OfficeAgileSpin(mode, null, 32, null, 1, salt, 1, hash));
        Assert.Equal(-1, RkNative.OfficeAgileSpin(mode, password, 32, null, 1, null, 1, hash));
        Assert.Equal(-1, RkNative.OfficeAgileSpin(mode, password, 32, null, 1, salt, 1, null));
        Assert.Equal(-1, RkNative.OfficeAgileSpin(9400, password, 32, null, 1, salt, 1, hash));
        Assert.All(new ReadOnlySpan<byte>(hash, 64).ToArray(), value => Assert.Equal((byte)0xcc, value));
        Assert.Equal(0, RkNative.OfficeAgileSpin(mode, null, 0, null, 0, salt, 0, null));
    }

    private static IEnumerable<(RkNative.Feature Features, int Bit)> Paths(RkNative.Feature features, int mode)
    {
        yield return (0, 1);
        if (features.HasFlag(RkNative.Feature.Avx2)) yield return (RkNative.Feature.Avx2, 2);
        if (features.HasFlag(RkNative.Feature.Avx512)) yield return (RkNative.Feature.Avx512 | RkNative.Feature.Avx2, 4);
        if (features.HasFlag(RkNative.Feature.Neon)) yield return (RkNative.Feature.Neon, 8);
        if (mode == 9500 && features.HasFlag(RkNative.Feature.ArmSha1)) yield return (RkNative.Feature.ArmSha1 | RkNative.Feature.Neon, 32);
        if (mode == 9500 && features.HasFlag(RkNative.Feature.ShaNi)) yield return (RkNative.Feature.ShaNi, 64);
        if (mode == 9600 && features.HasFlag(RkNative.Feature.ArmSha512)) yield return (RkNative.Feature.ArmSha512 | RkNative.Feature.Neon, 128);
    }

    private static byte[] ReferenceSpin(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, int mode, uint spins)
    {
        byte[] state = mode == 9500 ? SHA1.HashData([.. salt, .. password]) : SHA512.HashData([.. salt, .. password]);
        byte[] input = new byte[4 + state.Length];
        for (uint i = 0; i < spins; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(input, i);
            state.CopyTo(input, 4);
            state = mode == 9500 ? SHA1.HashData(input) : SHA512.HashData(input);
        }
        return state;
    }

    private static Stream Fixture(string name) => typeof(OfficeAgileCpuTests).Assembly.GetManifestResourceStream("RecoverKit.Tests.Fixtures.Office." + name)!;
}
