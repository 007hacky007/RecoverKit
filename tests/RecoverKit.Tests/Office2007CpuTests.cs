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
public sealed class Office2007CpuTests
{
    public const string HashcatExample = "$office$*2007*20*128*16*18410007331073848057180885845227*944c70a5ee6e5ab2a6a86ff54b5f621a*e6650f1f2630c27fd8fc0f5e56e2e01f99784b9f";

    public static IEnumerable<object[]> KnownAnswers
    {
        get
        {
            using var stream = Fixture("standard-vectors.json");
            using var json = JsonDocument.Parse(stream);
            foreach (var row in json.RootElement.EnumerateArray())
                yield return [row.GetProperty("name").GetString()!, row.GetProperty("hash").GetString()!,
                    row.GetProperty("password").GetString()!, row.GetProperty("spin").GetString()!];
        }
    }

    // Python hashlib + cryptography AES-ECB over the literal UTF-16 bytes, without a UTF-8 decoder.
    public static IEnumerable<object[]> RawUtf8KnownAnswers =>
    [
        ["f4908080", "00dc00dc", "$office$*2007*20*128*16*000102030405060708090a0b0c0d0e0f*a32308bf63dd22d0f0180e872b0a07ba*f340d372fcbf34cd82fd79759cf549dc840639a5"],
        ["f4908080", "00dc00dc", "$office$*2007*20*256*16*000102030405060708090a0b0c0d0e0f*1e3faefff1ce0e465e70f326041e8d05*4e96c9749087df42f9a9bcdcca3fb85a93f80887"],
        ["f4bfbfbf", "bfdcffdf", "$office$*2007*20*128*16*000102030405060708090a0b0c0d0e0f*45fec1966dfc4f09810ea82af90a523e*501ee02ff49e162a7455e215f1c46078611aae9f"],
        ["f4bfbfbf", "bfdcffdf", "$office$*2007*20*256*16*000102030405060708090a0b0c0d0e0f*f1de7540fde857d49f4cd2ebac92a84d*9d3fb9a8674b45f67726fffa9d9590be1f3aa7aa"],
    ];

    public static IEnumerable<object[]> RawUtf8WorkerCases => RawUtf8KnownAnswers
        .SelectMany(row => new[] { row.Concat(new object[] { false }).ToArray(), row.Concat(new object[] { true }).ToArray() });

    [Fact]
    public void HashcatKnownAnswerWorksWithManagedConfirmationAndWorker()
    {
        var kernel = Assert.IsType<Office2007Kernel>(Office2007Kernel.TryParse(HashcatExample));
        Assert.True(kernel.Verify("hashcat"u8));
        Assert.False(kernel.Verify("hashcau"u8));
        Assert.Equal(1, kernel.CreateWorker().Search("hashca"u8, "xtz"u8));
        Assert.Equal(4, kernel.CreateWorker().SearchBatch("wrong-hashca"u8, 2, "xtz"u8));
        Assert.Equal(1, kernel.CreateWorker().SearchPasswords("wrong!!hashcat"u8, 7, 2));
    }

    [Theory]
    [MemberData(nameof(KnownAnswers))]
    public void IndependentPythonVectorsConfirmUtf8AndPasswordBoundaries(string name, string hash, string password, string spin)
    {
        var kernel = Assert.IsType<Office2007Kernel>(Office2007Kernel.TryParse(hash));
        byte[] pw = Encoding.UTF8.GetBytes(password);
        Assert.True(kernel.Verify(pw), name);
        Assert.False(kernel.Verify("wrong"u8), name);
        Assert.Equal(0, kernel.CreateWorker().SearchPasswords(pw, pw.Length, 1));
        Span<byte> actual = stackalloc byte[20];
        Office2007Kernel.SpinManaged(Encoding.Unicode.GetBytes(password), Convert.FromHexString(hash.Split('*')[5]), actual);
        Assert.Equal(Convert.FromHexString(spin), actual.ToArray());
    }

    [Fact]
    public void Utf8MasksAndMaximumLengthMasksPreserveCandidateBytes()
    {
        foreach (var row in KnownAnswers.Where(r => (string)r[0] is "128-unicode" or "256-unicode" or "256-ascii-256"))
        {
            byte[] password = Encoding.UTF8.GetBytes((string)row[2]);
            var kernel = Office2007Kernel.TryParse((string)row[1])!;
            string mask = Convert.ToHexString(password.AsSpan(0, password.Length - 1)) + "?1";
            string last = Convert.ToHexString(new byte[] { (byte)(password[^1] ^ 1), password[^1] });
            var space = MaskSpace.FromHashcatArgs(["-a", "3", "--hex-charset", "-1", last, mask])!;
            var result = new NativeEngine(kernel, space) { Threads = 1 }.Run(null, CancellationToken.None);
            Assert.Equal(NativeOutcome.Found, result.Outcome);
            Assert.Equal(password, result.Password);
        }
    }

    [Fact]
    public void IndependentEncryptedDocumentExtractsAWorkingHash()
    {
        using var stream = Fixture("ecma376standard_password.docx");
        var detection = new Detection { FilePath = "unrelated.bin" };
        OfficeExtractor.Extract(new CompoundFile(stream), detection);
        Assert.Equal([9400], detection.Target!.Modes);
        var kernel = Assert.IsType<Office2007Kernel>(Office2007Kernel.TryParse(detection.Target.HashLines));
        Assert.True(kernel.Verify("Password1234_"u8));
        Assert.False(kernel.Verify("Password1234"u8));
        Assert.Equal(0, kernel.CreateWorker().Search("Password1234"u8, "_"u8));
    }

    [Fact]
    public void CorruptedVerifierAndVerifierHashCannotBeReportedAsHits()
    {
        foreach (int field in new[] { 6, 7 })
        {
            var fields = HashcatExample.Split('*');
            var bytes = Convert.FromHexString(fields[field]);
            bytes[0] ^= 1;
            fields[field] = Convert.ToHexString(bytes);
            var kernel = Assert.IsType<Office2007Kernel>(Office2007Kernel.TryParse(string.Join('*', fields)));
            Assert.False(kernel.Verify("hashcat"u8));
            Assert.Equal(-1, kernel.CreateWorker().SearchPasswords("hashcat"u8, 7, 1));
        }
    }

    [Fact]
    public void HashcatUtf8RejectsMalformedSequencesAndOversizedPasswords()
    {
        var kernel = Assert.IsType<Office2007Kernel>(Office2007Kernel.TryParse(HashcatExample));
        foreach (byte[] password in new byte[][] { [0x80], [0xc0, 0xaf], [0xc3], [0xed, 0xa0, 0x80], [0xf5, 0x80, 0x80, 0x80], new byte[257] })
        {
            Assert.False(kernel.SupportsDictionaryPassword(password));
            Assert.False(kernel.Verify(password));
            Assert.Equal(-1, kernel.CreateWorker().SearchPasswords(password, password.Length, 1));
        }
    }

    [Theory]
    [MemberData(nameof(RawUtf8WorkerCases))]
    public unsafe void HashcatF4SequencesPreserveRawSurrogateUnits(string rawHex, string utf16Hex, string hash, bool managedOnly)
    {
        bool disabled = RkNative.Disabled;
        try
        {
            if (managedOnly) RkNative.Disabled = true;
            byte[] password = Convert.FromHexString(rawHex);
            var kernel = Assert.IsType<Office2007Kernel>(Office2007Kernel.TryParse(hash));
            Assert.True(kernel.SupportsDictionaryPassword(password));
            Assert.True(kernel.Verify(password));
            Assert.Equal(0, kernel.CreateWorker().SearchPasswords(password, password.Length, 1));
            Assert.Equal(1, kernel.CreateWorker().Search(password.AsSpan(0, 3), [(byte)(password[3] ^ 1), password[3]]));
            if (RkNative.Available)
            {
                int hit = -1;
                fixed (byte* p = password)
                {
                    Assert.Equal(1, ((INativeFilter)kernel).Filter(p, password.Length, 1, &hit, 1));
                    Assert.Equal(0, hit);
                }
            }
            Span<byte> spin = stackalloc byte[20];
            Office2007Kernel.SpinManaged(Convert.FromHexString(utf16Hex), Convert.FromHexString(hash.Split('*')[5]), spin);
            Assert.Equal(ReferenceSpin(Convert.FromHexString(utf16Hex), Convert.FromHexString(hash.Split('*')[5])), spin.ToArray());
        }
        finally { RkNative.Disabled = disabled; }
    }

    [Fact]
    public void ParserRejectsUnsupportedAndMalformedParameters()
    {
        Assert.Null(Office2007Kernel.TryParse(""));
        Assert.Null(Office2007Kernel.TryParse(HashcatExample + "*extra"));
        foreach (var (index, value) in new (int, string)[]
        {
            (0, "$office"), (1, "2010"), (2, "19"), (2, "21"), (3, "192"), (3, "0"),
            (4, "15"), (4, "17"), (5, "00"), (5, new string('g', 32)),
            (6, "00"), (6, new string('0', 34)), (7, "00"), (7, new string('0', 38)),
            (7, new string('0', 64)), (7, new string('0', 66)),
        })
        {
            var fields = HashcatExample.Split('*');
            fields[index] = value;
            Assert.Null(Office2007Kernel.TryParse(string.Join('*', fields)));
        }
    }

    [Fact]
    public void ManagedFallbackFindsPasswordsWithoutNativeLibrary()
    {
        bool disabled = RkNative.Disabled;
        try
        {
            RkNative.Disabled = true;
            var kernel = Assert.IsType<Office2007Kernel>(NativeKernels.TryCreate(9400, HashcatExample));
            Assert.True(kernel.Verify("hashcat"u8));
            Assert.Equal(1, kernel.CreateWorker().SearchPasswords("wrong!!hashcat"u8, 7, 2));
            Assert.Equal(-1, kernel.CreateWorker().SearchPasswords("wrong!!"u8, 7, 1));
        }
        finally { RkNative.Disabled = disabled; }
    }

    [Fact]
    public void RandomSaltsAndBothAesKeySizesMatchDotNetReference()
    {
        var rng = new Random(9400);
        foreach (int bits in new[] { 128, 256 })
            for (int i = 0; i < 4; i++)
            {
                string password = $"pw-{rng.Next():x}-\u00e9-\U0001f510";
                var salt = new byte[16];
                var verifier = new byte[16];
                rng.NextBytes(salt);
                rng.NextBytes(verifier);
                byte[] final = SHA1.HashData([.. ReferenceSpin(Encoding.Unicode.GetBytes(password), salt), 0, 0, 0, 0]);
                byte[] material = new byte[40];
                foreach (var (pad, offset) in new[] { ((byte)0x36, 0), ((byte)0x5c, 20) })
                {
                    byte[] block = Enumerable.Repeat(pad, 64).ToArray();
                    for (int j = 0; j < final.Length; j++) block[j] ^= final[j];
                    SHA1.HashData(block).CopyTo(material, offset);
                }
                using var aes = Aes.Create();
                aes.Key = material[..(bits / 8)];
                byte[] encrypted = aes.EncryptEcb([.. verifier, .. SHA1.HashData(verifier), .. new byte[12]], PaddingMode.None);
                string hash = $"$office$*2007*20*{bits}*16*{Convert.ToHexString(salt)}*{Convert.ToHexString(encrypted, 0, 16)}*{Convert.ToHexString(encrypted, 16, 20)}";
                var kernel = Assert.IsType<Office2007Kernel>(Office2007Kernel.TryParse(hash));
                byte[] pw = Encoding.UTF8.GetBytes(password);
                Assert.True(kernel.Verify(pw));
                Assert.Equal(0, kernel.CreateWorker().SearchPasswords(pw, pw.Length, 1));
                pw[^1] ^= 1;
                Assert.False(kernel.Verify(pw));
            }
    }

    [Fact]
    public unsafe void EveryNativePathMatchesDotNetSha1AtLaneAndUtf16Boundaries()
    {
        if (!RkNative.Available) return;
        var saved = RkNative.Features;
        string? pathOverride = Environment.GetEnvironmentVariable("RECOVERKIT_OFFICE2007_PATH");
        var rng = new Random(2007);
        try
        {
            Environment.SetEnvironmentVariable("RECOVERKIT_OFFICE2007_PATH", null);
            foreach (var (features, bit) in Paths(saved))
            {
                RkNative.LimitFeatures(features);
                int lanes = RkNative.Office2007Lanes();
                Assert.True(lanes > 0);
                foreach (int count in new[] { 1, Math.Max(1, lanes - 1), lanes, lanes + 1, 2 * lanes + 3 }.Distinct())
                {
                    const int stride = 512;
                    var salt = new byte[16];
                    rng.NextBytes(salt);
                    var passwords = new byte[count * stride];
                    rng.NextBytes(passwords);
                    int[] lengths = Enumerable.Range(0, count).Select(i =>
                        new[] { 0, 2, 38, 40, 54, 56, 126, 128, 254, 256, 258, 510, 512 }[i % 13]).ToArray();
                    var expected = Enumerable.Range(0, count).SelectMany(i =>
                        ReferenceSpin(passwords.AsSpan(i * stride, lengths[i]), salt)).ToArray();
                    var actual = Enumerable.Repeat((byte)0xcc, count * 20 + 16).ToArray();
                    RkNative.ResetExecutedPaths(9400);
                    fixed (byte* p = passwords, s = salt, h = actual)
                    fixed (int* l = lengths)
                        Assert.Equal(0, RkNative.Office2007Spin(p, stride, l, count, s, h));
                    Assert.Equal(expected, actual.AsSpan(0, count * 20).ToArray());
                    Assert.All(actual.Skip(count * 20), b => Assert.Equal((byte)0xcc, b));
                    Assert.Equal(bit, RkNative.Office2007ExecutedPaths());
                }
                if (bit != 1) Assert.Equal(1, RkNative.Office2007SelfTestState());
            }
        }
        finally
        {
            RkNative.LimitFeatures(saved);
            Environment.SetEnvironmentVariable("RECOVERKIT_OFFICE2007_PATH", pathOverride);
        }
    }

    [Fact]
    public unsafe void NativeSpinRejectsInvalidArgumentsBeforeWriting()
    {
        if (!RkNative.Available) return;
        byte* password = stackalloc byte[32];
        byte* salt = stackalloc byte[16];
        byte* hash = stackalloc byte[20];
        new Span<byte>(hash, 20).Fill(0xcc);
        int length = 34;
        Assert.Equal(-1, RkNative.Office2007Spin(password, 32, &length, 1, salt, hash));
        length = -2;
        Assert.Equal(-1, RkNative.Office2007Spin(password, 32, &length, 1, salt, hash));
        length = 3;
        Assert.Equal(-1, RkNative.Office2007Spin(password, 32, &length, 1, salt, hash));
        Assert.Equal(-1, RkNative.Office2007Spin(password, 31, null, 1, salt, hash));
        Assert.Equal(-1, RkNative.Office2007Spin(password, 32, null, -1, salt, hash));
        Assert.Equal(-1, RkNative.Office2007Spin(null, 32, null, 1, salt, hash));
        Assert.Equal(-1, RkNative.Office2007Spin(password, 32, null, 1, null, hash));
        Assert.Equal(-1, RkNative.Office2007Spin(password, 32, null, 1, salt, null));
        Assert.All(new ReadOnlySpan<byte>(hash, 20).ToArray(), value => Assert.Equal((byte)0xcc, value));
        Assert.Equal(0, RkNative.Office2007Spin(null, 0, null, 0, salt, null));
    }

    [Fact]
    public unsafe void NativeFilterAndWorkerFindOnlyPlantedPasswordsInPartialBatches()
    {
        if (!RkNative.Available) return;
        var saved = RkNative.Features;
        string? pathOverride = Environment.GetEnvironmentVariable("RECOVERKIT_OFFICE2007_PATH");
        try
        {
            Environment.SetEnvironmentVariable("RECOVERKIT_OFFICE2007_PATH", null);
            int* hits = stackalloc int[2];
            foreach (var (features, _) in Paths(saved))
            {
                RkNative.LimitFeatures(features);
                int count = 2 * RkNative.Office2007Lanes() + 3;
                var kernel = Assert.IsType<Office2007Kernel>(Office2007Kernel.TryParse(HashcatExample));
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
            Environment.SetEnvironmentVariable("RECOVERKIT_OFFICE2007_PATH", pathOverride);
        }
    }

    private static IEnumerable<(RkNative.Feature Features, int Bit)> Paths(RkNative.Feature features)
    {
        yield return (0, 1);
        if (features.HasFlag(RkNative.Feature.Avx2)) yield return (RkNative.Feature.Avx2, 2);
        if (features.HasFlag(RkNative.Feature.Avx512)) yield return (RkNative.Feature.Avx512 | RkNative.Feature.Avx2, 4);
        if (features.HasFlag(RkNative.Feature.Neon)) yield return (RkNative.Feature.Neon, 8);
        if (features.HasFlag(RkNative.Feature.ArmSha1)) yield return (RkNative.Feature.ArmSha1 | RkNative.Feature.Neon, 32);
        if (features.HasFlag(RkNative.Feature.ShaNi)) yield return (RkNative.Feature.ShaNi, 64);
    }

    private static byte[] ReferenceSpin(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt)
    {
        byte[] h = SHA1.HashData([.. salt, .. password]);
        Span<byte> input = stackalloc byte[24];
        for (int i = 0; i < 50000; i++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(input, i);
            h.CopyTo(input[4..]);
            SHA1.HashData(input, h);
        }
        return h;
    }

    private static Stream Fixture(string name) => typeof(Office2007CpuTests).Assembly.GetManifestResourceStream("RecoverKit.Tests.Fixtures.Office." + name)!;
}
