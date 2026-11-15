using System.Security.Cryptography;
using RecoverKit.Core.Diagnostics;
using RecoverKit.Core.Formats;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

public sealed class WinZipAesCpuTests
{
    // Python hashlib/hmac reference vectors, independent of the kernel and ZIP generator.
    private static readonly string[] Vectors =
    [
        "$zip2$*0*1*0*0001020304050607*112d*25*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324*d21f7cc0b887a92d6985*$/zip2$",
        "$zip2$*0*2*0*000102030405060708090a0b*4151*25*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324*b36d4de9a77e7c4bce77*$/zip2$",
        "$zip2$*0*3*0*000102030405060708090a0b0c0d0e0f*cb23*25*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324*be14c3f6f8baa89a528a*$/zip2$",
    ];

    public static IEnumerable<object[]> KnownAnswers => Vectors.Select(line => new object[] { line });

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public void AllStrengthsConfirmFullAuthentication(int strength)
    {
        var kernel = Assert.IsType<WinZipAesKernel>(WinZipAesKernel.TryParse(Vectors[strength - 1]));
        Assert.True(kernel.Verify("winzip-test"u8));
        Assert.False(kernel.Verify("wrong"u8));
        Assert.Equal(1, kernel.CreateWorker().Search("winzip-tes"u8, "xtz"u8));
        Assert.Equal(4, kernel.CreateWorker().SearchBatch("wrong--teswinzip-tes"u8, 2, "xtz"u8));
        Assert.Equal(1, kernel.CreateWorker().SearchPasswords("wrong-wrongwinzip-test"u8, 11, 2));
        Assert.Equal(-1, kernel.CreateWorker().Search("wrong"u8, "123"u8));
        var damaged = Vectors[strength - 1].Split('*');
        damaged[8] = "00000000000000000000";
        Assert.False(Assert.IsType<WinZipAesKernel>(WinZipAesKernel.TryParse(string.Join('*', damaged))).Verify("winzip-test"u8));
        damaged = Vectors[strength - 1].Split('*');
        damaged[7] = damaged[7][..^2] + "00";
        Assert.False(Assert.IsType<WinZipAesKernel>(WinZipAesKernel.TryParse(string.Join('*', damaged))).Verify("winzip-test"u8));
    }

    [Fact]
    public void VerifierCollisionDoesNotBecomeAPasswordMatch()
    {
        byte[] salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        byte[] correct = "collision-0377"u8.ToArray(), wrong = "collision-0469"u8.ToArray();
        byte[] first = Rfc2898DeriveBytes.Pbkdf2(correct, salt, 1000, HashAlgorithmName.SHA1, 66);
        byte[] second = Rfc2898DeriveBytes.Pbkdf2(wrong, salt, 1000, HashAlgorithmName.SHA1, 66);
        Assert.Equal(Convert.FromHexString("33c7"), first[64..]);
        Assert.Equal(first[64..], second[64..]);
        var kernel = Assert.IsType<WinZipAesKernel>(WinZipAesKernel.TryParse(Hash(correct, 3)));
        Assert.True(kernel.Verify(correct));
        Assert.False(kernel.Verify(wrong));
        Assert.Equal(-1, kernel.CreateWorker().Search("collision-046"u8, "9"u8));
        Assert.Equal(1, kernel.CreateWorker().SearchPasswords([.. wrong, .. correct], correct.Length, 2));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public unsafe void NativeVerifierBlockFindsTheTailOfAPartialBatch(int strength)
    {
        if (!RkNative.Available) return;
        var kernel = Assert.IsType<WinZipAesKernel>(WinZipAesKernel.TryParse(Vectors[strength - 1]));
        byte[] passwords = Enumerable.Repeat((byte)'x', 129 * 11).ToArray();
        "winzip-test"u8.CopyTo(passwords.AsSpan(128 * 11));
        int* hits = stackalloc int[4];
        fixed (byte* p = passwords)
        {
            Assert.Equal(1, ((INativeFilter)kernel).Filter(p, 11, 129, hits, 4));
            Assert.Equal(128, hits[0]);
        }
        Assert.Equal(128, kernel.CreateWorker().SearchPasswords(passwords, 11, 129));
    }

    [Fact]
    public void EmptyCiphertextUsesItsAuthenticationCode()
    {
        var kernel = Assert.IsType<WinZipAesKernel>(WinZipAesKernel.TryParse(
            "$zip2$*0*1*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$"));
        Assert.True(kernel.Verify("hashcat"u8));
        Assert.False(kernel.Verify("wrong"u8));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(127)]
    [InlineData(256)]
    public void PasswordByteLengthsAndBinaryValuesArePreserved(int length)
    {
        byte[] password = Enumerable.Range(0, length).Select(i => (byte)(i * 29)).ToArray();
        var kernel = Assert.IsType<WinZipAesKernel>(WinZipAesKernel.TryParse(Hash(password, 3)));
        Assert.True(kernel.Verify(password));
        if (length > 0)
        {
            Assert.Equal(0, kernel.CreateWorker().SearchPasswords(password, length, 1));
            password[^1] ^= 1;
            Assert.False(kernel.Verify(password));
        }
    }

    [Fact]
    public void Utf8PasswordBytesAreNotRecoded()
    {
        byte[] password = System.Text.Encoding.UTF8.GetBytes("příliš-🔐");
        var kernel = Assert.IsType<WinZipAesKernel>(WinZipAesKernel.TryParse(Hash(password, 2)));
        Assert.True(kernel.Verify(password));
        Assert.Equal(0, kernel.CreateWorker().SearchPasswords(password, password.Length, 1));
        Assert.False(kernel.Verify(new byte[257]));
    }

    [Fact]
    public void HashExtractedFromArchiveAuthenticatesTheEncryptedPayload()
    {
        string path = Path.Combine(Environment.GetEnvironmentVariable("RECOVERKIT_HOME") ?? Path.GetTempPath(), "winzip-kernel-" + Guid.NewGuid().ToString("N") + ".zip");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        try
        {
            File.WriteAllBytes(path, DiagnosticZipSample.AesArchive("winzip-test"));
            var detection = FormatDetector.Detect(path);
            Assert.Null(detection.Message);
            var target = Assert.IsType<HashTarget>(detection.Target);
            Assert.Contains(13600, target.Modes);
            Assert.True(Assert.IsType<WinZipAesKernel>(WinZipAesKernel.TryParse(target.HashLines)).Verify("winzip-test"u8));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void MalformedAndUnsupportedHashesAreRejected()
    {
        string[] f = Vectors[0].Split('*');
        foreach (var change in new (int Field, string Value)[]
        {
            (0, "$zip3$"), (1, "1"), (2, "0"), (2, "4"), (2, "+1"), (3, "1"),
            (4, "00"), (4, "zz01020304050607"), (5, "112"), (5, "zzzz"),
            (6, "24"), (6, "-1"), (6, "7fffffff"), (6, "ffffffffffffffff"), (6, "zz"),
            (7, "00"), (7, new string('z', 74)), (8, "00"), (8, new string('z', 20)), (9, "$/zip2"),
        })
        {
            string[] malformed = (string[])f.Clone();
            malformed[change.Field] = change.Value;
            Assert.Null(WinZipAesKernel.TryParse(string.Join('*', malformed)));
        }
        Assert.Null(WinZipAesKernel.TryParse(""));
        Assert.Null(WinZipAesKernel.TryParse(null!));
        Assert.Null(WinZipAesKernel.TryParse(Vectors[0] + "*extra"));
    }

    private static string Hash(byte[] password, int strength)
    {
        int keyBytes = 8 * (strength + 1);
        byte[] salt = Enumerable.Range(0, keyBytes / 2).Select(i => (byte)i).ToArray();
        byte[] derived = Rfc2898DeriveBytes.Pbkdf2(password, salt, 1000, HashAlgorithmName.SHA1, keyBytes * 2 + 2);
        byte[] body = "authenticated ciphertext"u8.ToArray();
        byte[] auth = HMACSHA1.HashData(derived.AsSpan(keyBytes, keyBytes), body)[..10];
        return $"$zip2$*0*{strength}*0*{Convert.ToHexString(salt)}*{Convert.ToHexString(derived.AsSpan(keyBytes * 2))}*{body.Length:x}*{Convert.ToHexString(body)}*{Convert.ToHexString(auth)}*$/zip2$";
    }
}
