using System.Numerics;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using RecoverKit.Core;
using RecoverKit.Core.Attacks;
using RecoverKit.Core.Hashcat;
using RecoverKit.Core.Native.Kernels;
using RecoverKit.Core.Native;
using Xunit;

namespace RecoverKit.Tests;

public class TrueCryptWhirlpoolTests
{
    // hashcat mode 29331's published example, password "hashcat".
    internal const string Example = "$truecrypt$cf53d4153414b63285e701e52c2d99e148c6ccc4508132f82cb41862d0a0ac9ea16274285ac261c339c1508eec9fea54c33e382458662913678f2a88a84959a6$78e238973985ec670d50252677430587ee28b72bfa5edfb2f79c40b734ba8a54a3662642a6ab067e75f41154688ad4adb5d6decd891462dd537188195a51e06fa5baf22b69d0f472cfeeae77ab9a90091731863af1d8b5b380da179fa7d5227ef031732b1ae06e0fe34c0b28b7a64eac34e5a08e09d7001394b3afc804ac69bf819cdd2d383fe96a721f7c683628da8e529d84bdaa68d702573d8f7ef26f75d1bd5c91efa88cb33b1e9c006b87981c55ed3b8063ab7068f8e99b128bc56ea3e883efa55d6f340b2681e50405d91f5f6d76cdbeac404944164d329d3ee01311de0bc6547310f126b5a4c0e9fb74825f91faefa60b7ac828819d4544c1872ff5041e61d5cf093553f427358b2181046376d7b876e1bccf0774d5d251b7c922c214bb5c70c715165d028e1dca73e7adeca3396d77f6e597a10dd4c58f37fdbbdc1d04cd8890ba4c5025776a88a349bb925add13193becf1ca10fe32536db0c0b06a1ef799fb692e304b3716ca5a8a80859c4012ca3e06701b46b5a32f4d10e285a0cdaf6c24e0d98139e7f306e52503c9b503aa28f1fbbb236284907068074fcb3e267e3c4aab2bd3b79b24a7a08106bb55850fa2bb8e2f6d9919a6743cb822c164";

    [Fact]
    public void FindsPublishedExampleAndRejectsWrongPassword()
    {
        var kernel = TrueCryptWhirlpoolKernel.TryParse(Example);
        Assert.NotNull(kernel);
        Assert.True(kernel.Verify("hashcat"u8));
        Assert.False(kernel.Verify("hashcas"u8));
        Assert.Equal("hashcat", NativeEngineTests.Find(kernel, "-a", "3", "hashca?l"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(31)]
    [InlineData(32)]
    [InlineData(63)]
    [InlineData(64)]
    public unsafe void NativeDerivationMatchesIndependentWhirlpool(int len)
    {
        if (!RkNative.Available) return;
        var rng = new Random(29331 + len);
        var salt = new byte[64]; rng.NextBytes(salt);
        var passwords = new byte[5 * len]; rng.NextBytes(passwords);
        var keys = new byte[5 * 64];
        fixed (byte* s = salt, p = passwords, k = keys)
            Assert.Equal(5, RkNative.WhirlpoolPbkdf2(s, p, len, 5, k));
        for (int i = 0; i < 5; i++)
            Assert.Equal(TrueCryptWhirlpoolKernel.Derive(passwords.AsSpan(i * len, len), salt), keys.AsSpan(i * 64, 64).ToArray());
    }

    [Theory]
    [InlineData("AES")]
    [InlineData("Serpent")]
    [InlineData("Twofish")]
    public void EverySingleCipherFindsPasswordsAndRejectsDamagedHeaders(string cipher)
    {
        var line = MakeHeader(cipher);
        var k = TrueCryptWhirlpoolKernel.TryParse(line)!;
        Assert.True(k.Verify("test7"u8));
        Assert.False(k.Verify("test8"u8));
        Assert.False(k.Verify(new byte[65]));
        Assert.Equal("test7", NativeEngineTests.Find(k, "-a", "3", "test?d"));
        // First block still decrypts to TRUE, but either header CRC or key-area CRC is invalid.
        Assert.False(TrueCryptWhirlpoolKernel.TryParse(MakeHeader(cipher, 32))!.Verify("test7"u8));
        Assert.False(TrueCryptWhirlpoolKernel.TryParse(MakeHeader(cipher, 256))!.Verify("test7"u8));
        var longPassword = Enumerable.Range(0, 64).Select(i => (byte)(128 + i)).ToArray();
        Assert.True(TrueCryptWhirlpoolKernel.TryParse(MakeHeader(cipher, password: longPassword))!.Verify(longPassword));
    }

    [Fact]
    public void ParserRejectsMalformedAndExtendedHashLines()
    {
        foreach (var line in new[] { "", Example[..^1], Example + "$keyfile", Example.Replace("$truecrypt$", "$veracrypt$"), Example.Replace('c', 'z') })
            Assert.Null(TrueCryptWhirlpoolKernel.TryParse(line));
    }

    [Fact]
    public void PlannerKeepsGpuAndUnsupportedAttacksOnHashcat()
    {
        var settings = new Settings { UseNativeCpuEngine = true };
        var mask = new PreparedAttack { Description = "mask", Args = { "-a", "3", "hashca?l" } };
        var gpu = new BackendDevice { Id = 1, Type = "GPU", Name = "Test GPU" };
        Assert.Null(NativeRunner.Plan(29331, Example, mask, settings, [gpu]));
        Assert.Null(NativeRunner.Plan(29332, Example, mask, settings, []));
        Assert.Null(NativeRunner.Plan(29333, Example, mask, settings, []));
        Assert.Null(NativeRunner.Plan(29331, Example, new PreparedAttack { Description = "dictionary", Args = { "-a", "0", "words.txt" } }, settings, []));
        settings.UseNativeCpuEngine = false;
        Assert.Null(NativeRunner.Plan(29331, Example, mask, settings, []));
        settings.UseNativeCpuEngine = true;
        foreach (var extra in new[] { "--truecrypt-keyfiles keyfile.bin", "--keyboard-layout-mapping layout.hc" })
        {
            settings.ExtraArguments = extra;
            Assert.Null(NativeRunner.Plan(29331, Example, mask, settings, []));
        }
        settings.ExtraArguments = " ";
        Assert.Equal(RkNative.Available, NativeRunner.Plan(29331, Example, mask, settings, []) is not null);
    }

    // Fixed version-5 header with CRCs computed independently using Python zlib.crc32.
    internal static string MakeHeader(string name, int corruptOffset = -1, byte[]? password = null)
    {
        var salt = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
        var plain = Enumerable.Range(0, 448).Select(i => (byte)(i * 29 + 7)).ToArray();
        "TRUE"u8.CopyTo(plain);
        Convert.FromHexString("00050700").CopyTo(plain, 4);
        Convert.FromHexString("fe7000d5").CopyTo(plain, 8);
        Convert.FromHexString("e69fbd87").CopyTo(plain, 188);
        if (corruptOffset >= 0) plain[corruptOffset] ^= 1;
        var key = TrueCryptWhirlpoolKernel.Derive(password ?? "test7"u8.ToArray(), salt);
        IBlockCipher cipher = name switch { "AES" => new AesEngine(), "Serpent" => new SerpentEngine(), _ => new TwofishEngine() };
        var tweakBytes = new byte[16];
        cipher.Init(true, new KeyParameter(key[32..]));
        cipher.ProcessBlock(tweakBytes, 0, tweakBytes, 0);
        var tweak = new BigInteger(tweakBytes, isUnsigned: true, isBigEndian: false);
        var mask = (BigInteger.One << 128) - 1;
        cipher.Init(true, new KeyParameter(key[..32]));
        for (int offset = 0; offset < plain.Length; offset += 16)
        {
            Array.Clear(tweakBytes);
            tweak.TryWriteBytes(tweakBytes, out _, isUnsigned: true, isBigEndian: false);
            for (int j = 0; j < 16; j++) plain[offset + j] ^= tweakBytes[j];
            cipher.ProcessBlock(plain, offset, plain, offset);
            for (int j = 0; j < 16; j++) plain[offset + j] ^= tweakBytes[j];
            tweak <<= 1;
            if (tweak > mask) tweak = (tweak & mask) ^ 0x87;
        }
        return "$truecrypt$" + Convert.ToHexString(salt) + "$" + Convert.ToHexString(plain);
    }
}
