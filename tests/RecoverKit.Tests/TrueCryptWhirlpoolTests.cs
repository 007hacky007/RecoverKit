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
using RecoverKit.Core.Diagnostics;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public class TrueCryptWhirlpoolTests
{
    [Fact]
    public void ExperimentalSettingDefaultsOffAndRoundTrips()
    {
        Assert.False(new Settings().WhirlpoolAvx512);
        Assert.False(System.Text.Json.JsonSerializer.Deserialize<Settings>("{}")!.WhirlpoolAvx512);
        string file = Path.Combine(Settings.AppDataDir, "settings.json");
        byte[]? saved = File.Exists(file) ? File.ReadAllBytes(file) : null;
        try
        {
            foreach (bool enabled in new[] { true, false })
            {
                new Settings { WhirlpoolAvx512 = enabled }.Save();
                Assert.Equal(enabled, Settings.Load().WhirlpoolAvx512);
            }
        }
        finally
        {
            if (saved is null) File.Delete(file);
            else File.WriteAllBytes(file, saved);
        }
    }

    [Fact]
    public void ProfileExplanationDoesNotClaimIgnoredWhirlpoolVariant()
    {
        var settings = new Settings { WhirlpoolAvx512 = false,
            CpuPerformanceChoice = new() { Mode = 29331, Variant = "avx512", Threads = 1 } };
        string explanation = ProfileSettings.Explain(settings, [], cpuOnly: true, hybrid: false);
        Assert.DoesNotContain("avx512", explanation);
        Assert.Contains("CPU workers", explanation);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public unsafe void SettingControlsDispatchWithoutChangingKeys(bool enabled)
    {
        if (!RkNative.Available) return;
        bool saved = RkNative.WhirlpoolAvx512Enabled;
        try
        {
            // A measured profile must never override the user's Whirlpool preference.
            var settings = new Settings { WhirlpoolAvx512 = enabled,
                CpuPerformanceChoice = new() { Variant = enabled ? "scalar" : "avx512" } };
            using var selection = ProfileSettings.CpuSelection(settings, 29331);
            Assert.Equal(enabled, RkNative.WhirlpoolAvx512Enabled);
            NativeKernels.ResetCpuPath(29331);
            byte[] salt = new byte[64], passwords = new byte[8 * 7], keys = new byte[8 * 64];
            fixed (byte* s = salt, p = passwords, k = keys)
                Assert.Equal(8, RkNative.WhirlpoolPbkdf2(s, p, 7, 8, k));
            byte[] expected = TrueCryptWhirlpoolKernel.Derive(new byte[7], salt);
            for (int i = 0; i < 8; i++) Assert.Equal(expected, keys[(i * 64)..((i + 1) * 64)]);
            string? forced = Environment.GetEnvironmentVariable("RECOVERKIT_WHIRLPOOL_AVX512");
            bool wide = RkNative.Features.HasFlag(RkNative.Feature.Avx512) && forced != "0" && (enabled || forced == "1");
            Assert.Equal(wide ? 4 : 1, RkNative.WhirlpoolExecutedPaths());
            Assert.Equal(wide ? "native AVX-512" : "native scalar", NativeKernels.CpuPath(29331, actualOnly: true));
        }
        finally { RkNative.WhirlpoolAvx512Enabled = saved; }
    }

    [Fact]
    public unsafe void BenchmarkSelectionsIgnorePreferenceAndRestoreIt()
    {
        if (!RkNative.Available) return;
        bool saved = RkNative.WhirlpoolAvx512Enabled;
        var features = RkNative.Features;
        byte[] salt = new byte[64], passwords = new byte[8 * 7], keys = new byte[8 * 64];
        try
        {
            RkNative.WhirlpoolAvx512Enabled = true;
            using (KernelVariants.Select(29331, "scalar"))
            {
                NativeKernels.ResetCpuPath(29331);
                fixed (byte* s = salt, p = passwords, k = keys)
                    Assert.Equal(8, RkNative.WhirlpoolPbkdf2(s, p, 7, 8, k));
                Assert.Equal(1, RkNative.WhirlpoolExecutedPaths());
            }
            Assert.Equal(features, RkNative.Features);
            RkNative.WhirlpoolAvx512Enabled = false;
            if (KernelVariants.Supported(29331, "avx512"))
            {
                using (KernelVariants.Select(29331, "avx512"))
                {
                    Assert.True(RkNative.WhirlpoolAvx512Enabled);
                    NativeKernels.ResetCpuPath(29331);
                    fixed (byte* s = salt, p = passwords, k = keys)
                        Assert.Equal(8, RkNative.WhirlpoolPbkdf2(s, p, 7, 8, k));
                    Assert.Equal(Environment.GetEnvironmentVariable("RECOVERKIT_WHIRLPOOL_AVX512") == "0" ? 1 : 4,
                        RkNative.WhirlpoolExecutedPaths());
                }
                Assert.False(RkNative.WhirlpoolAvx512Enabled);
            }
            byte[] expected = TrueCryptWhirlpoolKernel.Derive(new byte[7], salt);
            for (int i = 0; i < 8; i++) Assert.Equal(expected, keys[(i * 64)..((i + 1) * 64)]);
        }
        finally { RkNative.WhirlpoolAvx512Enabled = saved; RkNative.LimitFeatures(features); }
    }

    [Fact]
    [Trait("Category", "Slow")]
    public unsafe void NativePathsMatchScalarAndIndependentWhirlpoolIncludingTails()
    {
        if (!RkNative.Available) return;
        var features = RkNative.Features;
        var rng = new Random(29331512);
        bool enabled = RkNative.WhirlpoolAvx512Enabled;
        try
        {
            RkNative.WhirlpoolAvx512Enabled = true;
            foreach (int len in new[] { 0, 1, 7, 8, 31, 32, 63, 64 })
            foreach (int n in new[] { 0, 1, 3, 7, 8, 9, 15, 16, 19 })
            {
                byte[] salt = new byte[64], passwords = new byte[n * len];
                rng.NextBytes(salt); rng.NextBytes(passwords);
                byte[] scalar = new byte[n * 64], actual = new byte[n * 64 + 16];
                Array.Fill(actual, (byte)0xa5);
                fixed (byte* s = salt, p = passwords, a = actual, b = scalar)
                {
                    RkNative.LimitFeatures(0);
                    Assert.Equal(n, RkNative.WhirlpoolPbkdf2(s, p, len, n, b));
                    RkNative.LimitFeatures(features);
                    NativeKernels.ResetCpuPath(29331);
                    Assert.Equal(n, RkNative.WhirlpoolPbkdf2(s, p, len, n, a));
                }
                Assert.Equal(scalar, actual[..(n * 64)]);
                Assert.All(actual[(n * 64)..], b => Assert.Equal(0xa5, b));
                for (int i = 0; i < n; i++)
                    Assert.Equal(TrueCryptWhirlpoolKernel.Derive(passwords.AsSpan(i * len, len), salt), actual.AsSpan(i * 64, 64).ToArray());
                if (n > 0 && features.HasFlag(RkNative.Feature.Avx512)
                    && Environment.GetEnvironmentVariable("RECOVERKIT_WHIRLPOOL_AVX512") != "0")
                {
                    Assert.Equal("passed", NativeKernels.WideSelfTestState(29331));
                    Assert.Equal("native AVX-512", NativeKernels.CpuPath(29331, actualOnly: true));
                }
            }
        }
        finally { RkNative.LimitFeatures(features); RkNative.WhirlpoolAvx512Enabled = enabled; }
    }

    [Fact]
    public unsafe void FeatureMaskForcesScalarAndReportsActualExecution()
    {
        if (!RkNative.Available) return;
        var saved = RkNative.Features;
        try
        {
            RkNative.LimitFeatures(0);
            NativeKernels.ResetCpuPath(29331);
            Assert.Equal("not run", NativeKernels.CpuPath(29331, actualOnly: true));
            byte[] salt = new byte[64], keys = new byte[64];
            fixed (byte* s = salt, p = "hashcat"u8, k = keys)
                Assert.Equal(1, RkNative.WhirlpoolPbkdf2(s, p, 7, 1, k));
            Assert.Equal(TrueCryptWhirlpoolKernel.Derive("hashcat"u8, salt), keys);
            Assert.Equal("native scalar", NativeKernels.CpuPath(29331, actualOnly: true));
        }
        finally { RkNative.LimitFeatures(saved); }
    }

    [Theory]
    [Trait("Category", "Slow")]
    [InlineData("1")]
    [InlineData("12x")]
    public void PrefixBatchesFindEveryPositionWithNativeAndManagedPaths(string last)
    {
        var kernel = TrueCryptWhirlpoolKernel.TryParse(MakeHeader("AES"))!;
        bool saved = RkNative.Disabled;
        bool enabled = RkNative.WhirlpoolAvx512Enabled;
        try
        {
            RkNative.WhirlpoolAvx512Enabled = true;
            foreach (bool disabled in new[] { false, true })
            {
                RkNative.Disabled = saved || disabled;
                var worker = kernel.CreateWorker();
                const int count = 11;
                for (int position = 0; position < count; position++)
                {
                    byte[] prefixes = Enumerable.Repeat("nope"u8.ToArray(), count).SelectMany(p => p).ToArray();
                    "test"u8.CopyTo(prefixes.AsSpan(position * 4));
                    byte[] suffixes = System.Text.Encoding.ASCII.GetBytes(last.Replace('1', '7'));
                    Assert.Equal(position * last.Length, worker.SearchBatch(prefixes, count, suffixes));
                }
                Assert.Equal(-1, worker.SearchBatch("nope"u8, 1, "7"u8));
                Assert.Equal(-1, worker.SearchBatch([], 0, "7"u8));
            }
        }
        finally { RkNative.Disabled = saved; RkNative.WhirlpoolAvx512Enabled = enabled; }
    }

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
