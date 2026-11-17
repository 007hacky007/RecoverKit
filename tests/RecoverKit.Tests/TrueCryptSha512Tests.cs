using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using RecoverKit.Core.Native;
using RecoverKit.Core.Native.Kernels;
using Xunit;

namespace RecoverKit.Tests;

[Collection("NativeFeatures")]
public class TrueCryptSha512Tests
{
    [Theory]
    [InlineData(29321)]
    [InlineData(29322)]
    [InlineData(29323)]
    [InlineData(29421)]
    [InlineData(29422)]
    [InlineData(29423)]
    public void PublishedExamplesHaveCpuKernel(int mode)
    {
        var kernel = NativeKernels.TryCreate(mode, Examples[mode]);
        Assert.NotNull(kernel);
        Assert.True(kernel.Verify("hashcat"u8));
        Assert.False(kernel.Verify("wrong"u8));
    }

    [Fact]
    public void KuznyechikMatchesRfc7801EncryptionAndDecryption()
    {
        IBlockCipher cipher = new KuznyechikEngine();
        var key = new KeyParameter(Convert.FromHexString("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef"));
        byte[] plain = Convert.FromHexString("1122334455667700ffeeddccbbaa9988"), actual = new byte[16];
        byte[] encrypted = Convert.FromHexString("7f679d90bebc24305a468d42b9d4edcd");
        cipher.Init(true, key);
        cipher.ProcessBlock(plain, 0, actual, 0);
        Assert.Equal(encrypted, actual);
        cipher.Init(false, key);
        cipher.ProcessBlock(encrypted, 0, actual, 0);
        Assert.Equal(plain, actual);
    }

    public static IEnumerable<object[]> CipherCases()
    {
        string[] tc = ["AES", "Serpent", "Twofish", "AES-Twofish", "Serpent-AES", "Twofish-Serpent", "AES-Twofish-Serpent", "Serpent-Twofish-AES"];
        string[] vc = [.. tc, "Camellia", "Kuznyechik", "Camellia-Kuznyechik", "Camellia-Serpent", "Kuznyechik-Twofish", "Kuznyechik-AES", "Kuznyechik-Serpent-Camellia"];
        foreach (int mode in new[] { 29321, 29322, 29323, 29421, 29422, 29423 })
        foreach (string cipher in mode >= 29400 ? vc : tc)
            if (cipher.Split('-').Length <= mode % 10) yield return [mode, cipher];
    }

    [Theory]
    [MemberData(nameof(CipherCases))]
    public void GeneratedHeadersCoverEveryCipherAndSmallerKeyLayouts(int mode, string cipher)
    {
        string line = MakeHeader(mode, cipher);
        var kernel = TrueCryptSha512Kernel.TryParse(mode, line)!;
        Assert.True(kernel.Verify("test7"u8));
        Assert.False(kernel.Verify("wrong"u8));
        Assert.Equal(1, kernel.CreateWorker().SearchPasswords("wrongtest7"u8, 5, 2));
    }

    [Theory]
    [InlineData(29321, 0)]
    [InlineData(29323, 64)]
    [InlineData(29421, 0)]
    [InlineData(29423, 128)]
    public void EmptyAndMaximumPasswordLengthsAreAccepted(int mode, int length)
    {
        byte[] password = Enumerable.Range(0, length).Select(i => (byte)(i * 11)).ToArray();
        var kernel = TrueCryptSha512Kernel.TryParse(mode, MakeHeader(mode, "AES", password))!;
        Assert.True(kernel.Verify(password));
        Assert.Equal(0, kernel.CreateWorker().SearchPasswords(password, length, 1));
        Assert.False(kernel.Verify(new byte[kernel.MaxPasswordLength + 1]));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    public void FixedVeraCryptPimUsesHashcatIterationFormula(int pim)
    {
        var kernel = TrueCryptSha512Kernel.TryParse(29423, MakeHeader(29423, "Kuznyechik-Serpent-Camellia", pim: pim), pim)!;
        Assert.Equal((15 + pim) * 1000, kernel.Iterations);
        Assert.True(kernel.Verify("test7"u8));
        Assert.Equal(0, kernel.CreateWorker().SearchPasswords("test7"u8, 5, 1));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(32)]
    [InlineData(256)]
    public void HeaderSignatureAndBothCrcsAreRequired(int corrupt)
    {
        Assert.False(TrueCryptSha512Kernel.TryParse(29323, MakeHeader(29323, "AES-Twofish-Serpent", corruptOffset: corrupt))!.Verify("test7"u8));
    }

    [Fact]
    public void HeaderVersionThreeDoesNotRequireHeaderCrc()
    {
        Assert.True(TrueCryptSha512Kernel.TryParse(29321, MakeHeader(29321, "AES", corruptOffset: 32, version: 3))!.Verify("test7"u8));
    }

    [Theory]
    [InlineData(29321, 6221)]
    [InlineData(29322, 6222)]
    [InlineData(29323, 6223)]
    [InlineData(29421, 13721)]
    [InlineData(29422, 13722)]
    [InlineData(29423, 13723)]
    public void LegacyAliasesUseTheSameKdf(int mode, int legacy)
    {
        Assert.True(TrueCryptSha512Kernel.TryParse(legacy, Examples[mode])!.Verify("hashcat"u8));
    }

    [Fact]
    public void ParserRejectsOtherAlgorithmsWrongBrandMalformedHexAndInvalidPim()
    {
        string line = Examples[29321];
        Assert.Null(TrueCryptSha512Kernel.TryParse(29331, line));
        Assert.Null(TrueCryptSha512Kernel.TryParse(29421, line));
        Assert.Null(TrueCryptSha512Kernel.TryParse(29321, line, 1));
        Assert.Null(TrueCryptSha512Kernel.TryParse(29421, Examples[29421], -1));
        Assert.Null(TrueCryptSha512Kernel.TryParse(29421, Examples[29421], int.MaxValue));
        Assert.Null(TrueCryptSha512Kernel.TryParse(29321, line[..^1]));
        Assert.Null(TrueCryptSha512Kernel.TryParse(29321, line[..^1] + "z"));
        Assert.Null(TrueCryptSha512Kernel.TryParse(29321, line + "\n" + line));
    }

    [Fact]
    public void PrefixBatchesAndManagedFallbackFindEveryLane()
    {
        var kernel = TrueCryptSha512Kernel.TryParse(29321, MakeHeader(29321, "AES"))!;
        bool saved = RkNative.Disabled;
        try
        {
            foreach (bool disabled in new[] { true, false })
            {
                RkNative.Disabled = saved || disabled;
                var worker = kernel.CreateWorker();
                for (int position = 0; position < 11; position++)
                {
                    byte[] prefixes = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("nope", 11)));
                    "test"u8.CopyTo(prefixes.AsSpan(position * 4));
                    Assert.Equal(position * 3 + 1, worker.SearchBatch(prefixes, 11, "x7z"u8));
                }
                Assert.Equal(-1, worker.SearchBatch("nope"u8, 1, "x7z"u8));
                Assert.Equal(-1, worker.SearchBatch([], 0, "7"u8));
                Assert.Equal(-1, worker.SearchPasswords([], 0, 0));
            }
        }
        finally { RkNative.Disabled = saved; }
    }

    [Fact]
    public unsafe void NativePathsMatchBouncyCastleAcrossLanesBlocksAndHmacBoundaries()
    {
        if (!RkNative.Available) return;
        var saved = RkNative.Features;
        var paths = new[] { (RkNative.Feature)0, RkNative.Feature.Avx2, RkNative.Feature.Avx2 | RkNative.Feature.Avx512,
            RkNative.Feature.Neon, RkNative.Feature.Neon | RkNative.Feature.ArmSha512 };
        var rng = new Random(29321512);
        int[] counts = [0, 1, 3, 7, 8, 9, 15, 16, 19], sizes = [1, 63, 64, 65, 128, 192];
        int[] saltLengths = [0, 1, 64, 107, 108, 127, 128, 137], passwordLengths = [0, 1, 7, 63, 64, 127, 128, 129];
        try
        {
            foreach (var path in paths)
            {
                if ((saved & path) != path) continue;
                RkNative.LimitFeatures(path);
                foreach (int count in counts)
                for (int c = 0; c < saltLengths.Length; c++)
                {
                    const int stride = 129;
                    int iterations = c % 3 == 0 ? 1 : c % 3 == 1 ? 2 : 37, keyLength = sizes[(count + c) % sizes.Length];
                    byte[] salt = new byte[saltLengths[c]], passwords = new byte[Math.Max(1, count * stride)], actual = new byte[count * keyLength + 16];
                    int[] lengths = Enumerable.Range(0, count).Select(i => passwordLengths[(c + i) % passwordLengths.Length]).ToArray();
                    rng.NextBytes(salt); rng.NextBytes(passwords); Array.Fill(actual, (byte)0xa5);
                    fixed (byte* pws = passwords, slt = salt, keys = actual)
                    fixed (int* lens = lengths)
                        Assert.Equal(count, RkNative.Pbkdf2Sha512(pws, stride, lens, count, slt, salt.Length, (uint)iterations, keys, keyLength));
                    for (int i = 0; i < count; i++)
                        Assert.Equal(TrueCryptSha512Kernel.Derive(passwords.AsSpan(i * stride, lengths[i]), salt, iterations, keyLength), actual.AsSpan(i * keyLength, keyLength).ToArray());
                    Assert.All(actual.AsSpan(count * keyLength).ToArray(), b => Assert.Equal(0xa5, b));
                }
            }
        }
        finally { RkNative.LimitFeatures(saved); }
    }

    // Framework PBKDF2 and BigInteger XTS arithmetic keep fixture generation independent of the kernel.
    internal static string MakeHeader(int mode, string cascade, byte[]? password = null, int pim = 0, int corruptOffset = -1, int version = 5, byte[]? salt = null)
    {
        bool vera = mode is >= 29421 and <= 29423 or >= 13721 and <= 13723;
        salt ??= Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
        var plain = Enumerable.Range(0, 448).Select(i => (byte)(i * 29 + 7)).ToArray();
        (vera ? "VERA"u8 : "TRUE"u8).CopyTo(plain);
        BinaryPrimitives.WriteUInt16BigEndian(plain.AsSpan(4), (ushort)version);
        BinaryPrimitives.WriteUInt16BigEndian(plain.AsSpan(6), 0x0700);
        BinaryPrimitives.WriteUInt32BigEndian(plain.AsSpan(8), Crc(plain.AsSpan(192, 256)));
        BinaryPrimitives.WriteUInt32BigEndian(plain.AsSpan(188), Crc(plain.AsSpan(0, 188)));
        if (corruptOffset >= 0) plain[corruptOffset] ^= 1;
        string[] layers = cascade.Split('-').Reverse().ToArray();
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password ?? "test7"u8.ToArray(), salt,
            vera ? pim == 0 ? 500000 : (15 + pim) * 1000 : 1000, HashAlgorithmName.SHA512, layers.Length * 64);
        for (int layer = 0; layer < layers.Length; layer++)
        {
            IBlockCipher cipher = layers[layer] switch
            {
                "AES" => new AesEngine(), "Serpent" => new SerpentEngine(), "Twofish" => new TwofishEngine(),
                "Camellia" => new CamelliaEngine(), "Kuznyechik" => new KuznyechikEngine(),
                _ => throw new ArgumentException("Unknown test cipher")
            };
            byte[] tweakBytes = new byte[16];
            cipher.Init(true, new KeyParameter(key.AsSpan((layers.Length + layer) * 32, 32).ToArray()));
            cipher.ProcessBlock(tweakBytes, 0, tweakBytes, 0);
            var tweak = new BigInteger(tweakBytes, isUnsigned: true, isBigEndian: false);
            var mask = (BigInteger.One << 128) - 1;
            cipher.Init(true, new KeyParameter(key.AsSpan(layer * 32, 32).ToArray()));
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
        }
        return (vera ? "$veracrypt$" : "$truecrypt$") + Convert.ToHexString(salt) + "$" + Convert.ToHexString(plain);
    }

    private static uint Crc(ReadOnlySpan<byte> bytes)
    {
        uint crc = uint.MaxValue;
        foreach (byte b in bytes)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++) crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xedb88320u : 0);
        }
        return ~crc;
    }

    internal static readonly IReadOnlyDictionary<int, string> Examples = new Dictionary<int, string>
    {
        [29321] = "$truecrypt$5ebff6b4050aaa3374f9946166a9c4134dd3ec0df1176da2fb103909d20e8b3c9b95cbbd6d1a7ad05411a1443ad6254e059e924d78bab6a0463e71cf7c3109b7$ef4e837bf6d7a548dd8333c451b59d1132098f44c6ff19c6cb921b1de3bd0aa675e0478a05f90204d46a5d6ff598bfa40370ac8795928a6d2e0f1347696e3cfa329738170fe54298981d84f40c63d1a338c5db62679338e849124a28a79a8e505bb89a4673f0457b2737a00b908116310281b5b2eb66c6fda5599196b313d51ef26201335d715c18f6b128454a5601671e619bdcce8e54acb47d498c4161614a05063bff5497a4a3d99bff1fce2a163727af2fe9ae7512461b9dcebf3a4f1031d6235d8ce09b734294d0cedc04eafc6295f212b1b080e7b9745580d0dd18e99cfd95afef982762d5aabeaa2d3a928dcf36322cc06b07fd719c88e0b9a2625a94a77502d4bd40a85ba138cbd0cf9561aa395dc552801f68cce16e5484a672aa5b78665dc531ab1e3e728185929dc443b7f4c8a5cb687c6589bb3f4ddc2a8639d959b839b0813d50e7711b761622c3693a92e540e4f932c6c89bf4e1bff1d69151848c3d01b2f6aba52b58e5b393f6cd58ff0d2e040b1205b042b5a28d5b12cb0cc95fa32f1bcdebd4c82d889a5d87c45dcfd34e80b19bf7be35696e0fa0cbd9338b314de24c1ee7bbc0a3b6824f86af2aa5d127d21444985ff566e921431938f6",
        [29322] = "$truecrypt$9f207bec0eded18a1b2e324d4f05d2f33f0bd1aeb43db65d33242fa48ac960fad4c14d04c553e06ad47e7e394d16e0a6544d35fb0b2415bd060bc5f537e42a58$b1681e991e2ec0b5773f6e8e5766e5fcc7335b19dd068d1f20260085ecda8eba366ff1521997c5654630ef09ba421b871a3dc66aa0dd5eba8a3bc7052398a7ad779506d86cbf687e76cd9dc50969e222820d2f905c0550995a9c068725bb6c8b04358c965ab77221fdfd829e57ce54cac6e2fa62db15043d720b72fa8962dd718a0b42c34577af9cb4a5ed04c1ae17b7af470c0d8b77987dc9e2d2593a52458c4acb83b628b1488371de85f78a2e25aeaebc18d20a8c3007d08949e93b80087707afd1fe4e07a0afee4244e5270f768e234b86852aa1556c53ffc0d6f60661369a484d55d063119e71e70af1ec775908466cac7b12bc22e1a9525c2bfa9f83f7901c8e0a1d56387ef65040b750656b0b75791738b5b7e453f24167eae56c057c94e1e4cf1a0d08894225f11b45bc31827cad1dfe62e148549385953aa16a0410dba231aace3a7b9fd9b1c2b930f01193377b59736d8a8959ca5b449655f79a4dbec0da566083f90caa2490b01a10c0a86dd4aaa719bdc1e4233db17217f03509cc20dab7246730e3f964944990690b6dcc84936e1dd487bd154ceefe58a838a0488cc93b854a112ea67f6802d2f409915e648ee5cf5fdc3c12e41acbfab7caa9",
        [29323] = "$truecrypt$721a7f40d2b88de8e11f1a203b04ffa97a1f5671623c6783f984cc7c55e04665f95a7f3fd52f402898aaaed68d048cc4c4fabf81c26832b589687dad082f3e4e$0f23c7caba28118f21a4cbb8f32b25914ff4022e7c4c8cdd45411801c7c6bde4033badbdcb82f96c77b42025d13fa71415b3278138100ea58ee4476c81ce66f78e89c59ac22cf454684ea7e8c3900374662f23c9491891b60ed7ce8231a7ac5710ee87b51a3f7bd9566a60dc6e7e701c41f3810d7977314b321e8194349909f2ca458a976851d854eaeb934c8df2b5e063d416d3d7c464e28173a0bbba88ec75cf8fe68f21067739b2473bd804fd710de1e4d3ae9451b374edcfd8e3cd613b23aeae272e0923007482dac26a7532ab09af8aad57cd7f1c451bc260cc912d5830cb0d5332f792519e009ed5450171434e5f0f2ba9e003676933a86d83c766419fac98a7ee232eeb593d1686528fab576d5f393d82f9602bcd65975153df205b6d1bc50dacad2ea5bb184696f978efd2b1c1656bf87e03a28a536c48320c430d407ff6c2fc6e7d4ae7b115e79fd0a88df08eca4743178c7c216f35035596a90b0f0fe9c173c7d0e3d76c33a8fce1f5b9b37674bd12e93fb714c9cbba6768c101b5db8f8fd137144453f00dccc7b66911a0a8d87b198807f30be6619400331c5746d481df7ad47a1f867c07f7b8cd296a0c5e03a121c1a7a60b4f768bea49799d2f",
        [29421] = "$veracrypt$2be25b279d8d2694e0ad1e5049902e717f1bdf741bbd678bf307d510741b649d78c54dca46fb2c92723afd9a40769b295e66d445ec232af5bddf91481ee41256$e56b77839e8bf55265077bab405901218ac7933f74073f1208f1de72aace5da4e07d5f83ca580c0216d36c200b54570a1d58e9d8e5c98a597dec23b74a465aeac572a99af70e1a1e20fd29c7c296099e4eed5b715cb470617ea4f20140b62ec4694af67d9158deac3ce846718e10518875ce8cea0286a487a295979e67159d06e871789bf5535b75c809b340f8627e18679e3dab839a1c9823ea14a07d5cc4251b777dddb408da147c70e7cc788a01c27b0ba4f4700d3248f59fa8217874ae4958ea4518522b44f7191ec19459faef7678422adecd58777487ef54a5305ff2caaa545dcb82f7e7a3eb30bd9f7ebab542d0964a367f9c710cf26bbd704e841d591428da3486db31c57f91c6167bf99e31839363cb93bc60d755031f96f2d2c964e1d85b7eaa104985ef801a21d99352c025d7415d5b2f1aa37dc513345d0ff6a1bca92ad7b8c265f322d04f2992895de32636c9b03318cf7154632d547debc1c5e0c8f8730a045efcf3d16ff956cf803716eee22168bc5a5ab72ddb5087436722cb0f59a5b7b03bc557ffb50e8757d1a5639e2bcddd8060de4ee5535fb614b4fc159c6a39040dcbe83889b9c6fac1c9364a7bea930d916ea23fafa0fde07ef609",
        [29422] = "$veracrypt$37e6db10454a5d74c1e75eca0bc8a70e67ac032357e4bd6a4315c0174cf9780f92210dfc0a3e977969f2890828d446aecc317dc40fb3162915998cc703e49257$a950a1603342913900052011a7fa85fb0b1fd4489f17237ac1a8bbfd644e871ab95a4019f14b2b938d627646b9958b530dd0739760024ad323d36962b60ba92908e55a876fc392ac2dce6a2410bcdd30a01cba90427f02ccb96e222ab1381266a6f626aa00b0f59e743c1a77433cbb28648f04c91853bdf9b8b29917b2341bf7deb013131ad228ea0c7f9435985318431dae59faff46db3726341b97a956da4ad11766124cd06644c1ba1083b36d3f380f20c272e460b958841fc23be1820ad2e0e6db66eaf4ea171035add0ab543ce8e853e3119ceb9d7f32c0948b81604b81075bcb33efe747fec300a7c68ec383d28d560cccce713c0acf51d74c0db718ba93a9e720b657dda2409adf1ce35aa7e1c0d7ed3df98dd0b6d455a355ce02bda8bea8afc0a8341ac78214efd4372b4430270009ec65badf186e5f0d815dcf597b4703af95e3bfc03313125d2a88b9bb3788b6bbc3c7212713cd584a226b155a2e6872b33730af6fba29aa3dccdb0ec35b5d6e3d981faf39c8dd35fdcff502d14736bc6a47af6e4d7f3518f8ef5e0a4e5d521589a761757f86e2bef471d9867e9b532903c479e4966dcc99189fcdfa3d676f50ccd33fb7cc0aa3e85542ff2648c9",
        [29423] = "$veracrypt$d44f26d1742260f88023d825729cc5a64cf8475d887632a2fb4a84af27af138cfadc4bcbb122f6ba68339ae8427d1f72c0c4aeef041291492ae0a7d8677d8da4$3227ae2a26d9a433076b44458b14f52766cf0e4baeb473a789180660d62e42bbea7c042379a5a74e259463e1c18381fa13aee27141264be381de71c12f8f704913f211c45fda0295e963d90fc35272e907858c0522601f6e7a73b43ff222663f149a485fc6c464e5f3b7cc0b6508f30621385365ca8a4e0bff4061f64f5fbdb11f70f19d77e56fa6ff015ad76ecaaccd759d30da05d2a6fbf00ac9673ac3c23efd339313c2a99511e928f976bf9b2664d97685498d5931af2d453edc6fb1129e324eaba64264711fbe21d0d202b3659106e8100634f09c38cd15b1b3acba79d7f31d31fe23c166392e300db09f10550c83187566dc0fdf768b872555851b34e3c15ad7e7438a72e6126c895cf1204987df4b42cb7bc2fe03c5777867d269378c6e496df2a1a3457b907f7143a139d800868ad95e2901723c6ebb991054b4e991c67fe4c17702d9829d9dc1fe8bf4a956460721c858e31dbcbe56850a4ed31558c6ee89ba2cba2ef4bde77fed11848f9f92e0add54964a683c3686dbab4695ebc42554da922a08c6fff32cac936ea447e771aa74a689eb269ffef677294ef297600dfd73bbbb734d2968e38a98b4a8a77ff0eec8246d93b542e3521a3eb636101",
    };
}
