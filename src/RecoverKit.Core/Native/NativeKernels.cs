using System.Diagnostics;
using RecoverKit.Core.Native.Kernels;
using RecoverKit.Core.Formats;

namespace RecoverKit.Core.Native;

/// <summary>Factory for the built-in CPU kernels and a benchmark helper.</summary>
public static class NativeKernels
{
    /// <summary>Creates the kernel for a hashcat mode and hash line, or null if the format is not built in.</summary>
    public static NativeKernel? TryCreate(int mode, string hashLine, ZipPartialTarget? partial = null) => mode switch
    {
        _ when TrueCryptSha512Kernel.SupportsMode(mode) => TrueCryptSha512Kernel.TryParse(mode, hashLine),
        29331 when RkNative.Available => TrueCryptWhirlpoolKernel.TryParse(hashLine),
        17200 or 17210 => ZipCryptoKernel.TryParse(hashLine, partial),
        // The native library's vector paths (AVX2 / NEON) run these regardless of .NET's vector support.
        12500 when Rar3Kernel.NativeFast => Rar3Kernel.TryParse(hashLine),
        10700 => PdfR6Kernel.NativeFast ? PdfR6Kernel.TryParse(hashLine) : null,
        13000 => Rar5Kernel.NativeFast ? Rar5Kernel.TryParse(hashLine) : null,
        9400 => Office2007Kernel.TryParse(hashLine),
        9500 or 9600 => OfficeAgileKernel.TryParse(hashLine) is { } agile && agile.Mode == mode ? agile : null,
        13600 => WinZipAesKernel.NativeFast ? WinZipAesKernel.TryParse(hashLine) : null,
        22000 => WpaKernel.NativeFast ? WpaKernel.TryParse(hashLine) : null,
        9700 when RkNative.HasVectorPath => Office97Kernel.TryParse(hashLine),
        9800 when RkNative.HasVectorPath => Office2003Kernel.TryParse(hashLine),
        10400 or 10500 or 10510 when RkNative.HasVectorPath => PdfRc4Kernel.TryParse(hashLine),
        // Without the library the managed Vector256 kernels need hardware AVX2. On arm64 .NET does not
        // accelerate Vector256: they run 2.5-9x slower than the native NEON paths there
        // (docs/benchmarks/apple-m1-pro-native.txt), so they stay off and hashcat is used instead.
        _ when !System.Runtime.Intrinsics.Vector256.IsHardwareAccelerated && !ForceVectorKernels => null,
        9700 => Office97Kernel.TryParse(hashLine),
        9800 => Office2003Kernel.TryParse(hashLine),
        10400 or 10500 or 10510 => PdfRc4Kernel.TryParse(hashLine),
        12500 => Rar3Kernel.TryParse(hashLine),
        _ => null,
    };

    /// <summary>The CPU features the built-in engine sees, for logs and benchmarks (any architecture).</summary>
    public static string CpuFeatures()
    {
        var arch = System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture;
        string native = RkNative.Available ? RkNative.Features.ToString() : "unavailable";
        string simd = arch is System.Runtime.InteropServices.Architecture.Arm64
            ? $"AdvSimd={System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported}, ArmAes={System.Runtime.Intrinsics.Arm.Aes.IsSupported}, ArmSha256={System.Runtime.Intrinsics.Arm.Sha256.IsSupported}"
            : $"AVX2 (.NET)={System.Runtime.Intrinsics.X86.Avx2.IsSupported}, AVX-512 F (.NET)={System.Runtime.Intrinsics.X86.Avx512F.IsSupported}, AVX2 (native)={RkNative.Features.HasFlag(RkNative.Feature.Avx2)}, AVX-512 F + OS ZMM (native)={RkNative.Features.HasFlag(RkNative.Feature.Avx512)}, SHA-NI (native)={RkNative.Features.HasFlag(RkNative.Feature.ShaNi)}, AES-NI={System.Runtime.Intrinsics.X86.Aes.IsSupported}";
        return $"{arch}, {simd}, Vector128={System.Runtime.Intrinsics.Vector128.IsHardwareAccelerated}, " +
               $"Vector256={System.Runtime.Intrinsics.Vector256.IsHardwareAccelerated}, rknative API={NativeApiVersion}: {native}";
    }

    /// <summary>Observed native execution, or the selected dispatch before the first call.</summary>
    public static string CpuPath(int mode, bool actualOnly = false)
    {
        if (Math.Abs(mode) is 17200 or 17210) return ZipCryptoPath;
        if (!RkNative.Available && (Math.Abs(mode) is 9400 or 9500 or 9600 || TrueCryptSha512Kernel.SupportsMode(Math.Abs(mode)))) return "managed scalar";
        if (!RkNative.Available) return System.Runtime.Intrinsics.Vector256.IsHardwareAccelerated ? "managed AVX2" : "managed scalar";
        bool sha512 = TrueCryptSha512Kernel.SupportsMode(Math.Abs(mode));
        int observed = sha512 ? RkNative.Pbkdf2Sha512ExecutedPaths() : Math.Abs(mode) switch
        {
            9400 => RkNative.Office2007ExecutedPaths(),
            9500 or 9600 => RkNative.OfficeAgileExecutedPaths(Math.Abs(mode)),
            12500 => RkNative.Rar3ExecutedPaths(),
            13000 => RkNative.Pbkdf2Sha256ExecutedPaths(),
            13600 or 22000 => RkNative.Pbkdf2Sha1ExecutedPaths(),
            29331 => RkNative.WhirlpoolExecutedPaths(),
            _ => 0,
        };
        if (observed != 0)
        {
            if ((sha512 || Math.Abs(mode) is 9400 or 9500 or 9600 or 13600 or 22000) && observed == 1) return "native scalar";
            if (Math.Abs(mode) == 29331)
                return observed == 4 ? "native AVX-512" : observed == 1 ? "native scalar" : "native AVX-512 + native scalar";
            var names = new[] { (1, "scalar fallback"), (2, "native AVX2"), (4, "native AVX-512"), (8, "native NEON"), (16, "native ARM SHA-256"), (32, "native ARM SHA-1"), (64, "native SHA-NI"), (128, "native ARM SHA-512") }
                .Where(p => (observed & p.Item1) != 0).Select(p => p.Item2);
            return string.Join(" + ", names);
        }
        if (actualOnly && (sha512 || Math.Abs(mode) is 9400 or 9500 or 9600 or 12500 or 13000 or 13600 or 22000 or 29331)) return "not run";
        var f = RkNative.Features;
        if (Math.Abs(mode) is 9400 or 9500 or 9600)
            return (Math.Abs(mode) == 9400 ? RkNative.Office2007SelectedPath() : RkNative.OfficeAgileSelectedPath(Math.Abs(mode))) switch
            {
                2 => "native AVX2", 4 => "native AVX-512", 8 => "native NEON",
                32 => "native ARM SHA-1", 64 => "native SHA-NI", 128 => "native ARM SHA-512", _ => "native scalar",
            };
        if (sha512)
            return RkNative.Pbkdf2Sha512Path() switch
            {
                2 => "native AVX2", 4 => "native AVX-512", 8 => "native NEON",
                128 => "native ARM SHA-512", _ => "native scalar",
            };
        if (Math.Abs(mode) == 29331)
            return RkNative.WhirlpoolLanes() == 8 ? "native AVX-512" : "native scalar";
        if (Math.Abs(mode) == 12500)
            return RkNative.Rar3Lanes() == 32 ? "native AVX-512" : f.HasFlag(RkNative.Feature.Avx2) ? "native AVX2" : f.HasFlag(RkNative.Feature.Neon) ? "native NEON" : "scalar";
        if (Math.Abs(mode) == 13000)
            return RkNative.Pbkdf2Sha256Lanes() == 16 ? "native AVX-512" : f.HasFlag(RkNative.Feature.Avx2) ? "native AVX2" : f.HasFlag(RkNative.Feature.ArmSha2) ? "native ARM SHA-256" : f.HasFlag(RkNative.Feature.Neon) ? "native NEON" : "scalar";
        if (Math.Abs(mode) is 13600 or 22000)
            return RkNative.Pbkdf2Sha1Lanes() == 1 ? "native scalar" : RkNative.Pbkdf2Sha1Lanes() == 16 ? "native AVX-512" : f.HasFlag(RkNative.Feature.Avx2) ? "native AVX2" : f.HasFlag(RkNative.Feature.ArmSha1) ? "native ARM SHA-1" : f.HasFlag(RkNative.Feature.Neon) ? "native NEON" : "scalar";
        if (Math.Abs(mode) is 9700 or 9800 or 10400 or 10500 or 10510)
            return RkNative.HasVectorPath ? f.HasFlag(RkNative.Feature.Neon) ? "native NEON" : "native AVX2" : "managed scalar";
        return Math.Abs(mode) == 10700 ? "native AES / SHA" : "native CPU";
    }

    public static bool WhirlpoolAvx512Supported => RkNative.Available && RkNative.Features.HasFlag(RkNative.Feature.Avx512);

    public static void ConfigureWhirlpool(Settings settings) => RkNative.WhirlpoolAvx512Enabled = settings.WhirlpoolAvx512;

    public static void ResetCpuPath(int mode)
    {
        if (RkNative.Available) RkNative.ResetExecutedPaths(Math.Abs(mode));
    }

    public static string WideSelfTestState(int mode) => Math.Abs(mode) is 17200 or 17210 ? "no native guard; diagnostic check only"
        : !RkNative.Available ? "not run" : (TrueCryptSha512Kernel.SupportsMode(Math.Abs(mode)) ? RkNative.Pbkdf2Sha512SelfTestState() : Math.Abs(mode) switch
        {
            9400 => RkNative.Office2007SelfTestState(),
            9500 or 9600 => RkNative.OfficeAgileSelfTestState(Math.Abs(mode)),
            12500 => RkNative.Rar3SelfTestState(),
            13000 => RkNative.Pbkdf2Sha256SelfTestState(),
            13600 or 22000 => RkNative.Pbkdf2Sha1SelfTestState(),
            29331 => RkNative.WhirlpoolSelfTestState(),
            _ => -1,
        }) switch { 0 => "not run", 1 => "passed", 2 => "failed", 3 => "switched off", _ => "not applicable" };

    /// <summary>Loaded native library API version, or zero when it is unavailable.</summary>
    public static int NativeApiVersion => RkNative.ApiVersion;

    /// <summary>Applies a measured ZIP variant; an explicit environment selector still wins.</summary>
    public static void SelectZipProfileVariant(string? variant) => ZipCryptoNative.ProfilePath =
        Diagnostics.CpuDiagnostics.Variants.FirstOrDefault(v => v.Name == variant && v.Supported)?.Selector;

    /// <summary>Selected ZIP search implementation, including managed fallback.</summary>
    public static string ZipCryptoPath => ZipCryptoNative.PathName;

    /// <summary>Tests use this to exercise the vector kernels on machines without AVX2.</summary>
    internal static bool ForceVectorKernels { get; set; }

    public static bool Supports(int mode) => BenchmarkHashes.ContainsKey(mode);

    /// <summary>Reference benchmark hashes, usually password "hashcat" ("hashcat!" for WPA).</summary>
    public static readonly IReadOnlyDictionary<int, string> BenchmarkHashes = new Dictionary<int, string>
    {
        // A small stored entry (the cputest.zip sample, password "zq7", data descriptor so the check byte
        // is the time's), a typical small-file sample: with large entries the cost of
        // confirming false positives dominates.
        [17200] = ZipCryptoSample.Extract(ZipCryptoSample.Archive(
            [new("synthetic.dat", ZipCryptoSample.Text(1024, new Random(17200)), true)], "hashcat"u8, new Random(17200))).HashLines,
        [17210] = "$pkzip2$1*1*2*0*29*1d*972eca9f*0*0*0*29*5220*5220*b3118b537bee6e1d72a8f76e6050fed3dca090b2ffbcade89854b9278e640b3abe76b02ac2a710c944*$/pkzip2$",
        [6221] = TrueCryptSha512Kernel.BenchmarkHash(6221),
        [6222] = TrueCryptSha512Kernel.BenchmarkHash(6222),
        [6223] = TrueCryptSha512Kernel.BenchmarkHash(6223),
        [13721] = TrueCryptSha512Kernel.BenchmarkHash(13721),
        [13722] = TrueCryptSha512Kernel.BenchmarkHash(13722),
        [13723] = TrueCryptSha512Kernel.BenchmarkHash(13723),
        [29321] = TrueCryptSha512Kernel.BenchmarkHash(29321),
        [29322] = TrueCryptSha512Kernel.BenchmarkHash(29322),
        [29323] = TrueCryptSha512Kernel.BenchmarkHash(29323),
        [29421] = TrueCryptSha512Kernel.BenchmarkHash(29421),
        [29422] = TrueCryptSha512Kernel.BenchmarkHash(29422),
        [29423] = TrueCryptSha512Kernel.BenchmarkHash(29423),
        [29331] = "$truecrypt$cf53d4153414b63285e701e52c2d99e148c6ccc4508132f82cb41862d0a0ac9ea16274285ac261c339c1508eec9fea54c33e382458662913678f2a88a84959a6$78e238973985ec670d50252677430587ee28b72bfa5edfb2f79c40b734ba8a54a3662642a6ab067e75f41154688ad4adb5d6decd891462dd537188195a51e06fa5baf22b69d0f472cfeeae77ab9a90091731863af1d8b5b380da179fa7d5227ef031732b1ae06e0fe34c0b28b7a64eac34e5a08e09d7001394b3afc804ac69bf819cdd2d383fe96a721f7c683628da8e529d84bdaa68d702573d8f7ef26f75d1bd5c91efa88cb33b1e9c006b87981c55ed3b8063ab7068f8e99b128bc56ea3e883efa55d6f340b2681e50405d91f5f6d76cdbeac404944164d329d3ee01311de0bc6547310f126b5a4c0e9fb74825f91faefa60b7ac828819d4544c1872ff5041e61d5cf093553f427358b2181046376d7b876e1bccf0774d5d251b7c922c214bb5c70c715165d028e1dca73e7adeca3396d77f6e597a10dd4c58f37fdbbdc1d04cd8890ba4c5025776a88a349bb925add13193becf1ca10fe32536db0c0b06a1ef799fb692e304b3716ca5a8a80859c4012ca3e06701b46b5a32f4d10e285a0cdaf6c24e0d98139e7f306e52503c9b503aa28f1fbbb236284907068074fcb3e267e3c4aab2bd3b79b24a7a08106bb55850fa2bb8e2f6d9919a6743cb822c164",
        [9400] = "$office$*2007*20*128*16*18410007331073848057180885845227*944c70a5ee6e5ab2a6a86ff54b5f621a*e6650f1f2630c27fd8fc0f5e56e2e01f99784b9f",
        [9500] = "$office$*2010*100000*128*16*34170046140146368675746031258762*de5bc114991bb3a5679a6e24320bdb09*1b72a4ddffba3dcd5395f6a5ff75b126cb832b733c298e86162028ca47a235a9",
        [9600] = "$office$*2013*100000*256*16*67805436882475302087847656644837*0c392d3b9ca889656d1e615c54f9f3c9*612b79e33b96322c3253fc8a0f314463cd76bc4efe1352f7efffca0f374f7e4b",
        [9700] = "$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2",
        [9800] = "$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd",
        [10400] = "$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000",
        [10500] = "$pdf$2*3*128*-4*1*16*62888255846156252261477183186121*32*6879919b1afd520bd3b7dbcc0868a0a500000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000",
        [10510] = "$pdf$1*3*40*-4*1*16*5e1f73575e1f73575e1f73575e1f7357*32*c0be424bef466277092f2a1ba0fbe506ebabe5c01db100dedc0ffeebabe5c01d*32*0ff1cedeadce110ff1cedeadce110ff1cedeadce110ff1cedeadce11babebabe",
        // A test document made for RecoverKit (password "Qz7#Kp2", outside the benchmark mask).
        [10700] = "$pdf$5*6*256*-3904*1*16*503b00505721f20ef74f37a47b7b93ea*127*5b152edd133e7a6af935153d535b08b0e4b26cd44ef0d51c06496d0943d7afd969b113434acc604df4c060075d1fe9ee00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*98880d8ec9a744cb9530953a94625bc48bc32556ac2ff265caf6bbd467fce4c88500976327697a668dc920cabb78cec600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000",
        [12500] = "$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317",
        [13000] = "$rar5$16$38466361001011015181344360681307$15$00000000000000000000000000000000$8$cc7a30583e62676a",
        [13600] = "$zip2$*0*1*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$",
        [22000] = "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***",
        [-17210] = "$pkzip2$1*1*2*0*1d1*1c5*eda7a8de*0*28*0*1d1*eda7*5096*1dea673da43d9fc7e2be1a1f4f664269fceb6cb88723a97408ae1fe07f774d31d1442ea8485081e63f919851ca0b7588d5e3442317fff19fe547a4ef97492ed75417c427eea3c4e146e16c100a2f8b6abd7e5988dc967e5a0e51f641401605d673630ea52ebb04da4b388489901656532c9aa474ca090dbac7cf8a21428d57b42a71da5f3d83fed927361e5d385ca8e480a6d42dea5b4bf497d3a24e79fc7be37c8d1721238cbe9e1ea3ae1eb91fc02aabdf33070d718d5105b70b3d7f3d2c28b3edd822e89a5abc0c8fee117c7fbfbfd4b4c8e130977b75cb0b1da080bfe1c0859e6483c42f459c8069d45a76220e046e6c2a2417392fd87e4aa4a2559eaab3baf78a77a1b94d8c8af16a977b4bb45e3da211838ad044f209428dba82666bf3d54d4eed82c64a9b3444a44746b9e398d0516a2596d84243b4a1d7e87d9843f38e45b6be67fd980107f3ad7b8453d87300e6c51ac9f5e3f6c3b702654440c543b1d808b62f7a313a83b31a6faaeedc2620de7057cd0df80f70346fe2d4dccc318f0b5ed128bcf0643e63d754bb05f53afb2b0fa90b34b538b2ad3648209dff587df4fa18698e4fa6d858ad44aa55d2bba3b08dfdedd3e28b8b7caf394d5d9d95e452c2ab1c836b9d74538c2f0d24b9b577*$/pkzip2$",
    };

    /// <summary>Micro-benchmarks of the building blocks (operations per second, one thread).</summary>
    public static unsafe List<(string Name, double PerSecond)> BenchmarkPrimitives()
    {
        var res = new List<(string Name, double PerSecond)>();
        const int N = 2_000_000;
        var s = stackalloc byte[256];
        var key = stackalloc byte[16];
        for (int i = 0; i < 16; i++) key[i] = (byte)(i * 37 + 1);
        var sw = Stopwatch.StartNew();
        for (int r = 0; r < N; r++) { key[0] = (byte)r; Simd.Rc4.Ksa(s, key, 16); }
        res.Add(("RC4 key schedule (16-byte key)", N / sw.Elapsed.TotalSeconds));

        var ks = stackalloc byte[1024];
        var kk = stackalloc byte[64];
        for (int i = 0; i < 64; i++) kk[i] = (byte)(i * 41 + 3);
        sw.Restart();
        for (int r = 0; r < N / 4; r++) { kk[0] = (byte)r; Simd.Rc4.Ksa16x4(ks, ks + 256, ks + 512, ks + 768, kk, kk + 16, kk + 32, kk + 48); }
        res.Add(("RC4 key schedule, 4 interleaved", N / sw.Elapsed.TotalSeconds));
        var si = stackalloc byte[2048];
        var kr = stackalloc ulong[16];
        for (int i = 0; i < 16; i++) kr[i] = 0x0123456789abcdefUL * (ulong)(i + 1);
        sw.Restart();
        for (int r = 0; r < N / 8; r++) { kr[0] = (ulong)r; Simd.Rc4.KsaInterleaved8(si, kr, 16); }
        res.Add(("RC4 key schedule, 8 byte-interleaved", N / sw.Elapsed.TotalSeconds));
        sw.Restart();
        for (int r = 0; r < N / 4; r++) { kk[0] = (byte)r; Simd.Rc4.Ksa16Fast4(ks, ks + 256, ks + 512, ks + 768, kk, kk + 16, kk + 32, kk + 48); }
        res.Add(("RC4 key schedule, fast 4-lane", N / sw.Elapsed.TotalSeconds));

        var w = new System.Runtime.Intrinsics.Vector256<uint>[16];
        for (int i = 0; i < 16; i++) w[i] = System.Runtime.Intrinsics.Vector256.Create((uint)i * 0x9e3779b9u);
        var a = Simd.Md5x8.IvA; var b = Simd.Md5x8.IvB; var c = Simd.Md5x8.IvC; var d = Simd.Md5x8.IvD;
        sw.Restart();
        for (int r = 0; r < N; r++) Simd.Md5x8.Compress(ref a, ref b, ref c, ref d, w);
        res.Add(("MD5 block x8 lanes (per lane)", 8.0 * N / sw.Elapsed.TotalSeconds + (a[0] & 0)));

        var wm = stackalloc System.Runtime.Intrinsics.Vector256<uint>[16];
        for (int i = 0; i < 16; i++) wm[i] = w[i];
        sw.Restart();
        for (int r = 0; r < N; r++) Simd.Md5x8.CompressMem(ref a, ref b, ref c, ref d, wm);
        res.Add(("MD5 block x8, memory message", 8.0 * N / sw.Elapsed.TotalSeconds + (a[0] & 0)));

        var s2 = stackalloc System.Runtime.Intrinsics.Vector256<uint>[10];
        var wm2 = stackalloc System.Runtime.Intrinsics.Vector256<uint>[16];
        for (int i = 0; i < 16; i++) wm2[i] = w[i] ^ System.Runtime.Intrinsics.Vector256.Create(7u);
        sw.Restart();
        for (int r = 0; r < N / 2; r++) Simd.Md5x8.Compress2(s2, wm, wm2);
        res.Add(("MD5 block 2x8 interleaved", 8.0 * N / sw.Elapsed.TotalSeconds + (s2[0][0] & 0)));

        var e = Simd.Sha1x8.IvE; a = Simd.Sha1x8.IvA; b = Simd.Sha1x8.IvB; c = Simd.Sha1x8.IvC; d = Simd.Sha1x8.IvD;
        sw.Restart();
        for (int r = 0; r < N; r++) Simd.Sha1x8.Compress(ref a, ref b, ref c, ref d, ref e, w);
        res.Add(("SHA-1 block x8 lanes (per lane)", 8.0 * N / sw.Elapsed.TotalSeconds + (a[0] & 0)));
        sw.Restart();
        for (int r = 0; r < N; r++) Simd.Sha1x8.CompressMem(ref a, ref b, ref c, ref d, ref e, wm);
        res.Add(("SHA-1 block x8, memory schedule", 8.0 * N / sw.Elapsed.TotalSeconds + (a[0] & 0)));
        sw.Restart();
        for (int r = 0; r < N / 2; r++) Simd.Sha1x8.Compress2(s2, wm, wm2);
        res.Add(("SHA-1 block 2x8 interleaved", 8.0 * N / sw.Elapsed.TotalSeconds + (s2[0][0] & 0)));
        return res;
    }

    internal static string[] BenchmarkMaskArguments(int mode, int length)
    {
        // A VeraCrypt prefix with 69 suffixes can take tens of seconds before publishing progress.
        // Keep its last position small while retaining a large keyspace and full SIMD prefix groups.
        if (mode is >= 29421 and <= 29423 or >= 13721 and <= 13723)
            return ["-a", "3", "-1", "?u?d?s", "-2", "AB", string.Concat(Enumerable.Repeat("?1", length - 1)) + "?2"];
        return ["-a", "3", "-1", "?u?d?s", string.Concat(Enumerable.Repeat("?1", length))];
    }

    /// <summary>
    /// Measures a kernel's speed (candidates/s) on all threads with a mask that does not contain the
    /// password, after a short warm-up.
    /// </summary>
    public static double Benchmark(int mode, int threads, TimeSpan duration, CancellationToken ct = default, int length = 0, ThreadPriority priority = ThreadPriority.Normal)
    {
        if (!BenchmarkHashes.TryGetValue(mode, out var hash) || TryCreate(Math.Abs(mode), hash) is not { } kernel) return 0;
        // Seven characters (like hashcat's example password) from upper-case + digits + specials: never
        // matches "hashcat"/"zq7" and is far too large to finish. Length matters for RAR3 (cost ~ 2L+11).
        // RAR 3's cost grows with the password length; 4 characters is the usual benchmark sample for it.
        if (length <= 0) length = Math.Abs(mode) == 12500 ? 4 : Math.Abs(mode) == 22000 ? 8 : 7;
        var space = MaskSpace.FromHashcatArgs(BenchmarkMaskArguments(mode, Math.Clamp(length, 3, 16)))!;
        var started = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var engine = new NativeEngine(kernel, space) { Threads = threads, Priority = priority, ProgressInterval = TimeSpan.FromSeconds(0.5) };
        // Average rate between the end of a one-second warm-up and the end of the run.
        double t0 = 0, t1 = 0;
        long d0 = -1, d1 = 0;
        engine.Progress += p =>
        {
            double t = started.Elapsed.TotalSeconds;
            if (d0 < 0 && t >= 1.0) { d0 = p.Done; t0 = t; }
            else if (d0 >= 0) { d1 = p.Done; t1 = t; }
            if (started.Elapsed > duration) cts.Cancel();
        };
        engine.Run(null, cts.Token);
        return d0 >= 0 && t1 > t0 ? (d1 - d0) / (t1 - t0) : 0;
    }
}
