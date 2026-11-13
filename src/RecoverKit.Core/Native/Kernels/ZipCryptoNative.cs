using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace RecoverKit.Core.Native.Kernels;

/// <summary>ZipCrypto path selection shared by search, tests and the CLI benchmark.</summary>
internal static class ZipCryptoNative
{
    // -2 managed scalar, -1 managed SIMD, 0 automatic, 1-5 native export selectors.
    internal static int RequestedPath { get; set; } = Environment.GetEnvironmentVariable("RECOVERKIT_ZIP_PATH") switch
    {
        "managed-scalar" => -2, "managed" => -1, "scalar" => 1, "neon" => 2,
        "avx2" => 3, "avx512" => 4, "arm-crc" => 5, _ => 0,
    };

    internal static int Path
    {
        get
        {
            if (RequestedPath < 0 || !RkNative.Available) return -1;
            // Unmeasured x86 paths stay opt-in until a remote comparison against managed AVX2.
            if (RequestedPath == 0) return -1;
            return RkNative.ZipPath(RequestedPath);
        }
    }

    internal static string PathName => Path switch
    {
        1 => "native scalar", 2 => "native NEON", 3 => "native AVX2", 4 => "native AVX-512", 5 => "native ARM CRC",
        _ => RequestedPath == -2 ? "managed scalar" : Avx2.IsSupported ? "managed AVX2"
            : AdvSimd.Arm64.IsSupported && ZipCryptoKernel.UseAdvSimd ? "managed NEON" : "managed scalar",
    };
}
