using System.Runtime.InteropServices;

namespace RecoverKit.Core.Native;

/// <summary>
/// The optional native kernel library (native/rknative.c: rknative.dll / librknative.dylib).
/// When it is missing, too old, or disabled with RECOVERKIT_NO_NATIVE_LIB=1, the managed kernels run.
/// </summary>
internal static unsafe partial class RkNative
{
    private const string Lib = "rknative";
    private const int RequiredVersion = 15;

    /// <summary>Mirrors RK_FEAT_* in rknative.c. The Arm* bits describe ARMv8 instructions.</summary>
    [Flags]
    public enum Feature { Avx2 = 1, ShaNi = 2, AesNi = 4, Neon = 8, ArmAes = 16, ArmSha1 = 32, ArmSha2 = 64, ArmSha512 = 128, ArmSha3 = 256, Avx512 = 512, ArmCrc = 1024 }

    [LibraryImport(Lib, EntryPoint = "rk_version")] private static partial int Version();
    [LibraryImport(Lib, EntryPoint = "rk_features")] private static partial int FeaturesRaw();
    [LibraryImport(Lib, EntryPoint = "rk_set_features")] private static partial void SetFeaturesRaw(int mask);

    [LibraryImport(Lib, EntryPoint = "rk_rar3_hash")]
    public static partial int Rar3Hash(byte* salt, byte* passwords, int len, int n, byte* out36);

    [LibraryImport(Lib, EntryPoint = "rk_rar3_decode_stream")]
    public static partial int Rar3DecodeStream(delegate* unmanaged[Cdecl]<nint, byte*, int, int> read,
        nint opaque, ulong packed, ulong unpacked, uint window, uint expectedCrc, int* stage);

    [LibraryImport(Lib, EntryPoint = "rk_rar3_decode_stream_alloc")]
    public static partial int Rar3DecodeStreamAlloc(delegate* unmanaged[Cdecl]<nint, byte*, int, int> read,
        nint opaque, ulong packed, ulong unpacked, uint window, uint expectedCrc, int* stage,
        delegate* unmanaged[Cdecl]<nint, nuint, void*> alloc);

    /// <summary>Candidates per RAR 3 batch: 32 AVX-512, 16 AVX2/NEON, 1 scalar. Runs the wide-path self-test once.</summary>
    [LibraryImport(Lib, EntryPoint = "rk_rar3_lanes")]
    public static partial int Rar3Lanes();

    /// <summary>AVX-512 guard: 0 not run, 1 passed, 2 failed, 3 switched off. Does not start the test.</summary>
    [LibraryImport(Lib, EntryPoint = "rk_rar3_selftest_state")]
    public static partial int Rar3SelfTestState();

    /// <summary>Paths executed by hashing calls: scalar 1, AVX2 2, AVX-512 4, NEON 8, ARM SHA-256 16.</summary>
    [LibraryImport(Lib, EntryPoint = "rk_rar3_executed_paths")]
    public static partial int Rar3ExecutedPaths();

    /// <summary>Clears executed paths for mode 12500, 13000 or 29331 before a CPU probe.</summary>
    [LibraryImport(Lib, EntryPoint = "rk_reset_executed_paths")]
    public static partial void ResetExecutedPaths(int mode);

    [LibraryImport(Lib, EntryPoint = "rk_office97_search")]
    public static partial int Office97Search(byte* salt16, byte* enc32, byte* pws, int len, int n, int* hits, int maxHits);

    [LibraryImport(Lib, EntryPoint = "rk_office2003_search")]
    public static partial int Office2003Search(byte* salt16, byte* enc36, byte* pws, int len, int n, int* hits, int maxHits);

    [StructLayout(LayoutKind.Sequential)]
    public struct PdfParams
    {
        public int R, KeyLen;
        public fixed byte O[32];
        public fixed uint Block2[16];
        public uint X0, U0, Pad0;
    }

    [LibraryImport(Lib, EntryPoint = "rk_pdf_search")]
    public static partial int PdfSearch(PdfParams* p, byte* pws, int len, int n, int* hits, int maxHits);

    [LibraryImport(Lib, EntryPoint = "rk_pdf6_search")]
    public static partial int Pdf6Search(byte* u48, byte* pws, int len, int n, int* hits, int maxHits);

    [LibraryImport(Lib, EntryPoint = "rk_whirlpool_pbkdf2")]
    private static partial int WhirlpoolPbkdf2Raw(byte* salt64, byte* pws, int len, int n, byte* out64);

    [LibraryImport(Lib, EntryPoint = "rk_whirlpool_lanes")]
    public static partial int WhirlpoolLanes();

    [LibraryImport(Lib, EntryPoint = "rk_whirlpool_selftest_state")]
    public static partial int WhirlpoolSelfTestState();

    [LibraryImport(Lib, EntryPoint = "rk_whirlpool_executed_paths")]
    public static partial int WhirlpoolExecutedPaths();

    [LibraryImport(Lib, EntryPoint = "rk_whirlpool_set_avx512")]
    private static partial void WhirlpoolSetAvx512(int enabled);

    private static bool _whirlpoolAvx512Enabled;
    internal static bool WhirlpoolAvx512Enabled
    {
        get => _whirlpoolAvx512Enabled;
        set
        {
            _whirlpoolAvx512Enabled = value;
            if (Available) WhirlpoolSetAvx512(value ? 1 : 0);
        }
    }

    private static int _whirlpoolFailureLogged, _whirlpoolLastPath;
    public static int WhirlpoolPbkdf2(byte* salt64, byte* pws, int len, int n, byte* out64)
    {
        int result = WhirlpoolPbkdf2Raw(salt64, pws, len, n, out64);
        int observed = WhirlpoolExecutedPaths();
        if (result > 0 && Interlocked.Exchange(ref _whirlpoolLastPath, observed) != observed)
            DebugLog.Info("Whirlpool CPU path: " + NativeKernels.CpuPath(29331, actualOnly: true));
        if (WhirlpoolSelfTestState() == 2 && Interlocked.Exchange(ref _whirlpoolFailureLogged, 1) == 0)
            DebugLog.Warn("Whirlpool AVX-512 self-test failed; using native scalar fallback.");
        return result;
    }

    /// <summary>PBKDF2-HMAC-SHA256 of n candidates at pws + i * stride (lengths in lens, or stride each when null).</summary>
    [LibraryImport(Lib, EntryPoint = "rk_pbkdf2_sha256")]
    public static partial int Pbkdf2Sha256(byte* pws, int stride, int* lens, int n, byte* salt, int saltLen, uint iterations, byte* dk, int dkLen);

    /// <summary>Candidates per group of the PBKDF2-SHA256 path in use (16 AVX-512, 8 AVX2, NEON or ARMv8 SHA-256, 1 scalar).</summary>
    [LibraryImport(Lib, EntryPoint = "rk_pbkdf2_sha256_lanes")]
    public static partial int Pbkdf2Sha256Lanes();

    /// <summary>AVX-512 guard: 0 not run, 1 passed, 2 failed, 3 switched off. Does not start the test.</summary>
    [LibraryImport(Lib, EntryPoint = "rk_pbkdf2_sha256_selftest_state")]
    public static partial int Pbkdf2Sha256SelfTestState();

    /// <summary>Paths executed by hashing calls: scalar 1, AVX2 2, AVX-512 4, NEON 8, ARM SHA-256 16.</summary>
    [LibraryImport(Lib, EntryPoint = "rk_pbkdf2_sha256_executed_paths")]
    public static partial int Pbkdf2Sha256ExecutedPaths();

    [LibraryImport(Lib, EntryPoint = "rk_rar5_search")]
    public static partial int Rar5Search(byte* salt16, int lg2, byte* check8, byte* pws, int len, int n, int* hits, int maxHits);

    [LibraryImport(Lib, EntryPoint = "rk_zip_path")]
    public static partial int ZipPath(int requested);

    [LibraryImport(Lib, EntryPoint = "rk_zip_search")]
    public static partial int ZipSearch(byte* header12, byte check1, byte check2, uint k0, uint k1, uint k2,
        byte* last, int n, int* hits, int maxHits, int path);

    [LibraryImport(Lib, EntryPoint = "rk_bench")]
    public static partial double Bench(int which, int reps);

    /// <summary>Three arrays of n prefix keys, with one final character per candidate; hits are flat indices.</summary>
    [LibraryImport(Lib, EntryPoint = "rk_zip_search_batch")]
    public static partial int ZipSearchBatch(byte* header12, byte check1, byte check2, uint* keys,
        byte* last, int n, int* hits, int capacity, int path);

    private static readonly Lazy<bool> _available = new(Probe);


    /// <summary>Test and benchmark switch; also set by RECOVERKIT_NO_NATIVE_LIB=1.</summary>
    internal static bool Disabled { get; set; } = Environment.GetEnvironmentVariable("RECOVERKIT_NO_NATIVE_LIB") == "1";

    public static int ApiVersion => Available ? Version() : 0;

    public static bool Available => !Disabled && _available.Value;

    public static Feature Features => Available ? (Feature)FeaturesRaw() : 0;

    /// <summary>Restricts the vector paths the library may use (benchmarks and tests).</summary>
    internal static void LimitFeatures(Feature mask) { if (Available) SetFeaturesRaw((int)mask); }

    /// <summary>
    /// True when the library is present and has a vector path for this CPU (AVX2 on x64, NEON on
    /// arm64): the RAR 3 hash and the Office 97 / 2003 and PDF RC4 filters.
    /// </summary>
    public static bool HasVectorPath => Available && (Features & (Feature.Avx2 | Feature.Neon)) != 0;

    /// <summary>True when the library's PDF R6 path can run (AVX2 + AES-NI, or the ARMv8 AES / SHA-2 / SHA-512 instructions).</summary>
    public static bool HasPdf6Path
    {
        get
        {
            const Feature x64 = Feature.Avx2 | Feature.AesNi, arm = Feature.ArmAes | Feature.ArmSha2 | Feature.ArmSha512;
            var f = Features;
            return (f & x64) == x64 || (f & arm) == arm;
        }
    }

    /// <summary>
    /// Prefixes per batch so that one call tests at least <paramref name="minCandidates"/> and its last
    /// 16-lane group is (nearly) full.
    /// </summary>
    public static int BatchFor(int lastCount, int minCandidates)
    {
        int c = Math.Max(1, (minCandidates + lastCount - 1) / lastCount);
        for (int k = c; k < c + 16; k++)
        {
            int n = k * lastCount, groups = (n + 15) / 16;
            if (n >= 0.98 * 16 * groups) return k;
        }
        return c;
    }

    private static bool Probe()
    {
        try
        {
            int v = Version();
            if (v != RequiredVersion) { DebugLog.Warn($"rknative version {v}, expected {RequiredVersion}; using managed kernels"); return false; }
            WhirlpoolSetAvx512(_whirlpoolAvx512Enabled ? 1 : 0);
            DebugLog.Info($"rknative loaded, features {(Feature)FeaturesRaw()}");
            return true;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            DebugLog.Info("rknative not available (" + ex.GetType().Name + "); using managed kernels");
            return false;
        }
    }
}

/// <summary>A kernel whose candidates the native library can pre-filter (32-bit check, hits re-verified).</summary>
internal unsafe interface INativeFilter
{
    /// <summary>Returns the number of hits (indices written to <paramref name="hits"/>), or -1 if unsupported.</summary>
    int Filter(byte* pws, int len, int n, int* hits, int maxHits);
}

/// <summary>Packs candidates, runs the native filter, and confirms hits with the kernel's reference check.</summary>
internal sealed unsafe class NativeFilterWorker(NativeKernel kernel, INativeFilter filter, KernelWorker fallback) : KernelWorker
{
    private byte[] _pws = [];
    private readonly int[] _hits = new int[64];

    public override int Search(ReadOnlySpan<byte> prefix, ReadOnlySpan<byte> last) => SearchBatch(prefix, 1, last);

    public override int SearchPasswords(ReadOnlySpan<byte> passwords, int length, int count)
    {
        if (!RkNative.Available) return fallback.SearchPasswords(passwords, length, count);
        int nh;
        fixed (byte* p = passwords)
        fixed (int* h = _hits)
            nh = filter.Filter(p, length, count, h, _hits.Length);
        if (nh < 0 || nh > _hits.Length) return fallback.SearchPasswords(passwords, length, count);
        for (int q = 0; q < nh; q++)
        {
            int idx = _hits[q];
            if (kernel.Verify(passwords.Slice(idx * length, length))) return idx;
        }
        return -1;
    }

    public override int SearchBatch(ReadOnlySpan<byte> prefixes, int count, ReadOnlySpan<byte> last)
    {
        int plen = prefixes.Length / count, len = plen + 1, n = count * last.Length;
        if (len > kernel.MaxPasswordLength) return -1;
        if (_pws.Length < n * len) _pws = new byte[n * len];
        for (int k = 0, o = 0; k < count; k++)
        {
            var pre = prefixes.Slice(k * plen, plen);
            for (int i = 0; i < last.Length; i++, o += len)
            {
                pre.CopyTo(_pws.AsSpan(o));
                _pws[o + plen] = last[i];
            }
        }
        int nh;
        fixed (byte* p = _pws)
        fixed (int* h = _hits)
            nh = filter.Filter(p, len, n, h, _hits.Length);
        if (nh < 0 || nh > _hits.Length) return fallback.SearchBatch(prefixes, count, last);
        for (int q = 0; q < nh; q++)
        {
            int idx = _hits[q];
            if (kernel.Verify(_pws.AsSpan(idx * len, len))) return idx;
        }
        return -1;
    }
}
