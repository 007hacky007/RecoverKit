using System.Runtime.InteropServices;

namespace RecoverKit.Core.Native;

/// <summary>
/// The optional native kernel library (native/rknative.c: rknative.dll / librknative.dylib).
/// When it is missing, too old, or disabled with RECOVERKIT_NO_NATIVE_LIB=1, the managed kernels run.
/// </summary>
internal static unsafe partial class RkNative
{
    private const string Lib = "rknative";
    private const int RequiredVersion = 4;

    [Flags]
    public enum Feature { Avx2 = 1, ShaNi = 2, AesNi = 4, Neon = 8 }

    [LibraryImport(Lib, EntryPoint = "rk_version")] private static partial int Version();
    [LibraryImport(Lib, EntryPoint = "rk_features")] private static partial int FeaturesRaw();
    [LibraryImport(Lib, EntryPoint = "rk_set_features")] private static partial void SetFeaturesRaw(int mask);

    [LibraryImport(Lib, EntryPoint = "rk_rar3_hash")]
    public static partial int Rar3Hash(byte* salt, byte* passwords, int len, int n, byte* out36);

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

    [LibraryImport(Lib, EntryPoint = "rk_bench")]
    public static partial double Bench(int which, int reps);

    private static readonly Lazy<bool> _available = new(Probe);


    /// <summary>Test and benchmark switch; also set by RECOVERKIT_NO_NATIVE_LIB=1.</summary>
    internal static bool Disabled { get; set; } = Environment.GetEnvironmentVariable("RECOVERKIT_NO_NATIVE_LIB") == "1";

    public static bool Available => !Disabled && _available.Value;

    public static Feature Features => Available ? (Feature)FeaturesRaw() : 0;

    /// <summary>Restricts the vector paths the library may use (benchmarks and tests).</summary>
    internal static void LimitFeatures(Feature mask) { if (Available) SetFeaturesRaw((int)mask); }

    /// <summary>True when the library is present and has a vector path for this CPU.</summary>
    public static bool HasVectorPath => Available && (Features & (Feature.Avx2 | Feature.Neon)) != 0;

    /// <summary>True when the library's AVX2 paths can run.</summary>
    public static bool HasAvx2 => Available && (Features & Feature.Avx2) != 0;

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
