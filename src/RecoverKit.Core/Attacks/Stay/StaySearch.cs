using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace RecoverKit.Core.Attacks.Stay;

/// <summary>Per-file inputs for the staged searches: the clear RNG bytes and the stored header.</summary>
internal sealed class StayFileData
{
    public required byte[] R { get; init; }        // r[0..9]
    public required byte[] Stored { get; init; }   // stored[0..11]

    /// <summary>Restricts a search to a window of the (K, Cv) space; null means everything.</summary>
    public readonly record struct Window(int KFrom, int KTo, int CvFrom, int CvTo)
    {
        public static readonly Window Full = new(0, 256, 0, 1 << 14);
    }
}

/// <summary>A (Cv, K, a0, bY) guess that passed every file's stage-1 filter.</summary>
internal sealed class Stage1Survivor
{
    public required uint Cv { get; init; }         // bits 2..15 of C = crc32(Z, 0)
    public required byte K { get; init; }          // position-0 keystream = keystream(Z)
    public required byte A0 { get; init; }         // bits 0..7 of A0 = crc32(X, 0)
    public required byte BY { get; init; }         // MSB(Y * M)
    /// <summary>Per file: the (m1E1, m1E2) pairs of every carry combo that passed (the true pair included).</summary>
    public required IReadOnlyList<(byte M1E1, byte M1E2)>[] PerFile { get; init; }
}

/// <summary>
/// Stage 1 of Stay's attack: 38-bit enumeration (Cv 14, K 8, a0 8, bY 8) filtered by the
/// position-1 header byte of every file. Equation (the paper's MSB addition form):
/// m1 = (bY + g + carry) mod 256 with g = MSB(l1*M + 1) and carry the bit-24 carry of
/// (Y*M) + (l1*M + 1); the position-1 keystream of a pass is f14(Cv ^ bits2..15(T[m1])).
/// </summary>
internal static class StayStage1
{
    private const uint M = 0x08088405u;

    private static readonly uint[] T = BuildCrcTable();
    /// <summary>bits 2..15 of every CRC table entry (what the keystream mixes with Cv).</summary>
    private static readonly ushort[] T14 = Array.ConvertAll(T, x => (ushort)((x >> 2) & 0x3fff));
    private static readonly byte[] Tlsb = Array.ConvertAll(T, x => (byte)x);

    public static bool FilterPasses(StayFileData f, uint cv, byte k, byte a0, byte bY)
    {
        int g1 = G(f, k, a0, pass: 0), g2 = G(f, k, a0, pass: 1);
        byte target = (byte)(f.Stored[1] ^ f.R[1]);
        int ka0 = F14(cv ^ T14[(bY + g1) & 0xff]);
        int ka1 = F14(cv ^ T14[(bY + g1 + 1) & 0xff]);
        int kb0 = F14(cv ^ T14[(bY + g2) & 0xff]);
        int kb1 = F14(cv ^ T14[(bY + g2 + 1) & 0xff]);
        return ((ka0 ^ kb0) & 0xff) == target || ((ka0 ^ kb1) & 0xff) == target
            || ((ka1 ^ kb0) & 0xff) == target || ((ka1 ^ kb1) & 0xff) == target;
    }

    /// <summary>The (carry1, carry2) combos that pass this file's position-1 filter.</summary>
    internal static List<(int C1, int C2)> PassingCarries(StayFileData f, uint cv, byte k, byte a0, byte bY)
    {
        int g1 = G(f, k, a0, pass: 0), g2 = G(f, k, a0, pass: 1);
        byte target = (byte)(f.Stored[1] ^ f.R[1]);
        var list = new List<(int, int)>(2);
        for (int c1 = 0; c1 < 2; c1++)
            for (int c2 = 0; c2 < 2; c2++)
                if (((F14(cv ^ T14[(bY + g1 + c1) & 0xff]) ^ F14(cv ^ T14[(bY + g2 + c2) & 0xff])) & 0xff) == target)
                    list.Add((c1, c2));
        return list;
    }

    /// <summary>g = MSB(l1*M + 1) for one pass, with l1 = a0 ^ LSB(T[byte 0 of that pass]).</summary>
    private static int G(StayFileData f, int k, int a0, int pass)
    {
        byte b0 = pass == 0 ? f.R[0] : (byte)(f.R[0] ^ k);
        byte l1 = (byte)(a0 ^ Tlsb[b0]);
        return (int)(((l1 * M) + 1) >> 24);
    }

    /// <summary>F14(v): the keystream byte produced by 14 known bits of k2 (t = (v&lt;&lt;2)|2, even).</summary>
    private static int F14(uint v)
    {
        uint t = ((v << 2) | 2) & 0xffff;
        return (int)((t * (t ^ 1)) >> 8);
    }

    // ---------------------------------------------------------------- searches

    /// <summary>Full stage-1 search: SIMD (AVX2 or NEON) when available, scalar otherwise, parallel over Cv.</summary>
    public static List<Stage1Survivor> Search(IReadOnlyList<StayFileData> files, CancellationToken ct,
        Action<double, long>? progress = null, StayFileData.Window? window = null)
    {
        return VectorWidth > 1
            ? SearchVector(files, window ?? StayFileData.Window.Full, ct, progress)
            : SearchScalar(files, window ?? StayFileData.Window.Full, ct, progress);
    }

    /// <summary>Bytes per SIMD step: 32 (AVX2), 16 (NEON), or 1 when only scalar is available.</summary>
    internal static int VectorWidth => Avx2.IsSupported ? 32 : System.Runtime.Intrinsics.Arm.AdvSimd.IsSupported ? 16 : 1;

    /// <summary>Scalar reference search over a window of the (K, Cv) space (a0 and bY always full).</summary>
    public static List<Stage1Survivor> SearchScalar(IReadOnlyList<StayFileData> files, StayFileData.Window w,
        CancellationToken ct = default, Action<double, long>? progress = null)
    {
        var survivors = new List<Stage1Survivor>();
        int cvCount = w.CvTo - w.CvFrom;
        long done = 0;
        var opts = new ParallelOptions { CancellationToken = ct };

        Parallel.For(0, cvCount, opts, () => new List<Stage1Survivor>(), (cvi, state, mine) =>
        {
            uint cv = (uint)(w.CvFrom + cvi);
            var ks = new byte[256];                    // per-Cv: f14(cv ^ T14[m]) for every m
            for (int m = 0; m < 256; m++)
                ks[m] = (byte)F14(cv ^ T14[m]);

            for (int k = w.KFrom; k < w.KTo; k++)
                for (int a0 = 0; a0 < 256; a0++)
                {
                    int g1f = G(files[0], k, a0, 0), g2f = G(files[0], k, a0, 1);
                    byte target = (byte)(files[0].Stored[1] ^ files[0].R[1]);

                    for (int bY = 0; bY < 256; bY++)
                    {
                        int ka0 = ks[(bY + g1f) & 0xff], ka1 = ks[(bY + g1f + 1) & 0xff];
                        int kb0 = ks[(bY + g2f) & 0xff], kb1 = ks[(bY + g2f + 1) & 0xff];
                        if (((ka0 ^ kb0) & 0xff) != target && ((ka0 ^ kb1) & 0xff) != target
                            && ((ka1 ^ kb0) & 0xff) != target && ((ka1 ^ kb1) & 0xff) != target)
                            continue;

                        bool all = true;
                        for (int i = 1; i < files.Count && all; i++)
                            all = FilterPasses(files[i], cv, (byte)k, (byte)a0, (byte)bY);
                        if (all)
                            mine.Add(MakeSurvivor(files, cv, k, a0, bY));
                    }
                }
            Interlocked.Increment(ref done);
            progress?.Invoke(Volatile.Read(ref done) / (double)cvCount, 0);
            return mine;
        }, mine =>
        {
            lock (survivors) survivors.AddRange(mine);
        });

        return survivors;
    }

    /// <summary>SIMD search (AVX2 32-wide / NEON 16-wide): keystream lookups are contiguous loads from a doubled table.</summary>
    public static List<Stage1Survivor> SearchVector(IReadOnlyList<StayFileData> files, StayFileData.Window w,
        CancellationToken ct = default, Action<double, long>? progress = null)
    {
        int width = VectorWidth;
        var survivors = new List<Stage1Survivor>();
        int cvCount = w.CvTo - w.CvFrom;
        long done = 0;
        var opts = new ParallelOptions { CancellationToken = ct };

        Parallel.For(0, cvCount, opts, () => new List<Stage1Survivor>(), (cvi, state, mine) =>
        {
            uint cv = (uint)(w.CvFrom + cvi);
            var ks2 = new byte[512];                   // per-Cv keystreams, doubled so 8-wide loads never wrap
            for (int m = 0; m < 256; m++)
            {
                var b = (byte)F14(cv ^ T14[m]);
                ks2[m] = b;
                ks2[m + 256] = b;
            }

            var g1f = new int[files.Count];
            var g2f = new int[files.Count];
            var targets = new byte[files.Count];

            for (int k = w.KFrom; k < w.KTo; k++)
                for (int a0 = 0; a0 < 256; a0++)
                {
                    for (int i = 0; i < files.Count; i++)
                    {
                        g1f[i] = G(files[i], k, a0, 0);
                        g2f[i] = G(files[i], k, a0, 1);
                        targets[i] = (byte)(files[i].Stored[1] ^ files[i].R[1]);
                    }

                    for (int bY8 = 0; bY8 < 256; bY8 += width)
                    {
                        if (!VectorAnyPass(ks2, bY8, width, g1f[0], g2f[0], targets[0])) continue;
                        bool all = true;
                        for (int i = 1; i < files.Count && all; i++)
                            all = VectorAnyPass(ks2, bY8, width, g1f[i], g2f[i], targets[i]);
                        if (!all) continue;

                        for (int lane = 0; lane < width; lane++)
                        {
                            byte bY = (byte)(bY8 + lane);
                            if (!files.All(f => FilterPasses(f, cv, (byte)k, (byte)a0, bY))) continue;
                            mine.Add(MakeSurvivor(files, cv, k, a0, bY));
                        }
                    }
                }
            Interlocked.Increment(ref done);
            progress?.Invoke(Volatile.Read(ref done) / (double)cvCount, 0);
            return mine;
        }, mine =>
        {
            lock (survivors) survivors.AddRange(mine);
        });

        return survivors;
    }

    private static Stage1Survivor MakeSurvivor(IReadOnlyList<StayFileData> files, uint cv, int k, int a0, int bY)
    {
        var perFile = new IReadOnlyList<(byte, byte)>[files.Count];
        for (int i = 0; i < files.Count; i++)
        {
            var list = new List<(byte, byte)>();
            int g1 = G(files[i], k, a0, 0), g2 = G(files[i], k, a0, 1);
            foreach (var (c1, c2) in PassingCarries(files[i], cv, (byte)k, (byte)a0, (byte)bY))
                list.Add(((byte)(bY + g1 + c1), (byte)(bY + g2 + c2)));
            perFile[i] = list;
        }
        return new Stage1Survivor { Cv = cv, K = (byte)k, A0 = (byte)a0, BY = (byte)bY, PerFile = perFile };
    }

    private static unsafe bool VectorAnyPass(byte[] ks2, int bY8, int width, int g1, int g2, byte target)
    {
        fixed (byte* p = ks2)
        {
            if (width == 32)
            {
                var va0 = Avx.LoadVector256(p + bY8 + g1);
                var va1 = Avx.LoadVector256(p + bY8 + g1 + 1);
                var vb0 = Avx.LoadVector256(p + bY8 + g2);
                var vb1 = Avx.LoadVector256(p + bY8 + g2 + 1);
                var vt = Vector256.Create(target);
                var m = Avx2.Or(
                    Avx2.Or(Avx2.CompareEqual(Avx2.Xor(va0, vb0), vt), Avx2.CompareEqual(Avx2.Xor(va0, vb1), vt)),
                    Avx2.Or(Avx2.CompareEqual(Avx2.Xor(va1, vb0), vt), Avx2.CompareEqual(Avx2.Xor(va1, vb1), vt)));
                return Avx2.MoveMask(m) != 0;
            }
            if (width == 16)
            {
                var va0 = System.Runtime.Intrinsics.Arm.AdvSimd.LoadVector128(p + bY8 + g1);
                var va1 = System.Runtime.Intrinsics.Arm.AdvSimd.LoadVector128(p + bY8 + g1 + 1);
                var vb0 = System.Runtime.Intrinsics.Arm.AdvSimd.LoadVector128(p + bY8 + g2);
                var vb1 = System.Runtime.Intrinsics.Arm.AdvSimd.LoadVector128(p + bY8 + g2 + 1);
                var vt = Vector128.Create(target);
                var m = System.Runtime.Intrinsics.Arm.AdvSimd.Or(
                    System.Runtime.Intrinsics.Arm.AdvSimd.Or(System.Runtime.Intrinsics.Arm.AdvSimd.CompareEqual(System.Runtime.Intrinsics.Arm.AdvSimd.Xor(va0, vb0), vt), System.Runtime.Intrinsics.Arm.AdvSimd.CompareEqual(System.Runtime.Intrinsics.Arm.AdvSimd.Xor(va0, vb1), vt)),
                    System.Runtime.Intrinsics.Arm.AdvSimd.Or(System.Runtime.Intrinsics.Arm.AdvSimd.CompareEqual(System.Runtime.Intrinsics.Arm.AdvSimd.Xor(va1, vb0), vt), System.Runtime.Intrinsics.Arm.AdvSimd.CompareEqual(System.Runtime.Intrinsics.Arm.AdvSimd.Xor(va1, vb1), vt)));
                return AdvSimd.Arm64.MaxAcross(m).ToScalar() != 0;
            }
            // scalar fallback lane
            for (int lane = 0; lane < width; lane++)
            {
                int b = bY8 + lane;
                int ka0 = ks2[(b + g1) & 0xff], ka1 = ks2[(b + g1 + 1) & 0xff];
                int kb0 = ks2[(b + g2) & 0xff], kb1 = ks2[(b + g2 + 1) & 0xff];
                if (((ka0 ^ kb0) & 0xff) == target || ((ka0 ^ kb1) & 0xff) == target
                    || ((ka1 ^ kb0) & 0xff) == target || ((ka1 ^ kb1) & 0xff) == target)
                    return true;
            }
            return false;
        }
    }

    private static uint[] BuildCrcTable()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int k = 0; k < 8; k++)
                c = (c >> 1) ^ (0xedb88320 & (uint)-(int)(c & 1));
            t[i] = c;
        }
        return t;
    }
}
