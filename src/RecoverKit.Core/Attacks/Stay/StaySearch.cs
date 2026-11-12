using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Numerics;
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
/// A carry constraint on Y: ((Y mod 2^24) * Mult) mod 2^24 is at least (or below) Threshold.
/// Mult is M for stage-1 carries and M² for stage-2 carries; the true Y always satisfies the
/// constraints of the true carry option.
/// </summary>
internal readonly record struct StayYConstraint(uint Mult, uint Threshold, bool AtLeast);

/// <summary>A stage-1 survivor refined by the position-2 filter: A0 bits 0..15 and C bits 0..23 known.</summary>
internal sealed class Stage2Survivor
{
    public required uint Cv { get; init; }          // bits 2..15 of C
    public required byte K { get; init; }
    public required byte A0Lo { get; init; }        // bits 0..7 of A0
    public required byte A1 { get; init; }          // bits 8..15 of A0
    public required byte BY { get; init; }          // MSB(Y*M)
    public required byte BY2 { get; init; }         // MSB(Y*M²)
    public required uint C24 { get; init; }         // bits 0..23 of C
    /// <summary>Per file: one constraint set per passing (m1 option × carry) combo; the true combo is among them.</summary>
    public required IReadOnlyList<IReadOnlyList<StayYConstraint>>[] PerFileOptions { get; init; }
}

/// <summary>Shared cipher tables and helpers for the staged searches.</summary>
internal static class StayTables
{
    public const uint M = 0x08088405u;
    public static readonly uint M2 = unchecked(M * M);

    public static readonly uint[] T = BuildCrcTable();
    /// <summary>bits 2..15 of every CRC table entry (what the keystream mixes with Cv).</summary>
    public static readonly ushort[] T14 = Array.ConvertAll(T, x => (ushort)((x >> 2) & 0x3fff));
    public static readonly byte[] Tlsb = Array.ConvertAll(T, x => (byte)x);

    /// <summary>Bytes per SIMD step: 32 (AVX2), 16 (NEON), or 1 when only scalar is available.</summary>
    public static int VectorWidth => Avx2.IsSupported ? 32 : AdvSimd.IsSupported ? 16 : 1;

    /// <summary>F14(v): the keystream byte produced by 14 known bits of k2 (t = (v&lt;&lt;2)|2, even).</summary>
    public static int F14(uint v)
    {
        uint t = ((v << 2) | 2) & 0xffff;
        return (int)((t * (t ^ 1)) >> 8);
    }

    /// <summary>g = MSB(l1*M + 1) for one pass, with l1 = a0 ^ LSB(T[byte 0 of that pass]).</summary>
    public static int G1(StayFileData f, int k, int a0, int pass)
    {
        byte b0 = pass == 0 ? f.R[0] : (byte)(f.R[0] ^ k);
        byte l1 = (byte)(a0 ^ Tlsb[b0]);
        return (int)(((l1 * M) + 1) >> 24);
    }

    /// <summary>Any-lane check of table1[b+g1+cc1] ^ table2[b+g2+cc2] == target for cc1, cc2 ∈ {0,1}.</summary>
    public static unsafe bool VectorAnyPass(byte[] table1, byte[] table2, int bY8, int width, int g1, int g2, byte target)
    {
        fixed (byte* p1 = table1)
        fixed (byte* p2 = table2)
        {
            if (width == 32)
            {
                var va0 = Avx.LoadVector256(p1 + bY8 + g1);
                var va1 = Avx.LoadVector256(p1 + bY8 + g1 + 1);
                var vb0 = Avx.LoadVector256(p2 + bY8 + g2);
                var vb1 = Avx.LoadVector256(p2 + bY8 + g2 + 1);
                var vt = Vector256.Create(target);
                var m = Avx2.Or(
                    Avx2.Or(Avx2.CompareEqual(Avx2.Xor(va0, vb0), vt), Avx2.CompareEqual(Avx2.Xor(va0, vb1), vt)),
                    Avx2.Or(Avx2.CompareEqual(Avx2.Xor(va1, vb0), vt), Avx2.CompareEqual(Avx2.Xor(va1, vb1), vt)));
                return Avx2.MoveMask(m) != 0;
            }
            if (width == 16)
            {
                var va0 = AdvSimd.LoadVector128(p1 + bY8 + g1);
                var va1 = AdvSimd.LoadVector128(p1 + bY8 + g1 + 1);
                var vb0 = AdvSimd.LoadVector128(p2 + bY8 + g2);
                var vb1 = AdvSimd.LoadVector128(p2 + bY8 + g2 + 1);
                var vt = Vector128.Create(target);
                var m = AdvSimd.Or(
                    AdvSimd.Or(AdvSimd.CompareEqual(AdvSimd.Xor(va0, vb0), vt), AdvSimd.CompareEqual(AdvSimd.Xor(va0, vb1), vt)),
                    AdvSimd.Or(AdvSimd.CompareEqual(AdvSimd.Xor(va1, vb0), vt), AdvSimd.CompareEqual(AdvSimd.Xor(va1, vb1), vt)));
                return AdvSimd.Arm64.MaxAcross(m).ToScalar() != 0;
            }
            for (int lane = 0; lane < width; lane++)
            {
                int b = bY8 + lane;
                int ka0 = table1[(b + g1) & 0xff], ka1 = table1[(b + g1 + 1) & 0xff];
                int kb0 = table2[(b + g2) & 0xff], kb1 = table2[(b + g2 + 1) & 0xff];
                if (((ka0 ^ kb0) & 0xff) == target || ((ka0 ^ kb1) & 0xff) == target
                    || ((ka1 ^ kb0) & 0xff) == target || ((ka1 ^ kb1) & 0xff) == target)
                    return true;
            }
            return false;
        }
    }

    /// <summary>Copies a 256-entry table into 512 bytes so width-wide loads never wrap past index 255.</summary>
    public static byte[] DoubleTable(byte[] t)
    {
        var d = new byte[512];
        Array.Copy(t, d, 256);
        Array.Copy(t, 0, d, 256, 256);
        return d;
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

/// <summary>
/// Stage 1 of Stay's attack: 38-bit enumeration (Cv 14, K 8, a0 8, bY 8) filtered by the
/// position-1 header byte of every file. Equation (the paper's MSB addition form):
/// m1 = (bY + g + carry) mod 256 with g = MSB(l1*M + 1) and carry the bit-24 carry of
/// (Y*M) + (l1*M + 1); the position-1 keystream of a pass is F14(Cv ^ bits2..15(T[m1])).
/// </summary>
internal static class StayStage1
{
    public static bool FilterPasses(StayFileData f, uint cv, byte k, byte a0, byte bY)
    {
        int g1 = StayTables.G1(f, k, a0, pass: 0), g2 = StayTables.G1(f, k, a0, pass: 1);
        byte target = (byte)(f.Stored[1] ^ f.R[1]);
        return CheckCombos(cv, bY, g1, g2, target);
    }

    /// <summary>The (carry1, carry2) combos that pass this file's position-1 filter.</summary>
    internal static List<(int C1, int C2)> PassingCarries(StayFileData f, uint cv, byte k, byte a0, byte bY)
    {
        int g1 = StayTables.G1(f, k, a0, pass: 0), g2 = StayTables.G1(f, k, a0, pass: 1);
        byte target = (byte)(f.Stored[1] ^ f.R[1]);
        var list = new List<(int, int)>(2);
        for (int c1 = 0; c1 < 2; c1++)
            for (int c2 = 0; c2 < 2; c2++)
                if (((StayTables.F14(cv ^ StayTables.T14[(bY + g1 + c1) & 0xff]) ^ StayTables.F14(cv ^ StayTables.T14[(bY + g2 + c2) & 0xff])) & 0xff) == target)
                    list.Add((c1, c2));
        return list;
    }

    private static bool CheckCombos(uint cv, byte bY, int g1, int g2, byte target)
    {
        int ka0 = StayTables.F14(cv ^ StayTables.T14[(bY + g1) & 0xff]);
        int ka1 = StayTables.F14(cv ^ StayTables.T14[(bY + g1 + 1) & 0xff]);
        int kb0 = StayTables.F14(cv ^ StayTables.T14[(bY + g2) & 0xff]);
        int kb1 = StayTables.F14(cv ^ StayTables.T14[(bY + g2 + 1) & 0xff]);
        return ((ka0 ^ kb0) & 0xff) == target || ((ka0 ^ kb1) & 0xff) == target
            || ((ka1 ^ kb0) & 0xff) == target || ((ka1 ^ kb1) & 0xff) == target;
    }

    // ---------------------------------------------------------------- searches

    /// <summary>Full stage-1 search: SIMD (AVX2 or NEON) when available, scalar otherwise, parallel over Cv.</summary>
    public static List<Stage1Survivor> Search(IReadOnlyList<StayFileData> files, CancellationToken ct,
        Action<double, long>? progress = null, StayFileData.Window? window = null)
    {
        return StayTables.VectorWidth > 1
            ? SearchVector(files, window ?? StayFileData.Window.Full, ct, progress)
            : SearchScalar(files, window ?? StayFileData.Window.Full, ct, progress);
    }

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
            var ks = new byte[256];                    // per-Cv: F14(cv ^ T14[m]) for every m
            for (int m = 0; m < 256; m++)
                ks[m] = (byte)StayTables.F14(cv ^ StayTables.T14[m]);

            for (int k = w.KFrom; k < w.KTo; k++)
                for (int a0 = 0; a0 < 256; a0++)
                {
                    int g1f = StayTables.G1(files[0], k, a0, 0), g2f = StayTables.G1(files[0], k, a0, 1);
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
        }, mine => { lock (survivors) survivors.AddRange(mine); });

        return survivors;
    }

    /// <summary>SIMD search (AVX2 32-wide / NEON 16-wide): keystream lookups are contiguous loads from a doubled table.</summary>
    public static List<Stage1Survivor> SearchVector(IReadOnlyList<StayFileData> files, StayFileData.Window w,
        CancellationToken ct = default, Action<double, long>? progress = null)
    {
        var survivors = new List<Stage1Survivor>();
        int cvCount = w.CvTo - w.CvFrom;
        int width = StayTables.VectorWidth;
        long done = 0;
        var opts = new ParallelOptions { CancellationToken = ct };

        Parallel.For(0, cvCount, opts, () => new List<Stage1Survivor>(), (cvi, state, mine) =>
        {
            uint cv = (uint)(w.CvFrom + cvi);
            var ks2 = StayTables.DoubleTable(Enumerable.Range(0, 256).Select(m => (byte)StayTables.F14(cv ^ StayTables.T14[m])).ToArray());

            var g1f = new int[files.Count];
            var g2f = new int[files.Count];
            var targets = new byte[files.Count];

            for (int k = w.KFrom; k < w.KTo; k++)
                for (int a0 = 0; a0 < 256; a0++)
                {
                    for (int i = 0; i < files.Count; i++)
                    {
                        g1f[i] = StayTables.G1(files[i], k, a0, 0);
                        g2f[i] = StayTables.G1(files[i], k, a0, 1);
                        targets[i] = (byte)(files[i].Stored[1] ^ files[i].R[1]);
                    }

                    for (int bY8 = 0; bY8 < 256; bY8 += width)
                    {
                        if (!StayTables.VectorAnyPass(ks2, ks2, bY8, width, g1f[0], g2f[0], targets[0])) continue;
                        bool all = true;
                        for (int i = 1; i < files.Count && all; i++)
                            all = StayTables.VectorAnyPass(ks2, ks2, bY8, width, g1f[i], g2f[i], targets[i]);
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
        }, mine => { lock (survivors) survivors.AddRange(mine); });

        return survivors;
    }

    private static Stage1Survivor MakeSurvivor(IReadOnlyList<StayFileData> files, uint cv, int k, int a0, int bY)
    {
        var perFile = new IReadOnlyList<(byte, byte)>[files.Count];
        for (int i = 0; i < files.Count; i++)
        {
            var list = new List<(byte, byte)>();
            int g1 = StayTables.G1(files[i], k, a0, 0), g2 = StayTables.G1(files[i], k, a0, 1);
            foreach (var (c1, c2) in PassingCarries(files[i], cv, (byte)k, (byte)a0, (byte)bY))
                list.Add(((byte)(bY + g1 + c1), (byte)(bY + g2 + c2)));
            perFile[i] = list;
        }
        return new Stage1Survivor { Cv = cv, K = (byte)k, A0 = (byte)a0, BY = (byte)bY, PerFile = perFile };
    }
}

/// <summary>
/// Stage 2 of Stay's attack: per stage-1 survivor, 26-bit enumeration (a1 8, bY2 8, Ch 8, Cl 2)
/// filtered by the position-2 header byte. Pass 2's byte 1 is c1[1] = r[1] ^ (pass-1 position-1
/// keystream), known from the stage-1 survivor. Every passing combo contributes carry constraints on Y.
/// </summary>
internal static class StayStage2
{
    /// <summary>Does file <paramref name="index"/> pass the position-2 filter for this guess (any option, any carries)?</summary>
    public static bool FilterPasses(StayFileData f, int index, Stage1Survivor s, byte a1, byte bY2, byte ch, byte cl)
        => PassingOptions(f, index, s, a1, bY2, ch, cl).Count > 0;

    /// <summary>All passing (option, carries) combos for one file, each with its four Y constraints.</summary>
    internal static List<IReadOnlyList<StayYConstraint>> PassingOptions(StayFileData f, int index, Stage1Survivor s,
        byte a1, byte bY2, byte ch, byte cl)
    {
        var result = new List<IReadOnlyList<StayYConstraint>>(1);
        uint c24 = ComposeC24(s.Cv, ch, cl);
        ushort a0lo16 = (ushort)(s.A0 | (a1 << 8));
        byte target = (byte)(f.Stored[2] ^ f.R[2]);

        foreach (var (m1e1, m1e2) in s.PerFile[index])
        {
            byte ksE1 = (byte)StayTables.F14(s.Cv ^ StayTables.T14[m1e1]);   // pass-1 position-1 keystream
            var p1 = PassG2(f, s.K, a0lo16, (byte)(f.R[0]), (byte)(f.R[1]));
            var p2 = PassG2(f, s.K, a0lo16, (byte)(f.R[0] ^ s.K), (byte)(f.R[1] ^ ksE1));
            var s2E1 = new int[2];
            var s2E2 = new int[2];
            for (int cc = 0; cc < 2; cc++)
            {
                s2E1[cc] = M2Stream(c24, m1e1, (byte)(bY2 + p1.G2 + cc));
                s2E2[cc] = M2Stream(c24, m1e2, (byte)(bY2 + p2.G2 + cc));
            }
            for (int cc1 = 0; cc1 < 2; cc1++)
                for (int cc2 = 0; cc2 < 2; cc2++)
                    if (((s2E1[cc1] ^ s2E2[cc2]) & 0xff) == target)
                        result.Add(ConstraintsFor(f, s, m1e1, m1e2, cc1, cc2, p1, p2));
        }
        return result;
    }

    /// <summary>Searches every stage-1 survivor's 26-bit space; returns refined survivors with constraints.</summary>
    public static List<Stage2Survivor> Search(IReadOnlyList<Stage1Survivor> stage1, IReadOnlyList<StayFileData> files,
        CancellationToken ct = default, Action<double, long>? progress = null)
    {
        var survivors = new List<Stage2Survivor>();
        int width = StayTables.VectorWidth;
        int total = stage1.Count * 256;   // (survivor, Ch) work units
        long done = 0;

        Parallel.For(0, total, new ParallelOptions { CancellationToken = ct }, () => new List<Stage2Survivor>(), (unit, _, mine) =>
        {
            int si = unit / 256, ch = unit % 256;
            var s = stage1[si];

            // per (Ch, Cl): per file, per option: doubled m2 -> position-2 keystream tables
            var tables = new List<(byte[] E1, byte[] E2, byte M1E1, byte M1E2)>[files.Count][];
            for (int cl = 0; cl < 4; cl++)
            {
                uint c24 = ComposeC24(s.Cv, (byte)ch, (byte)cl);
                tables[cl] = new List<(byte[], byte[], byte, byte)>[files.Count];
                for (int i = 0; i < files.Count; i++)
                {
                    var opts = new List<(byte[], byte[], byte, byte)>();
                    foreach (var (m1e1, m1e2) in s.PerFile[i])
                    {
                        var t1 = new byte[256];
                        var t2 = new byte[256];
                        for (int m2 = 0; m2 < 256; m2++)
                        {
                            t1[m2] = (byte)M2Stream(c24, m1e1, (byte)m2);
                            t2[m2] = (byte)M2Stream(c24, m1e2, (byte)m2);
                        }
                        opts.Add((StayTables.DoubleTable(t1), StayTables.DoubleTable(t2), m1e1, m1e2));
                    }
                    tables[cl][i] = opts;
                }

                for (int a1 = 0; a1 < 256; a1++)
                {
                    ushort a0lo16 = (ushort)(s.A0 | (a1 << 8));
                    var targets = new byte[files.Count];
                    var g2e1 = new List<int>[files.Count];
                    var g2e2 = new List<int>[files.Count];
                    for (int i = 0; i < files.Count; i++)
                    {
                        var f = files[i];
                        targets[i] = (byte)(f.Stored[2] ^ f.R[2]);
                        g2e1[i] = [];
                        g2e2[i] = [];
                        foreach (var (_, _, m1e1, _) in tables[cl][i])
                        {
                            byte ksE1 = (byte)StayTables.F14(s.Cv ^ StayTables.T14[m1e1]);
                            g2e1[i].Add(PassG2(f, s.K, a0lo16, (byte)(f.R[0]), (byte)(f.R[1])).G2);
                            g2e2[i].Add(PassG2(f, s.K, a0lo16, (byte)(f.R[0] ^ s.K), (byte)(f.R[1] ^ ksE1)).G2);
                        }
                    }

                    for (int bY8 = 0; bY8 < 256; bY8 += width)
                    {
                        if (!AnyOptionPasses(tables[cl], 0, g2e1, g2e2, targets, bY8, width)) continue;
                        bool all = true;
                        for (int i = 1; i < files.Count && all; i++)
                            all = AnyOptionPasses(tables[cl], i, g2e1, g2e2, targets, bY8, width);
                        if (!all) continue;

                        for (int lane = 0; lane < width; lane++)
                        {
                            byte bY2 = (byte)(bY8 + lane);
                            bool ok = true;
                            for (int i = 0; i < files.Count && ok; i++)
                                ok = FilterPasses(files[i], i, s, (byte)a1, bY2, (byte)ch, (byte)cl);
                            if (!ok) continue;
                            var perFile = new IReadOnlyList<IReadOnlyList<StayYConstraint>>[files.Count];
                            for (int i = 0; i < files.Count; i++)
                                perFile[i] = PassingOptions(files[i], i, s, (byte)a1, bY2, (byte)ch, (byte)cl);
                            mine.Add(new Stage2Survivor
                            {
                                Cv = s.Cv, K = s.K, A0Lo = s.A0, A1 = (byte)a1, BY = s.BY, BY2 = bY2,
                                C24 = c24, PerFileOptions = perFile,
                            });
                        }
                    }
                }
            }
            Interlocked.Increment(ref done);
            progress?.Invoke(Volatile.Read(ref done) / (double)total, 0);
            return mine;
        }, mine => { lock (survivors) survivors.AddRange(mine); });

        return survivors;
    }

    private static bool AnyOptionPasses(List<(byte[] E1, byte[] E2, byte M1E1, byte M1E2)>[] fileTables, int i,
        List<int>[] g2e1, List<int>[] g2e2, byte[] targets, int bY8, int width)
    {
        for (int o = 0; o < fileTables[i].Count; o++)
            if (StayTables.VectorAnyPass(fileTables[i][o].E1, fileTables[i][o].E2, bY8, width, g2e1[i][o], g2e2[i][o], targets[i]))
                return true;
        return false;
    }

    /// <summary>Position-2 helper for one pass: l1, l2, g2 = MSB(l1*M² + (l2+1)*M + 1).</summary>
    private static (byte L1, byte L2, int G2) PassG2(StayFileData f, int k, ushort a0lo16, byte byte0, byte byte1)
    {
        ushort k0_1 = (ushort)(a0lo16 ^ (StayTables.T[byte0] & 0xffff));
        byte l1 = (byte)k0_1;
        ushort k0_2 = (ushort)((k0_1 >> 8) ^ (StayTables.T[(k0_1 ^ byte1) & 0xff] & 0xffff));
        byte l2 = (byte)k0_2;
        int g2 = (int)(unchecked(StayTables.M2 * l1 + (uint)(l2 + 1) * StayTables.M + 1) >> 24);
        return (l1, l2, g2);
    }

    /// <summary>Position-2 keystream: F14(bits 2..15 of crc32(c24 ^ T[m1], m2)).</summary>
    private static int M2Stream(uint c24, byte m1, byte m2)
    {
        uint k2_1 = c24 ^ StayTables.T[m1];
        uint k2_2 = (k2_1 >> 8) ^ StayTables.T[(k2_1 ^ m2) & 0xff];
        return StayTables.F14((k2_2 >> 2) & 0x3fff);
    }

    private static uint ComposeC24(uint cv, byte ch, byte cl) => (uint)(cl & 3) | (cv << 2) | ((uint)ch << 16);

    /// <summary>The four carry constraints implied by one passing combo (two passes × two stages).</summary>
    private static IReadOnlyList<StayYConstraint> ConstraintsFor(StayFileData f, Stage1Survivor s,
        byte m1e1, byte m1e2, int cc1, int cc2, (byte L1, byte L2, int G2) p1, (byte L1, byte L2, int G2) p2)
    {
        var list = new List<StayYConstraint>(4);
        AddM1Constraint(list, f, s, m1e1, p1.L1, pass1: true);
        AddM1Constraint(list, f, s, m1e2, p2.L1, pass1: false);
        list.Add(M2Constraint(p1.L1, p1.L2, cc1 == 1));
        list.Add(M2Constraint(p2.L1, p2.L2, cc2 == 1));
        return list;
    }

    private static void AddM1Constraint(List<StayYConstraint> list, StayFileData f, Stage1Survivor s, byte m1, byte l1, bool pass1)
    {
        int g = StayTables.G1(f, s.K, s.A0, pass1 ? 0 : 1);
        int c = (m1 - s.BY - g) & 0xff;
        if (c is not (0 or 1)) return;   // inconsistent option (should not happen for recorded pairs)
        uint blo = (uint)(((ulong)l1 * StayTables.M + 1) & 0xffffff);
        list.Add(new StayYConstraint(StayTables.M, Threshold(blo), c == 1));
    }

    /// <summary>Stage-2 carry constraint: cc was the bit-24 carry of (Y*M²) + (l1*M² + (l2+1)*M + 1).</summary>
    private static StayYConstraint M2Constraint(byte l1, byte l2, bool carry)
    {
        uint blo = unchecked(StayTables.M2 * l1 + (uint)(l2 + 1) * StayTables.M + 1) & 0xffffff;
        return new StayYConstraint(StayTables.M2, Threshold(blo), carry);
    }

    private static uint Threshold(uint blo) => (1u << 24) - blo & 0xffffff;
}

// ---------------------------------------------------------------- stage 3

/// <summary>
/// Stage 3 of Stay's attack: recovers (X, Y, Z) from a stage-2 survivor. Z from C bits 0..23
/// plus the position-0 keystream; Y from the carry constraints (a bitset over Y mod 2^24,
/// intersecting per file the union over options) plus the high byte via bY; a2 by exact
/// position-3 filtering; a1/a2/a3 then give A0, inverted to X. Candidates are yielded for
/// exact verification by the caller.
/// </summary>
internal static class StayStage3
{
    private const int N24 = 1 << 24;

    public static IEnumerable<ZipStayKeys> RecoverKeys(Stage2Survivor s, IReadOnlyList<StayFileData> files, CancellationToken ct)
    {
        // constraint intersection does not depend on Z: compute Y candidates once
        var ys = YCandidates(s, files, ct).ToList();
        foreach (var z in ZCandidates(s))
        {
            ct.ThrowIfCancellationRequested();
            foreach (var y in ys)
            {
                foreach (var a2 in A2Candidates(s, y, z, files))
                {
                    foreach (var a3 in A3Candidates(s, y, z, a2, files))
                    {
                        uint a0 = (uint)(s.A0Lo | (s.A1 << 8) | (a2 << 16) | (a3 << 24));
                        foreach (var x in XCandidates(a0))
                        {
                            ct.ThrowIfCancellationRequested();
                            yield return new ZipStayKeys(x, y, z);
                        }
                    }
                }
            }
        }
    }

    /// <summary>Z candidates from C bits 0..23 and the position-0 keystream (typically 1-3).</summary>
    private static IEnumerable<uint> ZCandidates(Stage2Survivor s)
    {
        for (int lsb = 0; lsb < 256; lsb++)
        {
            uint z = (((s.C24 ^ StayTables.T[lsb]) & 0xffffff) << 8) | (uint)lsb;
            if ((byte)StayTables.F14((z >> 2) & 0x3fff) == s.K)
                yield return z;
        }
    }

    /// <summary>
    /// Y candidates: intersect (over files) the union (over options) of the carry constraint
    /// subsets of Z_2^24, then add the high byte from bY = MSB(Y*M).
    /// </summary>
    private static IEnumerable<uint> YCandidates(Stage2Survivor s, IReadOnlyList<StayFileData> files, CancellationToken ct)
    {
        var acc = new ulong[N24 / 64];
        Array.Fill(acc, ulong.MaxValue);
        var union = new ulong[N24 / 64];
        var scratch = new ulong[N24 / 64];
        var optMask = new ulong[N24 / 64];

        for (int i = 0; i < files.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            Array.Clear(union);
            foreach (var option in s.PerFileOptions[i])
            {
                Array.Fill(optMask, ulong.MaxValue);
                foreach (var c in option)
                {
                    BuildConstraintMask(c, scratch);
                    AndInto(optMask, scratch);
                }
                OrInto(union, optMask);
            }
            AndInto(acc, union);
        }

        for (int w = 0; w < acc.Length; w++)
        {
            ulong word = acc[w];
            while (word != 0)
            {
                int bit = BitOperations.TrailingZeroCount(word);
                word &= word - 1;
                uint y24 = (uint)(w * 64 + bit);
                for (int h = 0; h < 256; h++)
                {
                    uint y = ((uint)h << 24) | y24;
                    if ((byte)((y * StayTables.M) >> 24) == s.BY && (byte)((y * StayTables.M2) >> 24) == s.BY2)
                    {
                        ct.ThrowIfCancellationRequested();
                        yield return y;
                    }
                }
            }
        }
    }

    /// <summary>Sets mask[y] for every y in Z_2^24 where ((y*Mult) mod 2^24) meets the constraint.</summary>
    private static void BuildConstraintMask(StayYConstraint c, ulong[] mask)
    {
        Array.Clear(mask);
        uint w = 0;
        uint threshold = c.Threshold, mult = c.Mult;
        if (c.AtLeast)
        {
            for (int y = 0; y < N24; y++)
            {
                if (w >= threshold) mask[y >> 6] |= 1ul << (y & 63);
                w = (w + mult) & 0xffffff;
            }
        }
        else
        {
            for (int y = 0; y < N24; y++)
            {
                if (w < threshold) mask[y >> 6] |= 1ul << (y & 63);
                w = (w + mult) & 0xffffff;
            }
        }
    }

    private static void AndInto(ulong[] target, ulong[] source)
    {
        for (int i = 0; i < target.Length; i++)
            target[i] &= source[i];
    }

    private static void OrInto(ulong[] target, ulong[] source)
    {
        for (int i = 0; i < target.Length; i++)
            target[i] |= source[i];
    }

    /// <summary>
    /// a2 = A0 bits 16..23 that pass the exact position-3 keystream filter for every file.
    /// Positions 0..3 depend on A0 bits 0..23 only.
    /// </summary>
    private static IEnumerable<byte> A2Candidates(Stage2Survivor s, uint y, uint z, IReadOnlyList<StayFileData> files)
    {
        for (int a2 = 0; a2 < 256; a2++)
        {
            uint a0lo24 = (uint)(s.A0Lo | (s.A1 << 8) | (a2 << 16));
            bool all = true;
            for (int i = 0; i < files.Count && all; i++)
                all = PositionPasses(files[i], s, a0lo24, y, z, 3);
            if (all)
                yield return (byte)a2;
        }
    }

    /// <summary>a3 = A0 bits 24..31 that pass the exact position-4 keystream filter for every file.</summary>
    private static IEnumerable<byte> A3Candidates(Stage2Survivor s, uint y, uint z, byte a2, IReadOnlyList<StayFileData> files)
    {
        for (int a3 = 0; a3 < 256; a3++)
        {
            uint a0 = (uint)(s.A0Lo | (s.A1 << 8) | (a2 << 16) | (a3 << 24));
            bool all = true;
            for (int i = 0; i < files.Count && all; i++)
                all = PositionPasses(files[i], s, a0, y, z, 4);
            if (all)
                yield return (byte)a3;
        }
    }

    /// <summary>
    /// Exact keystream-cancellation check at position n (3 or 4) for one file: both passes'
    /// keystreams at position n must cancel to stored[n] ^ r[n]. The cipher state before byte 0
    /// is (A0-derived k0, Y, Z): the byte-0 update of k0 is k0' = A0 ^ T[byte]
    /// (crc32(X, b) = crc32(X, 0) ^ T[b]); later bytes use the standard CRC recurrence. Pass 2's
    /// bytes are c1[pos] = r[pos] ^ ksE1[pos]. A0 must carry all bits positions 0..n depend on
    /// (24 for n = 3, 32 for n = 4).
    /// </summary>
    private static bool PositionPasses(StayFileData f, Stage2Survivor s, uint a0, uint y, uint z, int n)
    {
        byte target = (byte)(f.Stored[n] ^ f.R[n]);
        Span<int> ksE1 = stackalloc int[5];

        // pass 1: bytes r[0..n]
        uint k1 = y, k2 = z, k0 = 0;
        for (int pos = 0; pos <= n; pos++)
        {
            ksE1[pos] = StayTables.F14((k2 >> 2) & 0x3fff);
            byte b = f.R[pos];
            k0 = pos == 0 ? a0 ^ StayTables.T[b] : (k0 >> 8) ^ StayTables.T[(k0 ^ b) & 0xff];
            k1 = unchecked((k1 + (k0 & 0xff)) * StayTables.M + 1);
            k2 = (k2 >> 8) ^ StayTables.T[(k2 ^ (k1 >> 24)) & 0xff];
        }

        // pass 2: bytes c1[pos] = r[pos] ^ ksE1[pos]; keystream at position n must cancel
        (k1, k2, k0) = (y, z, 0);
        int ksE2 = 0;
        for (int pos = 0; pos <= n; pos++)
        {
            ksE2 = StayTables.F14((k2 >> 2) & 0x3fff);
            byte b = (byte)(f.R[pos] ^ ksE1[pos]);
            k0 = pos == 0 ? a0 ^ StayTables.T[b] : (k0 >> 8) ^ StayTables.T[(k0 ^ b) & 0xff];
            k1 = unchecked((k1 + (k0 & 0xff)) * StayTables.M + 1);
            k2 = (k2 >> 8) ^ StayTables.T[(k2 ^ (k1 >> 24)) & 0xff];
        }
        return ((ksE1[n] ^ ksE2) & 0xff) == target;
    }

    /// <summary>X candidates by CRC inversion of A0: find zb with (A0 ^ T[zb]) >> 24 == 0, X = ((A0 ^ T[zb])&lt;&lt;8)|zb.</summary>
    private static IEnumerable<uint> XCandidates(uint a0)
    {
        for (int zb = 0; zb < 256; zb++)
        {
            uint v = a0 ^ StayTables.T[zb];
            if ((v >> 24) == 0)
                yield return (v << 8) | (uint)zb;
        }
    }
}
