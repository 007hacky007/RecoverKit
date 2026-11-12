using System.Runtime.CompilerServices;

namespace RecoverKit.Core.Native.Simd;

/// <summary>
/// RC4 on a caller-provided 256-byte state. The key schedule is bound by store throughput (two byte
/// stores per step), so it is kept as tight scalar code.
/// </summary>
internal static unsafe class Rc4
{
    private static readonly byte[] IdentityBytes = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Ksa(byte* s, byte* key, int keyLen)
    {
        fixed (byte* id = IdentityBytes) Unsafe.CopyBlockUnaligned(s, id, 256);
        if (keyLen == 16) Ksa16(s, key);
        else
        {
            uint j = 0;
            int k = 0;
            for (int i = 0; i < 256; i++)
            {
                byte si = s[i];
                j = (j + si + key[k]) & 0xff;
                s[i] = s[j];
                s[j] = si;
                if (++k == keyLen) k = 0;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Ksa16(byte* s, byte* key)
    {
        uint j = 0;
        for (int i = 0; i < 256; i += 4)
        {
            byte s0 = s[i]; j = (j + s0 + key[i & 15]) & 0xff; s[i] = s[j]; s[j] = s0;
            byte s1 = s[i + 1]; j = (j + s1 + key[(i + 1) & 15]) & 0xff; s[i + 1] = s[j]; s[j] = s1;
            byte s2 = s[i + 2]; j = (j + s2 + key[(i + 2) & 15]) & 0xff; s[i + 2] = s[j]; s[j] = s2;
            byte s3 = s[i + 3]; j = (j + s3 + key[(i + 3) & 15]) & 0xff; s[i + 3] = s[j]; s[j] = s3;
        }
    }

    /// <summary>Four independent 16-byte-key schedules in lockstep, so their load/store chains overlap.</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void Ksa16x4(byte* s0, byte* s1, byte* s2, byte* s3, byte* k0, byte* k1, byte* k2, byte* k3)
    {
        fixed (byte* id = IdentityBytes)
        {
            Unsafe.CopyBlockUnaligned(s0, id, 256); Unsafe.CopyBlockUnaligned(s1, id, 256);
            Unsafe.CopyBlockUnaligned(s2, id, 256); Unsafe.CopyBlockUnaligned(s3, id, 256);
        }
        uint j0 = 0, j1 = 0, j2 = 0, j3 = 0;
        for (int i = 0; i < 256; i++)
        {
            int ki = i & 15;
            byte a0 = s0[i], a1 = s1[i], a2 = s2[i], a3 = s3[i];
            j0 = (j0 + a0 + k0[ki]) & 0xff; j1 = (j1 + a1 + k1[ki]) & 0xff;
            j2 = (j2 + a2 + k2[ki]) & 0xff; j3 = (j3 + a3 + k3[ki]) & 0xff;
            s0[i] = s0[j0]; s0[j0] = a0;
            s1[i] = s1[j1]; s1[j1] = a1;
            s2[i] = s2[j2]; s2[j2] = a2;
            s3[i] = s3[j3]; s3[j3] = a3;
        }
    }

    /// <summary>
    /// Eight independent 16-byte-key schedules in lockstep. States are contiguous (lane l at
    /// <c>states + 256*l</c>), keys too (<c>keys + 16*l</c>), so one base pointer serves all lanes.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void Ksa16x8(byte* st, byte* keys)
    {
        fixed (byte* id = IdentityBytes)
            for (int l = 0; l < 8; l++) Unsafe.CopyBlockUnaligned(st + 256 * l, id, 256);
        uint j0 = 0, j1 = 0, j2 = 0, j3 = 0, j4 = 0, j5 = 0, j6 = 0, j7 = 0;
        for (int i = 0; i < 256; i++)
        {
            int ki = i & 15;
            { byte v = st[0 + i]; j0 = (j0 + v + keys[0 + ki]) & 0xff; st[0 + i] = st[0 + j0]; st[0 + j0] = v; }
            { byte v = st[256 + i]; j1 = (j1 + v + keys[16 + ki]) & 0xff; st[256 + i] = st[256 + j1]; st[256 + j1] = v; }
            { byte v = st[512 + i]; j2 = (j2 + v + keys[32 + ki]) & 0xff; st[512 + i] = st[512 + j2]; st[512 + j2] = v; }
            { byte v = st[768 + i]; j3 = (j3 + v + keys[48 + ki]) & 0xff; st[768 + i] = st[768 + j3]; st[768 + j3] = v; }
            { byte v = st[1024 + i]; j4 = (j4 + v + keys[64 + ki]) & 0xff; st[1024 + i] = st[1024 + j4]; st[1024 + j4] = v; }
            { byte v = st[1280 + i]; j5 = (j5 + v + keys[80 + ki]) & 0xff; st[1280 + i] = st[1280 + j5]; st[1280 + j5] = v; }
            { byte v = st[1536 + i]; j6 = (j6 + v + keys[96 + ki]) & 0xff; st[1536 + i] = st[1536 + j6]; st[1536 + j6] = v; }
            { byte v = st[1792 + i]; j7 = (j7 + v + keys[112 + ki]) & 0xff; st[1792 + i] = st[1792 + j7]; st[1792 + j7] = v; }
        }
    }

    /// <summary>Eight-lane PRGA: XORs n keystream bytes of each lane's state into data (shared), output at <c>output + n*l</c>.</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void Crypt8(byte* st, byte* data, byte* output, int n)
    {
        uint j0 = 0, j1 = 0, j2 = 0, j3 = 0, j4 = 0, j5 = 0, j6 = 0, j7 = 0;
        for (int k = 0; k < n; k++)
        {
            uint i = (uint)(k + 1) & 0xff;
            byte d = data[k];
            { byte si = st[0 + i]; j0 = (j0 + si) & 0xff; byte sj = st[0 + j0]; st[0 + i] = sj; st[0 + j0] = si; output[n * 0 + k] = (byte)(d ^ st[0 + (byte)(si + sj)]); }
            { byte si = st[256 + i]; j1 = (j1 + si) & 0xff; byte sj = st[256 + j1]; st[256 + i] = sj; st[256 + j1] = si; output[n * 1 + k] = (byte)(d ^ st[256 + (byte)(si + sj)]); }
            { byte si = st[512 + i]; j2 = (j2 + si) & 0xff; byte sj = st[512 + j2]; st[512 + i] = sj; st[512 + j2] = si; output[n * 2 + k] = (byte)(d ^ st[512 + (byte)(si + sj)]); }
            { byte si = st[768 + i]; j3 = (j3 + si) & 0xff; byte sj = st[768 + j3]; st[768 + i] = sj; st[768 + j3] = si; output[n * 3 + k] = (byte)(d ^ st[768 + (byte)(si + sj)]); }
            { byte si = st[1024 + i]; j4 = (j4 + si) & 0xff; byte sj = st[1024 + j4]; st[1024 + i] = sj; st[1024 + j4] = si; output[n * 4 + k] = (byte)(d ^ st[1024 + (byte)(si + sj)]); }
            { byte si = st[1280 + i]; j5 = (j5 + si) & 0xff; byte sj = st[1280 + j5]; st[1280 + i] = sj; st[1280 + j5] = si; output[n * 5 + k] = (byte)(d ^ st[1280 + (byte)(si + sj)]); }
            { byte si = st[1536 + i]; j6 = (j6 + si) & 0xff; byte sj = st[1536 + j6]; st[1536 + i] = sj; st[1536 + j6] = si; output[n * 6 + k] = (byte)(d ^ st[1536 + (byte)(si + sj)]); }
            { byte si = st[1792 + i]; j7 = (j7 + si) & 0xff; byte sj = st[1792 + j7]; st[1792 + i] = sj; st[1792 + j7] = si; output[n * 7 + k] = (byte)(d ^ st[1792 + (byte)(si + sj)]); }
        }
    }

    private static readonly ulong[] IdentityRows = Enumerable.Range(0, 256).Select(i => (ulong)i * 0x0101010101010101UL).ToArray();

    /// <summary>
    /// Eight RC4 states interleaved byte-wise (<c>S[index*8 + lane]</c>), keys likewise
    /// (<c>keyRows[k]</c> holds key byte k of all 8 lanes). Entry i of every lane is one 8-byte word,
    /// so each key-schedule step stores row i once plus the 8 single-byte S[j] writes (9 stores
    /// instead of 16). A lane with j == i still ends correct because its S[j] write lands last.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void KsaInterleaved8(byte* s, ulong* keyRows, int keyLen)
    {
        fixed (ulong* id = IdentityRows) Unsafe.CopyBlockUnaligned(s, id, 2048);
        uint j0 = 0, j1 = 0, j2 = 0, j3 = 0, j4 = 0, j5 = 0, j6 = 0, j7 = 0;
        int k = 0;
        for (int i = 0; i < 256; i++)
        {
            ulong row = *(ulong*)(s + 8 * i);
            ulong kr = keyRows[k];
            if (++k == keyLen) k = 0;
            byte s0 = (byte)(row >> 0); j0 = (j0 + s0 + (byte)(kr >> 0)) & 0xff; ulong t0 = s[8 * j0 + 0];
            byte s1 = (byte)(row >> 8); j1 = (j1 + s1 + (byte)(kr >> 8)) & 0xff; ulong t1 = s[8 * j1 + 1];
            byte s2 = (byte)(row >> 16); j2 = (j2 + s2 + (byte)(kr >> 16)) & 0xff; ulong t2 = s[8 * j2 + 2];
            byte s3 = (byte)(row >> 24); j3 = (j3 + s3 + (byte)(kr >> 24)) & 0xff; ulong t3 = s[8 * j3 + 3];
            byte s4 = (byte)(row >> 32); j4 = (j4 + s4 + (byte)(kr >> 32)) & 0xff; ulong t4 = s[8 * j4 + 4];
            byte s5 = (byte)(row >> 40); j5 = (j5 + s5 + (byte)(kr >> 40)) & 0xff; ulong t5 = s[8 * j5 + 5];
            byte s6 = (byte)(row >> 48); j6 = (j6 + s6 + (byte)(kr >> 48)) & 0xff; ulong t6 = s[8 * j6 + 6];
            byte s7 = (byte)(row >> 56); j7 = (j7 + s7 + (byte)(kr >> 56)) & 0xff; ulong t7 = s[8 * j7 + 7];
            *(ulong*)(s + 8 * i) = t0 | t1 << 8 | t2 << 16 | t3 << 24 | t4 << 32 | t5 << 40 | t6 << 48 | t7 << 56;
            s[8 * j0 + 0] = s0;
            s[8 * j1 + 1] = s1;
            s[8 * j2 + 2] = s2;
            s[8 * j3 + 3] = s3;
            s[8 * j4 + 4] = s4;
            s[8 * j5 + 5] = s5;
            s[8 * j6 + 6] = s6;
            s[8 * j7 + 7] = s7;
        }
    }

    /// <summary>Eight-lane PRGA on the interleaved layout; output for lane l at <c>output + n*l</c>.</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void CryptInterleaved8(byte* s, byte* data, byte* output, int n)
    {
        uint j0 = 0, j1 = 0, j2 = 0, j3 = 0, j4 = 0, j5 = 0, j6 = 0, j7 = 0;
        for (int k = 0; k < n; k++)
        {
            int i = (k + 1) & 0xff;
            ulong row = *(ulong*)(s + 8 * i);
            byte d = data[k];
            byte a0 = (byte)(row >> 0); j0 = (j0 + a0) & 0xff; ulong b0 = s[8 * j0 + 0];
            byte a1 = (byte)(row >> 8); j1 = (j1 + a1) & 0xff; ulong b1 = s[8 * j1 + 1];
            byte a2 = (byte)(row >> 16); j2 = (j2 + a2) & 0xff; ulong b2 = s[8 * j2 + 2];
            byte a3 = (byte)(row >> 24); j3 = (j3 + a3) & 0xff; ulong b3 = s[8 * j3 + 3];
            byte a4 = (byte)(row >> 32); j4 = (j4 + a4) & 0xff; ulong b4 = s[8 * j4 + 4];
            byte a5 = (byte)(row >> 40); j5 = (j5 + a5) & 0xff; ulong b5 = s[8 * j5 + 5];
            byte a6 = (byte)(row >> 48); j6 = (j6 + a6) & 0xff; ulong b6 = s[8 * j6 + 6];
            byte a7 = (byte)(row >> 56); j7 = (j7 + a7) & 0xff; ulong b7 = s[8 * j7 + 7];
            *(ulong*)(s + 8 * i) = b0 | b1 << 8 | b2 << 16 | b3 << 24 | b4 << 32 | b5 << 40 | b6 << 48 | b7 << 56;
            s[8 * j0 + 0] = a0;
            s[8 * j1 + 1] = a1;
            s[8 * j2 + 2] = a2;
            s[8 * j3 + 3] = a3;
            s[8 * j4 + 4] = a4;
            s[8 * j5 + 5] = a5;
            s[8 * j6 + 6] = a6;
            s[8 * j7 + 7] = a7;
            output[n * 0 + k] = (byte)(d ^ s[8 * (byte)(a0 + (byte)b0) + 0]);
            output[n * 1 + k] = (byte)(d ^ s[8 * (byte)(a1 + (byte)b1) + 1]);
            output[n * 2 + k] = (byte)(d ^ s[8 * (byte)(a2 + (byte)b2) + 2]);
            output[n * 3 + k] = (byte)(d ^ s[8 * (byte)(a3 + (byte)b3) + 3]);
            output[n * 4 + k] = (byte)(d ^ s[8 * (byte)(a4 + (byte)b4) + 4]);
            output[n * 5 + k] = (byte)(d ^ s[8 * (byte)(a5 + (byte)b5) + 5]);
            output[n * 6 + k] = (byte)(d ^ s[8 * (byte)(a6 + (byte)b6) + 6]);
            output[n * 7 + k] = (byte)(d ^ s[8 * (byte)(a7 + (byte)b7) + 7]);
        }
    }

    /// <summary>
    /// Four 16-byte-key schedules in lockstep, written for the JIT: native-sized indices (no sign
    /// extension), separate lane pointers that fit in registers, and 16-step unrolling so key bytes
    /// are read at constant offsets. About 8 instructions per lane per step.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void Ksa16Fast4(byte* s0, byte* s1, byte* s2, byte* s3, byte* k0, byte* k1, byte* k2, byte* k3)
    {
        fixed (byte* id = IdentityBytes)
        {
            Unsafe.CopyBlockUnaligned(s0, id, 256); Unsafe.CopyBlockUnaligned(s1, id, 256);
            Unsafe.CopyBlockUnaligned(s2, id, 256); Unsafe.CopyBlockUnaligned(s3, id, 256);
        }
        nuint j0 = 0, j1 = 0, j2 = 0, j3 = 0;
        for (nuint i = 0; i < 256; i += 16)
        {
            { byte v = s0[i + 0]; j0 = (j0 + v + k0[0]) & 0xff; s0[i + 0] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 0]; j1 = (j1 + v + k1[0]) & 0xff; s1[i + 0] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 0]; j2 = (j2 + v + k2[0]) & 0xff; s2[i + 0] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 0]; j3 = (j3 + v + k3[0]) & 0xff; s3[i + 0] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 1]; j0 = (j0 + v + k0[1]) & 0xff; s0[i + 1] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 1]; j1 = (j1 + v + k1[1]) & 0xff; s1[i + 1] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 1]; j2 = (j2 + v + k2[1]) & 0xff; s2[i + 1] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 1]; j3 = (j3 + v + k3[1]) & 0xff; s3[i + 1] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 2]; j0 = (j0 + v + k0[2]) & 0xff; s0[i + 2] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 2]; j1 = (j1 + v + k1[2]) & 0xff; s1[i + 2] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 2]; j2 = (j2 + v + k2[2]) & 0xff; s2[i + 2] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 2]; j3 = (j3 + v + k3[2]) & 0xff; s3[i + 2] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 3]; j0 = (j0 + v + k0[3]) & 0xff; s0[i + 3] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 3]; j1 = (j1 + v + k1[3]) & 0xff; s1[i + 3] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 3]; j2 = (j2 + v + k2[3]) & 0xff; s2[i + 3] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 3]; j3 = (j3 + v + k3[3]) & 0xff; s3[i + 3] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 4]; j0 = (j0 + v + k0[4]) & 0xff; s0[i + 4] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 4]; j1 = (j1 + v + k1[4]) & 0xff; s1[i + 4] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 4]; j2 = (j2 + v + k2[4]) & 0xff; s2[i + 4] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 4]; j3 = (j3 + v + k3[4]) & 0xff; s3[i + 4] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 5]; j0 = (j0 + v + k0[5]) & 0xff; s0[i + 5] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 5]; j1 = (j1 + v + k1[5]) & 0xff; s1[i + 5] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 5]; j2 = (j2 + v + k2[5]) & 0xff; s2[i + 5] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 5]; j3 = (j3 + v + k3[5]) & 0xff; s3[i + 5] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 6]; j0 = (j0 + v + k0[6]) & 0xff; s0[i + 6] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 6]; j1 = (j1 + v + k1[6]) & 0xff; s1[i + 6] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 6]; j2 = (j2 + v + k2[6]) & 0xff; s2[i + 6] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 6]; j3 = (j3 + v + k3[6]) & 0xff; s3[i + 6] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 7]; j0 = (j0 + v + k0[7]) & 0xff; s0[i + 7] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 7]; j1 = (j1 + v + k1[7]) & 0xff; s1[i + 7] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 7]; j2 = (j2 + v + k2[7]) & 0xff; s2[i + 7] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 7]; j3 = (j3 + v + k3[7]) & 0xff; s3[i + 7] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 8]; j0 = (j0 + v + k0[8]) & 0xff; s0[i + 8] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 8]; j1 = (j1 + v + k1[8]) & 0xff; s1[i + 8] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 8]; j2 = (j2 + v + k2[8]) & 0xff; s2[i + 8] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 8]; j3 = (j3 + v + k3[8]) & 0xff; s3[i + 8] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 9]; j0 = (j0 + v + k0[9]) & 0xff; s0[i + 9] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 9]; j1 = (j1 + v + k1[9]) & 0xff; s1[i + 9] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 9]; j2 = (j2 + v + k2[9]) & 0xff; s2[i + 9] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 9]; j3 = (j3 + v + k3[9]) & 0xff; s3[i + 9] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 10]; j0 = (j0 + v + k0[10]) & 0xff; s0[i + 10] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 10]; j1 = (j1 + v + k1[10]) & 0xff; s1[i + 10] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 10]; j2 = (j2 + v + k2[10]) & 0xff; s2[i + 10] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 10]; j3 = (j3 + v + k3[10]) & 0xff; s3[i + 10] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 11]; j0 = (j0 + v + k0[11]) & 0xff; s0[i + 11] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 11]; j1 = (j1 + v + k1[11]) & 0xff; s1[i + 11] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 11]; j2 = (j2 + v + k2[11]) & 0xff; s2[i + 11] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 11]; j3 = (j3 + v + k3[11]) & 0xff; s3[i + 11] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 12]; j0 = (j0 + v + k0[12]) & 0xff; s0[i + 12] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 12]; j1 = (j1 + v + k1[12]) & 0xff; s1[i + 12] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 12]; j2 = (j2 + v + k2[12]) & 0xff; s2[i + 12] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 12]; j3 = (j3 + v + k3[12]) & 0xff; s3[i + 12] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 13]; j0 = (j0 + v + k0[13]) & 0xff; s0[i + 13] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 13]; j1 = (j1 + v + k1[13]) & 0xff; s1[i + 13] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 13]; j2 = (j2 + v + k2[13]) & 0xff; s2[i + 13] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 13]; j3 = (j3 + v + k3[13]) & 0xff; s3[i + 13] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 14]; j0 = (j0 + v + k0[14]) & 0xff; s0[i + 14] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 14]; j1 = (j1 + v + k1[14]) & 0xff; s1[i + 14] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 14]; j2 = (j2 + v + k2[14]) & 0xff; s2[i + 14] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 14]; j3 = (j3 + v + k3[14]) & 0xff; s3[i + 14] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 15]; j0 = (j0 + v + k0[15]) & 0xff; s0[i + 15] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 15]; j1 = (j1 + v + k1[15]) & 0xff; s1[i + 15] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 15]; j2 = (j2 + v + k2[15]) & 0xff; s2[i + 15] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 15]; j3 = (j3 + v + k3[15]) & 0xff; s3[i + 15] = s3[j3]; s3[j3] = v; }
        }
    }

    /// <summary>Four 5-byte-key (40-bit) schedules in lockstep; unrolled by the key length (51 x 5 + 1 steps).</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void Ksa5Fast4(byte* s0, byte* s1, byte* s2, byte* s3, byte* k0, byte* k1, byte* k2, byte* k3)
    {
        fixed (byte* id = IdentityBytes)
        {
            Unsafe.CopyBlockUnaligned(s0, id, 256); Unsafe.CopyBlockUnaligned(s1, id, 256);
            Unsafe.CopyBlockUnaligned(s2, id, 256); Unsafe.CopyBlockUnaligned(s3, id, 256);
        }
        nuint j0 = 0, j1 = 0, j2 = 0, j3 = 0;
        nuint i = 0;
        for (; i < 255; i += 5)
        {
            { byte v = s0[i + 0]; j0 = (j0 + v + k0[0]) & 0xff; s0[i + 0] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 0]; j1 = (j1 + v + k1[0]) & 0xff; s1[i + 0] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 0]; j2 = (j2 + v + k2[0]) & 0xff; s2[i + 0] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 0]; j3 = (j3 + v + k3[0]) & 0xff; s3[i + 0] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 1]; j0 = (j0 + v + k0[1]) & 0xff; s0[i + 1] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 1]; j1 = (j1 + v + k1[1]) & 0xff; s1[i + 1] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 1]; j2 = (j2 + v + k2[1]) & 0xff; s2[i + 1] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 1]; j3 = (j3 + v + k3[1]) & 0xff; s3[i + 1] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 2]; j0 = (j0 + v + k0[2]) & 0xff; s0[i + 2] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 2]; j1 = (j1 + v + k1[2]) & 0xff; s1[i + 2] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 2]; j2 = (j2 + v + k2[2]) & 0xff; s2[i + 2] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 2]; j3 = (j3 + v + k3[2]) & 0xff; s3[i + 2] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 3]; j0 = (j0 + v + k0[3]) & 0xff; s0[i + 3] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 3]; j1 = (j1 + v + k1[3]) & 0xff; s1[i + 3] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 3]; j2 = (j2 + v + k2[3]) & 0xff; s2[i + 3] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 3]; j3 = (j3 + v + k3[3]) & 0xff; s3[i + 3] = s3[j3]; s3[j3] = v; }
            { byte v = s0[i + 4]; j0 = (j0 + v + k0[4]) & 0xff; s0[i + 4] = s0[j0]; s0[j0] = v; }
            { byte v = s1[i + 4]; j1 = (j1 + v + k1[4]) & 0xff; s1[i + 4] = s1[j1]; s1[j1] = v; }
            { byte v = s2[i + 4]; j2 = (j2 + v + k2[4]) & 0xff; s2[i + 4] = s2[j2]; s2[j2] = v; }
            { byte v = s3[i + 4]; j3 = (j3 + v + k3[4]) & 0xff; s3[i + 4] = s3[j3]; s3[j3] = v; }
        }
        { byte v = s0[255]; j0 = (j0 + v + k0[0]) & 0xff; s0[255] = s0[j0]; s0[j0] = v; }
        { byte v = s1[255]; j1 = (j1 + v + k1[0]) & 0xff; s1[255] = s1[j1]; s1[j1] = v; }
        { byte v = s2[255]; j2 = (j2 + v + k2[0]) & 0xff; s2[255] = s2[j2]; s2[j2] = v; }
        { byte v = s3[255]; j3 = (j3 + v + k3[0]) & 0xff; s3[255] = s3[j3]; s3[j3] = v; }
    }

    /// <summary>Four-lane PRGA in lockstep (JIT-friendly), XORing n keystream bytes into shared data; lane l writes <c>outp + n*l</c>.</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void CryptFast4(byte* s0, byte* s1, byte* s2, byte* s3, byte* data, byte* outp, nuint n)
    {
        nuint j0 = 0, j1 = 0, j2 = 0, j3 = 0;
        byte* o0 = outp, o1 = outp + n, o2 = outp + 2 * n, o3 = outp + 3 * n;
        for (nuint k = 0; k < n; k++)
        {
            nuint i = (k + 1) & 0xff;
            byte d = data[k];
            { byte a = s0[i]; j0 = (j0 + a) & 0xff; byte b = s0[j0]; s0[i] = b; s0[j0] = a; o0[k] = (byte)(d ^ s0[(byte)(a + b)]); }
            { byte a = s1[i]; j1 = (j1 + a) & 0xff; byte b = s1[j1]; s1[i] = b; s1[j1] = a; o1[k] = (byte)(d ^ s1[(byte)(a + b)]); }
            { byte a = s2[i]; j2 = (j2 + a) & 0xff; byte b = s2[j2]; s2[i] = b; s2[j2] = a; o2[k] = (byte)(d ^ s2[(byte)(a + b)]); }
            { byte a = s3[i]; j3 = (j3 + a) & 0xff; byte b = s3[j3]; s3[i] = b; s3[j3] = a; o3[k] = (byte)(d ^ s3[(byte)(a + b)]); }
        }
    }

    /// <summary>XORs <paramref name="n"/> keystream bytes into <paramref name="data"/> (state starts at i = j = 0).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Crypt(byte* s, byte* data, byte* output, int n)
    {
        uint i = 0, j = 0;
        for (int k = 0; k < n; k++)
        {
            i = (i + 1) & 0xff;
            byte si = s[i];
            j = (j + si) & 0xff;
            byte sj = s[j];
            s[i] = sj;
            s[j] = si;
            output[k] = (byte)(data[k] ^ s[(byte)(si + sj)]);
        }
    }

    /// <summary>Managed convenience used by reference implementations and tests.</summary>
    public static byte[] Apply(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        var s = stackalloc byte[256];
        var outp = new byte[data.Length];
        fixed (byte* k = key)
        fixed (byte* d = data)
        fixed (byte* o = outp)
        {
            Ksa(s, k, key.Length);
            Crypt(s, d, o, data.Length);
        }
        return outp;
    }
}
