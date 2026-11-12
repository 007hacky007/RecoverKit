using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace RecoverKit.Core.Native.Simd;

/// <summary>
/// MD5 compression of 8 independent blocks at once (one per Vector256 lane), fully unrolled.
/// Message words are given word-major: w[k] holds word k of every lane's block. Generated code.
/// </summary>
internal static class Md5x8
{
    public static readonly Vector256<uint> IvA = Vector256.Create(0x67452301u), IvB = Vector256.Create(0xefcdab89u),
        IvC = Vector256.Create(0x98badcfeu), IvD = Vector256.Create(0x10325476u);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> Rotl(Vector256<uint> x, [ConstantExpected] int n) =>
        Vector256.ShiftLeft(x, n) | Vector256.ShiftRightLogical(x, 32 - n);

    /// <summary>Adds one compressed block to the state (a, b, c, d).</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void Compress(ref Vector256<uint> sa, ref Vector256<uint> sb, ref Vector256<uint> sc, ref Vector256<uint> sd, ReadOnlySpan<Vector256<uint>> w)
    {
        Vector256<uint> a = sa, b = sb, c = sc, d = sd;
        Vector256<uint> w0 = w[0], w1 = w[1], w2 = w[2], w3 = w[3], w4 = w[4], w5 = w[5], w6 = w[6], w7 = w[7],
            w8 = w[8], w9 = w[9], w10 = w[10], w11 = w[11], w12 = w[12], w13 = w[13], w14 = w[14], w15 = w[15];
        { var rt = a + (d ^ (b & (c ^ d))) + Vector256.Create(0xd76aa478u) + w0; a = b + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = d + (c ^ (a & (b ^ c))) + Vector256.Create(0xe8c7b756u) + w1; d = a + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = c + (b ^ (d & (a ^ b))) + Vector256.Create(0x242070dbu) + w2; c = d + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = b + (a ^ (c & (d ^ a))) + Vector256.Create(0xc1bdceeeu) + w3; b = c + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = a + (d ^ (b & (c ^ d))) + Vector256.Create(0xf57c0fafu) + w4; a = b + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = d + (c ^ (a & (b ^ c))) + Vector256.Create(0x4787c62au) + w5; d = a + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = c + (b ^ (d & (a ^ b))) + Vector256.Create(0xa8304613u) + w6; c = d + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = b + (a ^ (c & (d ^ a))) + Vector256.Create(0xfd469501u) + w7; b = c + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = a + (d ^ (b & (c ^ d))) + Vector256.Create(0x698098d8u) + w8; a = b + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = d + (c ^ (a & (b ^ c))) + Vector256.Create(0x8b44f7afu) + w9; d = a + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = c + (b ^ (d & (a ^ b))) + Vector256.Create(0xffff5bb1u) + w10; c = d + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = b + (a ^ (c & (d ^ a))) + Vector256.Create(0x895cd7beu) + w11; b = c + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = a + (d ^ (b & (c ^ d))) + Vector256.Create(0x6b901122u) + w12; a = b + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = d + (c ^ (a & (b ^ c))) + Vector256.Create(0xfd987193u) + w13; d = a + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = c + (b ^ (d & (a ^ b))) + Vector256.Create(0xa679438eu) + w14; c = d + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = b + (a ^ (c & (d ^ a))) + Vector256.Create(0x49b40821u) + w15; b = c + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = a + (c ^ (d & (b ^ c))) + Vector256.Create(0xf61e2562u) + w1; a = b + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = d + (b ^ (c & (a ^ b))) + Vector256.Create(0xc040b340u) + w6; d = a + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = c + (a ^ (b & (d ^ a))) + Vector256.Create(0x265e5a51u) + w11; c = d + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = b + (d ^ (a & (c ^ d))) + Vector256.Create(0xe9b6c7aau) + w0; b = c + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = a + (c ^ (d & (b ^ c))) + Vector256.Create(0xd62f105du) + w5; a = b + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = d + (b ^ (c & (a ^ b))) + Vector256.Create(0x02441453u) + w10; d = a + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = c + (a ^ (b & (d ^ a))) + Vector256.Create(0xd8a1e681u) + w15; c = d + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = b + (d ^ (a & (c ^ d))) + Vector256.Create(0xe7d3fbc8u) + w4; b = c + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = a + (c ^ (d & (b ^ c))) + Vector256.Create(0x21e1cde6u) + w9; a = b + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = d + (b ^ (c & (a ^ b))) + Vector256.Create(0xc33707d6u) + w14; d = a + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = c + (a ^ (b & (d ^ a))) + Vector256.Create(0xf4d50d87u) + w3; c = d + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = b + (d ^ (a & (c ^ d))) + Vector256.Create(0x455a14edu) + w8; b = c + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = a + (c ^ (d & (b ^ c))) + Vector256.Create(0xa9e3e905u) + w13; a = b + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = d + (b ^ (c & (a ^ b))) + Vector256.Create(0xfcefa3f8u) + w2; d = a + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = c + (a ^ (b & (d ^ a))) + Vector256.Create(0x676f02d9u) + w7; c = d + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = b + (d ^ (a & (c ^ d))) + Vector256.Create(0x8d2a4c8au) + w12; b = c + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = a + (b ^ c ^ d) + Vector256.Create(0xfffa3942u) + w5; a = b + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = d + (a ^ b ^ c) + Vector256.Create(0x8771f681u) + w8; d = a + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = c + (d ^ a ^ b) + Vector256.Create(0x6d9d6122u) + w11; c = d + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = b + (c ^ d ^ a) + Vector256.Create(0xfde5380cu) + w14; b = c + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = a + (b ^ c ^ d) + Vector256.Create(0xa4beea44u) + w1; a = b + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = d + (a ^ b ^ c) + Vector256.Create(0x4bdecfa9u) + w4; d = a + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = c + (d ^ a ^ b) + Vector256.Create(0xf6bb4b60u) + w7; c = d + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = b + (c ^ d ^ a) + Vector256.Create(0xbebfbc70u) + w10; b = c + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = a + (b ^ c ^ d) + Vector256.Create(0x289b7ec6u) + w13; a = b + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = d + (a ^ b ^ c) + Vector256.Create(0xeaa127fau) + w0; d = a + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = c + (d ^ a ^ b) + Vector256.Create(0xd4ef3085u) + w3; c = d + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = b + (c ^ d ^ a) + Vector256.Create(0x04881d05u) + w6; b = c + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = a + (b ^ c ^ d) + Vector256.Create(0xd9d4d039u) + w9; a = b + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = d + (a ^ b ^ c) + Vector256.Create(0xe6db99e5u) + w12; d = a + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = c + (d ^ a ^ b) + Vector256.Create(0x1fa27cf8u) + w15; c = d + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = b + (c ^ d ^ a) + Vector256.Create(0xc4ac5665u) + w2; b = c + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = a + (c ^ (b | ~d)) + Vector256.Create(0xf4292244u) + w0; a = b + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = d + (b ^ (a | ~c)) + Vector256.Create(0x432aff97u) + w7; d = a + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = c + (a ^ (d | ~b)) + Vector256.Create(0xab9423a7u) + w14; c = d + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = b + (d ^ (c | ~a)) + Vector256.Create(0xfc93a039u) + w5; b = c + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = a + (c ^ (b | ~d)) + Vector256.Create(0x655b59c3u) + w12; a = b + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = d + (b ^ (a | ~c)) + Vector256.Create(0x8f0ccc92u) + w3; d = a + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = c + (a ^ (d | ~b)) + Vector256.Create(0xffeff47du) + w10; c = d + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = b + (d ^ (c | ~a)) + Vector256.Create(0x85845dd1u) + w1; b = c + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = a + (c ^ (b | ~d)) + Vector256.Create(0x6fa87e4fu) + w8; a = b + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = d + (b ^ (a | ~c)) + Vector256.Create(0xfe2ce6e0u) + w15; d = a + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = c + (a ^ (d | ~b)) + Vector256.Create(0xa3014314u) + w6; c = d + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = b + (d ^ (c | ~a)) + Vector256.Create(0x4e0811a1u) + w13; b = c + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = a + (c ^ (b | ~d)) + Vector256.Create(0xf7537e82u) + w4; a = b + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = d + (b ^ (a | ~c)) + Vector256.Create(0xbd3af235u) + w11; d = a + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = c + (a ^ (d | ~b)) + Vector256.Create(0x2ad7d2bbu) + w2; c = d + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = b + (d ^ (c | ~a)) + Vector256.Create(0xeb86d391u) + w9; b = c + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        sa += a; sb += b; sc += c; sd += d;
    }

    /// <summary>Same as <see cref="Compress"/> but reads message words from memory each time (fewer registers, no spills).</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static unsafe void CompressMem(ref Vector256<uint> sa, ref Vector256<uint> sb, ref Vector256<uint> sc, ref Vector256<uint> sd, Vector256<uint>* w)
    {
        Vector256<uint> a = sa, b = sb, c = sc, d = sd;
        { var rt = a + (d ^ (b & (c ^ d))) + Vector256.Create(0xd76aa478u) + w[0]; a = b + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = d + (c ^ (a & (b ^ c))) + Vector256.Create(0xe8c7b756u) + w[1]; d = a + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = c + (b ^ (d & (a ^ b))) + Vector256.Create(0x242070dbu) + w[2]; c = d + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = b + (a ^ (c & (d ^ a))) + Vector256.Create(0xc1bdceeeu) + w[3]; b = c + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = a + (d ^ (b & (c ^ d))) + Vector256.Create(0xf57c0fafu) + w[4]; a = b + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = d + (c ^ (a & (b ^ c))) + Vector256.Create(0x4787c62au) + w[5]; d = a + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = c + (b ^ (d & (a ^ b))) + Vector256.Create(0xa8304613u) + w[6]; c = d + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = b + (a ^ (c & (d ^ a))) + Vector256.Create(0xfd469501u) + w[7]; b = c + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = a + (d ^ (b & (c ^ d))) + Vector256.Create(0x698098d8u) + w[8]; a = b + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = d + (c ^ (a & (b ^ c))) + Vector256.Create(0x8b44f7afu) + w[9]; d = a + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = c + (b ^ (d & (a ^ b))) + Vector256.Create(0xffff5bb1u) + w[10]; c = d + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = b + (a ^ (c & (d ^ a))) + Vector256.Create(0x895cd7beu) + w[11]; b = c + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = a + (d ^ (b & (c ^ d))) + Vector256.Create(0x6b901122u) + w[12]; a = b + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = d + (c ^ (a & (b ^ c))) + Vector256.Create(0xfd987193u) + w[13]; d = a + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = c + (b ^ (d & (a ^ b))) + Vector256.Create(0xa679438eu) + w[14]; c = d + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = b + (a ^ (c & (d ^ a))) + Vector256.Create(0x49b40821u) + w[15]; b = c + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = a + (c ^ (d & (b ^ c))) + Vector256.Create(0xf61e2562u) + w[1]; a = b + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = d + (b ^ (c & (a ^ b))) + Vector256.Create(0xc040b340u) + w[6]; d = a + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = c + (a ^ (b & (d ^ a))) + Vector256.Create(0x265e5a51u) + w[11]; c = d + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = b + (d ^ (a & (c ^ d))) + Vector256.Create(0xe9b6c7aau) + w[0]; b = c + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = a + (c ^ (d & (b ^ c))) + Vector256.Create(0xd62f105du) + w[5]; a = b + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = d + (b ^ (c & (a ^ b))) + Vector256.Create(0x02441453u) + w[10]; d = a + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = c + (a ^ (b & (d ^ a))) + Vector256.Create(0xd8a1e681u) + w[15]; c = d + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = b + (d ^ (a & (c ^ d))) + Vector256.Create(0xe7d3fbc8u) + w[4]; b = c + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = a + (c ^ (d & (b ^ c))) + Vector256.Create(0x21e1cde6u) + w[9]; a = b + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = d + (b ^ (c & (a ^ b))) + Vector256.Create(0xc33707d6u) + w[14]; d = a + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = c + (a ^ (b & (d ^ a))) + Vector256.Create(0xf4d50d87u) + w[3]; c = d + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = b + (d ^ (a & (c ^ d))) + Vector256.Create(0x455a14edu) + w[8]; b = c + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = a + (c ^ (d & (b ^ c))) + Vector256.Create(0xa9e3e905u) + w[13]; a = b + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = d + (b ^ (c & (a ^ b))) + Vector256.Create(0xfcefa3f8u) + w[2]; d = a + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = c + (a ^ (b & (d ^ a))) + Vector256.Create(0x676f02d9u) + w[7]; c = d + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = b + (d ^ (a & (c ^ d))) + Vector256.Create(0x8d2a4c8au) + w[12]; b = c + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = a + (b ^ c ^ d) + Vector256.Create(0xfffa3942u) + w[5]; a = b + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = d + (a ^ b ^ c) + Vector256.Create(0x8771f681u) + w[8]; d = a + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = c + (d ^ a ^ b) + Vector256.Create(0x6d9d6122u) + w[11]; c = d + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = b + (c ^ d ^ a) + Vector256.Create(0xfde5380cu) + w[14]; b = c + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = a + (b ^ c ^ d) + Vector256.Create(0xa4beea44u) + w[1]; a = b + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = d + (a ^ b ^ c) + Vector256.Create(0x4bdecfa9u) + w[4]; d = a + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = c + (d ^ a ^ b) + Vector256.Create(0xf6bb4b60u) + w[7]; c = d + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = b + (c ^ d ^ a) + Vector256.Create(0xbebfbc70u) + w[10]; b = c + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = a + (b ^ c ^ d) + Vector256.Create(0x289b7ec6u) + w[13]; a = b + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = d + (a ^ b ^ c) + Vector256.Create(0xeaa127fau) + w[0]; d = a + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = c + (d ^ a ^ b) + Vector256.Create(0xd4ef3085u) + w[3]; c = d + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = b + (c ^ d ^ a) + Vector256.Create(0x04881d05u) + w[6]; b = c + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = a + (b ^ c ^ d) + Vector256.Create(0xd9d4d039u) + w[9]; a = b + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = d + (a ^ b ^ c) + Vector256.Create(0xe6db99e5u) + w[12]; d = a + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = c + (d ^ a ^ b) + Vector256.Create(0x1fa27cf8u) + w[15]; c = d + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = b + (c ^ d ^ a) + Vector256.Create(0xc4ac5665u) + w[2]; b = c + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = a + (c ^ (b | ~d)) + Vector256.Create(0xf4292244u) + w[0]; a = b + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = d + (b ^ (a | ~c)) + Vector256.Create(0x432aff97u) + w[7]; d = a + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = c + (a ^ (d | ~b)) + Vector256.Create(0xab9423a7u) + w[14]; c = d + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = b + (d ^ (c | ~a)) + Vector256.Create(0xfc93a039u) + w[5]; b = c + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = a + (c ^ (b | ~d)) + Vector256.Create(0x655b59c3u) + w[12]; a = b + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = d + (b ^ (a | ~c)) + Vector256.Create(0x8f0ccc92u) + w[3]; d = a + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = c + (a ^ (d | ~b)) + Vector256.Create(0xffeff47du) + w[10]; c = d + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = b + (d ^ (c | ~a)) + Vector256.Create(0x85845dd1u) + w[1]; b = c + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = a + (c ^ (b | ~d)) + Vector256.Create(0x6fa87e4fu) + w[8]; a = b + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = d + (b ^ (a | ~c)) + Vector256.Create(0xfe2ce6e0u) + w[15]; d = a + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = c + (a ^ (d | ~b)) + Vector256.Create(0xa3014314u) + w[6]; c = d + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = b + (d ^ (c | ~a)) + Vector256.Create(0x4e0811a1u) + w[13]; b = c + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = a + (c ^ (b | ~d)) + Vector256.Create(0xf7537e82u) + w[4]; a = b + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = d + (b ^ (a | ~c)) + Vector256.Create(0xbd3af235u) + w[11]; d = a + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = c + (a ^ (d | ~b)) + Vector256.Create(0x2ad7d2bbu) + w[2]; c = d + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = b + (d ^ (c | ~a)) + Vector256.Create(0xeb86d391u) + w[9]; b = c + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        sa += a; sb += b; sc += c; sd += d;
    }

    /// <summary>Two independent 8-lane MD5 compressions interleaved step by step (16 candidates) to hide the per-step latency.</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static unsafe void Compress2(Vector256<uint>* s, Vector256<uint>* w, Vector256<uint>* x)
    {
        // s[0..3]: state of group 1, s[4..7]: state of group 2; w, x: their message words.
        Vector256<uint> a = s[0], b = s[1], c = s[2], d = s[3], p = s[4], q = s[5], r = s[6], t = s[7];
        { var rt = a + (d ^ (b & (c ^ d))) + Vector256.Create(0xd76aa478u) + w[0]; a = b + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = p + (t ^ (q & (r ^ t))) + Vector256.Create(0xd76aa478u) + x[0]; p = q + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = d + (c ^ (a & (b ^ c))) + Vector256.Create(0xe8c7b756u) + w[1]; d = a + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = t + (r ^ (p & (q ^ r))) + Vector256.Create(0xe8c7b756u) + x[1]; t = p + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = c + (b ^ (d & (a ^ b))) + Vector256.Create(0x242070dbu) + w[2]; c = d + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = r + (q ^ (t & (p ^ q))) + Vector256.Create(0x242070dbu) + x[2]; r = t + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = b + (a ^ (c & (d ^ a))) + Vector256.Create(0xc1bdceeeu) + w[3]; b = c + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = q + (p ^ (r & (t ^ p))) + Vector256.Create(0xc1bdceeeu) + x[3]; q = r + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = a + (d ^ (b & (c ^ d))) + Vector256.Create(0xf57c0fafu) + w[4]; a = b + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = p + (t ^ (q & (r ^ t))) + Vector256.Create(0xf57c0fafu) + x[4]; p = q + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = d + (c ^ (a & (b ^ c))) + Vector256.Create(0x4787c62au) + w[5]; d = a + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = t + (r ^ (p & (q ^ r))) + Vector256.Create(0x4787c62au) + x[5]; t = p + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = c + (b ^ (d & (a ^ b))) + Vector256.Create(0xa8304613u) + w[6]; c = d + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = r + (q ^ (t & (p ^ q))) + Vector256.Create(0xa8304613u) + x[6]; r = t + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = b + (a ^ (c & (d ^ a))) + Vector256.Create(0xfd469501u) + w[7]; b = c + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = q + (p ^ (r & (t ^ p))) + Vector256.Create(0xfd469501u) + x[7]; q = r + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = a + (d ^ (b & (c ^ d))) + Vector256.Create(0x698098d8u) + w[8]; a = b + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = p + (t ^ (q & (r ^ t))) + Vector256.Create(0x698098d8u) + x[8]; p = q + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = d + (c ^ (a & (b ^ c))) + Vector256.Create(0x8b44f7afu) + w[9]; d = a + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = t + (r ^ (p & (q ^ r))) + Vector256.Create(0x8b44f7afu) + x[9]; t = p + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = c + (b ^ (d & (a ^ b))) + Vector256.Create(0xffff5bb1u) + w[10]; c = d + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = r + (q ^ (t & (p ^ q))) + Vector256.Create(0xffff5bb1u) + x[10]; r = t + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = b + (a ^ (c & (d ^ a))) + Vector256.Create(0x895cd7beu) + w[11]; b = c + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = q + (p ^ (r & (t ^ p))) + Vector256.Create(0x895cd7beu) + x[11]; q = r + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = a + (d ^ (b & (c ^ d))) + Vector256.Create(0x6b901122u) + w[12]; a = b + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = p + (t ^ (q & (r ^ t))) + Vector256.Create(0x6b901122u) + x[12]; p = q + (Vector256.ShiftLeft(rt, 7) | Vector256.ShiftRightLogical(rt, 25)); }
        { var rt = d + (c ^ (a & (b ^ c))) + Vector256.Create(0xfd987193u) + w[13]; d = a + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = t + (r ^ (p & (q ^ r))) + Vector256.Create(0xfd987193u) + x[13]; t = p + (Vector256.ShiftLeft(rt, 12) | Vector256.ShiftRightLogical(rt, 20)); }
        { var rt = c + (b ^ (d & (a ^ b))) + Vector256.Create(0xa679438eu) + w[14]; c = d + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = r + (q ^ (t & (p ^ q))) + Vector256.Create(0xa679438eu) + x[14]; r = t + (Vector256.ShiftLeft(rt, 17) | Vector256.ShiftRightLogical(rt, 15)); }
        { var rt = b + (a ^ (c & (d ^ a))) + Vector256.Create(0x49b40821u) + w[15]; b = c + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = q + (p ^ (r & (t ^ p))) + Vector256.Create(0x49b40821u) + x[15]; q = r + (Vector256.ShiftLeft(rt, 22) | Vector256.ShiftRightLogical(rt, 10)); }
        { var rt = a + (c ^ (d & (b ^ c))) + Vector256.Create(0xf61e2562u) + w[1]; a = b + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = p + (r ^ (t & (q ^ r))) + Vector256.Create(0xf61e2562u) + x[1]; p = q + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = d + (b ^ (c & (a ^ b))) + Vector256.Create(0xc040b340u) + w[6]; d = a + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = t + (q ^ (r & (p ^ q))) + Vector256.Create(0xc040b340u) + x[6]; t = p + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = c + (a ^ (b & (d ^ a))) + Vector256.Create(0x265e5a51u) + w[11]; c = d + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = r + (p ^ (q & (t ^ p))) + Vector256.Create(0x265e5a51u) + x[11]; r = t + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = b + (d ^ (a & (c ^ d))) + Vector256.Create(0xe9b6c7aau) + w[0]; b = c + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = q + (t ^ (p & (r ^ t))) + Vector256.Create(0xe9b6c7aau) + x[0]; q = r + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = a + (c ^ (d & (b ^ c))) + Vector256.Create(0xd62f105du) + w[5]; a = b + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = p + (r ^ (t & (q ^ r))) + Vector256.Create(0xd62f105du) + x[5]; p = q + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = d + (b ^ (c & (a ^ b))) + Vector256.Create(0x02441453u) + w[10]; d = a + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = t + (q ^ (r & (p ^ q))) + Vector256.Create(0x02441453u) + x[10]; t = p + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = c + (a ^ (b & (d ^ a))) + Vector256.Create(0xd8a1e681u) + w[15]; c = d + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = r + (p ^ (q & (t ^ p))) + Vector256.Create(0xd8a1e681u) + x[15]; r = t + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = b + (d ^ (a & (c ^ d))) + Vector256.Create(0xe7d3fbc8u) + w[4]; b = c + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = q + (t ^ (p & (r ^ t))) + Vector256.Create(0xe7d3fbc8u) + x[4]; q = r + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = a + (c ^ (d & (b ^ c))) + Vector256.Create(0x21e1cde6u) + w[9]; a = b + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = p + (r ^ (t & (q ^ r))) + Vector256.Create(0x21e1cde6u) + x[9]; p = q + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = d + (b ^ (c & (a ^ b))) + Vector256.Create(0xc33707d6u) + w[14]; d = a + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = t + (q ^ (r & (p ^ q))) + Vector256.Create(0xc33707d6u) + x[14]; t = p + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = c + (a ^ (b & (d ^ a))) + Vector256.Create(0xf4d50d87u) + w[3]; c = d + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = r + (p ^ (q & (t ^ p))) + Vector256.Create(0xf4d50d87u) + x[3]; r = t + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = b + (d ^ (a & (c ^ d))) + Vector256.Create(0x455a14edu) + w[8]; b = c + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = q + (t ^ (p & (r ^ t))) + Vector256.Create(0x455a14edu) + x[8]; q = r + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = a + (c ^ (d & (b ^ c))) + Vector256.Create(0xa9e3e905u) + w[13]; a = b + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = p + (r ^ (t & (q ^ r))) + Vector256.Create(0xa9e3e905u) + x[13]; p = q + (Vector256.ShiftLeft(rt, 5) | Vector256.ShiftRightLogical(rt, 27)); }
        { var rt = d + (b ^ (c & (a ^ b))) + Vector256.Create(0xfcefa3f8u) + w[2]; d = a + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = t + (q ^ (r & (p ^ q))) + Vector256.Create(0xfcefa3f8u) + x[2]; t = p + (Vector256.ShiftLeft(rt, 9) | Vector256.ShiftRightLogical(rt, 23)); }
        { var rt = c + (a ^ (b & (d ^ a))) + Vector256.Create(0x676f02d9u) + w[7]; c = d + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = r + (p ^ (q & (t ^ p))) + Vector256.Create(0x676f02d9u) + x[7]; r = t + (Vector256.ShiftLeft(rt, 14) | Vector256.ShiftRightLogical(rt, 18)); }
        { var rt = b + (d ^ (a & (c ^ d))) + Vector256.Create(0x8d2a4c8au) + w[12]; b = c + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = q + (t ^ (p & (r ^ t))) + Vector256.Create(0x8d2a4c8au) + x[12]; q = r + (Vector256.ShiftLeft(rt, 20) | Vector256.ShiftRightLogical(rt, 12)); }
        { var rt = a + (b ^ c ^ d) + Vector256.Create(0xfffa3942u) + w[5]; a = b + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = p + (q ^ r ^ t) + Vector256.Create(0xfffa3942u) + x[5]; p = q + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = d + (a ^ b ^ c) + Vector256.Create(0x8771f681u) + w[8]; d = a + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = t + (p ^ q ^ r) + Vector256.Create(0x8771f681u) + x[8]; t = p + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = c + (d ^ a ^ b) + Vector256.Create(0x6d9d6122u) + w[11]; c = d + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = r + (t ^ p ^ q) + Vector256.Create(0x6d9d6122u) + x[11]; r = t + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = b + (c ^ d ^ a) + Vector256.Create(0xfde5380cu) + w[14]; b = c + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = q + (r ^ t ^ p) + Vector256.Create(0xfde5380cu) + x[14]; q = r + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = a + (b ^ c ^ d) + Vector256.Create(0xa4beea44u) + w[1]; a = b + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = p + (q ^ r ^ t) + Vector256.Create(0xa4beea44u) + x[1]; p = q + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = d + (a ^ b ^ c) + Vector256.Create(0x4bdecfa9u) + w[4]; d = a + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = t + (p ^ q ^ r) + Vector256.Create(0x4bdecfa9u) + x[4]; t = p + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = c + (d ^ a ^ b) + Vector256.Create(0xf6bb4b60u) + w[7]; c = d + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = r + (t ^ p ^ q) + Vector256.Create(0xf6bb4b60u) + x[7]; r = t + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = b + (c ^ d ^ a) + Vector256.Create(0xbebfbc70u) + w[10]; b = c + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = q + (r ^ t ^ p) + Vector256.Create(0xbebfbc70u) + x[10]; q = r + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = a + (b ^ c ^ d) + Vector256.Create(0x289b7ec6u) + w[13]; a = b + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = p + (q ^ r ^ t) + Vector256.Create(0x289b7ec6u) + x[13]; p = q + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = d + (a ^ b ^ c) + Vector256.Create(0xeaa127fau) + w[0]; d = a + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = t + (p ^ q ^ r) + Vector256.Create(0xeaa127fau) + x[0]; t = p + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = c + (d ^ a ^ b) + Vector256.Create(0xd4ef3085u) + w[3]; c = d + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = r + (t ^ p ^ q) + Vector256.Create(0xd4ef3085u) + x[3]; r = t + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = b + (c ^ d ^ a) + Vector256.Create(0x04881d05u) + w[6]; b = c + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = q + (r ^ t ^ p) + Vector256.Create(0x04881d05u) + x[6]; q = r + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = a + (b ^ c ^ d) + Vector256.Create(0xd9d4d039u) + w[9]; a = b + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = p + (q ^ r ^ t) + Vector256.Create(0xd9d4d039u) + x[9]; p = q + (Vector256.ShiftLeft(rt, 4) | Vector256.ShiftRightLogical(rt, 28)); }
        { var rt = d + (a ^ b ^ c) + Vector256.Create(0xe6db99e5u) + w[12]; d = a + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = t + (p ^ q ^ r) + Vector256.Create(0xe6db99e5u) + x[12]; t = p + (Vector256.ShiftLeft(rt, 11) | Vector256.ShiftRightLogical(rt, 21)); }
        { var rt = c + (d ^ a ^ b) + Vector256.Create(0x1fa27cf8u) + w[15]; c = d + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = r + (t ^ p ^ q) + Vector256.Create(0x1fa27cf8u) + x[15]; r = t + (Vector256.ShiftLeft(rt, 16) | Vector256.ShiftRightLogical(rt, 16)); }
        { var rt = b + (c ^ d ^ a) + Vector256.Create(0xc4ac5665u) + w[2]; b = c + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = q + (r ^ t ^ p) + Vector256.Create(0xc4ac5665u) + x[2]; q = r + (Vector256.ShiftLeft(rt, 23) | Vector256.ShiftRightLogical(rt, 9)); }
        { var rt = a + (c ^ (b | ~d)) + Vector256.Create(0xf4292244u) + w[0]; a = b + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = p + (r ^ (q | ~t)) + Vector256.Create(0xf4292244u) + x[0]; p = q + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = d + (b ^ (a | ~c)) + Vector256.Create(0x432aff97u) + w[7]; d = a + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = t + (q ^ (p | ~r)) + Vector256.Create(0x432aff97u) + x[7]; t = p + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = c + (a ^ (d | ~b)) + Vector256.Create(0xab9423a7u) + w[14]; c = d + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = r + (p ^ (t | ~q)) + Vector256.Create(0xab9423a7u) + x[14]; r = t + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = b + (d ^ (c | ~a)) + Vector256.Create(0xfc93a039u) + w[5]; b = c + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = q + (t ^ (r | ~p)) + Vector256.Create(0xfc93a039u) + x[5]; q = r + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = a + (c ^ (b | ~d)) + Vector256.Create(0x655b59c3u) + w[12]; a = b + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = p + (r ^ (q | ~t)) + Vector256.Create(0x655b59c3u) + x[12]; p = q + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = d + (b ^ (a | ~c)) + Vector256.Create(0x8f0ccc92u) + w[3]; d = a + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = t + (q ^ (p | ~r)) + Vector256.Create(0x8f0ccc92u) + x[3]; t = p + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = c + (a ^ (d | ~b)) + Vector256.Create(0xffeff47du) + w[10]; c = d + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = r + (p ^ (t | ~q)) + Vector256.Create(0xffeff47du) + x[10]; r = t + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = b + (d ^ (c | ~a)) + Vector256.Create(0x85845dd1u) + w[1]; b = c + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = q + (t ^ (r | ~p)) + Vector256.Create(0x85845dd1u) + x[1]; q = r + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = a + (c ^ (b | ~d)) + Vector256.Create(0x6fa87e4fu) + w[8]; a = b + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = p + (r ^ (q | ~t)) + Vector256.Create(0x6fa87e4fu) + x[8]; p = q + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = d + (b ^ (a | ~c)) + Vector256.Create(0xfe2ce6e0u) + w[15]; d = a + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = t + (q ^ (p | ~r)) + Vector256.Create(0xfe2ce6e0u) + x[15]; t = p + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = c + (a ^ (d | ~b)) + Vector256.Create(0xa3014314u) + w[6]; c = d + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = r + (p ^ (t | ~q)) + Vector256.Create(0xa3014314u) + x[6]; r = t + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = b + (d ^ (c | ~a)) + Vector256.Create(0x4e0811a1u) + w[13]; b = c + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = q + (t ^ (r | ~p)) + Vector256.Create(0x4e0811a1u) + x[13]; q = r + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = a + (c ^ (b | ~d)) + Vector256.Create(0xf7537e82u) + w[4]; a = b + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = p + (r ^ (q | ~t)) + Vector256.Create(0xf7537e82u) + x[4]; p = q + (Vector256.ShiftLeft(rt, 6) | Vector256.ShiftRightLogical(rt, 26)); }
        { var rt = d + (b ^ (a | ~c)) + Vector256.Create(0xbd3af235u) + w[11]; d = a + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = t + (q ^ (p | ~r)) + Vector256.Create(0xbd3af235u) + x[11]; t = p + (Vector256.ShiftLeft(rt, 10) | Vector256.ShiftRightLogical(rt, 22)); }
        { var rt = c + (a ^ (d | ~b)) + Vector256.Create(0x2ad7d2bbu) + w[2]; c = d + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = r + (p ^ (t | ~q)) + Vector256.Create(0x2ad7d2bbu) + x[2]; r = t + (Vector256.ShiftLeft(rt, 15) | Vector256.ShiftRightLogical(rt, 17)); }
        { var rt = b + (d ^ (c | ~a)) + Vector256.Create(0xeb86d391u) + w[9]; b = c + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        { var rt = q + (t ^ (r | ~p)) + Vector256.Create(0xeb86d391u) + x[9]; q = r + (Vector256.ShiftLeft(rt, 21) | Vector256.ShiftRightLogical(rt, 11)); }
        s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += p; s[5] += q; s[6] += r; s[7] += t;
    }
}
