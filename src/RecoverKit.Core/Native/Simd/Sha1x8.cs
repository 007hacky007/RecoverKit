using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;

namespace RecoverKit.Core.Native.Simd;

/// <summary>
/// SHA-1 compression of 8 independent blocks at once (one per Vector256 lane), fully unrolled with a
/// rolling 16-word message schedule. Words are big-endian values, given word-major. Generated code.
/// </summary>
internal static class Sha1x8
{
    public static readonly Vector256<uint> IvA = Vector256.Create(0x67452301u), IvB = Vector256.Create(0xEFCDAB89u),
        IvC = Vector256.Create(0x98BADCFEu), IvD = Vector256.Create(0x10325476u), IvE = Vector256.Create(0xC3D2E1F0u);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<uint> Rotl(Vector256<uint> x, [ConstantExpected] int n) =>
        Vector256.ShiftLeft(x, n) | Vector256.ShiftRightLogical(x, 32 - n);

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static void Compress(ref Vector256<uint> sa, ref Vector256<uint> sb, ref Vector256<uint> sc, ref Vector256<uint> sd, ref Vector256<uint> se, ReadOnlySpan<Vector256<uint>> w)
    {
        Vector256<uint> a = sa, b = sb, c = sc, d = sd, e = se;
        Vector256<uint> w0 = w[0], w1 = w[1], w2 = w[2], w3 = w[3], w4 = w[4], w5 = w[5], w6 = w[6], w7 = w[7],
            w8 = w[8], w9 = w[9], w10 = w[10], w11 = w[11], w12 = w[12], w13 = w[13], w14 = w[14], w15 = w[15];
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (d ^ (b & (c ^ d))) + e + Vector256.Create(0x5A827999u) + w0; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (c ^ (a & (b ^ c))) + d + Vector256.Create(0x5A827999u) + w1; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (b ^ (e & (a ^ b))) + c + Vector256.Create(0x5A827999u) + w2; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (a ^ (d & (e ^ a))) + b + Vector256.Create(0x5A827999u) + w3; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (e ^ (c & (d ^ e))) + a + Vector256.Create(0x5A827999u) + w4; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (d ^ (b & (c ^ d))) + e + Vector256.Create(0x5A827999u) + w5; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (c ^ (a & (b ^ c))) + d + Vector256.Create(0x5A827999u) + w6; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (b ^ (e & (a ^ b))) + c + Vector256.Create(0x5A827999u) + w7; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (a ^ (d & (e ^ a))) + b + Vector256.Create(0x5A827999u) + w8; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (e ^ (c & (d ^ e))) + a + Vector256.Create(0x5A827999u) + w9; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (d ^ (b & (c ^ d))) + e + Vector256.Create(0x5A827999u) + w10; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (c ^ (a & (b ^ c))) + d + Vector256.Create(0x5A827999u) + w11; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (b ^ (e & (a ^ b))) + c + Vector256.Create(0x5A827999u) + w12; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (a ^ (d & (e ^ a))) + b + Vector256.Create(0x5A827999u) + w13; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (e ^ (c & (d ^ e))) + a + Vector256.Create(0x5A827999u) + w14; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (d ^ (b & (c ^ d))) + e + Vector256.Create(0x5A827999u) + w15; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w13 ^ w8 ^ w2 ^ w0; w0 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (c ^ (a & (b ^ c))) + d + Vector256.Create(0x5A827999u) + w0; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w14 ^ w9 ^ w3 ^ w1; w1 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (b ^ (e & (a ^ b))) + c + Vector256.Create(0x5A827999u) + w1; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w15 ^ w10 ^ w4 ^ w2; w2 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (a ^ (d & (e ^ a))) + b + Vector256.Create(0x5A827999u) + w2; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w0 ^ w11 ^ w5 ^ w3; w3 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (e ^ (c & (d ^ e))) + a + Vector256.Create(0x5A827999u) + w3; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w1 ^ w12 ^ w6 ^ w4; w4 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0x6ED9EBA1u) + w4; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w2 ^ w13 ^ w7 ^ w5; w5 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0x6ED9EBA1u) + w5; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w3 ^ w14 ^ w8 ^ w6; w6 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0x6ED9EBA1u) + w6; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w4 ^ w15 ^ w9 ^ w7; w7 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0x6ED9EBA1u) + w7; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w5 ^ w0 ^ w10 ^ w8; w8 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0x6ED9EBA1u) + w8; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w6 ^ w1 ^ w11 ^ w9; w9 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0x6ED9EBA1u) + w9; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w7 ^ w2 ^ w12 ^ w10; w10 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0x6ED9EBA1u) + w10; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w8 ^ w3 ^ w13 ^ w11; w11 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0x6ED9EBA1u) + w11; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w9 ^ w4 ^ w14 ^ w12; w12 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0x6ED9EBA1u) + w12; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w10 ^ w5 ^ w15 ^ w13; w13 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0x6ED9EBA1u) + w13; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w11 ^ w6 ^ w0 ^ w14; w14 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0x6ED9EBA1u) + w14; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w12 ^ w7 ^ w1 ^ w15; w15 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0x6ED9EBA1u) + w15; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w13 ^ w8 ^ w2 ^ w0; w0 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0x6ED9EBA1u) + w0; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w14 ^ w9 ^ w3 ^ w1; w1 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0x6ED9EBA1u) + w1; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w15 ^ w10 ^ w4 ^ w2; w2 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0x6ED9EBA1u) + w2; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w0 ^ w11 ^ w5 ^ w3; w3 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0x6ED9EBA1u) + w3; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w1 ^ w12 ^ w6 ^ w4; w4 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0x6ED9EBA1u) + w4; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w2 ^ w13 ^ w7 ^ w5; w5 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0x6ED9EBA1u) + w5; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w3 ^ w14 ^ w8 ^ w6; w6 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0x6ED9EBA1u) + w6; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w4 ^ w15 ^ w9 ^ w7; w7 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0x6ED9EBA1u) + w7; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w5 ^ w0 ^ w10 ^ w8; w8 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + ((b & c) | (d & (b | c))) + e + Vector256.Create(0x8F1BBCDCu) + w8; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w6 ^ w1 ^ w11 ^ w9; w9 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + ((a & b) | (c & (a | b))) + d + Vector256.Create(0x8F1BBCDCu) + w9; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w7 ^ w2 ^ w12 ^ w10; w10 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + ((e & a) | (b & (e | a))) + c + Vector256.Create(0x8F1BBCDCu) + w10; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w8 ^ w3 ^ w13 ^ w11; w11 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + ((d & e) | (a & (d | e))) + b + Vector256.Create(0x8F1BBCDCu) + w11; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w9 ^ w4 ^ w14 ^ w12; w12 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + ((c & d) | (e & (c | d))) + a + Vector256.Create(0x8F1BBCDCu) + w12; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w10 ^ w5 ^ w15 ^ w13; w13 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + ((b & c) | (d & (b | c))) + e + Vector256.Create(0x8F1BBCDCu) + w13; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w11 ^ w6 ^ w0 ^ w14; w14 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + ((a & b) | (c & (a | b))) + d + Vector256.Create(0x8F1BBCDCu) + w14; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w12 ^ w7 ^ w1 ^ w15; w15 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + ((e & a) | (b & (e | a))) + c + Vector256.Create(0x8F1BBCDCu) + w15; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w13 ^ w8 ^ w2 ^ w0; w0 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + ((d & e) | (a & (d | e))) + b + Vector256.Create(0x8F1BBCDCu) + w0; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w14 ^ w9 ^ w3 ^ w1; w1 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + ((c & d) | (e & (c | d))) + a + Vector256.Create(0x8F1BBCDCu) + w1; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w15 ^ w10 ^ w4 ^ w2; w2 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + ((b & c) | (d & (b | c))) + e + Vector256.Create(0x8F1BBCDCu) + w2; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w0 ^ w11 ^ w5 ^ w3; w3 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + ((a & b) | (c & (a | b))) + d + Vector256.Create(0x8F1BBCDCu) + w3; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w1 ^ w12 ^ w6 ^ w4; w4 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + ((e & a) | (b & (e | a))) + c + Vector256.Create(0x8F1BBCDCu) + w4; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w2 ^ w13 ^ w7 ^ w5; w5 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + ((d & e) | (a & (d | e))) + b + Vector256.Create(0x8F1BBCDCu) + w5; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w3 ^ w14 ^ w8 ^ w6; w6 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + ((c & d) | (e & (c | d))) + a + Vector256.Create(0x8F1BBCDCu) + w6; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w4 ^ w15 ^ w9 ^ w7; w7 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + ((b & c) | (d & (b | c))) + e + Vector256.Create(0x8F1BBCDCu) + w7; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w5 ^ w0 ^ w10 ^ w8; w8 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + ((a & b) | (c & (a | b))) + d + Vector256.Create(0x8F1BBCDCu) + w8; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w6 ^ w1 ^ w11 ^ w9; w9 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + ((e & a) | (b & (e | a))) + c + Vector256.Create(0x8F1BBCDCu) + w9; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w7 ^ w2 ^ w12 ^ w10; w10 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + ((d & e) | (a & (d | e))) + b + Vector256.Create(0x8F1BBCDCu) + w10; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w8 ^ w3 ^ w13 ^ w11; w11 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + ((c & d) | (e & (c | d))) + a + Vector256.Create(0x8F1BBCDCu) + w11; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w9 ^ w4 ^ w14 ^ w12; w12 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0xCA62C1D6u) + w12; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w10 ^ w5 ^ w15 ^ w13; w13 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0xCA62C1D6u) + w13; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w11 ^ w6 ^ w0 ^ w14; w14 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0xCA62C1D6u) + w14; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w12 ^ w7 ^ w1 ^ w15; w15 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0xCA62C1D6u) + w15; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w13 ^ w8 ^ w2 ^ w0; w0 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0xCA62C1D6u) + w0; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w14 ^ w9 ^ w3 ^ w1; w1 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0xCA62C1D6u) + w1; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w15 ^ w10 ^ w4 ^ w2; w2 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0xCA62C1D6u) + w2; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w0 ^ w11 ^ w5 ^ w3; w3 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0xCA62C1D6u) + w3; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w1 ^ w12 ^ w6 ^ w4; w4 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0xCA62C1D6u) + w4; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w2 ^ w13 ^ w7 ^ w5; w5 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0xCA62C1D6u) + w5; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w3 ^ w14 ^ w8 ^ w6; w6 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0xCA62C1D6u) + w6; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w4 ^ w15 ^ w9 ^ w7; w7 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0xCA62C1D6u) + w7; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w5 ^ w0 ^ w10 ^ w8; w8 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0xCA62C1D6u) + w8; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w6 ^ w1 ^ w11 ^ w9; w9 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0xCA62C1D6u) + w9; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w7 ^ w2 ^ w12 ^ w10; w10 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0xCA62C1D6u) + w10; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w8 ^ w3 ^ w13 ^ w11; w11 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0xCA62C1D6u) + w11; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w9 ^ w4 ^ w14 ^ w12; w12 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0xCA62C1D6u) + w12; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w10 ^ w5 ^ w15 ^ w13; w13 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0xCA62C1D6u) + w13; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w11 ^ w6 ^ w0 ^ w14; w14 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0xCA62C1D6u) + w14; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w12 ^ w7 ^ w1 ^ w15; w15 = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0xCA62C1D6u) + w15; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        sa += a; sb += b; sc += c; sd += d; se += e;
    }

    /// <summary>Same as <see cref="Compress"/> but keeps the message schedule in memory (fewer registers, no spills). Overwrites w.</summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static unsafe void CompressMem(ref Vector256<uint> sa, ref Vector256<uint> sb, ref Vector256<uint> sc, ref Vector256<uint> sd, ref Vector256<uint> se, Vector256<uint>* w)
    {
        Vector256<uint> a = sa, b = sb, c = sc, d = sd, e = se;
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (d ^ (b & (c ^ d))) + e + Vector256.Create(0x5A827999u) + w[0]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (c ^ (a & (b ^ c))) + d + Vector256.Create(0x5A827999u) + w[1]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (b ^ (e & (a ^ b))) + c + Vector256.Create(0x5A827999u) + w[2]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (a ^ (d & (e ^ a))) + b + Vector256.Create(0x5A827999u) + w[3]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (e ^ (c & (d ^ e))) + a + Vector256.Create(0x5A827999u) + w[4]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (d ^ (b & (c ^ d))) + e + Vector256.Create(0x5A827999u) + w[5]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (c ^ (a & (b ^ c))) + d + Vector256.Create(0x5A827999u) + w[6]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (b ^ (e & (a ^ b))) + c + Vector256.Create(0x5A827999u) + w[7]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (a ^ (d & (e ^ a))) + b + Vector256.Create(0x5A827999u) + w[8]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (e ^ (c & (d ^ e))) + a + Vector256.Create(0x5A827999u) + w[9]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (d ^ (b & (c ^ d))) + e + Vector256.Create(0x5A827999u) + w[10]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (c ^ (a & (b ^ c))) + d + Vector256.Create(0x5A827999u) + w[11]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (b ^ (e & (a ^ b))) + c + Vector256.Create(0x5A827999u) + w[12]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (a ^ (d & (e ^ a))) + b + Vector256.Create(0x5A827999u) + w[13]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (e ^ (c & (d ^ e))) + a + Vector256.Create(0x5A827999u) + w[14]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (d ^ (b & (c ^ d))) + e + Vector256.Create(0x5A827999u) + w[15]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[13] ^ w[8] ^ w[2] ^ w[0]; w[0] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (c ^ (a & (b ^ c))) + d + Vector256.Create(0x5A827999u) + w[0]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[14] ^ w[9] ^ w[3] ^ w[1]; w[1] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (b ^ (e & (a ^ b))) + c + Vector256.Create(0x5A827999u) + w[1]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[15] ^ w[10] ^ w[4] ^ w[2]; w[2] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (a ^ (d & (e ^ a))) + b + Vector256.Create(0x5A827999u) + w[2]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[0] ^ w[11] ^ w[5] ^ w[3]; w[3] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (e ^ (c & (d ^ e))) + a + Vector256.Create(0x5A827999u) + w[3]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w[1] ^ w[12] ^ w[6] ^ w[4]; w[4] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0x6ED9EBA1u) + w[4]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[2] ^ w[13] ^ w[7] ^ w[5]; w[5] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0x6ED9EBA1u) + w[5]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[3] ^ w[14] ^ w[8] ^ w[6]; w[6] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0x6ED9EBA1u) + w[6]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[4] ^ w[15] ^ w[9] ^ w[7]; w[7] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0x6ED9EBA1u) + w[7]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[5] ^ w[0] ^ w[10] ^ w[8]; w[8] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0x6ED9EBA1u) + w[8]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w[6] ^ w[1] ^ w[11] ^ w[9]; w[9] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0x6ED9EBA1u) + w[9]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[7] ^ w[2] ^ w[12] ^ w[10]; w[10] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0x6ED9EBA1u) + w[10]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[8] ^ w[3] ^ w[13] ^ w[11]; w[11] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0x6ED9EBA1u) + w[11]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[9] ^ w[4] ^ w[14] ^ w[12]; w[12] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0x6ED9EBA1u) + w[12]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[10] ^ w[5] ^ w[15] ^ w[13]; w[13] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0x6ED9EBA1u) + w[13]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w[11] ^ w[6] ^ w[0] ^ w[14]; w[14] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0x6ED9EBA1u) + w[14]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[12] ^ w[7] ^ w[1] ^ w[15]; w[15] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0x6ED9EBA1u) + w[15]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[13] ^ w[8] ^ w[2] ^ w[0]; w[0] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0x6ED9EBA1u) + w[0]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[14] ^ w[9] ^ w[3] ^ w[1]; w[1] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0x6ED9EBA1u) + w[1]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[15] ^ w[10] ^ w[4] ^ w[2]; w[2] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0x6ED9EBA1u) + w[2]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w[0] ^ w[11] ^ w[5] ^ w[3]; w[3] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0x6ED9EBA1u) + w[3]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[1] ^ w[12] ^ w[6] ^ w[4]; w[4] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0x6ED9EBA1u) + w[4]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[2] ^ w[13] ^ w[7] ^ w[5]; w[5] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0x6ED9EBA1u) + w[5]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[3] ^ w[14] ^ w[8] ^ w[6]; w[6] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0x6ED9EBA1u) + w[6]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[4] ^ w[15] ^ w[9] ^ w[7]; w[7] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0x6ED9EBA1u) + w[7]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w[5] ^ w[0] ^ w[10] ^ w[8]; w[8] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + ((b & c) | (d & (b | c))) + e + Vector256.Create(0x8F1BBCDCu) + w[8]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[6] ^ w[1] ^ w[11] ^ w[9]; w[9] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + ((a & b) | (c & (a | b))) + d + Vector256.Create(0x8F1BBCDCu) + w[9]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[7] ^ w[2] ^ w[12] ^ w[10]; w[10] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + ((e & a) | (b & (e | a))) + c + Vector256.Create(0x8F1BBCDCu) + w[10]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[8] ^ w[3] ^ w[13] ^ w[11]; w[11] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + ((d & e) | (a & (d | e))) + b + Vector256.Create(0x8F1BBCDCu) + w[11]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[9] ^ w[4] ^ w[14] ^ w[12]; w[12] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + ((c & d) | (e & (c | d))) + a + Vector256.Create(0x8F1BBCDCu) + w[12]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w[10] ^ w[5] ^ w[15] ^ w[13]; w[13] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + ((b & c) | (d & (b | c))) + e + Vector256.Create(0x8F1BBCDCu) + w[13]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[11] ^ w[6] ^ w[0] ^ w[14]; w[14] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + ((a & b) | (c & (a | b))) + d + Vector256.Create(0x8F1BBCDCu) + w[14]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[12] ^ w[7] ^ w[1] ^ w[15]; w[15] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + ((e & a) | (b & (e | a))) + c + Vector256.Create(0x8F1BBCDCu) + w[15]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[13] ^ w[8] ^ w[2] ^ w[0]; w[0] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + ((d & e) | (a & (d | e))) + b + Vector256.Create(0x8F1BBCDCu) + w[0]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[14] ^ w[9] ^ w[3] ^ w[1]; w[1] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + ((c & d) | (e & (c | d))) + a + Vector256.Create(0x8F1BBCDCu) + w[1]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w[15] ^ w[10] ^ w[4] ^ w[2]; w[2] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + ((b & c) | (d & (b | c))) + e + Vector256.Create(0x8F1BBCDCu) + w[2]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[0] ^ w[11] ^ w[5] ^ w[3]; w[3] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + ((a & b) | (c & (a | b))) + d + Vector256.Create(0x8F1BBCDCu) + w[3]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[1] ^ w[12] ^ w[6] ^ w[4]; w[4] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + ((e & a) | (b & (e | a))) + c + Vector256.Create(0x8F1BBCDCu) + w[4]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[2] ^ w[13] ^ w[7] ^ w[5]; w[5] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + ((d & e) | (a & (d | e))) + b + Vector256.Create(0x8F1BBCDCu) + w[5]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[3] ^ w[14] ^ w[8] ^ w[6]; w[6] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + ((c & d) | (e & (c | d))) + a + Vector256.Create(0x8F1BBCDCu) + w[6]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w[4] ^ w[15] ^ w[9] ^ w[7]; w[7] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + ((b & c) | (d & (b | c))) + e + Vector256.Create(0x8F1BBCDCu) + w[7]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[5] ^ w[0] ^ w[10] ^ w[8]; w[8] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + ((a & b) | (c & (a | b))) + d + Vector256.Create(0x8F1BBCDCu) + w[8]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[6] ^ w[1] ^ w[11] ^ w[9]; w[9] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + ((e & a) | (b & (e | a))) + c + Vector256.Create(0x8F1BBCDCu) + w[9]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[7] ^ w[2] ^ w[12] ^ w[10]; w[10] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + ((d & e) | (a & (d | e))) + b + Vector256.Create(0x8F1BBCDCu) + w[10]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[8] ^ w[3] ^ w[13] ^ w[11]; w[11] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + ((c & d) | (e & (c | d))) + a + Vector256.Create(0x8F1BBCDCu) + w[11]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w[9] ^ w[4] ^ w[14] ^ w[12]; w[12] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0xCA62C1D6u) + w[12]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[10] ^ w[5] ^ w[15] ^ w[13]; w[13] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0xCA62C1D6u) + w[13]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[11] ^ w[6] ^ w[0] ^ w[14]; w[14] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0xCA62C1D6u) + w[14]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[12] ^ w[7] ^ w[1] ^ w[15]; w[15] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0xCA62C1D6u) + w[15]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[13] ^ w[8] ^ w[2] ^ w[0]; w[0] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0xCA62C1D6u) + w[0]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w[14] ^ w[9] ^ w[3] ^ w[1]; w[1] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0xCA62C1D6u) + w[1]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[15] ^ w[10] ^ w[4] ^ w[2]; w[2] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0xCA62C1D6u) + w[2]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[0] ^ w[11] ^ w[5] ^ w[3]; w[3] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0xCA62C1D6u) + w[3]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[1] ^ w[12] ^ w[6] ^ w[4]; w[4] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0xCA62C1D6u) + w[4]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[2] ^ w[13] ^ w[7] ^ w[5]; w[5] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0xCA62C1D6u) + w[5]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w[3] ^ w[14] ^ w[8] ^ w[6]; w[6] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0xCA62C1D6u) + w[6]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[4] ^ w[15] ^ w[9] ^ w[7]; w[7] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0xCA62C1D6u) + w[7]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[5] ^ w[0] ^ w[10] ^ w[8]; w[8] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0xCA62C1D6u) + w[8]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[6] ^ w[1] ^ w[11] ^ w[9]; w[9] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0xCA62C1D6u) + w[9]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[7] ^ w[2] ^ w[12] ^ w[10]; w[10] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0xCA62C1D6u) + w[10]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        { var rt = w[8] ^ w[3] ^ w[13] ^ w[11]; w[11] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0xCA62C1D6u) + w[11]; b = (Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2)); }
        { var rt = w[9] ^ w[4] ^ w[14] ^ w[12]; w[12] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0xCA62C1D6u) + w[12]; a = (Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2)); }
        { var rt = w[10] ^ w[5] ^ w[15] ^ w[13]; w[13] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0xCA62C1D6u) + w[13]; e = (Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2)); }
        { var rt = w[11] ^ w[6] ^ w[0] ^ w[14]; w[14] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0xCA62C1D6u) + w[14]; d = (Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2)); }
        { var rt = w[12] ^ w[7] ^ w[1] ^ w[15]; w[15] = (Vector256.ShiftLeft(rt, 1) | Vector256.ShiftRightLogical(rt, 31)); }
        { a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0xCA62C1D6u) + w[15]; c = (Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2)); }
        sa += a; sb += b; sc += c; sd += d; se += e;
    }

    /// <summary>
    /// Two independent 8-lane SHA-1 compressions interleaved round by round (16 candidates); schedules
    /// stay in memory and are overwritten. Split into four 20-round stages: one 160-round method has
    /// more temporaries than the JIT tracks in registers.
    /// </summary>
    public static unsafe void Compress2(Vector256<uint>* s, Vector256<uint>* w, Vector256<uint>* x)
    {
        var init = stackalloc Vector256<uint>[10];
        for (int i = 0; i < 10; i++) init[i] = s[i];
        Stage0(s, w, x); Stage1(s, w, x); Stage2(s, w, x); Stage3(s, w, x);
        for (int i = 0; i < 10; i++) s[i] += init[i];
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.NoInlining)]
    private static unsafe void Stage0(Vector256<uint>* s, Vector256<uint>* w, Vector256<uint>* x)
    {
        Vector256<uint> a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], p = s[5], q = s[6], r = s[7], u = s[8], v = s[9];
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (d ^ (b & (c ^ d))) + e + Vector256.Create(0x5A827999u) + w[0]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + (u ^ (q & (r ^ u))) + v + Vector256.Create(0x5A827999u) + x[0]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (c ^ (a & (b ^ c))) + d + Vector256.Create(0x5A827999u) + w[1]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + (r ^ (p & (q ^ r))) + u + Vector256.Create(0x5A827999u) + x[1]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (b ^ (e & (a ^ b))) + c + Vector256.Create(0x5A827999u) + w[2]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + (q ^ (v & (p ^ q))) + r + Vector256.Create(0x5A827999u) + x[2]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (a ^ (d & (e ^ a))) + b + Vector256.Create(0x5A827999u) + w[3]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + (p ^ (u & (v ^ p))) + q + Vector256.Create(0x5A827999u) + x[3]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (e ^ (c & (d ^ e))) + a + Vector256.Create(0x5A827999u) + w[4]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + (v ^ (r & (u ^ v))) + p + Vector256.Create(0x5A827999u) + x[4]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (d ^ (b & (c ^ d))) + e + Vector256.Create(0x5A827999u) + w[5]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + (u ^ (q & (r ^ u))) + v + Vector256.Create(0x5A827999u) + x[5]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (c ^ (a & (b ^ c))) + d + Vector256.Create(0x5A827999u) + w[6]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + (r ^ (p & (q ^ r))) + u + Vector256.Create(0x5A827999u) + x[6]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (b ^ (e & (a ^ b))) + c + Vector256.Create(0x5A827999u) + w[7]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + (q ^ (v & (p ^ q))) + r + Vector256.Create(0x5A827999u) + x[7]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (a ^ (d & (e ^ a))) + b + Vector256.Create(0x5A827999u) + w[8]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + (p ^ (u & (v ^ p))) + q + Vector256.Create(0x5A827999u) + x[8]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (e ^ (c & (d ^ e))) + a + Vector256.Create(0x5A827999u) + w[9]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + (v ^ (r & (u ^ v))) + p + Vector256.Create(0x5A827999u) + x[9]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (d ^ (b & (c ^ d))) + e + Vector256.Create(0x5A827999u) + w[10]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + (u ^ (q & (r ^ u))) + v + Vector256.Create(0x5A827999u) + x[10]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (c ^ (a & (b ^ c))) + d + Vector256.Create(0x5A827999u) + w[11]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + (r ^ (p & (q ^ r))) + u + Vector256.Create(0x5A827999u) + x[11]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (b ^ (e & (a ^ b))) + c + Vector256.Create(0x5A827999u) + w[12]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + (q ^ (v & (p ^ q))) + r + Vector256.Create(0x5A827999u) + x[12]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (a ^ (d & (e ^ a))) + b + Vector256.Create(0x5A827999u) + w[13]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + (p ^ (u & (v ^ p))) + q + Vector256.Create(0x5A827999u) + x[13]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (e ^ (c & (d ^ e))) + a + Vector256.Create(0x5A827999u) + w[14]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + (v ^ (r & (u ^ v))) + p + Vector256.Create(0x5A827999u) + x[14]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (d ^ (b & (c ^ d))) + e + Vector256.Create(0x5A827999u) + w[15]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + (u ^ (q & (r ^ u))) + v + Vector256.Create(0x5A827999u) + x[15]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[13] ^ w[8] ^ w[2] ^ w[0]; w[0] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (c ^ (a & (b ^ c))) + d + Vector256.Create(0x5A827999u) + w[0]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[13] ^ x[8] ^ x[2] ^ x[0]; x[0] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + (r ^ (p & (q ^ r))) + u + Vector256.Create(0x5A827999u) + x[0]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[14] ^ w[9] ^ w[3] ^ w[1]; w[1] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (b ^ (e & (a ^ b))) + c + Vector256.Create(0x5A827999u) + w[1]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[14] ^ x[9] ^ x[3] ^ x[1]; x[1] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + (q ^ (v & (p ^ q))) + r + Vector256.Create(0x5A827999u) + x[1]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[15] ^ w[10] ^ w[4] ^ w[2]; w[2] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (a ^ (d & (e ^ a))) + b + Vector256.Create(0x5A827999u) + w[2]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[15] ^ x[10] ^ x[4] ^ x[2]; x[2] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + (p ^ (u & (v ^ p))) + q + Vector256.Create(0x5A827999u) + x[2]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[0] ^ w[11] ^ w[5] ^ w[3]; w[3] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (e ^ (c & (d ^ e))) + a + Vector256.Create(0x5A827999u) + w[3]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[0] ^ x[11] ^ x[5] ^ x[3]; x[3] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + (v ^ (r & (u ^ v))) + p + Vector256.Create(0x5A827999u) + x[3]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        s[0] = a; s[1] = b; s[2] = c; s[3] = d; s[4] = e; s[5] = p; s[6] = q; s[7] = r; s[8] = u; s[9] = v;
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.NoInlining)]
    private static unsafe void Stage1(Vector256<uint>* s, Vector256<uint>* w, Vector256<uint>* x)
    {
        Vector256<uint> a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], p = s[5], q = s[6], r = s[7], u = s[8], v = s[9];
        { var m = w[1] ^ w[12] ^ w[6] ^ w[4]; w[4] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0x6ED9EBA1u) + w[4]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        { var m = x[1] ^ x[12] ^ x[6] ^ x[4]; x[4] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + (q ^ r ^ u) + v + Vector256.Create(0x6ED9EBA1u) + x[4]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[2] ^ w[13] ^ w[7] ^ w[5]; w[5] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0x6ED9EBA1u) + w[5]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[2] ^ x[13] ^ x[7] ^ x[5]; x[5] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + (p ^ q ^ r) + u + Vector256.Create(0x6ED9EBA1u) + x[5]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[3] ^ w[14] ^ w[8] ^ w[6]; w[6] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0x6ED9EBA1u) + w[6]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[3] ^ x[14] ^ x[8] ^ x[6]; x[6] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + (v ^ p ^ q) + r + Vector256.Create(0x6ED9EBA1u) + x[6]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[4] ^ w[15] ^ w[9] ^ w[7]; w[7] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0x6ED9EBA1u) + w[7]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[4] ^ x[15] ^ x[9] ^ x[7]; x[7] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + (u ^ v ^ p) + q + Vector256.Create(0x6ED9EBA1u) + x[7]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[5] ^ w[0] ^ w[10] ^ w[8]; w[8] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0x6ED9EBA1u) + w[8]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[5] ^ x[0] ^ x[10] ^ x[8]; x[8] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + (r ^ u ^ v) + p + Vector256.Create(0x6ED9EBA1u) + x[8]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        { var m = w[6] ^ w[1] ^ w[11] ^ w[9]; w[9] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0x6ED9EBA1u) + w[9]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        { var m = x[6] ^ x[1] ^ x[11] ^ x[9]; x[9] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + (q ^ r ^ u) + v + Vector256.Create(0x6ED9EBA1u) + x[9]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[7] ^ w[2] ^ w[12] ^ w[10]; w[10] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0x6ED9EBA1u) + w[10]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[7] ^ x[2] ^ x[12] ^ x[10]; x[10] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + (p ^ q ^ r) + u + Vector256.Create(0x6ED9EBA1u) + x[10]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[8] ^ w[3] ^ w[13] ^ w[11]; w[11] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0x6ED9EBA1u) + w[11]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[8] ^ x[3] ^ x[13] ^ x[11]; x[11] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + (v ^ p ^ q) + r + Vector256.Create(0x6ED9EBA1u) + x[11]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[9] ^ w[4] ^ w[14] ^ w[12]; w[12] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0x6ED9EBA1u) + w[12]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[9] ^ x[4] ^ x[14] ^ x[12]; x[12] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + (u ^ v ^ p) + q + Vector256.Create(0x6ED9EBA1u) + x[12]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[10] ^ w[5] ^ w[15] ^ w[13]; w[13] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0x6ED9EBA1u) + w[13]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[10] ^ x[5] ^ x[15] ^ x[13]; x[13] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + (r ^ u ^ v) + p + Vector256.Create(0x6ED9EBA1u) + x[13]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        { var m = w[11] ^ w[6] ^ w[0] ^ w[14]; w[14] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0x6ED9EBA1u) + w[14]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        { var m = x[11] ^ x[6] ^ x[0] ^ x[14]; x[14] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + (q ^ r ^ u) + v + Vector256.Create(0x6ED9EBA1u) + x[14]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[12] ^ w[7] ^ w[1] ^ w[15]; w[15] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0x6ED9EBA1u) + w[15]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[12] ^ x[7] ^ x[1] ^ x[15]; x[15] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + (p ^ q ^ r) + u + Vector256.Create(0x6ED9EBA1u) + x[15]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[13] ^ w[8] ^ w[2] ^ w[0]; w[0] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0x6ED9EBA1u) + w[0]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[13] ^ x[8] ^ x[2] ^ x[0]; x[0] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + (v ^ p ^ q) + r + Vector256.Create(0x6ED9EBA1u) + x[0]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[14] ^ w[9] ^ w[3] ^ w[1]; w[1] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0x6ED9EBA1u) + w[1]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[14] ^ x[9] ^ x[3] ^ x[1]; x[1] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + (u ^ v ^ p) + q + Vector256.Create(0x6ED9EBA1u) + x[1]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[15] ^ w[10] ^ w[4] ^ w[2]; w[2] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0x6ED9EBA1u) + w[2]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[15] ^ x[10] ^ x[4] ^ x[2]; x[2] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + (r ^ u ^ v) + p + Vector256.Create(0x6ED9EBA1u) + x[2]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        { var m = w[0] ^ w[11] ^ w[5] ^ w[3]; w[3] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0x6ED9EBA1u) + w[3]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        { var m = x[0] ^ x[11] ^ x[5] ^ x[3]; x[3] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + (q ^ r ^ u) + v + Vector256.Create(0x6ED9EBA1u) + x[3]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[1] ^ w[12] ^ w[6] ^ w[4]; w[4] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0x6ED9EBA1u) + w[4]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[1] ^ x[12] ^ x[6] ^ x[4]; x[4] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + (p ^ q ^ r) + u + Vector256.Create(0x6ED9EBA1u) + x[4]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[2] ^ w[13] ^ w[7] ^ w[5]; w[5] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0x6ED9EBA1u) + w[5]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[2] ^ x[13] ^ x[7] ^ x[5]; x[5] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + (v ^ p ^ q) + r + Vector256.Create(0x6ED9EBA1u) + x[5]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[3] ^ w[14] ^ w[8] ^ w[6]; w[6] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0x6ED9EBA1u) + w[6]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[3] ^ x[14] ^ x[8] ^ x[6]; x[6] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + (u ^ v ^ p) + q + Vector256.Create(0x6ED9EBA1u) + x[6]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[4] ^ w[15] ^ w[9] ^ w[7]; w[7] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0x6ED9EBA1u) + w[7]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[4] ^ x[15] ^ x[9] ^ x[7]; x[7] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + (r ^ u ^ v) + p + Vector256.Create(0x6ED9EBA1u) + x[7]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        s[0] = a; s[1] = b; s[2] = c; s[3] = d; s[4] = e; s[5] = p; s[6] = q; s[7] = r; s[8] = u; s[9] = v;
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.NoInlining)]
    private static unsafe void Stage2(Vector256<uint>* s, Vector256<uint>* w, Vector256<uint>* x)
    {
        Vector256<uint> a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], p = s[5], q = s[6], r = s[7], u = s[8], v = s[9];
        { var m = w[5] ^ w[0] ^ w[10] ^ w[8]; w[8] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + ((b & c) | (d & (b | c))) + e + Vector256.Create(0x8F1BBCDCu) + w[8]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        { var m = x[5] ^ x[0] ^ x[10] ^ x[8]; x[8] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + ((q & r) | (u & (q | r))) + v + Vector256.Create(0x8F1BBCDCu) + x[8]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[6] ^ w[1] ^ w[11] ^ w[9]; w[9] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + ((a & b) | (c & (a | b))) + d + Vector256.Create(0x8F1BBCDCu) + w[9]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[6] ^ x[1] ^ x[11] ^ x[9]; x[9] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + ((p & q) | (r & (p | q))) + u + Vector256.Create(0x8F1BBCDCu) + x[9]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[7] ^ w[2] ^ w[12] ^ w[10]; w[10] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + ((e & a) | (b & (e | a))) + c + Vector256.Create(0x8F1BBCDCu) + w[10]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[7] ^ x[2] ^ x[12] ^ x[10]; x[10] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + ((v & p) | (q & (v | p))) + r + Vector256.Create(0x8F1BBCDCu) + x[10]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[8] ^ w[3] ^ w[13] ^ w[11]; w[11] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + ((d & e) | (a & (d | e))) + b + Vector256.Create(0x8F1BBCDCu) + w[11]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[8] ^ x[3] ^ x[13] ^ x[11]; x[11] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + ((u & v) | (p & (u | v))) + q + Vector256.Create(0x8F1BBCDCu) + x[11]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[9] ^ w[4] ^ w[14] ^ w[12]; w[12] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + ((c & d) | (e & (c | d))) + a + Vector256.Create(0x8F1BBCDCu) + w[12]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[9] ^ x[4] ^ x[14] ^ x[12]; x[12] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + ((r & u) | (v & (r | u))) + p + Vector256.Create(0x8F1BBCDCu) + x[12]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        { var m = w[10] ^ w[5] ^ w[15] ^ w[13]; w[13] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + ((b & c) | (d & (b | c))) + e + Vector256.Create(0x8F1BBCDCu) + w[13]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        { var m = x[10] ^ x[5] ^ x[15] ^ x[13]; x[13] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + ((q & r) | (u & (q | r))) + v + Vector256.Create(0x8F1BBCDCu) + x[13]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[11] ^ w[6] ^ w[0] ^ w[14]; w[14] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + ((a & b) | (c & (a | b))) + d + Vector256.Create(0x8F1BBCDCu) + w[14]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[11] ^ x[6] ^ x[0] ^ x[14]; x[14] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + ((p & q) | (r & (p | q))) + u + Vector256.Create(0x8F1BBCDCu) + x[14]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[12] ^ w[7] ^ w[1] ^ w[15]; w[15] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + ((e & a) | (b & (e | a))) + c + Vector256.Create(0x8F1BBCDCu) + w[15]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[12] ^ x[7] ^ x[1] ^ x[15]; x[15] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + ((v & p) | (q & (v | p))) + r + Vector256.Create(0x8F1BBCDCu) + x[15]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[13] ^ w[8] ^ w[2] ^ w[0]; w[0] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + ((d & e) | (a & (d | e))) + b + Vector256.Create(0x8F1BBCDCu) + w[0]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[13] ^ x[8] ^ x[2] ^ x[0]; x[0] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + ((u & v) | (p & (u | v))) + q + Vector256.Create(0x8F1BBCDCu) + x[0]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[14] ^ w[9] ^ w[3] ^ w[1]; w[1] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + ((c & d) | (e & (c | d))) + a + Vector256.Create(0x8F1BBCDCu) + w[1]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[14] ^ x[9] ^ x[3] ^ x[1]; x[1] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + ((r & u) | (v & (r | u))) + p + Vector256.Create(0x8F1BBCDCu) + x[1]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        { var m = w[15] ^ w[10] ^ w[4] ^ w[2]; w[2] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + ((b & c) | (d & (b | c))) + e + Vector256.Create(0x8F1BBCDCu) + w[2]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        { var m = x[15] ^ x[10] ^ x[4] ^ x[2]; x[2] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + ((q & r) | (u & (q | r))) + v + Vector256.Create(0x8F1BBCDCu) + x[2]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[0] ^ w[11] ^ w[5] ^ w[3]; w[3] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + ((a & b) | (c & (a | b))) + d + Vector256.Create(0x8F1BBCDCu) + w[3]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[0] ^ x[11] ^ x[5] ^ x[3]; x[3] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + ((p & q) | (r & (p | q))) + u + Vector256.Create(0x8F1BBCDCu) + x[3]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[1] ^ w[12] ^ w[6] ^ w[4]; w[4] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + ((e & a) | (b & (e | a))) + c + Vector256.Create(0x8F1BBCDCu) + w[4]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[1] ^ x[12] ^ x[6] ^ x[4]; x[4] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + ((v & p) | (q & (v | p))) + r + Vector256.Create(0x8F1BBCDCu) + x[4]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[2] ^ w[13] ^ w[7] ^ w[5]; w[5] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + ((d & e) | (a & (d | e))) + b + Vector256.Create(0x8F1BBCDCu) + w[5]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[2] ^ x[13] ^ x[7] ^ x[5]; x[5] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + ((u & v) | (p & (u | v))) + q + Vector256.Create(0x8F1BBCDCu) + x[5]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[3] ^ w[14] ^ w[8] ^ w[6]; w[6] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + ((c & d) | (e & (c | d))) + a + Vector256.Create(0x8F1BBCDCu) + w[6]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[3] ^ x[14] ^ x[8] ^ x[6]; x[6] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + ((r & u) | (v & (r | u))) + p + Vector256.Create(0x8F1BBCDCu) + x[6]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        { var m = w[4] ^ w[15] ^ w[9] ^ w[7]; w[7] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + ((b & c) | (d & (b | c))) + e + Vector256.Create(0x8F1BBCDCu) + w[7]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        { var m = x[4] ^ x[15] ^ x[9] ^ x[7]; x[7] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + ((q & r) | (u & (q | r))) + v + Vector256.Create(0x8F1BBCDCu) + x[7]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[5] ^ w[0] ^ w[10] ^ w[8]; w[8] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + ((a & b) | (c & (a | b))) + d + Vector256.Create(0x8F1BBCDCu) + w[8]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[5] ^ x[0] ^ x[10] ^ x[8]; x[8] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + ((p & q) | (r & (p | q))) + u + Vector256.Create(0x8F1BBCDCu) + x[8]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[6] ^ w[1] ^ w[11] ^ w[9]; w[9] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + ((e & a) | (b & (e | a))) + c + Vector256.Create(0x8F1BBCDCu) + w[9]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[6] ^ x[1] ^ x[11] ^ x[9]; x[9] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + ((v & p) | (q & (v | p))) + r + Vector256.Create(0x8F1BBCDCu) + x[9]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[7] ^ w[2] ^ w[12] ^ w[10]; w[10] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + ((d & e) | (a & (d | e))) + b + Vector256.Create(0x8F1BBCDCu) + w[10]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[7] ^ x[2] ^ x[12] ^ x[10]; x[10] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + ((u & v) | (p & (u | v))) + q + Vector256.Create(0x8F1BBCDCu) + x[10]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[8] ^ w[3] ^ w[13] ^ w[11]; w[11] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + ((c & d) | (e & (c | d))) + a + Vector256.Create(0x8F1BBCDCu) + w[11]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[8] ^ x[3] ^ x[13] ^ x[11]; x[11] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + ((r & u) | (v & (r | u))) + p + Vector256.Create(0x8F1BBCDCu) + x[11]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        s[0] = a; s[1] = b; s[2] = c; s[3] = d; s[4] = e; s[5] = p; s[6] = q; s[7] = r; s[8] = u; s[9] = v;
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.NoInlining)]
    private static unsafe void Stage3(Vector256<uint>* s, Vector256<uint>* w, Vector256<uint>* x)
    {
        Vector256<uint> a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], p = s[5], q = s[6], r = s[7], u = s[8], v = s[9];
        { var m = w[9] ^ w[4] ^ w[14] ^ w[12]; w[12] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0xCA62C1D6u) + w[12]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        { var m = x[9] ^ x[4] ^ x[14] ^ x[12]; x[12] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + (q ^ r ^ u) + v + Vector256.Create(0xCA62C1D6u) + x[12]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[10] ^ w[5] ^ w[15] ^ w[13]; w[13] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0xCA62C1D6u) + w[13]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[10] ^ x[5] ^ x[15] ^ x[13]; x[13] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + (p ^ q ^ r) + u + Vector256.Create(0xCA62C1D6u) + x[13]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[11] ^ w[6] ^ w[0] ^ w[14]; w[14] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0xCA62C1D6u) + w[14]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[11] ^ x[6] ^ x[0] ^ x[14]; x[14] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + (v ^ p ^ q) + r + Vector256.Create(0xCA62C1D6u) + x[14]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[12] ^ w[7] ^ w[1] ^ w[15]; w[15] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0xCA62C1D6u) + w[15]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[12] ^ x[7] ^ x[1] ^ x[15]; x[15] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + (u ^ v ^ p) + q + Vector256.Create(0xCA62C1D6u) + x[15]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[13] ^ w[8] ^ w[2] ^ w[0]; w[0] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0xCA62C1D6u) + w[0]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[13] ^ x[8] ^ x[2] ^ x[0]; x[0] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + (r ^ u ^ v) + p + Vector256.Create(0xCA62C1D6u) + x[0]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        { var m = w[14] ^ w[9] ^ w[3] ^ w[1]; w[1] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0xCA62C1D6u) + w[1]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        { var m = x[14] ^ x[9] ^ x[3] ^ x[1]; x[1] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + (q ^ r ^ u) + v + Vector256.Create(0xCA62C1D6u) + x[1]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[15] ^ w[10] ^ w[4] ^ w[2]; w[2] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0xCA62C1D6u) + w[2]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[15] ^ x[10] ^ x[4] ^ x[2]; x[2] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + (p ^ q ^ r) + u + Vector256.Create(0xCA62C1D6u) + x[2]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[0] ^ w[11] ^ w[5] ^ w[3]; w[3] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0xCA62C1D6u) + w[3]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[0] ^ x[11] ^ x[5] ^ x[3]; x[3] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + (v ^ p ^ q) + r + Vector256.Create(0xCA62C1D6u) + x[3]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[1] ^ w[12] ^ w[6] ^ w[4]; w[4] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0xCA62C1D6u) + w[4]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[1] ^ x[12] ^ x[6] ^ x[4]; x[4] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + (u ^ v ^ p) + q + Vector256.Create(0xCA62C1D6u) + x[4]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[2] ^ w[13] ^ w[7] ^ w[5]; w[5] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0xCA62C1D6u) + w[5]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[2] ^ x[13] ^ x[7] ^ x[5]; x[5] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + (r ^ u ^ v) + p + Vector256.Create(0xCA62C1D6u) + x[5]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        { var m = w[3] ^ w[14] ^ w[8] ^ w[6]; w[6] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0xCA62C1D6u) + w[6]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        { var m = x[3] ^ x[14] ^ x[8] ^ x[6]; x[6] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + (q ^ r ^ u) + v + Vector256.Create(0xCA62C1D6u) + x[6]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[4] ^ w[15] ^ w[9] ^ w[7]; w[7] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0xCA62C1D6u) + w[7]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[4] ^ x[15] ^ x[9] ^ x[7]; x[7] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + (p ^ q ^ r) + u + Vector256.Create(0xCA62C1D6u) + x[7]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[5] ^ w[0] ^ w[10] ^ w[8]; w[8] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0xCA62C1D6u) + w[8]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[5] ^ x[0] ^ x[10] ^ x[8]; x[8] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + (v ^ p ^ q) + r + Vector256.Create(0xCA62C1D6u) + x[8]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[6] ^ w[1] ^ w[11] ^ w[9]; w[9] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0xCA62C1D6u) + w[9]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[6] ^ x[1] ^ x[11] ^ x[9]; x[9] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + (u ^ v ^ p) + q + Vector256.Create(0xCA62C1D6u) + x[9]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[7] ^ w[2] ^ w[12] ^ w[10]; w[10] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0xCA62C1D6u) + w[10]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[7] ^ x[2] ^ x[12] ^ x[10]; x[10] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + (r ^ u ^ v) + p + Vector256.Create(0xCA62C1D6u) + x[10]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        { var m = w[8] ^ w[3] ^ w[13] ^ w[11]; w[11] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        e = (Vector256.ShiftLeft(a, 5) | Vector256.ShiftRightLogical(a, 27)) + (b ^ c ^ d) + e + Vector256.Create(0xCA62C1D6u) + w[11]; b = Vector256.ShiftLeft(b, 30) | Vector256.ShiftRightLogical(b, 2);
        { var m = x[8] ^ x[3] ^ x[13] ^ x[11]; x[11] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        v = (Vector256.ShiftLeft(p, 5) | Vector256.ShiftRightLogical(p, 27)) + (q ^ r ^ u) + v + Vector256.Create(0xCA62C1D6u) + x[11]; q = Vector256.ShiftLeft(q, 30) | Vector256.ShiftRightLogical(q, 2);
        { var m = w[9] ^ w[4] ^ w[14] ^ w[12]; w[12] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        d = (Vector256.ShiftLeft(e, 5) | Vector256.ShiftRightLogical(e, 27)) + (a ^ b ^ c) + d + Vector256.Create(0xCA62C1D6u) + w[12]; a = Vector256.ShiftLeft(a, 30) | Vector256.ShiftRightLogical(a, 2);
        { var m = x[9] ^ x[4] ^ x[14] ^ x[12]; x[12] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        u = (Vector256.ShiftLeft(v, 5) | Vector256.ShiftRightLogical(v, 27)) + (p ^ q ^ r) + u + Vector256.Create(0xCA62C1D6u) + x[12]; p = Vector256.ShiftLeft(p, 30) | Vector256.ShiftRightLogical(p, 2);
        { var m = w[10] ^ w[5] ^ w[15] ^ w[13]; w[13] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        c = (Vector256.ShiftLeft(d, 5) | Vector256.ShiftRightLogical(d, 27)) + (e ^ a ^ b) + c + Vector256.Create(0xCA62C1D6u) + w[13]; e = Vector256.ShiftLeft(e, 30) | Vector256.ShiftRightLogical(e, 2);
        { var m = x[10] ^ x[5] ^ x[15] ^ x[13]; x[13] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        r = (Vector256.ShiftLeft(u, 5) | Vector256.ShiftRightLogical(u, 27)) + (v ^ p ^ q) + r + Vector256.Create(0xCA62C1D6u) + x[13]; v = Vector256.ShiftLeft(v, 30) | Vector256.ShiftRightLogical(v, 2);
        { var m = w[11] ^ w[6] ^ w[0] ^ w[14]; w[14] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        b = (Vector256.ShiftLeft(c, 5) | Vector256.ShiftRightLogical(c, 27)) + (d ^ e ^ a) + b + Vector256.Create(0xCA62C1D6u) + w[14]; d = Vector256.ShiftLeft(d, 30) | Vector256.ShiftRightLogical(d, 2);
        { var m = x[11] ^ x[6] ^ x[0] ^ x[14]; x[14] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        q = (Vector256.ShiftLeft(r, 5) | Vector256.ShiftRightLogical(r, 27)) + (u ^ v ^ p) + q + Vector256.Create(0xCA62C1D6u) + x[14]; u = Vector256.ShiftLeft(u, 30) | Vector256.ShiftRightLogical(u, 2);
        { var m = w[12] ^ w[7] ^ w[1] ^ w[15]; w[15] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        a = (Vector256.ShiftLeft(b, 5) | Vector256.ShiftRightLogical(b, 27)) + (c ^ d ^ e) + a + Vector256.Create(0xCA62C1D6u) + w[15]; c = Vector256.ShiftLeft(c, 30) | Vector256.ShiftRightLogical(c, 2);
        { var m = x[12] ^ x[7] ^ x[1] ^ x[15]; x[15] = Vector256.ShiftLeft(m, 1) | Vector256.ShiftRightLogical(m, 31); }
        p = (Vector256.ShiftLeft(q, 5) | Vector256.ShiftRightLogical(q, 27)) + (r ^ u ^ v) + p + Vector256.Create(0xCA62C1D6u) + x[15]; r = Vector256.ShiftLeft(r, 30) | Vector256.ShiftRightLogical(r, 2);
        s[0] = a; s[1] = b; s[2] = c; s[3] = d; s[4] = e; s[5] = p; s[6] = q; s[7] = r; s[8] = u; s[9] = v;
    }
}
