/*
 * Multi-lane PBKDF2-HMAC-SHA256 iterations, included by rknative.c once per lane width:
 *
 *   #define PS_SUFFIX _avx2    function name suffix
 *   #define PS_V      v8u      lane vector (a clang/GCC vector type, or uint32_t for one lane)
 *   #define PS_L      8        lanes in PS_V
 *   #define PS_FN     AVX2     target attribute of the generated functions (may be empty)
 *   #define PS_LANE(v, l)      lane l of v as an lvalue (optional; default (v)[l])
 *
 * The code uses only generic vector arithmetic, so the same source gives AVX-512 (rotates become
 * VPROLD and the logic trees VPTERNLOGD), AVX2, NEON and plain scalar code. Each lane is one
 * candidate; the HMAC inner and outer states are fixed per lane, so their first SHA-256 round is
 * computed once per call, and the message words 8..15 (padding of a 32-byte message after one
 * 64-byte block) are constants that the compiler folds into the schedule.
 */
#define PS_CAT2(a, b) a##b
#define PS_CAT(a, b) PS_CAT2(a, b)
#define PS_F(name) PS_CAT(name, PS_SUFFIX)
#ifndef PS_LANE
#define PS_LANE(v, l) (v)[l]
#endif

#ifndef PS_ROUND_MACROS
#define PS_ROUND_MACROS
#define PS_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define PS_BSIG0(x) (PS_ROTR(x, 2) ^ PS_ROTR(x, 13) ^ PS_ROTR(x, 22))
#define PS_BSIG1(x) (PS_ROTR(x, 6) ^ PS_ROTR(x, 11) ^ PS_ROTR(x, 25))
#define PS_SSIG0(x) (PS_ROTR(x, 7) ^ PS_ROTR(x, 18) ^ ((x) >> 3))
#define PS_SSIG1(x) (PS_ROTR(x, 17) ^ PS_ROTR(x, 19) ^ ((x) >> 10))
#define PS_CH(e, f, g) ((g) ^ ((e) & ((f) ^ (g))))
#define PS_MAJ(a, b, c) (((a) & (b)) | ((c) & ((a) | (b))))
#endif

/*
 * Round 0 of a compression from fixed state st depends on the message only through W0:
 * a1 = pre[0] + W0, e1 = pre[1] + W0.
 */
PS_FN static inline __attribute__((always_inline)) void PS_F(ps_round0)(const PS_V* st, PS_V* pre)
{
    PS_V t1 = st[7] + PS_BSIG1(st[4]) + PS_CH(st[4], st[5], st[6]) + SHA256_K[0];
    PS_V t2 = PS_BSIG0(st[0]) + PS_MAJ(st[0], st[1], st[2]);
    pre[0] = t1 + t2;
    pre[1] = st[3] + t1;
}

/* out = SHA-256 compression of st over (m[0..7] || 0x80 || zeros || bit length 768). */
PS_FN static inline __attribute__((always_inline)) void PS_F(ps_c32)(const PS_V* st, const PS_V* pre, const PS_V* m, PS_V* out)
{
    const PS_V Z = { 0 };
    PS_V W[16];
    for (int j = 0; j < 8; j++) W[j] = m[j];
    W[8] = Z + 0x80000000u;
    for (int j = 9; j < 15; j++) W[j] = Z;
    W[15] = Z + 768u;
    PS_V a = pre[0] + W[0], b = st[0], c = st[1], d = st[2], e = pre[1] + W[0], f = st[4], g = st[5], h = st[6];
#pragma clang loop unroll(full)
    for (int t = 1; t < 64; t++)
    {
        if (t >= 16) W[t & 15] += PS_SSIG0(W[(t + 1) & 15]) + W[(t + 9) & 15] + PS_SSIG1(W[(t + 14) & 15]);
        PS_V t1 = h + PS_BSIG1(e) + PS_CH(e, f, g) + (W[t & 15] + SHA256_K[t]);
        PS_V t2 = PS_BSIG0(a) + PS_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    out[0] = st[0] + a; out[1] = st[1] + b; out[2] = st[2] + c; out[3] = st[3] + d;
    out[4] = st[4] + e; out[5] = st[5] + f; out[6] = st[6] + g; out[7] = st[7] + h;
}

/*
 * PS_L lanes of PBKDF2-HMAC-SHA256 iterations 2..iter for one output block. ist/ost: the lanes'
 * HMAC inner and outer states after the 64-byte key block; u: U1 on entry, U1 ^ ... ^ U_iter on
 * return. All words are numeric (big-endian decoded) SHA-256 words.
 */
PS_FN static void PS_F(pbkdf2_sha256_iter)(const uint32_t (*ist)[8], const uint32_t (*ost)[8], uint32_t (*u)[8], uint32_t iter)
{
    PS_V is[8], os[8], ip[2], op[2], U[8], T[8];
    for (int j = 0; j < 8; j++)
    {
        for (int l = 0; l < PS_L; l++) { PS_LANE(is[j], l) = ist[l][j]; PS_LANE(os[j], l) = ost[l][j]; PS_LANE(U[j], l) = u[l][j]; }
        T[j] = U[j];
    }
    PS_F(ps_round0)(is, ip);
    PS_F(ps_round0)(os, op);
    for (uint32_t i = 1; i < iter; i++)
    {
        PS_V x[8];
        PS_F(ps_c32)(is, ip, U, x);
        PS_F(ps_c32)(os, op, x, U);
        for (int j = 0; j < 8; j++) T[j] ^= U[j];
    }
    for (int j = 0; j < 8; j++)
    {
        for (int l = 0; l < PS_L; l++) u[l][j] = PS_LANE(T[j], l);
    }
}

#undef PS_SUFFIX
#undef PS_V
#undef PS_L
#undef PS_FN
#undef PS_LANE
