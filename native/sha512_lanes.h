/*
 * SHA-512 compression over numeric big-endian words, instantiated per lane width.
 * S5_SUFFIX, S5_V, S5_L, S5_FN and optional S5_LANE select scalar/AVX2/AVX-512/NEON.
 * One vector lane is one independent message. SHA512_K is supplied by the includer.
 */
#define S5_CAT2(a, b) a##b
#define S5_CAT(a, b) S5_CAT2(a, b)
#define S5_F(name) S5_CAT(name, S5_SUFFIX)
#ifndef S5_LANE
#define S5_LANE(v, l) (v)[l]
#endif
#ifndef S5_ROTR
#define S5_ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define S5_BSIG0(x) (S5_ROTR(x, 28) ^ S5_ROTR(x, 34) ^ S5_ROTR(x, 39))
#define S5_BSIG1(x) (S5_ROTR(x, 14) ^ S5_ROTR(x, 18) ^ S5_ROTR(x, 41))
#define S5_SSIG0(x) (S5_ROTR(x, 1) ^ S5_ROTR(x, 8) ^ ((x) >> 7))
#define S5_SSIG1(x) (S5_ROTR(x, 19) ^ S5_ROTR(x, 61) ^ ((x) >> 6))
#define S5_CH(e, f, g) ((g) ^ ((e) & ((f) ^ (g))))
#define S5_MAJ(a, b, c) (((a) & (b)) | ((c) & ((a) | (b))))
#endif

S5_FN static inline __attribute__((always_inline)) void S5_F(sha512_compress)(const S5_V* st, S5_V* w, S5_V* out)
{
    S5_V a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
#pragma clang loop unroll(full)
    for (int t = 0; t < 80; t++)
    {
        if (t >= 16) w[t & 15] += S5_SSIG0(w[(t + 1) & 15]) + w[(t + 9) & 15] + S5_SSIG1(w[(t + 14) & 15]);
        S5_V t1 = h + S5_BSIG1(e) + S5_CH(e, f, g) + (w[t & 15] + SHA512_K[t]);
        S5_V t2 = S5_BSIG0(a) + S5_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    out[0] = st[0] + a; out[1] = st[1] + b; out[2] = st[2] + c; out[3] = st[3] + d;
    out[4] = st[4] + e; out[5] = st[5] + f; out[6] = st[6] + g; out[7] = st[7] + h;
}

/* HMAC continuation: 64 message bytes after a 128-byte key block; constant padding folds. */
S5_FN static inline __attribute__((always_inline)) void S5_F(sha512_c64)(const S5_V* st, const S5_V* message, S5_V* out)
{
    const S5_V z = { 0 };
    S5_V w[16];
    for (int j = 0; j < 8; j++) w[j] = message[j];
    w[8] = z + UINT64_C(0x8000000000000000);
    for (int j = 9; j < 15; j++) w[j] = z;
    w[15] = z + 1536;
    S5_F(sha512_compress)(st, w, out);
}
