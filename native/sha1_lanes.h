/* Fixed 20-byte HMAC messages, one candidate per lane. Included once per vector width. */
#define P1_CAT2(a, b) a##b
#define P1_CAT(a, b) P1_CAT2(a, b)
#define P1_F(name) P1_CAT(name, P1_SUFFIX)
#ifndef P1_LANE
#define P1_LANE(v, l) (v)[l]
#endif
#define P1_ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

P1_FN static inline __attribute__((always_inline)) void P1_F(sha1_c20)(const P1_V* st, const P1_V* msg, P1_V* out)
{
    const P1_V Z = { 0 };
    P1_V w[16];
    for (int j = 0; j < 5; j++) w[j] = msg[j];
    w[5] = Z + 0x80000000u;
    for (int j = 6; j < 15; j++) w[j] = Z;
    w[15] = Z + 672u;
    P1_V a = st[0], b = st[1], c = st[2], d = st[3], e = st[4];
#pragma clang loop unroll(full)
    for (int t = 0; t < 80; t++)
    {
        if (t >= 16) w[t & 15] = P1_ROL(w[(t - 3) & 15] ^ w[(t - 8) & 15] ^ w[(t - 14) & 15] ^ w[t & 15], 1);
        P1_V f;
        uint32_t k;
        if (t < 20) { f = d ^ (b & (c ^ d)); k = 0x5a827999u; }
        else if (t < 40) { f = b ^ c ^ d; k = 0x6ed9eba1u; }
        else if (t < 60) { f = (b & c) | (d & (b | c)); k = 0x8f1bbcdcu; }
        else { f = b ^ c ^ d; k = 0xca62c1d6u; }
        P1_V v = P1_ROL(a, 5) + f + e + w[t & 15] + k;
        e = d; d = c; c = P1_ROL(b, 30); b = a; a = v;
    }
    out[0] = st[0] + a; out[1] = st[1] + b; out[2] = st[2] + c;
    out[3] = st[3] + d; out[4] = st[4] + e;
}

P1_FN static void P1_F(pbkdf2_sha1_iter)(const uint32_t (*ist)[5], const uint32_t (*ost)[5], uint32_t (*u)[5], uint32_t iter)
{
    P1_V is[5], os[5], x[5], total[5];
    for (int j = 0; j < 5; j++)
    {
        for (int l = 0; l < P1_L; l++)
        {
            P1_LANE(is[j], l) = ist[l][j]; P1_LANE(os[j], l) = ost[l][j]; P1_LANE(x[j], l) = u[l][j];
        }
        total[j] = x[j];
    }
    for (uint32_t i = 1; i < iter; i++)
    {
        P1_V inner[5];
        P1_F(sha1_c20)(is, x, inner);
        P1_F(sha1_c20)(os, inner, x);
        for (int j = 0; j < 5; j++) total[j] ^= x[j];
    }
    for (int j = 0; j < 5; j++)
        for (int l = 0; l < P1_L; l++) u[l][j] = P1_LANE(total[j], l);
}

#undef P1_SUFFIX
#undef P1_V
#undef P1_L
#undef P1_FN
#undef P1_LANE
#undef P1_ROL
