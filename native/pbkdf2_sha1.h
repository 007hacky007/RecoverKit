/* PBKDF2-HMAC-SHA1. Only the repeated 20-byte HMAC messages run in vector lanes. */
static void sha1_bytes(uint32_t st[5], const uint8_t* bytes)
{
    uint32_t w[16];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)bytes[4 * i] << 24 | (uint32_t)bytes[4 * i + 1] << 16 |
               (uint32_t)bytes[4 * i + 2] << 8 | bytes[4 * i + 3];
    sha1_block(st, w);
}

static void sha1_tail(uint32_t st[5], const uint8_t* m, size_t n, uint64_t prefix)
{
    while (n >= 64) { sha1_bytes(st, m); m += 64; n -= 64; prefix += 64; }
    uint8_t b[128] = { 0 };
    if (n) memcpy(b, m, n);
    b[n] = 0x80;
    int nb = n < 56 ? 1 : 2;
    uint64_t bits = (prefix + n) * 8;
    for (int i = 0; i < 8; i++) b[64 * nb - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (int i = 0; i < nb; i++) sha1_bytes(st, b + 64 * i);
}

static void hmac_sha1_states(const uint8_t* key, size_t len, uint32_t ist[5], uint32_t ost[5])
{
    uint8_t k[64] = { 0 }, b[64];
    if (len > 64)
    {
        uint32_t s[5];
        memcpy(s, SHA1_IV, sizeof s);
        sha1_tail(s, key, len, 0);
        for (int j = 0; j < 5; j++) put_be32(k + 4 * j, s[j]);
    }
    else if (len) memcpy(k, key, len);
    for (int j = 0; j < 64; j++) b[j] = k[j] ^ 0x36;
    memcpy(ist, SHA1_IV, 20); sha1_bytes(ist, b);
    for (int j = 0; j < 64; j++) b[j] = k[j] ^ 0x5c;
    memcpy(ost, SHA1_IV, 20); sha1_bytes(ost, b);
}

static void pbkdf2_sha1_u1(const uint32_t ist[5], const uint32_t ost[5], const uint8_t* salt,
                            size_t slen, uint32_t block, uint32_t u[5])
{
    uint32_t st[5];
    memcpy(st, ist, 20);
    uint64_t prefix = 64;
    while (slen >= 64) { sha1_bytes(st, salt); salt += 64; slen -= 64; prefix += 64; }
    uint8_t b[68], d[20];
    if (slen) memcpy(b, salt, slen);
    put_be32(b + slen, block);
    sha1_tail(st, b, slen + 4, prefix);
    for (int j = 0; j < 5; j++) put_be32(d + 4 * j, st[j]);
    memcpy(u, ost, 20); sha1_tail(u, d, 20, 64);
}

#define P1_SUFFIX _1
#define P1_V uint32_t
#define P1_L 1
#define P1_FN
#define P1_LANE(v, l) (v)
#include "sha1_lanes.h"
#if RK_X64
#define P1_SUFFIX _avx2
#define P1_V v8u
#define P1_L 8
#define P1_FN AVX2
#include "sha1_lanes.h"
#define P1_SUFFIX _avx512
#define P1_V v16u
#define P1_L 16
#define P1_FN AVX512
#include "sha1_lanes.h"
#elif RK_ARM64
#define P1_SUFFIX _neon
#define P1_V v8u
#define P1_L 8
#define P1_FN
#include "sha1_lanes.h"

#define SHA1_CE_STREAMS 8
ARMCE static inline __attribute__((always_inline)) void sha1ce_c20(const uint32x4_t* abcd,
    const uint32_t* es, uint32x4_t* x, uint32_t* xe)
{
    uint32x4_t m[SHA1_CE_STREAMS][4], st[SHA1_CE_STREAMS];
    uint32_t e[SHA1_CE_STREAMS];
    for (int l = 0; l < SHA1_CE_STREAMS; l++)
    {
        m[l][0] = x[l];
        uint32_t pad[4] = { xe[l], 0x80000000u, 0, 0 };
        m[l][1] = vld1q_u32(pad); m[l][2] = vdupq_n_u32(0);
        m[l][3] = vsetq_lane_u32(672, vdupq_n_u32(0), 3);
        st[l] = abcd[l]; e[l] = es[l];
    }
#pragma clang loop unroll(full)
    for (int i = 0; i < 20; i++)
    {
        uint32_t k = i < 5 ? 0x5a827999u : i < 10 ? 0x6ed9eba1u : i < 15 ? 0x8f1bbcdcu : 0xca62c1d6u;
#pragma clang loop unroll(full)
        for (int l = 0; l < SHA1_CE_STREAMS; l++)
        {
            if (i >= 4) m[l][i & 3] = vsha1su1q_u32(vsha1su0q_u32(m[l][i & 3], m[l][(i + 1) & 3], m[l][(i + 2) & 3]), m[l][(i + 3) & 3]);
            uint32x4_t wk = vaddq_u32(m[l][i & 3], vdupq_n_u32(k));
            uint32_t next = vsha1h_u32(vgetq_lane_u32(st[l], 0));
            if (i < 5) st[l] = vsha1cq_u32(st[l], e[l], wk);
            else if (i < 10 || i >= 15) st[l] = vsha1pq_u32(st[l], e[l], wk);
            else st[l] = vsha1mq_u32(st[l], e[l], wk);
            e[l] = next;
        }
    }
    for (int l = 0; l < SHA1_CE_STREAMS; l++) { x[l] = vaddq_u32(st[l], abcd[l]); xe[l] = e[l] + es[l]; }
}

ARMCE static void pbkdf2_sha1_iter_ce(const uint32_t (*ist)[5], const uint32_t (*ost)[5], uint32_t (*u)[5], uint32_t iter)
{
    uint32x4_t is[SHA1_CE_STREAMS], os[SHA1_CE_STREAMS], x[SHA1_CE_STREAMS], t[SHA1_CE_STREAMS];
    uint32_t ie[SHA1_CE_STREAMS], oe[SHA1_CE_STREAMS], xe[SHA1_CE_STREAMS], te[SHA1_CE_STREAMS];
    for (int l = 0; l < SHA1_CE_STREAMS; l++)
    {
        is[l] = vld1q_u32(ist[l]); os[l] = vld1q_u32(ost[l]);
        x[l] = t[l] = vld1q_u32(u[l]);
        ie[l] = ist[l][4]; oe[l] = ost[l][4]; xe[l] = te[l] = u[l][4];
    }
    for (uint32_t i = 1; i < iter; i++)
    {
        sha1ce_c20(is, ie, x, xe); sha1ce_c20(os, oe, x, xe);
        for (int l = 0; l < SHA1_CE_STREAMS; l++) { t[l] = veorq_u32(t[l], x[l]); te[l] ^= xe[l]; }
    }
    for (int l = 0; l < SHA1_CE_STREAMS; l++) { vst1q_u32(u[l], t[l]); u[l][4] = te[l]; }
}
#endif

typedef void (*pbkdf2_sha1_iter_fn)(const uint32_t (*)[5], const uint32_t (*)[5], uint32_t (*)[5], uint32_t);
#include "pbkdf2_sha1_selftest.h"

#if RK_X64
static int pbkdf2_sha1_wide_ok(void)
{
    if (wide_switched_off("RECOVERKIT_PBKDF2_SHA1_AVX512")) return 0;
    int state = atomic_load(&g_pbkdf2_sha1_wide_test);
    if (state == 0 && atomic_compare_exchange_strong(&g_pbkdf2_sha1_wide_test, &state, 1))
    {
        state = pbkdf2_sha1_selftest(pbkdf2_sha1_iter_avx512) ? 2 : 3;
        atomic_store(&g_pbkdf2_sha1_wide_test, state);
    }
    return state == 2;
}
#endif

static pbkdf2_sha1_iter_fn pbkdf2_sha1_path(int* lanes, int* path)
{
    const char* selected = getenv("RECOVERKIT_PBKDF2_SHA1_PATH");
    int automatic = !selected || !*selected || strcmp(selected, "default") == 0;
    int f = features(); (void)f;
    *lanes = 1; *path = RK_PATH_SCALAR;
#if RK_X64
    if ((automatic || strcmp(selected, "avx512") == 0) && (f & RK_FEAT_AVX512) && pbkdf2_sha1_wide_ok())
    { *lanes = 16; *path = RK_PATH_AVX512; return pbkdf2_sha1_iter_avx512; }
    if ((automatic || strcmp(selected, "avx2") == 0 || strcmp(selected, "avx512") == 0) && (f & RK_FEAT_AVX2))
    { *lanes = 8; *path = RK_PATH_AVX2; return pbkdf2_sha1_iter_avx2; }
#elif RK_ARM64
    if ((automatic || strcmp(selected, "arm-sha1") == 0) && (f & RK_FEAT_ARM_SHA1))
    { *lanes = SHA1_CE_STREAMS; *path = RK_PATH_ARM_SHA1; return pbkdf2_sha1_iter_ce; }
    if ((automatic || strcmp(selected, "neon") == 0 || strcmp(selected, "arm-sha1") == 0) && (f & RK_FEAT_NEON))
    { *lanes = 8; *path = RK_PATH_NEON; return pbkdf2_sha1_iter_neon; }
#endif
    return pbkdf2_sha1_iter_1;
}

static void pbkdf2_sha1(const uint8_t* pws, int stride, const int* lens, int n, const uint8_t* salt, int slen,
    uint32_t iter, uint32_t first, uint8_t* dk, int dklen)
{
    int L, path;
    pbkdf2_sha1_iter_fn fn = pbkdf2_sha1_path(&L, &path);
    if (n > 0) atomic_fetch_or(&g_pbkdf2_sha1_paths, iter > 1 ? path : RK_PATH_SCALAR);
    uint32_t ist[PBKDF2_MAXLANES][5], ost[PBKDF2_MAXLANES][5], u[PBKDF2_MAXLANES][5];
    for (int i0 = 0; i0 < n; i0 += L)
    {
        int m = n - i0 < L ? n - i0 : L;
        for (int l = 0; l < m; l++)
            hmac_sha1_states(pws ? pws + (size_t)(i0 + l) * stride : NULL, (size_t)(lens ? lens[i0 + l] : stride), ist[l], ost[l]);
        for (int l = m; l < L; l++) { memcpy(ist[l], ist[0], 20); memcpy(ost[l], ost[0], 20); }
        for (int b = 0; b < dklen; )
        {
            for (int l = 0; l < L; l++) pbkdf2_sha1_u1(ist[l], ost[l], salt, (size_t)slen, first + (uint32_t)(b / 20), u[l]);
            if (iter > 1) fn(ist, ost, u, iter);
            int take = dklen - b < 20 ? dklen - b : 20;
            for (int l = 0; l < m; l++)
            {
                uint8_t block[20];
                for (int j = 0; j < 5; j++) put_be32(block + 4 * j, u[l][j]);
                memcpy(dk + (size_t)(i0 + l) * dklen + b, block, (size_t)take);
            }
            b += take;
        }
    }
}

static int pbkdf2_sha1_args(const uint8_t* pws, int stride, const int* lens, int n, const uint8_t* salt, int slen,
    uint32_t iter, uint8_t* dk, int dklen)
{
    if (n < 0 || stride < 0 || slen < 0 || !iter || dklen < 1 || (n > 0 && (!dk || (!pws && stride))) || (slen && !salt)) return 0;
    if (lens) for (int i = 0; i < n; i++) if (lens[i] < 0 || lens[i] > stride) return 0;
    return 1;
}

RK_EXPORT int rk_pbkdf2_sha1_lanes(void) { int L, path; pbkdf2_sha1_path(&L, &path); return L; }
RK_EXPORT int rk_pbkdf2_sha1(const uint8_t* pws, int stride, const int* lens, int n, const uint8_t* salt, int slen,
    uint32_t iter, uint8_t* dk, int dklen)
{
    if (!pbkdf2_sha1_args(pws, stride, lens, n, salt, slen, iter, dk, dklen)) return -1;
    pbkdf2_sha1(pws, stride, lens, n, salt, slen, iter, 1, dk, dklen);
    return 0;
}
RK_EXPORT int rk_pbkdf2_sha1_block(const uint8_t* pws, int stride, const int* lens, int n, const uint8_t* salt, int slen,
    uint32_t iter, uint32_t block, uint8_t* dk)
{
    if (!block || !pbkdf2_sha1_args(pws, stride, lens, n, salt, slen, iter, dk, 20)) return -1;
    pbkdf2_sha1(pws, stride, lens, n, salt, slen, iter, block, dk, 20);
    return 0;
}
