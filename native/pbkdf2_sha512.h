/* PBKDF2-HMAC-SHA512: fixed HMAC states, one independent candidate per SIMD lane. */
#define S5_SUFFIX _1
#define S5_V uint64_t
#define S5_L 1
#define S5_FN
#define S5_LANE(v, l) (v)
#include "pbkdf2_sha512_lanes.h"
#if RK_X64
typedef uint64_t sha512_v4 __attribute__((vector_size(32)));
typedef uint64_t sha512_v8 __attribute__((vector_size(64)));
#define S5_SUFFIX _avx2
#define S5_V sha512_v4
#define S5_L 4
#define S5_FN AVX2
#include "pbkdf2_sha512_lanes.h"
#define S5_SUFFIX _avx512
#define S5_V sha512_v8
#define S5_L 8
#define S5_FN AVX512
#include "pbkdf2_sha512_lanes.h"
#elif RK_ARM64
typedef uint64_t sha512_v2 __attribute__((vector_size(16)));
#define S5_SUFFIX _neon
#define S5_V sha512_v2
#define S5_L 2
#define S5_FN
#include "pbkdf2_sha512_lanes.h"
#include "sha512_arm.h"

ARMCE static inline __attribute__((always_inline)) void sha512_ce_c64(const uint64x2_t (*st)[4], uint64x2_t (*x)[4])
{
    uint64x2_t s[SHA512_CE_STREAMS][4], w[SHA512_CE_STREAMS][8];
    for (int l = 0; l < SHA512_CE_STREAMS; l++)
    {
        for (int j = 0; j < 4; j++) { s[l][j] = st[l][j]; w[l][j] = x[l][j]; }
        w[l][4] = vsetq_lane_u64(UINT64_C(0x8000000000000000), vdupq_n_u64(0), 0);
        w[l][5] = w[l][6] = vdupq_n_u64(0);
        w[l][7] = vsetq_lane_u64(1536, vdupq_n_u64(0), 1);
    }
    sha512_ce_compress(s, w);
    for (int l = 0; l < SHA512_CE_STREAMS; l++) for (int j = 0; j < 4; j++) x[l][j] = s[l][j];
}

ARMCE static void pbkdf2_sha512_iter_ce(const uint64_t (*ist)[8], const uint64_t (*ost)[8], uint64_t (*u)[8], uint32_t iter)
{
    uint64x2_t is[SHA512_CE_STREAMS][4], os[SHA512_CE_STREAMS][4], x[SHA512_CE_STREAMS][4], t[SHA512_CE_STREAMS][4];
    for (int l = 0; l < SHA512_CE_STREAMS; l++) for (int j = 0; j < 4; j++)
    {
        is[l][j] = vld1q_u64(ist[l] + 2 * j); os[l][j] = vld1q_u64(ost[l] + 2 * j);
        x[l][j] = t[l][j] = vld1q_u64(u[l] + 2 * j);
    }
    for (uint32_t i = 1; i < iter; i++)
    {
        sha512_ce_c64(is, x); sha512_ce_c64(os, x);
        for (int l = 0; l < SHA512_CE_STREAMS; l++) for (int j = 0; j < 4; j++) t[l][j] = veorq_u64(t[l][j], x[l][j]);
    }
    for (int l = 0; l < SHA512_CE_STREAMS; l++) for (int j = 0; j < 4; j++) vst1q_u64(u[l] + 2 * j, t[l][j]);
}
#endif

static void sha512_put_be64(uint8_t* p, uint64_t v)
{
    for (int j = 0; j < 8; j++) p[7 - j] = (uint8_t)(v >> (8 * j));
}

static void sha512_bytes(uint64_t st[8], const uint8_t* p)
{
    uint64_t w[16];
    for (int j = 0; j < 16; j++)
    {
        w[j] = 0;
        for (int k = 0; k < 8; k++) w[j] = (w[j] << 8) | p[j * 8 + k];
    }
    sha512_compress_1(st, w, st);
}

static void sha512_tail(uint64_t st[8], const uint8_t* p, size_t len, uint64_t prefix)
{
    while (len >= 128) { sha512_bytes(st, p); p += 128; len -= 128; prefix += 128; }
    uint8_t b[256] = { 0 };
    if (len) memcpy(b, p, len);
    b[len] = 0x80;
    int nb = len < 112 ? 1 : 2;
    sha512_put_be64(b + 128 * nb - 8, (prefix + len) * 8);
    for (int j = 0; j < nb; j++) sha512_bytes(st, b + 128 * j);
}

static void hmac_sha512_states(const uint8_t* pw, size_t len, uint64_t ist[8], uint64_t ost[8])
{
    uint8_t k[128] = { 0 }, b[128];
    if (len > 128)
    {
        uint64_t s[8];
        memcpy(s, SHA512_IV, 64); sha512_tail(s, pw, len, 0);
        for (int j = 0; j < 8; j++) sha512_put_be64(k + 8 * j, s[j]);
    }
    else if (len) memcpy(k, pw, len);
    for (int j = 0; j < 128; j++) b[j] = k[j] ^ 0x36;
    memcpy(ist, SHA512_IV, 64); sha512_bytes(ist, b);
    for (int j = 0; j < 128; j++) b[j] = k[j] ^ 0x5c;
    memcpy(ost, SHA512_IV, 64); sha512_bytes(ost, b);
}

static void pbkdf2_sha512_u1(const uint64_t ist[8], const uint64_t ost[8], const uint8_t* salt,
    size_t slen, uint32_t block, uint64_t u[8])
{
    uint64_t st[8];
    memcpy(st, ist, 64);
    uint64_t prefix = 128;
    while (slen >= 128) { sha512_bytes(st, salt); salt += 128; slen -= 128; prefix += 128; }
    uint8_t b[132], d[64];
    if (slen) memcpy(b, salt, slen);
    put_be32(b + slen, block);
    sha512_tail(st, b, slen + 4, prefix);
    for (int j = 0; j < 8; j++) sha512_put_be64(d + 8 * j, st[j]);
    memcpy(u, ost, 64); sha512_tail(u, d, 64, 128);
}

typedef void (*pbkdf2_sha512_iter_fn)(const uint64_t (*)[8], const uint64_t (*)[8], uint64_t (*)[8], uint32_t);
#include "pbkdf2_sha512_selftest.h"

/* Every accelerated implementation is checked independently before the first candidate batch. */
static atomic_int g_sha512_tests[4] = { 0, 0, 0, 0 };
static int pbkdf2_sha512_guard(pbkdf2_sha512_iter_fn fn, int lanes, int guard)
{
    int state = atomic_load(&g_sha512_tests[guard]);
    if (state == 0 && atomic_compare_exchange_strong(&g_sha512_tests[guard], &state, 1))
    {
        state = pbkdf2_sha512_selftest(fn, lanes) ? 2 : 3;
        atomic_store(&g_sha512_tests[guard], state);
    }
    return state == 2;
}

/* Selection alone does not start a self-test, so diagnostics can inspect an unused path. */
static pbkdf2_sha512_iter_fn pbkdf2_sha512_selected(int* lanes, int* path, int* guard)
{
    const char* selected = getenv("RECOVERKIT_PBKDF2_SHA512_PATH");
    int automatic = !selected || !*selected || strcmp(selected, "default") == 0;
    int f = features(); (void)f;
    *lanes = 1; *path = RK_PATH_SCALAR; *guard = -1;
#if RK_X64
    if ((automatic || strcmp(selected, "avx512") == 0) && (f & RK_FEAT_AVX512)
        && !wide_switched_off("RECOVERKIT_PBKDF2_SHA512_AVX512"))
    { *lanes = 8; *path = RK_PATH_AVX512; *guard = 0; return pbkdf2_sha512_iter_avx512; }
    if ((automatic || strcmp(selected, "avx2") == 0 || strcmp(selected, "avx512") == 0) && (f & RK_FEAT_AVX2))
    { *lanes = 4; *path = RK_PATH_AVX2; *guard = 1; return pbkdf2_sha512_iter_avx2; }
#elif RK_ARM64
    if ((automatic || strcmp(selected, "arm-sha512") == 0) && (f & RK_FEAT_ARM_SHA512))
    { *lanes = SHA512_CE_STREAMS; *path = RK_PATH_ARM_SHA512; *guard = 2; return pbkdf2_sha512_iter_ce; }
    if ((automatic || strcmp(selected, "neon") == 0 || strcmp(selected, "arm-sha512") == 0) && (f & RK_FEAT_NEON))
    { *lanes = 2; *path = RK_PATH_NEON; *guard = 3; return pbkdf2_sha512_iter_neon; }
#endif
    return pbkdf2_sha512_iter_1;
}

static pbkdf2_sha512_iter_fn pbkdf2_sha512_path(int* lanes, int* path)
{
    int guard;
    pbkdf2_sha512_iter_fn fn = pbkdf2_sha512_selected(lanes, path, &guard);
    if (guard >= 0 && !pbkdf2_sha512_guard(fn, *lanes, guard))
    { *lanes = 1; *path = RK_PATH_SCALAR; return pbkdf2_sha512_iter_1; }
    return fn;
}

RK_EXPORT int rk_pbkdf2_sha512_selftest_state(void)
{
    int lanes, path, guard;
    pbkdf2_sha512_selected(&lanes, &path, &guard);
    if (guard < 0) return 0;
    int state = atomic_load(&g_sha512_tests[guard]);
    return state == 2 ? 1 : state == 3 ? 2 : 0;
}
RK_EXPORT int rk_pbkdf2_sha512_executed_paths(void) { return atomic_load(&g_pbkdf2_sha512_paths); }
RK_EXPORT int rk_pbkdf2_sha512_lanes(void) { int lanes, path; pbkdf2_sha512_path(&lanes, &path); return lanes; }
RK_EXPORT int rk_pbkdf2_sha512_path(void) { int lanes, path; pbkdf2_sha512_path(&lanes, &path); return path; }

RK_EXPORT int rk_pbkdf2_sha512(const uint8_t* pws, int stride, const int* lens, int n, const uint8_t* salt, int slen,
    uint32_t iter, uint8_t* dk, int dklen)
{
    if (n < 0 || stride < 0 || slen < 0 || !iter || dklen < 1 || (n > 0 && (!dk || (!pws && stride))) || (slen && !salt)) return -1;
    if (lens) for (int i = 0; i < n; i++) if (lens[i] < 0 || lens[i] > stride) return -1;
    int lanes, path;
    pbkdf2_sha512_iter_fn fn = pbkdf2_sha512_path(&lanes, &path);
    if (n > 0) atomic_fetch_or(&g_pbkdf2_sha512_paths, iter > 1 ? path : RK_PATH_SCALAR);
    uint64_t ist[8][8], ost[8][8], u[8][8];
    for (int i0 = 0; i0 < n; )
    {
        int count = n - i0 < lanes ? n - i0 : lanes;
        for (int l = 0; l < count; l++)
            hmac_sha512_states(pws ? pws + (size_t)(i0 + l) * stride : NULL, (size_t)(lens ? lens[i0 + l] : stride), ist[l], ost[l]);
        for (int l = count; l < lanes; l++) { memcpy(ist[l], ist[0], 64); memcpy(ost[l], ost[0], 64); }
        for (int b = 0; b < dklen; )
        {
            for (int l = 0; l < lanes; l++) pbkdf2_sha512_u1(ist[l], ost[l], salt, (size_t)slen, 1 + (uint32_t)(b / 64), u[l]);
            if (iter > 1) fn(ist, ost, u, iter);
            int take = dklen - b < 64 ? dklen - b : 64;
            for (int l = 0; l < count; l++)
            {
                uint8_t block[64];
                for (int j = 0; j < 8; j++) sha512_put_be64(block + 8 * j, u[l][j]);
                memcpy(dk + (size_t)(i0 + l) * dklen + b, block, (size_t)take);
            }
            b += take;
        }
        i0 += count;
    }
    return n;
}
