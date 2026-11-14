/* Whirlpool (2003 revision), with cached round keys for the fixed HMAC states. */
static const uint8_t whirl_sbox[256] = {
    0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
    0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
    0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
    0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
    0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
    0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
    0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
    0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
    0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
    0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
    0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
    0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
    0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
    0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
    0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
    0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86,
};

static uint64_t whirl_load(const uint8_t* p)
{
    uint64_t x; memcpy(&x, p, 8); return __builtin_bswap64(x);
}

static void whirl_store(uint8_t* p, uint64_t x)
{
    x = __builtin_bswap64(x); memcpy(p, &x, 8);
}

static void whirl_tables(uint64_t t[8][256])
{
    for (int i = 0; i < 256; i++)
    {
        unsigned s = whirl_sbox[i];
        unsigned s2 = (s << 1) ^ ((s & 128) ? 0x11d : 0);
        unsigned s4 = (s2 << 1) ^ ((s2 & 128) ? 0x11d : 0);
        unsigned s8 = (s4 << 1) ^ ((s4 & 128) ? 0x11d : 0);
        t[0][i] = (uint64_t)s << 56 | (uint64_t)s << 48 | (uint64_t)s4 << 40 |
            (uint64_t)s << 32 | (uint64_t)s8 << 24 | (uint64_t)(s4 ^ s) << 16 |
            (uint64_t)s2 << 8 | (s8 ^ s);
        for (int j = 1; j < 8; j++) t[j][i] = (t[j-1][i] >> 8) | (t[j-1][i] << 56);
    }
}

static inline void whirl_round(uint64_t* y, const uint64_t* x, const uint64_t t[8][256])
{
    y[0] = t[0][(x[0] >> 56) & 255] ^ t[1][(x[7] >> 48) & 255] ^ t[2][(x[6] >> 40) & 255] ^ t[3][(x[5] >> 32) & 255] ^ t[4][(x[4] >> 24) & 255] ^ t[5][(x[3] >> 16) & 255] ^ t[6][(x[2] >> 8) & 255] ^ t[7][(x[1] >> 0) & 255];
    y[1] = t[0][(x[1] >> 56) & 255] ^ t[1][(x[0] >> 48) & 255] ^ t[2][(x[7] >> 40) & 255] ^ t[3][(x[6] >> 32) & 255] ^ t[4][(x[5] >> 24) & 255] ^ t[5][(x[4] >> 16) & 255] ^ t[6][(x[3] >> 8) & 255] ^ t[7][(x[2] >> 0) & 255];
    y[2] = t[0][(x[2] >> 56) & 255] ^ t[1][(x[1] >> 48) & 255] ^ t[2][(x[0] >> 40) & 255] ^ t[3][(x[7] >> 32) & 255] ^ t[4][(x[6] >> 24) & 255] ^ t[5][(x[5] >> 16) & 255] ^ t[6][(x[4] >> 8) & 255] ^ t[7][(x[3] >> 0) & 255];
    y[3] = t[0][(x[3] >> 56) & 255] ^ t[1][(x[2] >> 48) & 255] ^ t[2][(x[1] >> 40) & 255] ^ t[3][(x[0] >> 32) & 255] ^ t[4][(x[7] >> 24) & 255] ^ t[5][(x[6] >> 16) & 255] ^ t[6][(x[5] >> 8) & 255] ^ t[7][(x[4] >> 0) & 255];
    y[4] = t[0][(x[4] >> 56) & 255] ^ t[1][(x[3] >> 48) & 255] ^ t[2][(x[2] >> 40) & 255] ^ t[3][(x[1] >> 32) & 255] ^ t[4][(x[0] >> 24) & 255] ^ t[5][(x[7] >> 16) & 255] ^ t[6][(x[6] >> 8) & 255] ^ t[7][(x[5] >> 0) & 255];
    y[5] = t[0][(x[5] >> 56) & 255] ^ t[1][(x[4] >> 48) & 255] ^ t[2][(x[3] >> 40) & 255] ^ t[3][(x[2] >> 32) & 255] ^ t[4][(x[1] >> 24) & 255] ^ t[5][(x[0] >> 16) & 255] ^ t[6][(x[7] >> 8) & 255] ^ t[7][(x[6] >> 0) & 255];
    y[6] = t[0][(x[6] >> 56) & 255] ^ t[1][(x[5] >> 48) & 255] ^ t[2][(x[4] >> 40) & 255] ^ t[3][(x[3] >> 32) & 255] ^ t[4][(x[2] >> 24) & 255] ^ t[5][(x[1] >> 16) & 255] ^ t[6][(x[0] >> 8) & 255] ^ t[7][(x[7] >> 0) & 255];
    y[7] = t[0][(x[7] >> 56) & 255] ^ t[1][(x[6] >> 48) & 255] ^ t[2][(x[5] >> 40) & 255] ^ t[3][(x[4] >> 32) & 255] ^ t[4][(x[3] >> 24) & 255] ^ t[5][(x[2] >> 16) & 255] ^ t[6][(x[1] >> 8) & 255] ^ t[7][(x[0] >> 0) & 255];
}

static uint64_t whirl_rc(int r)
{
    return whirl_load(whirl_sbox + 8 * r);
}

static void whirl_keys(uint64_t keys[10][8], const uint64_t* h, const uint64_t t[8][256])
{
    uint64_t k[8]; memcpy(k, h, 64);
    for (int r = 0; r < 10; r++)
    {
        whirl_round(keys[r], k, t); keys[r][0] ^= whirl_rc(r);
        memcpy(k, keys[r], 64);
    }
}

static void whirl_compress(uint64_t* h, const uint64_t* m, const uint64_t t[8][256], const uint64_t keys[10][8])
{
    uint64_t k[8], s[8], v[8], q[8];
    memcpy(k, h, 64);
    for (int i = 0; i < 8; i++) s[i] = m[i] ^ h[i];
    for (int r = 0; r < 10; r++)
    {
        if (keys) memcpy(k, keys[r], 64);
        else { whirl_round(q, k, t); q[0] ^= whirl_rc(r); memcpy(k, q, 64); }
        whirl_round(v, s, t);
        for (int i = 0; i < 8; i++) s[i] = v[i] ^ k[i];
    }
    for (int i = 0; i < 8; i++) h[i] ^= s[i] ^ m[i];
}

static void whirl_hmac64(uint64_t* out, const uint64_t* msg, const uint64_t* ip, const uint64_t* op,
    const uint64_t ik[10][8], const uint64_t ok[10][8], const uint64_t t[8][256])
{
    const uint64_t pad[8] = { 0x8000000000000000ULL, 0, 0, 0, 0, 0, 0, 1024 };
    uint64_t h[8]; memcpy(h, ip, 64);
    whirl_compress(h, msg, t, ik); whirl_compress(h, pad, t, NULL);
    memcpy(out, op, 64);
    whirl_compress(out, h, t, ok); whirl_compress(out, pad, t, NULL);
}

/* Salt is exactly 64 bytes; TrueCrypt uses 1,000 iterations and a 64-byte XTS key. */
static int whirl_scalar(const uint8_t* salt, const uint8_t* pws, int len, int n, uint8_t* out)
{
    if (len < 0 || len > 64 || n < 0) return -1;
    uint64_t t[8][256] __attribute__((aligned(64)));
    whirl_tables(t);
    uint64_t sm[8]; for (int i = 0; i < 8; i++) sm[i] = whirl_load(salt + 8*i);
    const uint64_t first_pad[8] = { 0x0000000180000000ULL, 0, 0, 0, 0, 0, 0, 1056 };
    const uint64_t pad[8] = { 0x8000000000000000ULL, 0, 0, 0, 0, 0, 0, 1024 };
    for (int c = 0; c < n; c++)
    {
        uint8_t pw[64] = {0}; if (len) memcpy(pw, pws + (size_t)c*len, len);
        uint64_t ip[8] = {0}, op[8] = {0}, m[8], ik[10][8], ok[10][8];
        for (int i = 0; i < 8; i++) m[i] = whirl_load(pw+8*i) ^ 0x3636363636363636ULL;
        whirl_compress(ip, m, t, NULL);
        for (int i = 0; i < 8; i++) m[i] ^= 0x6a6a6a6a6a6a6a6aULL;
        whirl_compress(op, m, t, NULL);
        whirl_keys(ik, ip, t); whirl_keys(ok, op, t);
        uint64_t h[8], u[8], dk[8]; memcpy(h, ip, 64);
        whirl_compress(h, sm, t, ik); whirl_compress(h, first_pad, t, NULL);
        memcpy(u, op, 64); whirl_compress(u, h, t, ok); whirl_compress(u, pad, t, NULL);
        memcpy(dk, u, 64);
        for (int r = 1; r < 1000; r++)
        {
            whirl_hmac64(u, u, ip, op, ik, ok, t);
            for (int i = 0; i < 8; i++) dk[i] ^= u[i];
        }
        for (int i = 0; i < 8; i++) whirl_store(out+(size_t)c*64+8*i, dk[i]);
    }
    return n;
}

typedef int (*whirl_derive_fn)(const uint8_t*, const uint8_t*, int, int, uint8_t*);
#include "whirlpool_selftest.h"

RK_EXPORT void rk_whirlpool_set_avx512(int enabled) { atomic_store(&g_whirl_avx512, enabled != 0); }

static int whirl_wide_enabled(void)
{
    const char* value = getenv("RECOVERKIT_WHIRLPOOL_AVX512");
    if (value && strcmp(value, "0") == 0) return 0;
    if (value && strcmp(value, "1") == 0) return 1;
    return atomic_load(&g_whirl_avx512);
}

#if RK_X64
#include "whirlpool_avx512.h"

static int whirl_wide_ok(void)
{
    if (!whirl_wide_enabled()) return 0;
    int state = atomic_load(&g_whirl_wide_test);
    if (state == 0 && atomic_compare_exchange_strong(&g_whirl_wide_test, &state, 1))
    {
        state = whirl_selftest(whirl_avx512) ? 2 : 3;
        atomic_store(&g_whirl_wide_test, state);
    }
    return state == 2;
}
#endif

RK_EXPORT int rk_whirlpool_lanes(void)
{
#if RK_X64
    if ((features() & RK_FEAT_AVX512) && whirl_wide_ok()) return 8;
#endif
    return 1;
}

RK_EXPORT int rk_whirlpool_selftest_state(void)
{
    if (!whirl_wide_enabled()) return 3;
    return wide_selftest_state("RECOVERKIT_WHIRLPOOL_AVX512", &g_whirl_wide_test);
}

RK_EXPORT int rk_whirlpool_executed_paths(void) { return atomic_load(&g_whirl_paths); }

RK_EXPORT int rk_whirlpool_pbkdf2(const uint8_t* salt, const uint8_t* pws, int len, int n, uint8_t* out)
{
    if (len < 0 || len > 64 || n < 0) return -1;
    if (n == 0) return 0;
#if RK_X64
    if (rk_whirlpool_lanes() == 8)
    {
        atomic_fetch_or(&g_whirl_paths, RK_PATH_AVX512);
        return whirl_avx512(salt, pws, len, n, out);
    }
#endif
    atomic_fetch_or(&g_whirl_paths, RK_PATH_SCALAR);
    return whirl_scalar(salt, pws, len, n, out);
}
