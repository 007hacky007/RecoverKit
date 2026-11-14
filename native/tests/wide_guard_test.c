/* Host checks for guard state and actual execution; never execute AVX-512 here. */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static int allocations_until_failure;
static void* test_malloc(size_t bytes)
{
    if (allocations_until_failure && --allocations_until_failure == 0) return NULL;
    return malloc(bytes);
}
#define malloc test_malloc
#include "../rknative.c"
#undef malloc

static void scalar16(const uint32_t (*ist)[8], const uint32_t (*ost)[8], uint32_t (*u)[8], uint32_t iter)
{
    for (int l = 0; l < 16; l++) pbkdf2_sha256_iter_1(ist + l, ost + l, u + l, iter);
}

#if RK_VEC
static void narrow16(const uint32_t (*ist)[8], const uint32_t (*ost)[8], uint32_t (*u)[8], uint32_t iter)
{
    for (int l = 0; l < 16; l += 8)
#if RK_X64
        pbkdf2_sha256_iter_avx2(ist + l, ost + l, u + l, iter);
#else
        pbkdf2_sha256_iter_neon(ist + l, ost + l, u + l, iter);
#endif
}
#endif

static void corrupt_last_lane(const uint32_t (*ist)[8], const uint32_t (*ost)[8], uint32_t (*u)[8], uint32_t iter)
{
    scalar16(ist, ost, u, iter);
    u[15][7] ^= 1;
}

int main(void)
{
    int f = rk_features();
    unsetenv("RECOVERKIT_RAR3_AVX512");
    unsetenv("RECOVERKIT_RAR5_AVX512");
    assert(rk_rar3_selftest_state() == 0);
    assert(rk_pbkdf2_sha256_selftest_state() == 0);
    assert(rk_rar3_executed_paths() == 0);
    assert(rk_pbkdf2_sha256_executed_paths() == 0);
    atomic_store(&g_rar3_wide_test, 1);
    atomic_store(&g_pbkdf2_wide_test, 1);
    assert(rk_rar3_selftest_state() == 0);
    assert(rk_pbkdf2_sha256_selftest_state() == 0);
    assert(atomic_load(&g_rar3_wide_test) == 1);
    assert(atomic_load(&g_pbkdf2_wide_test) == 1);
    assert(pbkdf2_sha256_selftest(scalar16));
    assert(!pbkdf2_sha256_selftest(corrupt_last_lane));
    assert(rk_pbkdf2_sha256_executed_paths() == 0);
    atomic_store(&g_rar3_wide_test, 2);
    atomic_store(&g_pbkdf2_wide_test, 2);
    assert(rk_rar3_selftest_state() == 1);
    assert(rk_pbkdf2_sha256_selftest_state() == 1);
    setenv("RECOVERKIT_RAR3_AVX512", "0", 1);
    setenv("RECOVERKIT_RAR5_AVX512", "0", 1);
    assert(rk_rar3_selftest_state() == 3);
    assert(rk_pbkdf2_sha256_selftest_state() == 3);
#if RK_X64
    g_features = f | RK_FEAT_AVX512; /* Selection only: the cached/off guards must reject it. */
#endif
    assert(rk_rar3_lanes() <= 16);
    assert(rk_pbkdf2_sha256_lanes() <= 8);
    assert(rk_rar3_executed_paths() == 0);
    assert(rk_pbkdf2_sha256_executed_paths() == 0);
    setenv("RECOVERKIT_RAR3_AVX512", "1", 1);
    setenv("RECOVERKIT_RAR5_AVX512", "1", 1);
    atomic_store(&g_rar3_wide_test, 3);
    atomic_store(&g_pbkdf2_wide_test, 3);
    assert(rk_rar3_selftest_state() == 2);
    assert(rk_pbkdf2_sha256_selftest_state() == 2);
    assert(rk_rar3_lanes() <= 16);
    assert(rk_pbkdf2_sha256_lanes() <= 8);
#if RK_VEC
    if (f & RK_FEAT_VEC) assert(pbkdf2_sha256_selftest(narrow16));
#endif
    assert(rk_pbkdf2_sha256_executed_paths() == 0);
    rk_set_features(f & ~RK_FEAT_AVX512);
    int lanes = rk_pbkdf2_sha256_lanes();
    assert(lanes <= 8);
    assert(rk_pbkdf2_sha256_executed_paths() == 0);
    uint8_t pw = 0x21, dk[32], out[36], salt[8] = { 0x45, 0x10, 0x9a, 0xf8, 0xab, 0x5f, 0x29, 0x7a };
    assert(rk_pbkdf2_sha256(&pw, 1, NULL, 0, salt, 8, 7, dk, 32) == 0);
    assert(rk_pbkdf2_sha256_executed_paths() == 0);
    assert(rk_pbkdf2_sha256(&pw, 1, NULL, 1, salt, 8, 7, dk, 32) == 0);
    int path = 1;
#if RK_X64
    if (f & RK_FEAT_AVX2) path = 2;
#elif RK_ARM64
    if (f & RK_FEAT_ARM_SHA2) path = 16;
    else if (f & RK_FEAT_NEON) path = 8;
#endif
    assert(rk_pbkdf2_sha256_executed_paths() == path);
    static const uint8_t want[32] = { 0xa0, 0xd7, 0xdd, 0xfa, 0x38, 0xb0, 0x66, 0xb3, 0xe0, 0x7b, 0x69, 0x00, 0x8e, 0x3b, 0x19, 0xcf, 0x8a, 0x27, 0xc8, 0xdf, 0xe8, 0x6d, 0x96, 0xff, 0xa0, 0xcf, 0x1d, 0x52, 0xf7, 0xa7, 0x03, 0x57 };
    assert(memcmp(dk, want, 32) == 0);
#if RK_ARM64
    if (f & RK_FEAT_NEON)
    {
        rk_set_features(RK_FEAT_NEON);
        assert(rk_pbkdf2_sha256(&pw, 1, NULL, 1, salt, 8, 7, dk, 32) == 0);
        assert(memcmp(dk, want, 32) == 0);
        path |= 8;
        assert(rk_pbkdf2_sha256_executed_paths() == path);
    }
#endif
    assert(rk_pbkdf2_sha256(&pw, 1, NULL, 1, salt, 8, 1, dk, 32) == 0);
    assert(rk_pbkdf2_sha256_executed_paths() == (path | 1));
    rk_set_features(0);
    assert(rk_pbkdf2_sha256(&pw, 1, NULL, 1, salt, 8, 7, dk, 32) == 0);
    assert(rk_pbkdf2_sha256_executed_paths() == (path | 1));
    assert(memcmp(dk, want, 32) == 0);
    assert(rk_rar3_hash(salt, &pw, 0, 1, out) == -1);
    assert(rk_rar3_executed_paths() == 0);
#if RK_VEC
    rk_set_features(f & ~RK_FEAT_AVX512);
    if (f & RK_FEAT_VEC)
    {
        allocations_until_failure = 2; /* layout succeeds, vector scratch fails */
        assert(rk_rar3_hash(salt, &pw, 1, 1, out) == 0);
        assert(memcmp(out, RAR3_TEST_ANSWERS[0][0], 36) == 0);
        assert(rk_rar3_executed_paths() == 1);
        assert(rk_rar3_hash(salt, &pw, 1, 1, out) == 0);
        assert(memcmp(out, RAR3_TEST_ANSWERS[0][0], 36) == 0);
#if RK_X64
        assert(rk_rar3_executed_paths() == (1 | 2));
#else
        assert(rk_rar3_executed_paths() == (1 | 8));
#endif
    }
#endif
    rk_set_features(0);
    assert(rk_rar3_hash(salt, &pw, 1, 1, out) == 0);
    int rar3_paths = rk_rar3_executed_paths(), pbkdf2_paths = rk_pbkdf2_sha256_executed_paths();
    rk_reset_executed_paths(0);
    assert(rk_rar3_executed_paths() == rar3_paths);
    assert(rk_pbkdf2_sha256_executed_paths() == pbkdf2_paths);
    rk_reset_executed_paths(13000);
    assert(rk_rar3_executed_paths() == rar3_paths);
    assert(rk_pbkdf2_sha256_executed_paths() == 0);
    assert(rk_pbkdf2_sha256(&pw, 1, NULL, 1, salt, 8, 7, dk, 32) == 0);
    rk_reset_executed_paths(12500);
    assert(rk_rar3_executed_paths() == 0);
    assert(rk_pbkdf2_sha256_executed_paths() == 1);
    rk_reset_executed_paths(13000);
    assert(rk_pbkdf2_sha256_executed_paths() == 0);
    assert(rk_rar3_selftest_state() == 2);
    assert(rk_pbkdf2_sha256_selftest_state() == 2);
    puts("guard known answers, mismatch rejection, state queries, off switches, executed paths, and scoped resets: passed");
    return 0;
}
