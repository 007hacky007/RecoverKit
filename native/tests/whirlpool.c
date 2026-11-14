/* Build with the same compiler as rknative, then run on the target CPU. */
#include "../rknative.c"
#undef NDEBUG
#include <assert.h>
#include <stdio.h>

static int corrupt_whirlpool(const uint8_t* salt, const uint8_t* pws, int len, int n, uint8_t* out)
{
    int result = whirl_scalar(salt, pws, len, n, out);
    out[7 * 64 + 63] ^= 1;
    return result;
}

int main(void)
{
    assert(whirl_selftest(whirl_scalar));
    assert(!whirl_selftest(corrupt_whirlpool));
    puts("Whirlpool scalar known answers: 32 passed; corrupt final lane rejected");
    assert(atomic_load(&g_whirl_avx512) == 0);
    if (!whirl_wide_enabled())
    {
        uint8_t salt[64] = {0}, pw[7] = {0}, expected[64], actual[64];
        whirl_scalar(salt, pw, 7, 1, expected);
        assert(rk_whirlpool_lanes() == 1);
        assert(rk_whirlpool_selftest_state() == 3);
        rk_reset_executed_paths(29331);
        assert(rk_whirlpool_pbkdf2(salt, pw, 7, 1, actual) == 1);
        assert(memcmp(expected, actual, 64) == 0);
        assert(rk_whirlpool_executed_paths() == RK_PATH_SCALAR);
        puts("Whirlpool default/off switch: scalar output and execution state passed");
    }
    rk_whirlpool_set_avx512(1);
    if (wide_switched_off("RECOVERKIT_WHIRLPOOL_AVX512")) assert(rk_whirlpool_lanes() == 1);
#if RK_X64
    if ((features() & RK_FEAT_AVX512) && !wide_switched_off("RECOVERKIT_WHIRLPOOL_AVX512"))
    {
        assert(whirl_selftest(whirl_avx512));
        assert(rk_whirlpool_lanes() == 8);
        assert(rk_whirlpool_selftest_state() == 1);
        /* A failed guard must never reach the vector implementation. */
        uint8_t salt[64] = {0}, pw[7] = {0}, expected[64], actual[64];
        whirl_scalar(salt, pw, 7, 1, expected);
        atomic_store(&g_whirl_wide_test, 3);
        rk_reset_executed_paths(29331);
        assert(rk_whirlpool_pbkdf2(salt, pw, 7, 1, actual) == 1);
        assert(memcmp(expected, actual, 64) == 0);
        assert(rk_whirlpool_executed_paths() == RK_PATH_SCALAR);
        assert(rk_whirlpool_selftest_state() == 2);
        puts("Whirlpool AVX-512 known answers: 32 passed; failed guard fell back to scalar");
    }
    else puts("Whirlpool AVX-512: not executed (unsupported or switched off)");
#else
    puts("Whirlpool AVX-512: not executed (not x86-64)");
#endif
    return 0;
}
