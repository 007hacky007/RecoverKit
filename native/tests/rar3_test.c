/* Standalone checks for the startup guard, including a mismatch in the last IV byte of lane 31.
 * Build with the same CFLAGS as build.sh, then run on the host (or x64 under Rosetta).
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static int fail_next_allocation;
static void* test_malloc(size_t bytes)
{
    if (fail_next_allocation) { fail_next_allocation = 0; return NULL; }
    return malloc(bytes);
}

#define malloc test_malloc
#include "../rknative.c"
#undef malloc

#if RK_VEC
static int corrupt_last_lane(const rar3_layout* L, const uint8_t* pws, int n, uint8_t* out)
{
    int ran = rar3_vec_8(L, pws, n, out);
    out[36 * n - 1] ^= 1;
    return ran;
}

static int fail_vector_allocation(const rar3_layout* L, const uint8_t* pws, int n, uint8_t* out)
{
    fail_next_allocation = 1;
    int ran = rar3_vec_8(L, pws, n, out);
    // The ordinary call must still produce the correct scalar result.
    assert(memcmp(out, RAR3_TEST_ANSWERS[0], 32 * 36) == 0);
    return ran;
}
#endif

int main(void)
{
    int f = rk_features();
    printf("features=%d, RAR3 batch=%d\n", f, rk_rar3_lanes());
#if RK_VEC
    if (f & RK_FEAT_VEC)
    {
        assert(rar3_selftest(rar3_vec_8));
        assert(!rar3_selftest(corrupt_last_lane));
        assert(!rar3_selftest(fail_vector_allocation));
        puts("narrow known answers: passed; corrupt lane 31 IV and allocation fallback: rejected");
    }
    else puts("narrow known answers: skipped (no vector ISA)");
#endif
#if RK_X64
    /* A cached failure must keep selecting AVX2, including on an AVX-512 host. */
    atomic_store(&g_rar3_wide_test, 3);
    assert(!rar3_wide_ok());
    assert(rk_rar3_lanes() == ((f & RK_FEAT_AVX2) ? 16 : 1));
    puts("failed self-test fallback: passed");
#endif
    rk_set_features(0);
    assert(rk_rar3_lanes() == 1);
    puts("scalar selection: passed");
    return 0;
}
