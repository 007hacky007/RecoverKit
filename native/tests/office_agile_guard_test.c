/* Build as a standalone executable with the native build flags, then run on the host. */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include "../rknative.c"

static void corrupt_sha1(uint32_t (*h)[5], uint32_t spins)
{
    for (int l=0;l<16;l++) office2007_iter_scalar(h+l,spins);
    h[15][4]^=1;
}

static void corrupt_sha512(uint64_t (*h)[8], uint32_t spins)
{
    for (int l=0;l<8;l++) office_agile_iter_1(h+l,spins);
    h[7][7]^=1;
}

static void check_path(int mode, const char* selected, int expected, int slot)
{
    const char* env=mode==9500?"RECOVERKIT_OFFICE2010_PATH":"RECOVERKIT_OFFICE2013_PATH";
    const char* wide=mode==9500?"RECOVERKIT_OFFICE2010_AVX512":"RECOVERKIT_OFFICE2013_AVX512";
    int index=mode==9600;
    uint8_t salt[16],output[64],want[64];
    for (int j=0;j<16;j++) salt[j]=(uint8_t)j;
    if (mode==9500) for (int j=0;j<5;j++) put_be32(want+4*j,AGILE_9500_ANSWERS[0][j]);
    else for (int j=0;j<8;j++) sha512_put_be64(want+8*j,AGILE_9600_ANSWERS[0][j]);
    int other=atomic_load(&g_office_agile_tests[!index][slot]);
    setenv(env,selected,1); unsetenv(wide);
    assert(rk_office_agile_selftest_state(mode)==0);
    assert(rk_office_agile_selected_path(mode)==expected);
    assert(rk_office_agile_selftest_state(mode)==1);
    assert(rk_office_agile_executed_paths(mode)==0);
    assert(atomic_load(&g_office_agile_tests[!index][slot])==other);
    assert(rk_office_agile_spin(mode,NULL,0,NULL,1,salt,100000,output)==0);
    assert(memcmp(output,want,mode==9500?20:64)==0);
    assert(rk_office_agile_executed_paths(mode)==expected);
    rk_reset_executed_paths(mode);
    for (int state=1;state<=3;state+=2)
    {
        atomic_store(&g_office_agile_tests[index][slot],state);
        assert(rk_office_agile_selftest_state(mode)==(state==3?2:0));
        assert(rk_office_agile_selected_path(mode)==RK_PATH_SCALAR);
        assert(rk_office_agile_lanes(mode)==1);
        assert(rk_office_agile_spin(mode,NULL,0,NULL,1,salt,100000,output)==0);
        assert(memcmp(output,want,mode==9500?20:64)==0);
        assert(rk_office_agile_executed_paths(mode)==RK_PATH_SCALAR);
        rk_reset_executed_paths(mode);
    }
    atomic_store(&g_office_agile_tests[index][slot],2);
    if (slot==2)
    {
        setenv(wide,"0",1);
        assert(rk_office_agile_selected_path(mode)==RK_PATH_SCALAR);
        assert(rk_office_agile_selftest_state(mode)==3);
        unsetenv(wide);
    }
    unsetenv(env);
    printf("%d %s guard, failed/testing fallback, and execution state passed\n",mode,selected);
}

int main(void)
{
    assert(rk_version()==19);
    assert(office2007_selftest(office2007_iter_scalar,1));
    assert(office_agile_selftest_sha1(office2007_iter_scalar,1));
    assert(office_agile_selftest_sha512(office_agile_iter_1,1));
    assert(!office_agile_selftest_sha1(corrupt_sha1,16));
    assert(!office_agile_selftest_sha512(corrupt_sha512,8));
    int f=features();
#if RK_X64
    if (f&RK_FEAT_AVX2) { check_path(9500,"avx2",RK_PATH_AVX2,1); check_path(9600,"avx2",RK_PATH_AVX2,1); }
    if (f&RK_FEAT_SHANI) check_path(9500,"sha-ni",RK_PATH_SHANI,3);
    if (f&RK_FEAT_AVX512) { check_path(9500,"avx512",RK_PATH_AVX512,2); check_path(9600,"avx512",RK_PATH_AVX512,2); }
#elif RK_ARM64
    if (f&RK_FEAT_NEON) { check_path(9500,"neon",RK_PATH_NEON,4); check_path(9600,"neon",RK_PATH_NEON,4); }
    if (f&RK_FEAT_ARM_SHA1) check_path(9500,"arm-sha1",RK_PATH_ARM_SHA1,5);
    if (f&RK_FEAT_ARM_SHA512) check_path(9600,"arm-sha512",RK_PATH_ARM_SHA512,6);
#endif
    atomic_store(&g_office_agile_paths[0],2); atomic_store(&g_office_agile_paths[1],4);
    rk_reset_executed_paths(9500);
    assert(rk_office_agile_executed_paths(9500)==0 && rk_office_agile_executed_paths(9600)==4);
    atomic_store(&g_office_agile_paths[0],2);
    rk_reset_executed_paths(9600);
    assert(rk_office_agile_executed_paths(9500)==2 && rk_office_agile_executed_paths(9600)==0);
    assert(atomic_load(&g_office2007_tests[4])==0 && atomic_load(&g_sha512_tests[3])==0);
    puts("Agile full-spin known answers, final-lane corruption, independent guards and scoped resets passed");
    return 0;
}
