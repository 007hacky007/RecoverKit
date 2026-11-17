/* Office 2007: H0=SHA1(salt || UTF16LE(password)); Hi+1=SHA1(LE32(i) || Hi). */
#define O7_SUFFIX _scalar
#define O7_V uint32_t
#define O7_L 1
#define O7_FN
#define O7_LANE(v,l) (v)
#include "office2007_lanes.h"
#if RK_X64
#define O7_SUFFIX _avx2
#define O7_V v8u
#define O7_L 8
#define O7_FN AVX2
#include "office2007_lanes.h"
#define O7_SUFFIX _avx512
#define O7_V v16u
#define O7_L 16
#define O7_FN AVX512
#include "office2007_lanes.h"
#elif RK_ARM64
#define O7_SUFFIX _neon
#define O7_V uint32x4_t
#define O7_L 4
#define O7_FN
#include "office2007_lanes.h"
#endif
#include "office2007_crypto.h"

typedef void (*office2007_iter_fn)(uint32_t (*)[5], uint32_t);
static atomic_int g_office2007_tests[7];

static void office2007_initial(const uint8_t* pw, int len, const uint8_t* salt, uint32_t h[5])
{
    uint8_t first[64];
    memcpy(h,SHA1_IV,20); memcpy(first,salt,16);
    int take=len<48?len:48;
    if (take) memcpy(first+16,pw,(size_t)take);
    if (len<48) sha1_tail(h,first,(size_t)len+16,0);
    else { sha1_bytes(h,first); sha1_tail(h,pw+48,(size_t)len-48,64); }
}
#include "office2007_selftest.h"

static int office2007_guard(int slot, office2007_iter_fn fn, int lanes)
{
    int state=atomic_load(&g_office2007_tests[slot]);
    if (state==0 && atomic_compare_exchange_strong(&g_office2007_tests[slot],&state,1))
    {
        state=office2007_selftest(fn,lanes)?2:3;
        atomic_store(&g_office2007_tests[slot],state);
    }
    return state==2;
}

/* Slot and path are separate because path values are shared with other native kernels. */
static office2007_iter_fn office2007_requested(int* lanes, int* path, int* slot)
{
    const char* selected=getenv("RECOVERKIT_OFFICE2007_PATH");
    int automatic=!selected || !*selected || strcmp(selected,"default")==0;
    int f=features(); (void)f;
    *lanes=1; *path=RK_PATH_SCALAR; *slot=0;
#if RK_X64
    if ((automatic || strcmp(selected,"avx512")==0) && (f&RK_FEAT_AVX512))
    { *lanes=16; *path=RK_PATH_AVX512; *slot=2; return office2007_iter_avx512; }
    if ((automatic || strcmp(selected,"sha-ni")==0) && (f&RK_FEAT_SHANI))
    { *lanes=O7_SHA_STREAMS; *path=RK_PATH_SHANI; *slot=3; return office2007_iter_shani; }
    if ((automatic || strcmp(selected,"avx2")==0) && (f&RK_FEAT_AVX2))
    { *lanes=8; *path=RK_PATH_AVX2; *slot=1; return office2007_iter_avx2; }
#elif RK_ARM64
    if ((automatic || strcmp(selected,"arm-sha1")==0) && (f&RK_FEAT_ARM_SHA1))
    { *lanes=O7_SHA_STREAMS; *path=RK_PATH_ARM_SHA1; *slot=5; return office2007_iter_armsha1; }
    if ((automatic || strcmp(selected,"neon")==0) && (f&RK_FEAT_NEON))
    { *lanes=4; *path=RK_PATH_NEON; *slot=4; return office2007_iter_neon; }
#endif
    return office2007_iter_scalar;
}

static office2007_iter_fn office2007_path(int* lanes, int* path)
{
    int slot; office2007_iter_fn fn=office2007_requested(lanes,path,&slot);
    if (slot && !(slot==2 && wide_switched_off("RECOVERKIT_OFFICE2007_AVX512")) && office2007_guard(slot,fn,*lanes)) return fn;
    *lanes=1; *path=RK_PATH_SCALAR;
    return office2007_iter_scalar;
}

RK_EXPORT int rk_office2007_selected_path(void) { int lanes,path; office2007_path(&lanes,&path); return path; }
RK_EXPORT int rk_office2007_lanes(void) { int lanes,path; office2007_path(&lanes,&path); return lanes; }
RK_EXPORT int rk_office2007_executed_paths(void) { return atomic_load(&g_office2007_paths); }
RK_EXPORT int rk_office2007_selftest_state(void)
{
    int lanes,path,slot; office2007_requested(&lanes,&path,&slot);
    if (slot==2 && wide_switched_off("RECOVERKIT_OFFICE2007_AVX512")) return 3;
    int state=atomic_load(&g_office2007_tests[slot]);
    return state==2?1:state==3?2:0;
}

/* Output is the 50000-spin digest, before the Office final key derivation. */
RK_EXPORT int rk_office2007_spin(const uint8_t* pws, int stride, const int* lens, int n,
    const uint8_t* salt, uint8_t* hashes)
{
    if (n<0 || stride<0 || !salt || (n && (!hashes || (!pws && stride)))) return -1;
    if (lens) { for (int l=0;l<n;l++) if (lens[l]<0 || lens[l]>stride || (lens[l]&1)) return -1; }
    else if (stride&1) return -1;
    int lanes,path; office2007_iter_fn fn=office2007_path(&lanes,&path);
    if (n) atomic_fetch_or(&g_office2007_paths,path);
    uint32_t h[16][5];
    for (int b=0;b<n;)
    {
        int m=n-b<lanes?n-b:lanes;
        for (int l=0;l<m;l++) office2007_initial(pws?pws+(size_t)(b+l)*stride:NULL,lens?lens[b+l]:stride,salt,h[l]);
        for (int l=m;l<lanes;l++) memcpy(h[l],h[0],20);
        fn(h,50000);
        for (int l=0;l<m;l++) for (int j=0;j<5;j++) put_be32(hashes+(size_t)(b+l)*20+4*j,h[l][j]);
        b+=m;
    }
    return 0;
}
