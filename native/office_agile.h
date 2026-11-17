/* Office Agile shares the Office 2007 SHA1 spin and the PBKDF2 SHA512 compression. */
#define A5_SUFFIX _1
#define A5_V uint64_t
#define A5_L 1
#define A5_FN
#define A5_LANE(v,l) (v)
#include "office_agile_sha512_lanes.h"
#if RK_X64
#define A5_SUFFIX _avx2
#define A5_V sha512_v4
#define A5_L 4
#define A5_FN AVX2
#include "office_agile_sha512_lanes.h"
#define A5_SUFFIX _avx512
#define A5_V sha512_v8
#define A5_L 8
#define A5_FN AVX512
#include "office_agile_sha512_lanes.h"
#elif RK_ARM64
#define A5_SUFFIX _neon
#define A5_V sha512_v2
#define A5_L 2
#define A5_FN
#include "office_agile_sha512_lanes.h"

ARMCE static void office_agile_iter_ce(uint64_t (*hash)[8], uint32_t spins)
{
    uint64x2_t x[SHA512_CE_STREAMS][4];
    for (int l=0;l<SHA512_CE_STREAMS;l++) for (int j=0;j<4;j++) x[l][j]=vld1q_u64(hash[l]+2*j);
    for (uint32_t i=0;i<spins;i++)
    {
        uint64x2_t s[SHA512_CE_STREAMS][4], w[SHA512_CE_STREAMS][8];
        for (int l=0;l<SHA512_CE_STREAMS;l++)
        {
            uint64x2_t previous=vdupq_n_u64(__builtin_bswap32(i));
            for (int j=0;j<4;j++)
            {
                w[l][j]=vorrq_u64(vshlq_n_u64(vextq_u64(previous,x[l][j],1),32),vshrq_n_u64(x[l][j],32));
                previous=x[l][j]; s[l][j]=vld1q_u64(SHA512_IV+2*j);
            }
            w[l][4]=vsetq_lane_u64((vgetq_lane_u64(x[l][3],1)<<32) | UINT64_C(0x80000000),vdupq_n_u64(0),0);
            w[l][5]=w[l][6]=vdupq_n_u64(0);
            w[l][7]=vsetq_lane_u64(544,vdupq_n_u64(0),1);
        }
        sha512_ce_compress(s,w);
        for (int l=0;l<SHA512_CE_STREAMS;l++) for (int j=0;j<4;j++) x[l][j]=s[l][j];
    }
    for (int l=0;l<SHA512_CE_STREAMS;l++) for (int j=0;j<4;j++) vst1q_u64(hash[l]+2*j,x[l][j]);
}
#endif

typedef void (*office_agile_sha512_fn)(uint64_t (*)[8], uint32_t);
static atomic_int g_office_agile_tests[2][7];

static void office_agile_initial_sha512(const uint8_t* pw, int len, const uint8_t* salt, uint64_t h[8])
{
    uint8_t first[128];
    memcpy(h,SHA512_IV,64); memcpy(first,salt,16);
    int take=len<112?len:112;
    if (take) memcpy(first+16,pw,(size_t)take);
    if (len<112) sha512_tail(h,first,(size_t)len+16,0);
    else { sha512_bytes(h,first); sha512_tail(h,pw+112,(size_t)len-112,128); }
}

#include "office_agile_kat.h"

static void office_agile_test_password(uint8_t* pw, int lane, int len)
{
    for (int q=0;q<len;q++) pw[q]=(uint8_t)(q%2==0?1+(lane*17+q*7)%255:(lane*29+q*11)%256);
}

static int office_agile_selftest_sha1(office2007_iter_fn fn, int lanes)
{
    uint8_t pw[512],salt[16]; uint32_t h[16][5];
    for (int j=0;j<16;j++) salt[j]=(uint8_t)j;
    for (int b=0;b<16;b+=lanes)
    {
        int m=16-b<lanes?16-b:lanes;
        for (int l=0;l<lanes;l++)
        {
            int q=b+(l<m?l:0);
            office_agile_test_password(pw,q,AGILE_TEST_LENGTHS[q]);
            office2007_initial(pw,AGILE_TEST_LENGTHS[q],salt,h[l]);
        }
        fn(h,100000);
        for (int l=0;l<m;l++) if (memcmp(h[l],AGILE_9500_ANSWERS[b+l],20)!=0) return 0;
    }
    return 1;
}

static int office_agile_selftest_sha512(office_agile_sha512_fn fn, int lanes)
{
    uint8_t pw[512],salt[16]; uint64_t h[8][8];
    for (int j=0;j<16;j++) salt[j]=(uint8_t)j;
    for (int b=0;b<16;b+=lanes)
    {
        int m=16-b<lanes?16-b:lanes;
        for (int l=0;l<lanes;l++)
        {
            int q=b+(l<m?l:0);
            office_agile_test_password(pw,q,AGILE_TEST_LENGTHS[q]);
            office_agile_initial_sha512(pw,AGILE_TEST_LENGTHS[q],salt,h[l]);
        }
        fn(h,100000);
        for (int l=0;l<m;l++) if (memcmp(h[l],AGILE_9600_ANSWERS[b+l],64)!=0) return 0;
    }
    return 1;
}

/* Slots match Office 2007; the two modes have independent guards and switches. */
static int office_agile_requested(int mode, int* lanes, int* slot)
{
    const char* selected=getenv(mode==9500?"RECOVERKIT_OFFICE2010_PATH":"RECOVERKIT_OFFICE2013_PATH");
    int automatic=!selected || !*selected || strcmp(selected,"default")==0;
    int f=features(); (void)f;
    *lanes=1; *slot=0;
#if RK_X64
    if ((automatic || strcmp(selected,"avx512")==0) && (f&RK_FEAT_AVX512))
    { *lanes=mode==9500?16:8; *slot=2; return RK_PATH_AVX512; }
    if (mode==9500 && (automatic || strcmp(selected,"sha-ni")==0) && (f&RK_FEAT_SHANI))
    { *lanes=O7_SHA_STREAMS; *slot=3; return RK_PATH_SHANI; }
    if ((automatic || strcmp(selected,"avx2")==0) && (f&RK_FEAT_AVX2))
    { *lanes=mode==9500?8:4; *slot=1; return RK_PATH_AVX2; }
#elif RK_ARM64
    if (mode==9500 && (automatic || strcmp(selected,"arm-sha1")==0) && (f&RK_FEAT_ARM_SHA1))
    { *lanes=O7_SHA_STREAMS; *slot=5; return RK_PATH_ARM_SHA1; }
    if (mode==9600 && (automatic || strcmp(selected,"arm-sha512")==0) && (f&RK_FEAT_ARM_SHA512))
    { *lanes=SHA512_CE_STREAMS; *slot=6; return RK_PATH_ARM_SHA512; }
    if ((automatic || strcmp(selected,"neon")==0) && (f&RK_FEAT_NEON))
    { *lanes=mode==9500?4:2; *slot=4; return RK_PATH_NEON; }
#endif
    return RK_PATH_SCALAR;
}

static office2007_iter_fn office_agile_sha1_fn(int path)
{
    switch (path)
    {
#if RK_X64
        case RK_PATH_AVX2: return office2007_iter_avx2;
        case RK_PATH_AVX512: return office2007_iter_avx512;
        case RK_PATH_SHANI: return office2007_iter_shani;
#elif RK_ARM64
        case RK_PATH_NEON: return office2007_iter_neon;
        case RK_PATH_ARM_SHA1: return office2007_iter_armsha1;
#endif
        default: return office2007_iter_scalar;
    }
}

static office_agile_sha512_fn office_agile_sha512_path_fn(int path)
{
    switch (path)
    {
#if RK_X64
        case RK_PATH_AVX2: return office_agile_iter_avx2;
        case RK_PATH_AVX512: return office_agile_iter_avx512;
#elif RK_ARM64
        case RK_PATH_NEON: return office_agile_iter_neon;
        case RK_PATH_ARM_SHA512: return office_agile_iter_ce;
#endif
        default: return office_agile_iter_1;
    }
}

static int office_agile_wide_off(int mode, int slot)
{
    return slot==2 && wide_switched_off(mode==9500?"RECOVERKIT_OFFICE2010_AVX512":"RECOVERKIT_OFFICE2013_AVX512");
}

static int office_agile_path(int mode, int* lanes)
{
    int slot, path=office_agile_requested(mode,lanes,&slot);
    if (!slot) return path;
    atomic_int* guard=&g_office_agile_tests[mode==9600][slot];
    if (!office_agile_wide_off(mode,slot))
    {
        int state=atomic_load(guard);
        if (state==0 && atomic_compare_exchange_strong(guard,&state,1))
        {
            int ok=mode==9500?office_agile_selftest_sha1(office_agile_sha1_fn(path),*lanes)
                :office_agile_selftest_sha512(office_agile_sha512_path_fn(path),*lanes);
            state=ok?2:3;
            atomic_store(guard,state);
        }
        if (state==2) return path;
    }
    *lanes=1;
    return RK_PATH_SCALAR;
}

RK_EXPORT int rk_office_agile_selected_path(int mode)
{
    if (mode!=9500 && mode!=9600) return -1;
    int lanes; return office_agile_path(mode,&lanes);
}
RK_EXPORT int rk_office_agile_lanes(int mode)
{
    if (mode!=9500 && mode!=9600) return -1;
    int lanes; office_agile_path(mode,&lanes); return lanes;
}
RK_EXPORT int rk_office_agile_executed_paths(int mode)
{
    return mode==9500 || mode==9600?atomic_load(&g_office_agile_paths[mode==9600]):-1;
}
RK_EXPORT int rk_office_agile_selftest_state(int mode)
{
    if (mode!=9500 && mode!=9600) return -1;
    int lanes,slot; office_agile_requested(mode,&lanes,&slot);
    if (office_agile_wide_off(mode,slot)) return 3;
    int state=atomic_load(&g_office_agile_tests[mode==9600][slot]);
    return state==2?1:state==3?2:0;
}

/* Passwords are already UTF16LE. Output is the raw spin digest, in digest byte order. */
RK_EXPORT int rk_office_agile_spin(int mode, const uint8_t* pws, int stride, const int* lens, int n,
    const uint8_t* salt, uint32_t spins, uint8_t* hashes)
{
    if ((mode!=9500 && mode!=9600) || n<0 || stride<0 || !salt || (n && (!hashes || (!pws && stride)))) return -1;
    if (lens)
    { for (int l=0;l<n;l++) if (lens[l]<0 || lens[l]>stride || lens[l]>512 || (lens[l]&1)) return -1; }
    else if (stride>512 || (stride&1)) return -1;
    if (!n) return 0;
    int lanes,path=office_agile_path(mode,&lanes);
    atomic_fetch_or(&g_office_agile_paths[mode==9600],spins?path:RK_PATH_SCALAR);
    office2007_iter_fn fn1=office_agile_sha1_fn(path);
    office_agile_sha512_fn fn512=office_agile_sha512_path_fn(path);
    uint32_t h1[16][5]; uint64_t h512[8][8];
    for (int b=0;b<n;)
    {
        int m=n-b<lanes?n-b:lanes;
        for (int l=0;l<m;l++)
        {
            const uint8_t* pw=pws?pws+(size_t)(b+l)*stride:NULL;
            int len=lens?lens[b+l]:stride;
            if (mode==9500) office2007_initial(pw,len,salt,h1[l]);
            else office_agile_initial_sha512(pw,len,salt,h512[l]);
        }
        if (mode==9500)
        {
            for (int l=m;l<lanes;l++) memcpy(h1[l],h1[0],20);
            if (spins) fn1(h1,spins);
            for (int l=0;l<m;l++) for (int j=0;j<5;j++) put_be32(hashes+(size_t)(b+l)*20+4*j,h1[l][j]);
        }
        else
        {
            for (int l=m;l<lanes;l++) memcpy(h512[l],h512[0],64);
            if (spins) fn512(h512,spins);
            for (int l=0;l<m;l++) for (int j=0;j<8;j++) sha512_put_be64(hashes+(size_t)(b+l)*64+8*j,h512[l][j]);
        }
        b+=m;
    }
    return 0;
}
