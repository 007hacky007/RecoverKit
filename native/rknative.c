/*
 * rknative - RecoverKit's native CPU kernels.
 *
 * Plain C with compiler intrinsics. Every vector path is compiled with a per-function target
 * attribute and chosen at run time, so the library loads on any x86-64 (or arm64) CPU. On arm64
 * the 8-lane AVX2 kernels run on NEON register pairs (clang vector types, the same source), and
 * PDF R6 uses the ARMv8 AES / SHA-2 / SHA-512 instructions. The .NET side keeps its managed
 * kernels as a fallback when this library is missing.
 *
 * Built with build.sh (zig cc) for win-x64 and osx-arm64.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>

#if defined(_WIN32)
#define RK_EXPORT __declspec(dllexport)
#else
#define RK_EXPORT __attribute__((visibility("default")))
#endif

#if defined(__x86_64__) || defined(_M_X64)
#define RK_X64 1
#include <immintrin.h>
#define AVX2 __attribute__((target("avx2")))
#define AVX512 __attribute__((target("avx512f,evex512")))
#elif defined(__aarch64__)
#define RK_ARM64 1
#include <arm_neon.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <sys/auxv.h>
#endif
/* ARMv8 Crypto Extensions; clang puts the SHA-512 instructions under "sha3". */
#define ARMCE __attribute__((target("aes,sha2,sha3")))
#endif
#if defined(RK_X64) || defined(RK_ARM64)
#define RK_VEC 1                /* the 16-lane MD5 / SHA-1 kernels and the RC4 filters */
#endif

#define RK_API_VERSION 15

enum
{
    RK_FEAT_AVX2 = 1, RK_FEAT_SHANI = 2, RK_FEAT_AESNI = 4, RK_FEAT_NEON = 8,
    RK_FEAT_ARM_AES = 16, RK_FEAT_ARM_SHA1 = 32, RK_FEAT_ARM_SHA2 = 64, RK_FEAT_ARM_SHA512 = 128, RK_FEAT_ARM_SHA3 = 256,
    RK_FEAT_ARM_CRC = 1024,
    RK_FEAT_AVX512 = 512,      /* AVX-512 F with the OS saving the ZMM state: 16-lane vector paths */
};

/* The feature that enables the 16-lane vector kernels on this architecture. */
#if RK_X64
#define RK_FEAT_VEC RK_FEAT_AVX2
#elif RK_ARM64
#define RK_FEAT_VEC RK_FEAT_NEON
#endif

static int g_features = -1;

static int detect_features(void)
{
    int f = 0;
#if RK_X64
    unsigned a, b, c, d, xlo = 0, xhi = 0;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0), "c"(0));
    unsigned maxLeaf = a;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    unsigned ecx1 = c;
    if (ecx1 & (1u << 25)) f |= RK_FEAT_AESNI;
    int osAvx = 0;
    if ((ecx1 & (1u << 27)) && (ecx1 & (1u << 28)))   /* OSXSAVE + AVX: the OS saves YMM state? */
    {
        __asm__ volatile("xgetbv" : "=a"(xlo), "=d"(xhi) : "c"(0));
        osAvx = (xlo & 6) == 6;
    }
    if (maxLeaf >= 7)
    {
        __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(7), "c"(0));
        if (osAvx && (b & (1u << 5))) f |= RK_FEAT_AVX2;
        if (b & (1u << 29)) f |= RK_FEAT_SHANI;
        if (osAvx && (b & (1u << 16)) && (xlo & 0xe0) == 0xe0) f |= RK_FEAT_AVX512;   /* AVX512F; XCR0 opmask + ZMM */
    }
#elif RK_ARM64
    f |= RK_FEAT_NEON;      /* Advanced SIMD is mandatory on AArch64 */
#if defined(__APPLE__)
    static const struct { const char* name; int bit; } arm[] = {
        { "hw.optional.arm.FEAT_CRC32", RK_FEAT_ARM_CRC },
        { "hw.optional.arm.FEAT_AES", RK_FEAT_ARM_AES }, { "hw.optional.arm.FEAT_SHA1", RK_FEAT_ARM_SHA1 },
        { "hw.optional.arm.FEAT_SHA256", RK_FEAT_ARM_SHA2 }, { "hw.optional.arm.FEAT_SHA512", RK_FEAT_ARM_SHA512 },
        { "hw.optional.arm.FEAT_SHA3", RK_FEAT_ARM_SHA3 },
    };
    for (size_t i = 0; i < sizeof arm / sizeof arm[0]; i++)
    {
        int v = 0;
        size_t sz = sizeof v;
        if (sysctlbyname(arm[i].name, &v, &sz, NULL, 0) == 0 && v) f |= arm[i].bit;
    }
#elif defined(__linux__)
    unsigned long hw = getauxval(AT_HWCAP);
    if (hw & (1ul << 7)) f |= RK_FEAT_ARM_CRC;
    if (hw & (1ul << 3)) f |= RK_FEAT_ARM_AES;
    if (hw & (1ul << 5)) f |= RK_FEAT_ARM_SHA1;
    if (hw & (1ul << 6)) f |= RK_FEAT_ARM_SHA2;
    if (hw & (1ul << 17)) f |= RK_FEAT_ARM_SHA3;
    if (hw & (1ul << 21)) f |= RK_FEAT_ARM_SHA512;
#endif
#endif
    return f;
}

/* Feature mask; the caller may clear bits through rk_set_features (benchmarks, tests). */
static int features(void)
{
    if (g_features < 0) g_features = detect_features();
    return g_features;
}

RK_EXPORT int rk_version(void) { return RK_API_VERSION; }
RK_EXPORT int rk_features(void) { return features(); }
RK_EXPORT void rk_set_features(int mask) { g_features = detect_features() & mask; }

static void* aligned_buf(size_t bytes, void** raw)
{
    *raw = malloc(bytes + 63);
    if (!*raw) return NULL;
    return (void*)(((uintptr_t)*raw + 63) & ~(uintptr_t)63);
}

/* ------------------------------------------------------------------------------------------ */
/* Scalar SHA-1                                                                                */
/* ------------------------------------------------------------------------------------------ */

static inline uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static const uint32_t SHA1_IV[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u };

static void sha1_expand(uint32_t* w)
{
    for (int t = 16; t < 80; t++) w[t] = rol32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
}

static void sha1_rounds(uint32_t st[5], const uint32_t* w)
{
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4];
    for (int t = 0; t < 80; t++)
    {
        uint32_t f, k;
        if (t < 20) { f = d ^ (b & (c ^ d)); k = 0x5A827999u; }
        else if (t < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1u; }
        else if (t < 60) { f = (b & c) | (d & (b | c)); k = 0x8F1BBCDCu; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6u; }
        uint32_t tmp = rol32(a, 5) + f + e + k + w[t];
        e = d; d = c; c = rol32(b, 30); b = a; a = tmp;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e;
}

static void sha1_block(uint32_t st[5], const uint32_t* w16)
{
    uint32_t w[80];
    memcpy(w, w16, 64);
    sha1_expand(w);
    sha1_rounds(st, w);
}

/* ------------------------------------------------------------------------------------------ */
/* RAR 3.x key derivation (hashcat 12500)                                                       */
/*                                                                                            */
/* SHA-1 over 262,144 rounds of (UTF-16LE password || 8-byte salt || 24-bit LE counter). One    */
/* round is P = 2L + 11 bytes; P is odd, so the layout over 64-byte blocks repeats every 64      */
/* rounds (P blocks, a "period"). Inside a period every message byte is either template          */
/* (password prefix, salt, low counter byte r), one of the period's counter bytes, or the        */
/* candidate's last character.                                                                 */
/*                                                                                            */
/* The SHA-1 message schedule is linear over XOR, and those three parts occupy disjoint bytes,   */
/* so W = Exp(template + counters) ^ Exp(last character). The first part is the same for every   */
/* candidate and is expanded once per period for all blocks; the second depends only on the     */
/* block and the candidate, so it is expanded once per candidate group. The hot loop then needs  */
/* no schedule computation at all: one broadcast and one XOR per word.                         */
/* ------------------------------------------------------------------------------------------ */

#define RAR3_ROUNDS 0x40000
#define RAR3_PERIODS (RAR3_ROUNDS / 64)
#define RAR3_MAXLEN 26
#define RAR3_NBP 64              /* fixed column stride of the shared schedule: constant offsets in the hot loop */

typedef struct
{
    int len, p, nb, nbp;        /* password length, bytes per round, blocks per period, column stride */
    uint32_t tpl[64 * 16];      /* template words, block-major */
    uint32_t m0[64 * 16], m1[64 * 16], m2[64 * 16];   /* counter byte masks */
    uint8_t nent[64 * 16];      /* lane-dependent password bytes in the word (0..2) */
    uint8_t entq[64 * 16][2];   /* their password positions */
    uint8_t ents[64 * 16][2];   /* and shifts */
    uint32_t lcm[64];           /* per block: bit j set when message word j holds a lane-dependent byte */
    int ctr[64 * 16], nctr;     /* words that contain counter bytes */
} rar3_layout;

/*
 * Layout for n candidates of one length. Password positions that are equal in every candidate go
 * into the shared template; the others ("lane bytes") are applied per lane. Candidates handed in
 * together usually differ only in their last one or two characters.
 */
static void rar3_layout_init(rar3_layout* L, const uint8_t* salt, const uint8_t* pws, int len, int n)
{
    memset(L, 0, sizeof *L);
    int p = 2 * len + 11;
    L->len = len; L->p = p; L->nb = p; L->nbp = RAR3_NBP;
    uint8_t vary[RAR3_MAXLEN] = { 0 };
    for (int i = 1; i < n; i++)
        for (int q = 0; q < len; q++)
            if (pws[i * len + q] != pws[q]) vary[q] = 1;
    uint8_t tpl[64 * 64] = { 0 }, role[64 * 64] = { 0 };   /* 0 template, 1..3 counter byte, 4+q lane byte q */
    for (int r = 0; r < 64; r++)
    {
        int o = r * p;
        for (int q = 0; q < len; q++)
            if (vary[q]) role[o + 2 * q] = (uint8_t)(4 + q);
            else tpl[o + 2 * q] = pws[q];
        memcpy(tpl + o + 2 * len, salt, 8);
        tpl[o + 2 * len + 8] = (uint8_t)r; role[o + 2 * len + 8] = 1;
        role[o + 2 * len + 9] = 2;
        role[o + 2 * len + 10] = 3;
    }
    int words = p * 16;
    for (int w = 0; w < words; w++)
    {
        for (int b = 0; b < 4; b++)
        {
            int pos = 4 * w + b, sh = 8 * (3 - b);
            L->tpl[w] |= (uint32_t)tpl[pos] << sh;
            switch (role[pos])
            {
                case 0: break;
                case 1: L->m0[w] |= 0xffu << sh; break;
                case 2: L->m1[w] |= 0xffu << sh; break;
                case 3: L->m2[w] |= 0xffu << sh; break;
                default:   /* UTF-16 puts a zero byte between characters: at most two per word */
                    L->entq[w][L->nent[w]] = (uint8_t)(role[pos] - 4);
                    L->ents[w][L->nent[w]] = (uint8_t)sh;
                    L->nent[w]++;
                    L->lcm[w >> 4] |= 1u << (w & 15);
                    break;
            }
        }
        if (L->m0[w] | L->m1[w] | L->m2[w]) L->ctr[L->nctr++] = w;
    }
}

/* Message words of period s for every block: M[j * nbp + blk] (word-major, block-minor). */
static void rar3_period_words(const rar3_layout* L, int s, uint32_t* M)
{
    uint32_t b0 = ((64u * (uint32_t)s) & 0xffu) * 0x01010101u;
    uint32_t c1 = (((uint32_t)s >> 2) & 0xffu) * 0x01010101u;
    uint32_t c2 = (((uint32_t)s >> 10) & 0xffu) * 0x01010101u;
    for (int q = 0; q < L->nctr; q++)
    {
        int w = L->ctr[q];
        M[(w & 15) * L->nbp + (w >> 4)] = L->tpl[w] | (b0 & L->m0[w]) | (c1 & L->m1[w]) | (c2 & L->m2[w]);
    }
}

static void rar3_template_words(const rar3_layout* L, uint32_t* M)
{
    memset(M, 0, 80 * (size_t)L->nbp * 4);
    for (int w = 0; w < L->nb * 16; w++) M[(w & 15) * L->nbp + (w >> 4)] = L->tpl[w];
}

static void rar3_expand_scalar(const rar3_layout* L, uint32_t* S)
{
    int n = L->nbp;
    for (int t = 16; t < 80; t++)
        for (int b = 0; b < L->nb; b++)
            S[t * n + b] = rol32(S[(t - 3) * n + b] ^ S[(t - 8) * n + b] ^ S[(t - 14) * n + b] ^ S[(t - 16) * n + b], 1);
}

static uint32_t be32(const uint8_t* p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static void put_be32(uint8_t* p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

/* Portable path: one candidate at a time. Slow; used only where no vector path exists. */
static void rar3_scalar(const rar3_layout* L, const uint8_t* pws, int n, uint8_t* out)
{
    int nbp = L->nbp, p = L->p;
    uint32_t* S = (uint32_t*)malloc(80 * (size_t)nbp * 4);
    uint32_t* st = (uint32_t*)malloc((size_t)n * 5 * 4);
    uint8_t* iv = (uint8_t*)calloc((size_t)n, 16);
    if (!S || !st || !iv) { free(S); free(st); free(iv); memset(out, 0, (size_t)n * 36); return; }
    for (int i = 0; i < n; i++) memcpy(st + 5 * i, SHA1_IV, 20);
    rar3_template_words(L, S);
    int cutOff = p % 64;
    uint32_t w[80];
    for (int s = 0; s < RAR3_PERIODS; s++)
    {
        rar3_period_words(L, s, S);
        int ivPoint = (s & 255) == 0;
        for (int blk = 0; blk < L->nb; blk++)
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    int wi = blk * 16 + j;
                    uint32_t v = S[j * nbp + blk];
                    for (int k = 0; k < L->nent[wi]; k++) v |= (uint32_t)pws[i * L->len + L->entq[wi][k]] << L->ents[wi][k];
                    w[j] = v;
                }
                if (ivPoint && blk == 0)
                {
                    uint32_t cs[5], pw[16];
                    memcpy(cs, st + 5 * i, 20);
                    for (int j = 0; j < 16; j++)
                    {
                        int start = 4 * j;
                        uint32_t v = w[j];
                        if (start >= cutOff) v = 0;
                        else if (start + 4 > cutOff) v &= 0xffffffffu << (8 * (start + 4 - cutOff));
                        pw[j] = v;
                    }
                    pw[cutOff / 4] |= 0x80u << (8 * (3 - cutOff % 4));
                    uint64_t bits = ((uint64_t)(64 * s) + 1) * (uint64_t)p * 8;
                    if (cutOff > 55) { sha1_block(cs, pw); memset(pw, 0, 56); }
                    pw[14] = (uint32_t)(bits >> 32); pw[15] = (uint32_t)bits;
                    sha1_block(cs, pw);
                    iv[16 * i + (s >> 8)] = (uint8_t)cs[4];
                }
                sha1_block(st + 5 * i, w);
            }
    }
    uint32_t fin[16] = { 0x80000000u };
    uint64_t total = (uint64_t)RAR3_ROUNDS * (uint64_t)p * 8;
    fin[14] = (uint32_t)(total >> 32); fin[15] = (uint32_t)total;
    for (int i = 0; i < n; i++)
    {
        sha1_block(st + 5 * i, fin);
        for (int q = 0; q < 5; q++) put_be32(out + 36 * i + 4 * q, st[5 * i + q]);
        memcpy(out + 36 * i + 20, iv + 16 * i, 16);
    }
    free(S); free(st); free(iv);
}

/* ---- Eight 32-bit lanes: one AVX2 register, or two NEON registers through a clang vector type ---- */
#if RK_X64
#define V256 __m256i
#define VADD _mm256_add_epi32
#define VXOR _mm256_xor_si256
#define VAND _mm256_and_si256
#define VOR _mm256_or_si256
#define VROTL(x, n) VOR(_mm256_slli_epi32((x), (n)), _mm256_srli_epi32((x), 32 - (n)))
#define VSET1(x) _mm256_set1_epi32((int)(x))
#define VSRLI(x, n) _mm256_srli_epi32((x), (n))
#define VSLLV(x, s) _mm256_sllv_epi32((x), (s))
#define VZERO _mm256_setzero_si256()
#define VLOAD(p) _mm256_load_si256((const V256*)(p))
#define VSTORE(p, v) _mm256_store_si256((V256*)(p), (v))
#define VLOADU(p) _mm256_loadu_si256((const V256*)(p))
#define VSTOREU(p, v) _mm256_storeu_si256((V256*)(p), (v))
#define VEQMASK(a, b) ((uint32_t)_mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpeq_epi32((a), (b)))))
#define VECFN AVX2
#elif RK_ARM64
typedef uint32_t V256 __attribute__((vector_size(32), aligned(32)));
#define VADD(a, b) ((a) + (b))
#define VXOR(a, b) ((a) ^ (b))
#define VAND(a, b) ((a) & (b))
#define VOR(a, b) ((a) | (b))
#define VROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))      /* shl + usra */
#define VSET1(x) v8_set1((uint32_t)(x))
#define VSRLI(x, n) ((x) >> (n))
#define VSLLV(x, s) ((x) << (s))
#define VZERO ((V256){ 0 })
#define VLOAD(p) (*(const V256*)(p))
#define VSTORE(p, v) (*(V256*)(p) = (v))
#define VLOADU(p) v8_loadu(p)
#define VSTOREU(p, v) do { V256 v_ = (v); memcpy((p), &v_, 32); } while (0)
#define VEQMASK(a, b) v8_eqmask((a), (b))
#define VECFN
static inline V256 v8_set1(uint32_t x) { return (V256){ x, x, x, x, x, x, x, x }; }
static inline V256 v8_loadu(const void* p) { V256 v; memcpy(&v, p, 32); return v; }
/* Bit l set when lane l of a equals lane l of b (movemask of a compare). */
static inline uint32_t v8_eqmask(V256 a, V256 b)
{
    V256 m = (V256)(a == b) & (V256){ 1, 2, 4, 8, 16, 32, 64, 128 };
    uint32x4_t lo, hi;
    memcpy(&lo, &m, 16); memcpy(&hi, (const uint8_t*)&m + 16, 16);
    return vaddvq_u32(vorrq_u32(lo, hi));
}
#endif

#if RK_VEC
#define F1(b, c, d) VXOR(d, VAND(b, VXOR(c, d)))
#define F2(b, c, d) VXOR(VXOR(b, c), d)
#define F3(b, c, d) VOR(VAND(b, c), VAND(d, VOR(b, c)))

typedef uint32_t rar3_v8 __attribute__((vector_size(32)));
#define R3_V rar3_v8
#define R3_L 8
#define R3_SUFFIX _8
#define R3_FN VECFN
#include "rar3_lanes.h"
#endif

#if RK_X64
typedef uint32_t rar3_v16 __attribute__((vector_size(64)));
#define R3_V rar3_v16
#define R3_L 16
#define R3_SUFFIX _16
#define R3_FN AVX512
#include "rar3_lanes.h"
#endif

#if RK_VEC
#include "rar3_selftest.h"
#endif

/* Guard states are internal: 0 untested, 1 testing, 2 passed, 3 failed. */
static atomic_int g_rar3_paths = 0, g_pbkdf2_paths = 0;
static atomic_int g_rar3_wide_test = 0, g_pbkdf2_wide_test = 0;
static atomic_int g_whirl_paths = 0, g_whirl_wide_test = 0, g_whirl_avx512 = 0;

enum { RK_PATH_SCALAR = 1, RK_PATH_AVX2 = 2, RK_PATH_AVX512 = 4, RK_PATH_NEON = 8, RK_PATH_ARM_SHA256 = 16 };

static int wide_switched_off(const char* name)
{
    const char* value = getenv(name);
    return value && strcmp(value, "0") == 0;
}

/* Reading state never starts a guard; an explicit off switch always takes precedence. */
static int wide_selftest_state(const char* name, atomic_int* guard)
{
    if (wide_switched_off(name)) return 3;
    int state = atomic_load(guard);
    return state == 2 ? 1 : state == 3 ? 2 : 0;
}

RK_EXPORT int rk_rar3_selftest_state(void) { return wide_selftest_state("RECOVERKIT_RAR3_AVX512", &g_rar3_wide_test); }
RK_EXPORT int rk_pbkdf2_sha256_selftest_state(void) { return wide_selftest_state("RECOVERKIT_RAR5_AVX512", &g_pbkdf2_wide_test); }
RK_EXPORT int rk_rar3_executed_paths(void) { return atomic_load(&g_rar3_paths); }
RK_EXPORT int rk_pbkdf2_sha256_executed_paths(void) { return atomic_load(&g_pbkdf2_paths); }
RK_EXPORT void rk_reset_executed_paths(int mode)
{
    if (mode == 12500) atomic_store(&g_rar3_paths, 0);
    else if (mode == 13000) atomic_store(&g_pbkdf2_paths, 0);
    else if (mode == 29331) atomic_store(&g_whirl_paths, 0);
}

#if RK_X64
static int rar3_wide_ok(void)
{
    if (wide_switched_off("RECOVERKIT_RAR3_AVX512")) return 0;
    int state = atomic_load(&g_rar3_wide_test);
    if (state == 0 && atomic_compare_exchange_strong(&g_rar3_wide_test, &state, 1))
    {
        state = rar3_selftest(rar3_vec_16) ? 2 : 3;
        atomic_store(&g_rar3_wide_test, state);
    }
    /* Other threads use AVX2 while the first caller tests the wide path. */
    return state == 2;
}
#endif

/* Candidates per call group, including the two interleaved vectors. */
RK_EXPORT int rk_rar3_lanes(void)
{
    int f = features();
#if RK_X64
    if ((f & RK_FEAT_AVX512) && rar3_wide_ok()) return 32;
    if (f & RK_FEAT_AVX2) return 16;
#elif RK_ARM64
    if (f & RK_FEAT_NEON) return 16;
#else
    (void)f;
#endif
    return 1;
}

/*
 * n candidates of length len, packed in pws (n * len bytes). For each: the 20-byte SHA-1 digest
 * (big-endian words) followed by the 16-byte IV, at out + 36 * i. Returns 0, or -1 when the request
 * is not supported.
 */
RK_EXPORT int rk_rar3_hash(const uint8_t* salt, const uint8_t* pws, int len, int n, uint8_t* out)
{
    if (len < 1 || len > RAR3_MAXLEN || n <= 0) return -1;
    rar3_layout* L = (rar3_layout*)malloc(sizeof(rar3_layout));
    if (!L) return -1;
    rar3_layout_init(L, salt, pws, len, n);
    int path = RK_PATH_SCALAR;
#if RK_X64
    if (rk_rar3_lanes() == 32) { if (rar3_vec_16(L, pws, n, out)) path = RK_PATH_AVX512; }
    else if (features() & RK_FEAT_AVX2) { if (rar3_vec_8(L, pws, n, out)) path = RK_PATH_AVX2; }
    else
#elif RK_ARM64
    /* NEON, 16 lanes: on the M1 the SHA-1 instructions (one sha1c per 4 cycles) are ~30 % slower. */
    if (features() & RK_FEAT_NEON) { if (rar3_vec_8(L, pws, n, out)) path = RK_PATH_NEON; }
    else
#endif
        rar3_scalar(L, pws, n, out);
    atomic_fetch_or(&g_rar3_paths, path);
    free(L);
    return 0;
}

/* ------------------------------------------------------------------------------------------ */
/* RC4                                                                                         */
/*                                                                                            */
/* The key schedule is bound by its two stores per byte; interleaving independent streams       */
/* hides the load latency so the loop runs close to that limit.                                */
/* ------------------------------------------------------------------------------------------ */

static const uint8_t RC4_ID[256] __attribute__((aligned(64))) = {
#define R16(x) x, x + 1, x + 2, x + 3, x + 4, x + 5, x + 6, x + 7, x + 8, x + 9, x + 10, x + 11, x + 12, x + 13, x + 14, x + 15
    R16(0), R16(16), R16(32), R16(48), R16(64), R16(80), R16(96), R16(112),
    R16(128), R16(144), R16(160), R16(176), R16(192), R16(208), R16(224), R16(240)
#undef R16
};

#define KSA_STEP(S, j, K, i, kl) do { uint8_t v_ = S[i]; j = (uint8_t)(j + v_ + K[(i) % (kl)]); S[i] = S[j]; S[j] = v_; } while (0)

/* N streams, states at S + 256 * l, keys at K + kstride * l, key length kl. */
static inline void rc4_ksa_n(uint8_t* S, const uint8_t* K, int kstride, int kl, int n)
{
    for (int l = 0; l < n; l++) memcpy(S + 256 * l, RC4_ID, 256);
    uint8_t j[8] = { 0 };
    if (n == 4)
    {
        uint8_t *s0 = S, *s1 = S + 256, *s2 = S + 512, *s3 = S + 768;
        const uint8_t *k0 = K, *k1 = K + kstride, *k2 = K + 2 * kstride, *k3 = K + 3 * kstride;
        uint8_t j0 = 0, j1 = 0, j2 = 0, j3 = 0;
        for (int i = 0; i < 256; i++)
        {
            KSA_STEP(s0, j0, k0, i, kl); KSA_STEP(s1, j1, k1, i, kl);
            KSA_STEP(s2, j2, k2, i, kl); KSA_STEP(s3, j3, k3, i, kl);
        }
        return;
    }
    for (int i = 0; i < 256; i++)
        for (int l = 0; l < n; l++)
        {
            uint8_t* s = S + 256 * l;
            const uint8_t* k = K + kstride * l;
            KSA_STEP(s, j[l], k, i, kl);
        }
}

/* 16-byte keys, 8 streams, fully specialised. */
static void rc4_ksa16x8(uint8_t* S, const uint8_t* K /* 8 x 16 */)
{
    for (int l = 0; l < 8; l++) memcpy(S + 256 * l, RC4_ID, 256);
    uint8_t *s0 = S, *s1 = S + 256, *s2 = S + 512, *s3 = S + 768, *s4 = S + 1024, *s5 = S + 1280, *s6 = S + 1536, *s7 = S + 1792;
    const uint8_t *k0 = K, *k1 = K + 16, *k2 = K + 32, *k3 = K + 48, *k4 = K + 64, *k5 = K + 80, *k6 = K + 96, *k7 = K + 112;
    uint8_t j0 = 0, j1 = 0, j2 = 0, j3 = 0, j4 = 0, j5 = 0, j6 = 0, j7 = 0;
    for (int i = 0; i < 256; i++)
    {
        KSA_STEP(s0, j0, k0, i, 16); KSA_STEP(s1, j1, k1, i, 16); KSA_STEP(s2, j2, k2, i, 16); KSA_STEP(s3, j3, k3, i, 16);
        KSA_STEP(s4, j4, k4, i, 16); KSA_STEP(s5, j5, k5, i, 16); KSA_STEP(s6, j6, k6, i, 16); KSA_STEP(s7, j7, k7, i, 16);
    }
}

static void rc4_ksa16x4(uint8_t* S, const uint8_t* K /* 4 x 16 */)
{
    for (int l = 0; l < 4; l++) memcpy(S + 256 * l, RC4_ID, 256);
    uint8_t *s0 = S, *s1 = S + 256, *s2 = S + 512, *s3 = S + 768;
    const uint8_t *k0 = K, *k1 = K + 16, *k2 = K + 32, *k3 = K + 48;
    uint8_t j0 = 0, j1 = 0, j2 = 0, j3 = 0;
    for (int i = 0; i < 256; i++)
    {
        KSA_STEP(s0, j0, k0, i, 16); KSA_STEP(s1, j1, k1, i, 16); KSA_STEP(s2, j2, k2, i, 16); KSA_STEP(s3, j3, k3, i, 16);
    }
}

/* First n keystream bytes of a scheduled state (the state is consumed). */
static inline void rc4_stream(uint8_t* s, uint8_t* out, int n)
{
    uint8_t i = 0, j = 0;
    for (int q = 0; q < n; q++)
    {
        i++;
        uint8_t v = s[i];
        j = (uint8_t)(j + v);
        s[i] = s[j]; s[j] = v;
        out[q] = s[(uint8_t)(s[i] + v)];
    }
}


/* ------------------------------------------------------------------------------------------ */
/* MD5 and SHA-1 on 16 candidates (two groups of 8: AVX2, or NEON register pairs)            */
/*                                                                                            */
/* Message words that are equal in every lane come as scalars (cw), the others as vectors       */
/* (WA, WB). `mask` (bit g = word g is per lane) is a compile-time constant at every call, so   */
/* each instantiation adds the round constant to the shared words for free.                    */
/* ------------------------------------------------------------------------------------------ */

static const uint32_t MD5_IV[4] = { 0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u };

#define FORCE __attribute__((always_inline)) inline
#if RK_VEC
#define MF(b, c, d) VXOR(d, VAND(b, VXOR(c, d)))
#define MG(b, c, d) VXOR(c, VAND(d, VXOR(b, c)))
#define MH(b, c, d) VXOR(VXOR(b, c), d)
#define MI(b, c, d) VXOR(c, VOR(b, VXOR(d, ones)))

#define MSTEP(F, a, b, c, d, g, k, s)                                                   \
    do {                                                                                \
        V256 wa_, wb_;                                                                  \
        if ((mask >> (g)) & 1) { V256 k_ = VSET1(k); wa_ = VADD(WA[g], k_); wb_ = VADD(WB[g], k_); } \
        else wa_ = wb_ = VSET1(cw[g] + (k));                                            \
        a##0 = VADD(b##0, VROTL(VADD(VADD(a##0, F(b##0, c##0, d##0)), wa_), s));        \
        a##1 = VADD(b##1, VROTL(VADD(VADD(a##1, F(b##1, c##1, d##1)), wb_), s));        \
    } while (0)

/* st: a0 b0 c0 d0 a1 b1 c1 d1 (updated in place). */
VECFN static FORCE void md5x16(V256* st, const V256* WA, const V256* WB, const uint32_t* cw, const uint32_t mask)
{
    const V256 ones = VSET1(-1);
    V256 a0 = st[0], b0 = st[1], c0 = st[2], d0 = st[3], a1 = st[4], b1 = st[5], c1 = st[6], d1 = st[7];
    MSTEP(MF, a, b, c, d, 0, 0xd76aa478u, 7);
    MSTEP(MF, d, a, b, c, 1, 0xe8c7b756u, 12);
    MSTEP(MF, c, d, a, b, 2, 0x242070dbu, 17);
    MSTEP(MF, b, c, d, a, 3, 0xc1bdceeeu, 22);
    MSTEP(MF, a, b, c, d, 4, 0xf57c0fafu, 7);
    MSTEP(MF, d, a, b, c, 5, 0x4787c62au, 12);
    MSTEP(MF, c, d, a, b, 6, 0xa8304613u, 17);
    MSTEP(MF, b, c, d, a, 7, 0xfd469501u, 22);
    MSTEP(MF, a, b, c, d, 8, 0x698098d8u, 7);
    MSTEP(MF, d, a, b, c, 9, 0x8b44f7afu, 12);
    MSTEP(MF, c, d, a, b, 10, 0xffff5bb1u, 17);
    MSTEP(MF, b, c, d, a, 11, 0x895cd7beu, 22);
    MSTEP(MF, a, b, c, d, 12, 0x6b901122u, 7);
    MSTEP(MF, d, a, b, c, 13, 0xfd987193u, 12);
    MSTEP(MF, c, d, a, b, 14, 0xa679438eu, 17);
    MSTEP(MF, b, c, d, a, 15, 0x49b40821u, 22);
    MSTEP(MG, a, b, c, d, 1, 0xf61e2562u, 5);
    MSTEP(MG, d, a, b, c, 6, 0xc040b340u, 9);
    MSTEP(MG, c, d, a, b, 11, 0x265e5a51u, 14);
    MSTEP(MG, b, c, d, a, 0, 0xe9b6c7aau, 20);
    MSTEP(MG, a, b, c, d, 5, 0xd62f105du, 5);
    MSTEP(MG, d, a, b, c, 10, 0x02441453u, 9);
    MSTEP(MG, c, d, a, b, 15, 0xd8a1e681u, 14);
    MSTEP(MG, b, c, d, a, 4, 0xe7d3fbc8u, 20);
    MSTEP(MG, a, b, c, d, 9, 0x21e1cde6u, 5);
    MSTEP(MG, d, a, b, c, 14, 0xc33707d6u, 9);
    MSTEP(MG, c, d, a, b, 3, 0xf4d50d87u, 14);
    MSTEP(MG, b, c, d, a, 8, 0x455a14edu, 20);
    MSTEP(MG, a, b, c, d, 13, 0xa9e3e905u, 5);
    MSTEP(MG, d, a, b, c, 2, 0xfcefa3f8u, 9);
    MSTEP(MG, c, d, a, b, 7, 0x676f02d9u, 14);
    MSTEP(MG, b, c, d, a, 12, 0x8d2a4c8au, 20);
    MSTEP(MH, a, b, c, d, 5, 0xfffa3942u, 4);
    MSTEP(MH, d, a, b, c, 8, 0x8771f681u, 11);
    MSTEP(MH, c, d, a, b, 11, 0x6d9d6122u, 16);
    MSTEP(MH, b, c, d, a, 14, 0xfde5380cu, 23);
    MSTEP(MH, a, b, c, d, 1, 0xa4beea44u, 4);
    MSTEP(MH, d, a, b, c, 4, 0x4bdecfa9u, 11);
    MSTEP(MH, c, d, a, b, 7, 0xf6bb4b60u, 16);
    MSTEP(MH, b, c, d, a, 10, 0xbebfbc70u, 23);
    MSTEP(MH, a, b, c, d, 13, 0x289b7ec6u, 4);
    MSTEP(MH, d, a, b, c, 0, 0xeaa127fau, 11);
    MSTEP(MH, c, d, a, b, 3, 0xd4ef3085u, 16);
    MSTEP(MH, b, c, d, a, 6, 0x04881d05u, 23);
    MSTEP(MH, a, b, c, d, 9, 0xd9d4d039u, 4);
    MSTEP(MH, d, a, b, c, 12, 0xe6db99e5u, 11);
    MSTEP(MH, c, d, a, b, 15, 0x1fa27cf8u, 16);
    MSTEP(MH, b, c, d, a, 2, 0xc4ac5665u, 23);
    MSTEP(MI, a, b, c, d, 0, 0xf4292244u, 6);
    MSTEP(MI, d, a, b, c, 7, 0x432aff97u, 10);
    MSTEP(MI, c, d, a, b, 14, 0xab9423a7u, 15);
    MSTEP(MI, b, c, d, a, 5, 0xfc93a039u, 21);
    MSTEP(MI, a, b, c, d, 12, 0x655b59c3u, 6);
    MSTEP(MI, d, a, b, c, 3, 0x8f0ccc92u, 10);
    MSTEP(MI, c, d, a, b, 10, 0xffeff47du, 15);
    MSTEP(MI, b, c, d, a, 1, 0x85845dd1u, 21);
    MSTEP(MI, a, b, c, d, 8, 0x6fa87e4fu, 6);
    MSTEP(MI, d, a, b, c, 15, 0xfe2ce6e0u, 10);
    MSTEP(MI, c, d, a, b, 6, 0xa3014314u, 15);
    MSTEP(MI, b, c, d, a, 13, 0x4e0811a1u, 21);
    MSTEP(MI, a, b, c, d, 4, 0xf7537e82u, 6);
    MSTEP(MI, d, a, b, c, 11, 0xbd3af235u, 10);
    MSTEP(MI, c, d, a, b, 2, 0x2ad7d2bbu, 15);
    MSTEP(MI, b, c, d, a, 9, 0xeb86d391u, 21);
    st[0] = VADD(st[0], a0); st[1] = VADD(st[1], b0); st[2] = VADD(st[2], c0); st[3] = VADD(st[3], d0);
    st[4] = VADD(st[4], a1); st[5] = VADD(st[5], b1); st[6] = VADD(st[6], c1); st[7] = VADD(st[7], d1);
}

VECFN static FORCE void md5x16_iv(V256* st)
{
    for (int q = 0; q < 4; q++) st[q] = st[4 + q] = VSET1(MD5_IV[q]);
}

/* SHA-1, 16 lanes; words 0..15 big-endian. st: a b c d e for group 0, then group 1. */
#define SROUND(F, K, t, a, b, c, d, e)                                                  \
    do {                                                                                \
        V256 wa_, wb_;                                                                  \
        if ((t) >= 16 || ((mask >> (t)) & 1)) { wa_ = VADD(K, xa[(t) & 15]); wb_ = VADD(K, xb[(t) & 15]); } \
        else wa_ = wb_ = VSET1(cw[(t) & 15] + kk[(t) / 20]);                            \
        e##0 = VADD(VADD(e##0, wa_), VADD(VROTL(a##0, 5), F(b##0, c##0, d##0)));        \
        e##1 = VADD(VADD(e##1, wb_), VADD(VROTL(a##1, 5), F(b##1, c##1, d##1)));        \
        b##0 = VROTL(b##0, 30); b##1 = VROTL(b##1, 30);                                 \
    } while (0)
#define SEXP(t)                                                                          \
    do {                                                                                \
        xa[(t) & 15] = VROTL(VXOR(VXOR(xa[((t) - 3) & 15], xa[((t) - 8) & 15]), VXOR(xa[((t) - 14) & 15], xa[(t) & 15])), 1); \
        xb[(t) & 15] = VROTL(VXOR(VXOR(xb[((t) - 3) & 15], xb[((t) - 8) & 15]), VXOR(xb[((t) - 14) & 15], xb[(t) & 15])), 1); \
    } while (0)
#define S5(F, K, t)                                                                     \
    if ((t) >= 16) SEXP(t); SROUND(F, K, (t), a, b, c, d, e);                           \
    if ((t) + 1 >= 16) SEXP((t) + 1); SROUND(F, K, (t) + 1, e, a, b, c, d);             \
    if ((t) + 2 >= 16) SEXP((t) + 2); SROUND(F, K, (t) + 2, d, e, a, b, c);             \
    if ((t) + 3 >= 16) SEXP((t) + 3); SROUND(F, K, (t) + 3, c, d, e, a, b);             \
    if ((t) + 4 >= 16) SEXP((t) + 4); SROUND(F, K, (t) + 4, b, c, d, e, a)

VECFN static FORCE void sha1x16(V256* st, const V256* WA, const V256* WB, const uint32_t* cw, const uint32_t mask)
{
    static const uint32_t kk[4] = { 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xCA62C1D6u };
    const V256 k1 = VSET1(0x5A827999), k2 = VSET1(0x6ED9EBA1);
    const V256 k3 = VSET1(0x8F1BBCDCu), k4 = VSET1(0xCA62C1D6u);
    V256 xa[16], xb[16];
    for (int t = 0; t < 16; t++)
    {
        if ((mask >> t) & 1) { xa[t] = WA[t]; xb[t] = WB[t]; }
        else xa[t] = xb[t] = VSET1(cw[t]);
    }
    V256 a0 = st[0], b0 = st[1], c0 = st[2], d0 = st[3], e0 = st[4];
    V256 a1 = st[5], b1 = st[6], c1 = st[7], d1 = st[8], e1 = st[9];
    S5(F1, k1, 0); S5(F1, k1, 5); S5(F1, k1, 10); S5(F1, k1, 15);
    S5(F2, k2, 20); S5(F2, k2, 25); S5(F2, k2, 30); S5(F2, k2, 35);
    S5(F3, k3, 40); S5(F3, k3, 45); S5(F3, k3, 50); S5(F3, k3, 55);
    S5(F2, k4, 60); S5(F2, k4, 65); S5(F2, k4, 70); S5(F2, k4, 75);
    st[0] = VADD(st[0], a0); st[1] = VADD(st[1], b0); st[2] = VADD(st[2], c0); st[3] = VADD(st[3], d0); st[4] = VADD(st[4], e0);
    st[5] = VADD(st[5], a1); st[6] = VADD(st[6], b1); st[7] = VADD(st[7], c1); st[8] = VADD(st[8], d1); st[9] = VADD(st[9], e1);
}

VECFN static FORCE void sha1x16_iv(V256* st)
{
    for (int q = 0; q < 5; q++) st[q] = st[5 + q] = VSET1(SHA1_IV[q]);
}

/* Lane words for 16 candidates: v[lane] -> two vectors. */
VECFN static FORCE void load16(const uint32_t* v, V256* a, V256* b)
{
    *a = VLOADU(v);
    *b = VLOADU(v + 8);
}

/* Copies st vectors (words q of 16 lanes) out as per-lane little-endian byte keys (16 bytes each). */
VECFN static FORCE void keys_le16(const V256* g0, const V256* g1, uint8_t* K /* 16 x 16 */)
{
    uint32_t w[4][16];
    for (int q = 0; q < 4; q++) { VSTOREU(w[q], g0[q]); VSTOREU(w[q] + 8, g1[q]); }
    for (int l = 0; l < 16; l++)
        for (int q = 0; q < 4; q++) memcpy(K + 16 * l + 4 * q, &w[q][l], 4);
}
#endif

/* ---- RC4, 8 interleaved streams, specialised per key layout ---- */

static FORCE void rc4_init8(uint8_t* S)
{
    for (int l = 0; l < 8; l++) memcpy(S + 256 * l, RC4_ID, 256);
}

/* kl = key length (the key repeats); z5 = key bytes 5..15 are zero (40-bit key padded to 16). */
#define KSA8_BODY(KEYB)                                                                       \
    uint8_t *s0 = S, *s1 = S + 256, *s2 = S + 512, *s3 = S + 768, *s4 = S + 1024, *s5 = S + 1280, *s6 = S + 1536, *s7 = S + 1792; \
    uint8_t j0 = 0, j1 = 0, j2 = 0, j3 = 0, j4 = 0, j5 = 0, j6 = 0, j7 = 0;                 \
    for (int i = 0; i < 256; i++)                                                           \
    {                                                                                       \
        int c = i % kl;                                                                     \
        { uint8_t v = s0[i]; j0 = (uint8_t)(j0 + v + KEYB(0, c)); s0[i] = s0[j0]; s0[j0] = v; } \
        { uint8_t v = s1[i]; j1 = (uint8_t)(j1 + v + KEYB(1, c)); s1[i] = s1[j1]; s1[j1] = v; } \
        { uint8_t v = s2[i]; j2 = (uint8_t)(j2 + v + KEYB(2, c)); s2[i] = s2[j2]; s2[j2] = v; } \
        { uint8_t v = s3[i]; j3 = (uint8_t)(j3 + v + KEYB(3, c)); s3[i] = s3[j3]; s3[j3] = v; } \
        { uint8_t v = s4[i]; j4 = (uint8_t)(j4 + v + KEYB(4, c)); s4[i] = s4[j4]; s4[j4] = v; } \
        { uint8_t v = s5[i]; j5 = (uint8_t)(j5 + v + KEYB(5, c)); s5[i] = s5[j5]; s5[j5] = v; } \
        { uint8_t v = s6[i]; j6 = (uint8_t)(j6 + v + KEYB(6, c)); s6[i] = s6[j6]; s6[j6] = v; } \
        { uint8_t v = s7[i]; j7 = (uint8_t)(j7 + v + KEYB(7, c)); s7[i] = s7[j7]; s7[j7] = v; } \
    }

#define KEY_PLAIN(l, c) K[16 * (l) + (c)]
/* Keys at K + 16 * l, length kl (1..16). */
static void rc4_ksa8(uint8_t* S, const uint8_t* K, const int kl)
{
    rc4_init8(S);
    KSA8_BODY(KEY_PLAIN)
}
static void rc4_ksa8_16_c(uint8_t* S, const uint8_t* K) { const int kl = 16; rc4_init8(S); KSA8_BODY(KEY_PLAIN) }
static void rc4_ksa8_5(uint8_t* S, const uint8_t* K) { const int kl = 5; rc4_init8(S); KSA8_BODY(KEY_PLAIN) }
#define KEY_Z5(l, c) ((c) < 5 ? K[16 * (l) + (c)] : 0)
static void rc4_ksa8_16z5_c(uint8_t* S, const uint8_t* K) { const int kl = 16; rc4_init8(S); KSA8_BODY(KEY_Z5) }

#if RK_X64

/* 8 streams, 16-byte keys at K + 16 * l. Hand-scheduled: each j lives in the low
   byte of a register whose upper bits stay zero, so it indexes memory without a zero-extend. */
static void rc4_ksa8_16_asm(uint8_t* S, const uint8_t* K)
{
    rc4_init8(S);
    uint64_t j0 = 0, j1 = 0, j2 = 0, j3 = 0, j4 = 0, j5 = 0, j6 = 0, j7 = 0, v, t;
    for (uint64_t i = 0; i < 256; i += 16)
        __asm__ volatile(
            "movzbl 0(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 0(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 0(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 256(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 16(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 256(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 512(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 32(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 512(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 768(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 48(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 768(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1024(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 64(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1024(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1280(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 80(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1280(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1536(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 96(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1536(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1792(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 112(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1792(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 1(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 1(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 1(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 257(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 17(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 257(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 513(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 33(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 513(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 769(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 49(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 769(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1025(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 65(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1025(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1281(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 81(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1281(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1537(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 97(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1537(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1793(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 113(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1793(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 2(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 2(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 2(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 258(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 18(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 258(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 514(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 34(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 514(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 770(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 50(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 770(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1026(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 66(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1026(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1282(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 82(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1282(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1538(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 98(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1538(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1794(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 114(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1794(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 3(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 3(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 3(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 259(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 19(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 259(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 515(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 35(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 515(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 771(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 51(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 771(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1027(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 67(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1027(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1283(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 83(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1283(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1539(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 99(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1539(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1795(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 115(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1795(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 4(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 4(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 4(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 260(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 20(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 260(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 516(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 36(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 516(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 772(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 52(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 772(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1028(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 68(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1028(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1284(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 84(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1284(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1540(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 100(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1540(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1796(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 116(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1796(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 5(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 5(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 5(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 261(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 21(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 261(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 517(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 37(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 517(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 773(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 53(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 773(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1029(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 69(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1029(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1285(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 85(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1285(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1541(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 101(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1541(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1797(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 117(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1797(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 6(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 6(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 6(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 262(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 22(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 262(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 518(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 38(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 518(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 774(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 54(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 774(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1030(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 70(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1030(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1286(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 86(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1286(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1542(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 102(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1542(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1798(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 118(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1798(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 7(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 7(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 7(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 263(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 23(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 263(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 519(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 39(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 519(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 775(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 55(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 775(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1031(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 71(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1031(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1287(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 87(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1287(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1543(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 103(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1543(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1799(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 119(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1799(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 8(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 8(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 8(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 264(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 24(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 264(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 520(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 40(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 520(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 776(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 56(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 776(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1032(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 72(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1032(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1288(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 88(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1288(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1544(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 104(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1544(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1800(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 120(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1800(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 9(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 9(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 9(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 265(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 25(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 265(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 521(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 41(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 521(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 777(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 57(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 777(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1033(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 73(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1033(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1289(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 89(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1289(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1545(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 105(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1545(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1801(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 121(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1801(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 10(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 10(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 10(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 266(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 26(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 266(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 522(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 42(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 522(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 778(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 58(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 778(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1034(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 74(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1034(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1290(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 90(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1290(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1546(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 106(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1546(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1802(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 122(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1802(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 11(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 11(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 11(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 267(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 27(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 267(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 523(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 43(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 523(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 779(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 59(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 779(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1035(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 75(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1035(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1291(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 91(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1291(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1547(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 107(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1547(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1803(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 123(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1803(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 12(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 12(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 12(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 268(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 28(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 268(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 524(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 44(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 524(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 780(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 60(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 780(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1036(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 76(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1036(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1292(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 92(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1292(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1548(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 108(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1548(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1804(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 124(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1804(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 13(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 13(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 13(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 269(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 29(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 269(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 525(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 45(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 525(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 781(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 61(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 781(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1037(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 77(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1037(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1293(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 93(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1293(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1549(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 109(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1549(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1805(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 125(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1805(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 14(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 14(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 14(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 270(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 30(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 270(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 526(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 46(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 526(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 782(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 62(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 782(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1038(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 78(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1038(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1294(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 94(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1294(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1550(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 110(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1550(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1806(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 126(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1806(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 15(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 15(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 15(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 271(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 31(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 271(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 527(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 47(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 527(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 783(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 63(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 783(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1039(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 79(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1039(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1295(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 95(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1295(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1551(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 111(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1551(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1807(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 127(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1807(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            : [j0] "+r"(j0), [j1] "+r"(j1), [j2] "+r"(j2), [j3] "+r"(j3), [j4] "+r"(j4), [j5] "+r"(j5), [j6] "+r"(j6), [j7] "+r"(j7),
              [v] "=&r"(v), [t] "=&r"(t)
            : [S] "r"(S), [K] "r"(K), [i] "r"(i)
            : "memory", "cc");
}

/* 8 streams, 16-byte keys at K + 16 * l, bytes 5..15 zero. Hand-scheduled: each j lives in the low
   byte of a register whose upper bits stay zero, so it indexes memory without a zero-extend. */
static void rc4_ksa8_16z5_asm(uint8_t* S, const uint8_t* K)
{
    rc4_init8(S);
    uint64_t j0 = 0, j1 = 0, j2 = 0, j3 = 0, j4 = 0, j5 = 0, j6 = 0, j7 = 0, v, t;
    for (uint64_t i = 0; i < 256; i += 16)
        __asm__ volatile(
            "movzbl 0(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 0(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 0(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 256(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 16(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 256(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 512(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 32(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 512(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 768(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 48(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 768(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1024(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 64(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1024(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1280(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 80(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1280(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1536(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 96(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1536(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1792(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 112(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1792(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 1(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 1(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 1(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 257(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 17(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 257(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 513(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 33(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 513(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 769(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 49(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 769(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1025(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 65(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1025(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1281(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 81(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1281(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1537(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 97(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1537(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1793(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 113(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1793(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 2(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 2(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 2(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 258(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 18(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 258(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 514(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 34(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 514(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 770(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 50(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 770(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1026(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 66(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1026(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1282(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 82(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1282(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1538(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 98(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1538(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1794(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 114(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1794(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 3(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 3(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 3(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 259(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 19(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 259(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 515(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 35(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 515(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 771(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 51(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 771(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1027(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 67(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1027(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1283(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 83(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1283(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1539(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 99(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1539(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1795(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 115(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1795(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 4(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "addb 4(%[K]), %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 4(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 260(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "addb 20(%[K]), %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 260(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 516(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "addb 36(%[K]), %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 516(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 772(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "addb 52(%[K]), %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 772(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1028(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "addb 68(%[K]), %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1028(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1284(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "addb 84(%[K]), %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1284(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1540(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "addb 100(%[K]), %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1540(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1796(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "addb 116(%[K]), %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1796(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 5(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 5(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 261(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 261(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 517(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 517(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 773(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 773(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1029(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1029(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1285(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1285(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1541(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1541(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1797(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1797(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 6(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 6(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 262(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 262(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 518(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 518(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 774(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 774(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1030(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1030(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1286(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1286(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1542(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1542(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1798(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1798(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 7(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 7(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 263(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 263(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 519(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 519(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 775(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 775(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1031(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1031(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1287(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1287(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1543(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1543(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1799(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1799(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 8(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 8(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 264(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 264(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 520(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 520(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 776(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 776(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1032(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1032(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1288(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1288(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1544(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1544(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1800(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1800(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 9(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 9(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 265(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 265(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 521(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 521(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 777(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 777(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1033(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1033(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1289(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1289(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1545(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1545(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1801(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1801(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 10(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 10(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 266(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 266(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 522(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 522(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 778(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 778(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1034(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1034(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1290(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1290(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1546(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1546(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1802(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1802(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 11(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 11(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 267(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 267(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 523(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 523(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 779(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 779(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1035(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1035(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1291(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1291(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1547(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1547(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1803(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1803(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 12(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 12(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 268(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 268(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 524(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 524(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 780(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 780(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1036(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1036(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1292(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1292(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1548(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1548(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1804(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1804(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 13(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 13(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 269(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 269(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 525(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 525(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 781(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 781(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1037(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1037(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1293(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1293(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1549(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1549(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1805(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1805(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 14(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 14(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 270(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 270(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 526(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 526(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 782(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 782(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1038(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1038(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1294(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1294(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1550(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1550(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1806(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1806(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            "movzbl 15(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j0]\n\t"
            "movzbl 0(%[S],%[j0]), %k[t]\n\t"
            "movb %b[t], 15(%[S],%[i])\n\t"
            "movb %b[v], 0(%[S],%[j0])\n\t"
            "movzbl 271(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j1]\n\t"
            "movzbl 256(%[S],%[j1]), %k[t]\n\t"
            "movb %b[t], 271(%[S],%[i])\n\t"
            "movb %b[v], 256(%[S],%[j1])\n\t"
            "movzbl 527(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j2]\n\t"
            "movzbl 512(%[S],%[j2]), %k[t]\n\t"
            "movb %b[t], 527(%[S],%[i])\n\t"
            "movb %b[v], 512(%[S],%[j2])\n\t"
            "movzbl 783(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j3]\n\t"
            "movzbl 768(%[S],%[j3]), %k[t]\n\t"
            "movb %b[t], 783(%[S],%[i])\n\t"
            "movb %b[v], 768(%[S],%[j3])\n\t"
            "movzbl 1039(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j4]\n\t"
            "movzbl 1024(%[S],%[j4]), %k[t]\n\t"
            "movb %b[t], 1039(%[S],%[i])\n\t"
            "movb %b[v], 1024(%[S],%[j4])\n\t"
            "movzbl 1295(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j5]\n\t"
            "movzbl 1280(%[S],%[j5]), %k[t]\n\t"
            "movb %b[t], 1295(%[S],%[i])\n\t"
            "movb %b[v], 1280(%[S],%[j5])\n\t"
            "movzbl 1551(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j6]\n\t"
            "movzbl 1536(%[S],%[j6]), %k[t]\n\t"
            "movb %b[t], 1551(%[S],%[i])\n\t"
            "movb %b[v], 1536(%[S],%[j6])\n\t"
            "movzbl 1807(%[S],%[i]), %k[v]\n\t"
            "addb %b[v], %b[j7]\n\t"
            "movzbl 1792(%[S],%[j7]), %k[t]\n\t"
            "movb %b[t], 1807(%[S],%[i])\n\t"
            "movb %b[v], 1792(%[S],%[j7])\n\t"
            : [j0] "+r"(j0), [j1] "+r"(j1), [j2] "+r"(j2), [j3] "+r"(j3), [j4] "+r"(j4), [j5] "+r"(j5), [j6] "+r"(j6), [j7] "+r"(j7),
              [v] "=&r"(v), [t] "=&r"(t)
            : [S] "r"(S), [K] "r"(K), [i] "r"(i)
            : "memory", "cc");
}
#endif

#if RK_X64
#define rc4_ksa8_16 rc4_ksa8_16_asm
#define rc4_ksa8_16z5 rc4_ksa8_16z5_asm
#else
#define rc4_ksa8_16 rc4_ksa8_16_c
#define rc4_ksa8_16z5 rc4_ksa8_16z5_c
#endif

/* First n keystream bytes of 8 scheduled states, out + 32 * l (n <= 32). */
static void rc4_prga8(uint8_t* S, uint8_t* out, int n)
{
    uint8_t j[8] = { 0 };
    for (int q = 0; q < n; q++)
    {
        uint8_t i = (uint8_t)(q + 1);
        for (int l = 0; l < 8; l++)
        {
            uint8_t* s = S + 256 * l;
            uint8_t v = s[i];
            j[l] = (uint8_t)(j[l] + v);
            uint8_t t = s[j[l]];
            s[i] = t; s[j[l]] = v;
            out[32 * l + q] = s[(uint8_t)(t + v)];
        }
    }
}

static int add_hit(int* hits, int nh, int maxh, int idx) { if (nh < maxh) hits[nh] = idx; return nh + 1; }

/* ---- PDF R2-R4 RC4 (hashcat 10400/10500) ---- */

typedef struct
{
    int32_t r, keylen;          /* revision 2..4; key bytes 5..16 */
    uint8_t o[32];              /* O entry */
    uint32_t block2[16];        /* second key-derivation block (P, ID, padding), little-endian words */
    uint32_t x0, u0, pad0;      /* first words of MD5(PAD || ID), U and PAD */
} rk_pdf_params;

static const uint8_t PDF_PAD[32] = { 0x28,0xbf,0x4e,0x5e,0x4e,0x75,0x8a,0x41,0x64,0x00,0x4e,0x56,0xff,0xfa,0x01,0x08,
                                     0x2e,0x2e,0x00,0xb6,0xd0,0x68,0x3e,0x80,0x2f,0x0c,0xa9,0xfe,0x64,0x53,0x69,0x7a };

#if RK_VEC
/* ---- MS Office 97-2000 (hashcat 9700) ---- */
VECFN static int office97_vec(const uint8_t* salt, const uint8_t* enc, const uint8_t* pws, int len, int n, int* hits, int maxh)
{
    /* H1 message: 16 x (H0[0..5] || salt) || 0x80 || ... || 2688 bits. Per word: constant part and
       up to 4 H0 bytes (index, shift). */
    uint32_t h1c[96] = { 0 };
    uint8_t h1n[96] = { 0 }, h1i[96][4], h1s[96][4];
    for (int p = 0; p < 384; p++)
    {
        int w = p >> 2, sh = 8 * (p & 3), v;
        if (p < 336) { int q = p % 21; if (q < 5) { h1i[w][h1n[w]] = (uint8_t)q; h1s[w][h1n[w]] = (uint8_t)sh; h1n[w]++; continue; } v = salt[q - 5]; }
        else if (p == 336) v = 0x80;
        else if (p >= 376) v = (int)((2688ull >> (8 * (p - 376))) & 0xff);
        else v = 0;
        h1c[w] |= (uint32_t)v << sh;
    }
    uint32_t encw[8];
    memcpy(encw, enc, 32);
    uint8_t S[2][8 * 256] __attribute__((aligned(64)));
    uint8_t K[16 * 16], ks[2][8 * 32];
    uint32_t lw[16][16];
    int nh = 0;
    const V256 ff = VSET1(0xff);
    for (int i0 = 0; i0 < n; i0 += 16)
    {
        /* H0 = MD5(UTF-16LE password). */
        memset(lw, 0, sizeof lw);
        for (int l = 0; l < 16; l++)
        {
            const uint8_t* pw = pws + (size_t)(i0 + l < n ? i0 + l : n - 1) * len;
            for (int q = 0; q < len; q++) lw[(2 * q) >> 2][l] |= (uint32_t)pw[q] << (8 * ((2 * q) & 3));
            lw[(2 * len) >> 2][l] |= 0x80u << (8 * ((2 * len) & 3));
            lw[14][l] = (uint32_t)(16 * len);
        }
        V256 WA[16], WB[16], st[8];
        for (int j = 0; j < 16; j++) load16(lw[j], &WA[j], &WB[j]);
        uint32_t none[16] = { 0 };
        md5x16_iv(st);
        md5x16(st, WA, WB, none, 0xffff);
        V256 tb[2][5];
        for (int g = 0; g < 2; g++)
        {
            V256 x0 = st[4 * g], x1 = st[4 * g + 1];
            tb[g][0] = VAND(x0, ff); tb[g][1] = VAND(VSRLI(x0, 8), ff); tb[g][2] = VAND(VSRLI(x0, 16), ff);
            tb[g][3] = VSRLI(x0, 24); tb[g][4] = VAND(x1, ff);
        }
        /* H1: six blocks. */
        md5x16_iv(st);
#define H1BLOCK(b, m)                                                                         \
        for (int j = 0; j < 16; j++)                                                          \
        {                                                                                     \
            int w = 16 * (b) + j;                                                             \
            if (!h1n[w]) continue;                                                            \
            V256 va = VSET1(h1c[w]), vb = va;                                                 \
            for (int e = 0; e < h1n[w]; e++)                                                  \
            {                                                                                 \
                V256 sh = VSET1(h1s[w][e]);                                                   \
                va = VOR(va, VSLLV(tb[0][h1i[w][e]], sh));                                    \
                vb = VOR(vb, VSLLV(tb[1][h1i[w][e]], sh));                                    \
            }                                                                                 \
            WA[j] = va; WB[j] = vb;                                                           \
        }                                                                                     \
        md5x16(st, WA, WB, h1c + 16 * (b), m)
        H1BLOCK(0, 0x8c63); H1BLOCK(1, 0x8c61); H1BLOCK(2, 0x8c31); H1BLOCK(3, 0x8631); H1BLOCK(4, 0xc631); H1BLOCK(5, 0x0000);
#undef H1BLOCK
        /* RC4 key = MD5(H1[0..5] || 00 00 00 00). */
        {
            uint32_t cw[16] = { 0 };
            cw[2] = 0x8000u; cw[14] = 72;
            WA[0] = st[0]; WB[0] = st[4];
            WA[1] = VAND(st[1], ff); WB[1] = VAND(st[5], ff);
            md5x16_iv(st);
            md5x16(st, WA, WB, cw, 0x3);
        }
        keys_le16(st, st + 4, K);
        rc4_ksa8_16(S[0], K);
        rc4_ksa8_16(S[1], K + 128);
        rc4_prga8(S[0], ks[0], 20);
        rc4_prga8(S[1], ks[1], 20);
        /* MD5(decrypted verifier) == decrypted verifier hash (first word). */
        uint32_t vw[5][16];
        for (int l = 0; l < 16; l++)
        {
            const uint8_t* k = ks[l >> 3] + 32 * (l & 7);
            for (int q = 0; q < 5; q++) { uint32_t x; memcpy(&x, k + 4 * q, 4); vw[q][l] = x ^ encw[q]; }
        }
        {
            uint32_t cw[16] = { 0 };
            cw[4] = 0x80u; cw[14] = 128;
            for (int q = 0; q < 4; q++) load16(vw[q], &WA[q], &WB[q]);
            md5x16_iv(st);
            md5x16(st, WA, WB, cw, 0xf);
        }
        V256 ha, hb;
        load16(vw[4], &ha, &hb);
        uint32_t m = VEQMASK(st[0], ha) | VEQMASK(st[4], hb) << 8;
        while (m)
        {
            int l = __builtin_ctz(m);
            m &= m - 1;
            if (i0 + l < n) nh = add_hit(hits, nh, maxh, i0 + l);
        }
    }
    return nh;
}

/* ---- MS Office XP-2003 RC4 CryptoAPI (hashcat 9800) ---- */

VECFN static int office2003_vec(const uint8_t* salt, const uint8_t* enc, const uint8_t* pws, int len, int n, int* hits, int maxh)
{
    uint8_t blk[64] = { 0 };
    memcpy(blk, salt, 16);
    uint32_t c0[16];
    for (int j = 0; j < 16; j++) c0[j] = be32(blk + 4 * j);
    c0[15] = (uint32_t)((16 + 2 * len) * 8);
    uint8_t S[2][8 * 256] __attribute__((aligned(64)));
    uint8_t K[16 * 16], ks[2][8 * 32];
    uint32_t lw[16][16];
    int nh = 0;
    for (int i0 = 0; i0 < n; i0 += 16)
    {
        /* H0 = SHA-1(salt || UTF-16LE password); words 4..11 carry the password and the 0x80. */
        memset(lw, 0, sizeof lw);
        for (int l = 0; l < 16; l++)
        {
            const uint8_t* pw = pws + (size_t)(i0 + l < n ? i0 + l : n - 1) * len;
            uint8_t b[32] = { 0 };
            for (int q = 0; q < len; q++) b[2 * q] = pw[q];
            b[2 * len] = 0x80;
            for (int j = 0; j < 8; j++) lw[4 + j][l] = be32(b + 4 * j);
        }
        V256 WA[16], WB[16], st[10];
        for (int j = 4; j < 12; j++) load16(lw[j], &WA[j], &WB[j]);
        sha1x16_iv(st);
        sha1x16(st, WA, WB, c0, 0x0ff0);
        /* Hf = SHA-1(H0 || 00000000). */
        {
            uint32_t cw[16] = { 0 };
            cw[6] = 0x80000000u; cw[15] = 192;
            for (int q = 0; q < 5; q++) { WA[q] = st[q]; WB[q] = st[5 + q]; }
            sha1x16_iv(st);
            sha1x16(st, WA, WB, cw, 0x1f);
        }
        /* Key: first 5 digest bytes, zero-padded to 16. */
        {
            uint32_t w0[16], w1[16];
            VSTOREU(w0, st[0]); VSTOREU(w0 + 8, st[5]);
            VSTOREU(w1, st[1]); VSTOREU(w1 + 8, st[6]);
            for (int l = 0; l < 16; l++)
            {
                uint8_t* k = K + 16 * l;
                k[0] = (uint8_t)(w0[l] >> 24); k[1] = (uint8_t)(w0[l] >> 16); k[2] = (uint8_t)(w0[l] >> 8); k[3] = (uint8_t)w0[l];
                k[4] = (uint8_t)(w1[l] >> 24);
            }
        }
        rc4_ksa8_16z5(S[0], K);
        rc4_ksa8_16z5(S[1], K + 128);
        rc4_prga8(S[0], ks[0], 20);
        rc4_prga8(S[1], ks[1], 20);
        uint32_t vw[5][16];
        for (int l = 0; l < 16; l++)
        {
            const uint8_t* k = ks[l >> 3] + 32 * (l & 7);
            uint8_t d[20];
            for (int q = 0; q < 20; q++) d[q] = k[q] ^ enc[q];
            for (int q = 0; q < 5; q++) vw[q][l] = be32(d + 4 * q);
        }
        {
            uint32_t cw[16] = { 0 };
            cw[4] = 0x80000000u; cw[15] = 128;
            for (int q = 0; q < 4; q++) load16(vw[q], &WA[q], &WB[q]);
            sha1x16_iv(st);
            sha1x16(st, WA, WB, cw, 0xf);
        }
        V256 ha, hb;
        load16(vw[4], &ha, &hb);
        uint32_t m = VEQMASK(st[0], ha) | VEQMASK(st[5], hb) << 8;
        while (m)
        {
            int l = __builtin_ctz(m);
            m &= m - 1;
            if (i0 + l < n) nh = add_hit(hits, nh, maxh, i0 + l);
        }
    }
    return nh;
}

VECFN static int pdf_vec(const rk_pdf_params* P, const uint8_t* pws, int len, int n, int* hits, int maxh)
{
    int kl = P->keylen;
    uint8_t S[2][8 * 256] __attribute__((aligned(64)));
    uint8_t K[16 * 16], XK[16 * 16], ks[2][8 * 32];
    uint32_t lw[16][16];
    uint32_t c1[16];
    {
        uint8_t b[64];
        for (int q = 0; q < 32; q++) b[q] = q < len ? 0 : PDF_PAD[q - len];
        memcpy(b + 32, P->o, 32);
        for (int j = 0; j < 16; j++) memcpy(&c1[j], b + 4 * j, 4);
    }
    uint32_t mask1 = 0;     /* words holding password bytes */
    for (int q = 0; q < len; q++) mask1 |= 1u << (q >> 2);
    int nh = 0;
    for (int i0 = 0; i0 < n; i0 += 16)
    {
        for (int j = 0; j < 8; j++)
            for (int l = 0; l < 16; l++) lw[j][l] = c1[j];
        for (int l = 0; l < 16; l++)
        {
            const uint8_t* pw = pws + (size_t)(i0 + l < n ? i0 + l : n - 1) * len;
            for (int q = 0; q < len; q++) lw[q >> 2][l] |= (uint32_t)pw[q] << (8 * (q & 3));
        }
        V256 WA[16], WB[16], st[8];
        for (int j = 0; j < 8; j++) load16(lw[j], &WA[j], &WB[j]);
        md5x16_iv(st);
        if (mask1 == 0xff) md5x16(st, WA, WB, c1, 0xff);
        else
        {
            /* Short passwords: the trailing pad words are shared; treat them as lane words anyway. */
            for (int j = 0; j < 8; j++) if (!((mask1 >> j) & 1)) WA[j] = WB[j] = VSET1(c1[j]);
            md5x16(st, WA, WB, c1, 0xff);
        }
        md5x16(st, WA, WB, P->block2, 0x0);
        if (P->r >= 3)
        {
            uint32_t cw[16] = { 0 };
            if (kl == 16)
            {
                cw[4] = 0x80u; cw[14] = 128;
                for (int it = 0; it < 50; it++)
                {
                    for (int q = 0; q < 4; q++) { WA[q] = st[q]; WB[q] = st[4 + q]; }
                    md5x16_iv(st);
                    md5x16(st, WA, WB, cw, 0xf);
                }
            }
            else
            {
                /* Key length 5..15: whole words, then a partial word with 0x80 appended. */
                cw[14] = (uint32_t)(kl * 8);
                int pq = kl / 4;
                uint32_t keep = kl % 4 ? (1u << (8 * (kl % 4))) - 1 : 0;
                V256 vkeep = VSET1(keep), vpad = VSET1(0x80u << (8 * (kl % 4)));
                for (int it = 0; it < 50; it++)
                {
                    for (int q = 0; q < 5; q++) { WA[q] = WB[q] = VZERO; }
                    for (int q = 0; q < pq; q++) { WA[q] = st[q]; WB[q] = st[4 + q]; }
                    WA[pq] = VOR(VAND(pq < 4 ? st[pq] : WA[pq], vkeep), vpad);
                    WB[pq] = VOR(VAND(pq < 4 ? st[4 + pq] : WB[pq], vkeep), vpad);
                    md5x16_iv(st);
                    md5x16(st, WA, WB, cw, 0x1f);
                }
            }
        }
        keys_le16(st, st + 4, K);
        uint32_t y[16];
        if (P->r == 2)
        {
            rc4_ksa8_5(S[0], K);
            rc4_ksa8_5(S[1], K + 128);
            rc4_prga8(S[0], ks[0], 4);
            rc4_prga8(S[1], ks[1], 4);
            for (int l = 0; l < 16; l++) { uint32_t x; memcpy(&x, ks[l >> 3] + 32 * (l & 7), 4); y[l] = x ^ P->pad0; }
        }
        else
        {
            for (int l = 0; l < 16; l++) y[l] = P->x0;
            for (int pass = 0; pass < 20; pass++)
            {
                for (int q = 0; q < 256; q++) XK[q] = (uint8_t)(K[q] ^ pass);
                if (kl == 16) { rc4_ksa8_16(S[0], XK); rc4_ksa8_16(S[1], XK + 128); }
                else if (kl == 5) { rc4_ksa8_5(S[0], XK); rc4_ksa8_5(S[1], XK + 128); }
                else { rc4_ksa8(S[0], XK, kl); rc4_ksa8(S[1], XK + 128, kl); }
                rc4_prga8(S[0], ks[0], 4);
                rc4_prga8(S[1], ks[1], 4);
                for (int l = 0; l < 16; l++) { uint32_t x; memcpy(&x, ks[l >> 3] + 32 * (l & 7), 4); y[l] ^= x; }
            }
        }
        for (int l = 0; l < 16 && i0 + l < n; l++)
            if (y[l] == P->u0) nh = add_hit(hits, nh, maxh, i0 + l);
    }
    return nh;
}
#endif

/* ------------------------------------------------------------------------------------------ */
/* PDF R6 (hashcat 10700): ISO 32000-2 algorithm 2.B                                           */
/* ------------------------------------------------------------------------------------------ */
/*
 * K = SHA-256(pw || salt); then at least 64 rounds of
 *   E = AES-128-CBC(key K[0..16], iv K[16..32], (pw || K) x 64),  K = SHA-256/384/512(E)
 * where the hash is picked by the first 16 bytes of E (sum mod 3), until round >= 64 and
 * E[last] <= round - 32. Candidates diverge in hash function and K length, so each thread keeps a
 * pool of lanes and runs whichever (function, |K|) bin has eight lanes ready. E is never stored:
 * the AES blocks of eight independent CBC chains are produced block by block and fed straight
 * into an eight-lane SHA-256 or two four-lane SHA-384/512 compressions.
 */
static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};
static const uint64_t SHA512_K[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
    0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
    0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
    0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
    0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
    0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull,
    0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull,
    0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
    0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
    0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
    0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
    0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
    0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
    0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};
static const uint32_t SHA256_IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};
static const uint64_t SHA512_IV[8] = {
    0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
    0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
};
static const uint64_t SHA384_IV[8] = {
    0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull, 0x9159015a3070dd17ull, 0x152fecd8f70e5939ull,
    0x67332667ffc00b31ull, 0x8eb44a8768581511ull, 0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull,
};

static inline uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void sha256_block(uint32_t s[8], const uint8_t* p)
{
    uint32_t w[64];
    for (int t = 0; t < 16; t++) w[t] = be32(p + 4 * t);
    for (int t = 16; t < 64; t++)
    {
        uint32_t s0 = ror32(w[t - 15], 7) ^ ror32(w[t - 15], 18) ^ (w[t - 15] >> 3);
        uint32_t s1 = ror32(w[t - 2], 17) ^ ror32(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    for (int t = 0; t < 64; t++)
    {
        uint32_t t1 = h + (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)) + (g ^ (e & (f ^ g))) + SHA256_K[t] + w[t];
        uint32_t t2 = (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)) + ((a & b) | (c & (a | b)));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

/* SHA-256 of a short message (the initial K: password || 8-byte salt). */
static void sha256_short(const uint8_t* m, int n, uint8_t out[32])
{
    uint32_t s[8];
    memcpy(s, SHA256_IV, sizeof s);
    uint8_t b[192] = { 0 };
    memcpy(b, m, (size_t)n);
    b[n] = 0x80;
    int nb = (n + 9 + 63) / 64;
    uint64_t bits = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) b[nb * 64 - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (int i = 0; i < nb; i++) sha256_block(s, b + 64 * i);
    for (int i = 0; i < 8; i++) put_be32(out + 4 * i, s[i]);
}

#define PDF6_POOL 64            /* > 9 bins x 7: some bin always has eight lanes while the pool is full */
#define PDF6_MAXLEN 127

#if RK_X64
#define AVXAES __attribute__((target("avx2,aes")))
#define PDF6FN AVXAES
typedef __m128i V128;
#define V128_LAST(x) ((uint8_t)_mm_extract_epi8((x), 15))
#elif RK_ARM64
#define PDF6FN ARMCE
typedef uint8x16_t V128;
#define V128_LAST(x) vgetq_lane_u8((x), 15)
#endif

#if RK_VEC
typedef struct
{
    V128 rk[11];                /* AES-128 round keys from K[0..16] */
    V128 c;                     /* CBC chain: the last E block produced */
    V128 e0;                    /* E block 0 (computed when the lane is binned) */
    uint8_t k[64];
    uint8_t pk[2 * (PDF6_MAXLEN + 64) + 16];    /* (pw || K) twice: any 16 bytes of the period */
    int idx, round, kl;
} pdf6_lane;
#endif

#if RK_X64

#define AES_EXP(i, rc) do { __m128i g_ = _mm_shuffle_epi32(_mm_aeskeygenassist_si128(k_, rc), 0xff); \
    k_ = _mm_xor_si128(k_, _mm_slli_si128(k_, 4)); k_ = _mm_xor_si128(k_, _mm_slli_si128(k_, 4));     \
    k_ = _mm_xor_si128(k_, _mm_slli_si128(k_, 4)); k_ = _mm_xor_si128(k_, g_); rk[i] = k_; } while (0)

AVXAES static void aes128_expand(__m128i* rk, const uint8_t* key)
{
    __m128i k_ = _mm_loadu_si128((const __m128i*)key);
    rk[0] = k_;
    AES_EXP(1, 0x01); AES_EXP(2, 0x02); AES_EXP(3, 0x04); AES_EXP(4, 0x08); AES_EXP(5, 0x10);
    AES_EXP(6, 0x20); AES_EXP(7, 0x40); AES_EXP(8, 0x80); AES_EXP(9, 0x1b); AES_EXP(10, 0x36);
}

/* Sets up round `l->round` for K = l->k: key schedule, E block 0, and the lane's bin. */
AVXAES static int pdf6_prep(pdf6_lane* l, const uint8_t* pw, int len)
{
    int p = len + l->kl;
    memcpy(l->pk, pw, (size_t)len);
    memcpy(l->pk + len, l->k, (size_t)l->kl);
    memcpy(l->pk + p, l->pk, (size_t)p);
    aes128_expand(l->rk, l->k);
    __m128i x = _mm_xor_si128(_mm_loadu_si128((const __m128i*)l->pk), _mm_loadu_si128((const __m128i*)(l->k + 16)));
    x = _mm_xor_si128(x, l->rk[0]);
    for (int r = 1; r < 10; r++) x = _mm_aesenc_si128(x, l->rk[r]);
    x = _mm_aesenclast_si128(x, l->rk[10]);
    l->e0 = l->c = x;
    __m128i sad = _mm_sad_epu8(x, _mm_setzero_si128());
    int sum = _mm_cvtsi128_si32(sad) + _mm_extract_epi16(sad, 4);
    return (sum % 3) * 3 + (l->kl == 32 ? 0 : l->kl == 48 ? 1 : 2);
}

#define R32(x, n) VOR(_mm256_srli_epi32((x), (n)), _mm256_slli_epi32((x), 32 - (n)))
AVX2 static void sha256x8(V256* st, V256* W)
{
    V256 a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
#pragma clang loop unroll(full)
    for (int t = 0; t < 64; t++)
    {
        if (t >= 16)
        {
            V256 w15 = W[(t + 1) & 15], w2 = W[(t + 14) & 15];
            V256 s0 = VXOR(VXOR(R32(w15, 7), R32(w15, 18)), _mm256_srli_epi32(w15, 3));
            V256 s1 = VXOR(VXOR(R32(w2, 17), R32(w2, 19)), _mm256_srli_epi32(w2, 10));
            W[t & 15] = VADD(VADD(W[t & 15], s0), VADD(W[(t + 9) & 15], s1));
        }
        V256 t1 = VADD(VADD(h, VXOR(VXOR(R32(e, 6), R32(e, 11)), R32(e, 25))),
                       VADD(VXOR(g, VAND(e, VXOR(f, g))), VADD(_mm256_set1_epi32((int)SHA256_K[t]), W[t & 15])));
        V256 t2 = VADD(VXOR(VXOR(R32(a, 2), R32(a, 13)), R32(a, 22)), VOR(VAND(a, b), VAND(c, VOR(a, b))));
        h = g; g = f; f = e; e = VADD(d, t1); d = c; c = b; b = a; a = VADD(t1, t2);
    }
    st[0] = VADD(st[0], a); st[1] = VADD(st[1], b); st[2] = VADD(st[2], c); st[3] = VADD(st[3], d);
    st[4] = VADD(st[4], e); st[5] = VADD(st[5], f); st[6] = VADD(st[6], g); st[7] = VADD(st[7], h);
}

#define A64 _mm256_add_epi64
#define R64(x, n) VOR(_mm256_srli_epi64((x), (n)), _mm256_slli_epi64((x), 64 - (n)))
AVX2 static void sha512x4(V256* st, V256* W)
{
    V256 a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
#pragma clang loop unroll(full)
    for (int t = 0; t < 80; t++)
    {
        if (t >= 16)
        {
            V256 w15 = W[(t + 1) & 15], w2 = W[(t + 14) & 15];
            V256 s0 = VXOR(VXOR(R64(w15, 1), R64(w15, 8)), _mm256_srli_epi64(w15, 7));
            V256 s1 = VXOR(VXOR(R64(w2, 19), R64(w2, 61)), _mm256_srli_epi64(w2, 6));
            W[t & 15] = A64(A64(W[t & 15], s0), A64(W[(t + 9) & 15], s1));
        }
        V256 t1 = A64(A64(h, VXOR(VXOR(R64(e, 14), R64(e, 18)), R64(e, 41))),
                      A64(VXOR(g, VAND(e, VXOR(f, g))), A64(_mm256_set1_epi64x((long long)SHA512_K[t]), W[t & 15])));
        V256 t2 = A64(VXOR(VXOR(R64(a, 28), R64(a, 34)), R64(a, 39)), VOR(VAND(a, b), VAND(c, VOR(a, b))));
        h = g; g = f; f = e; e = A64(d, t1); d = c; c = b; b = a; a = A64(t1, t2);
    }
    st[0] = A64(st[0], a); st[1] = A64(st[1], b); st[2] = A64(st[2], c); st[3] = A64(st[3], d);
    st[4] = A64(st[4], e); st[5] = A64(st[5], f); st[6] = A64(st[6], g); st[7] = A64(st[7], h);
}

/* r[i] = row i (8 x 32-bit) -> r[j] = column j. */
AVX2 static void tr8x8_32(V256* r)
{
    V256 t0 = _mm256_unpacklo_epi32(r[0], r[1]), t1 = _mm256_unpackhi_epi32(r[0], r[1]);
    V256 t2 = _mm256_unpacklo_epi32(r[2], r[3]), t3 = _mm256_unpackhi_epi32(r[2], r[3]);
    V256 t4 = _mm256_unpacklo_epi32(r[4], r[5]), t5 = _mm256_unpackhi_epi32(r[4], r[5]);
    V256 t6 = _mm256_unpacklo_epi32(r[6], r[7]), t7 = _mm256_unpackhi_epi32(r[6], r[7]);
    V256 u0 = _mm256_unpacklo_epi64(t0, t2), u1 = _mm256_unpackhi_epi64(t0, t2);
    V256 u2 = _mm256_unpacklo_epi64(t1, t3), u3 = _mm256_unpackhi_epi64(t1, t3);
    V256 u4 = _mm256_unpacklo_epi64(t4, t6), u5 = _mm256_unpackhi_epi64(t4, t6);
    V256 u6 = _mm256_unpacklo_epi64(t5, t7), u7 = _mm256_unpackhi_epi64(t5, t7);
    r[0] = _mm256_permute2x128_si256(u0, u4, 0x20); r[1] = _mm256_permute2x128_si256(u1, u5, 0x20);
    r[2] = _mm256_permute2x128_si256(u2, u6, 0x20); r[3] = _mm256_permute2x128_si256(u3, u7, 0x20);
    r[4] = _mm256_permute2x128_si256(u0, u4, 0x31); r[5] = _mm256_permute2x128_si256(u1, u5, 0x31);
    r[6] = _mm256_permute2x128_si256(u2, u6, 0x31); r[7] = _mm256_permute2x128_si256(u3, u7, 0x31);
}

/* r[i] = row i (4 x 64-bit) -> r[j] = column j. */
AVX2 static void tr4x4_64(V256* r)
{
    V256 t0 = _mm256_unpacklo_epi64(r[0], r[1]), t1 = _mm256_unpackhi_epi64(r[0], r[1]);
    V256 t2 = _mm256_unpacklo_epi64(r[2], r[3]), t3 = _mm256_unpackhi_epi64(r[2], r[3]);
    r[0] = _mm256_permute2x128_si256(t0, t2, 0x20); r[1] = _mm256_permute2x128_si256(t1, t3, 0x20);
    r[2] = _mm256_permute2x128_si256(t0, t2, 0x31); r[3] = _mm256_permute2x128_si256(t1, t3, 0x31);
}

/*
 * One round for up to eight lanes of bin `bin` (all with the same |K|, so the same E length):
 * E is generated 16 bytes at a time per lane and hashed as it is produced. Missing lanes repeat
 * lane 0. Updates k, kl, round and c (whose last byte is E's).
 */
AVXAES static void pdf6_round(pdf6_lane** g, int bin, int len)
{
    const int fn = bin / 3, kl = 32 + 16 * (bin % 3), p = len + kl;
    const int T = 64 * p, nchunks = T / 16;
    const int bsz = fn == 0 ? 64 : 128, cpb = bsz / 16;
    const int nb = (T + (fn == 0 ? 9 : 17) + bsz - 1) / bsz;
    uint8_t buf[8][128] __attribute__((aligned(32)));
    __m128i c[8];
    for (int l = 0; l < 8; l++) c[l] = g[l]->c;
    V256 st[16], W[16];
    if (fn == 0) for (int i = 0; i < 8; i++) st[i] = _mm256_set1_epi32((int)SHA256_IV[i]);
    else for (int i = 0; i < 8; i++) st[i] = st[8 + i] = _mm256_set1_epi64x((long long)(fn == 1 ? SHA384_IV : SHA512_IV)[i]);
    const V256 bs32 = _mm256_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
    const V256 bs64 = _mm256_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8);
    int off = 16, q = 0;
    for (int b = 0; b < nb; b++)
    {
        for (int ci = 0; ci < cpb; ci++, q++)
        {
            if (q == 0) { for (int l = 0; l < 8; l++) _mm_store_si128((__m128i*)buf[l], g[l]->e0); continue; }
            if (q < nchunks)
            {
                __m128i x[8];
                for (int l = 0; l < 8; l++) x[l] = _mm_xor_si128(_mm_xor_si128(_mm_loadu_si128((const __m128i*)(g[l]->pk + off)), c[l]), g[l]->rk[0]);
                for (int r = 1; r < 10; r++)
                    for (int l = 0; l < 8; l++) x[l] = _mm_aesenc_si128(x[l], g[l]->rk[r]);
                for (int l = 0; l < 8; l++) { c[l] = x[l] = _mm_aesenclast_si128(x[l], g[l]->rk[10]); _mm_store_si128((__m128i*)(buf[l] + 16 * ci), x[l]); }
                off += 16;
                if (off >= p) off -= p;
            }
            else
            {
                /* Padding: 0x80 right after E, zeros, the bit length in the block's last 8 bytes. */
                uint8_t pad[16] = { 0 };
                if (q == nchunks) pad[0] = 0x80;
                if (b == nb - 1 && ci == cpb - 1)
                {
                    uint64_t bits = (uint64_t)T * 8;
                    for (int i = 0; i < 8; i++) pad[15 - i] = (uint8_t)(bits >> (8 * i));
                }
                for (int l = 0; l < 8; l++) memcpy(buf[l] + 16 * ci, pad, 16);
            }
        }
        if (fn == 0)
        {
            for (int h = 0; h < 2; h++)
            {
                for (int l = 0; l < 8; l++) W[8 * h + l] = _mm256_load_si256((const V256*)(buf[l] + 32 * h));
                tr8x8_32(W + 8 * h);
            }
            for (int i = 0; i < 16; i++) W[i] = _mm256_shuffle_epi8(W[i], bs32);
            sha256x8(st, W);
        }
        else
        {
            for (int gi = 0; gi < 2; gi++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int l = 0; l < 4; l++) W[4 * j + l] = _mm256_load_si256((const V256*)(buf[4 * gi + l] + 32 * j));
                    tr4x4_64(W + 4 * j);
                }
                for (int i = 0; i < 16; i++) W[i] = _mm256_shuffle_epi8(W[i], bs64);
                sha512x4(st + 8 * gi, W);
            }
        }
    }
    /* New K per lane: the state words, big-endian. */
    int nkl = fn == 0 ? 32 : fn == 1 ? 48 : 64;
    if (fn == 0)
    {
        tr8x8_32(st);
        for (int l = 0; l < 8; l++) _mm256_store_si256((V256*)buf[l], _mm256_shuffle_epi8(st[l], bs32));
    }
    else
    {
        for (int gi = 0; gi < 2; gi++)
            for (int j = 0; j < 2; j++)
            {
                V256* s4 = st + 8 * gi + 4 * j;
                tr4x4_64(s4);
                for (int l = 0; l < 4; l++) _mm256_store_si256((V256*)(buf[4 * gi + l] + 32 * j), _mm256_shuffle_epi8(s4[l], bs64));
            }
    }
    for (int l = 0; l < 8; l++)
    {
        memcpy(g[l]->k, buf[l], (size_t)nkl);
        g[l]->kl = nkl;
        g[l]->c = c[l];
        g[l]->round++;
    }
}
#elif RK_ARM64
/*
 * ARMv8 Crypto Extensions: AESE/AESMC for the CBC chains, SHA256H/SHA512H for the hashes. The
 * hash instructions work on one message at a time, so the eight lanes of a group are eight
 * independent streams, interleaved to cover the instruction latency; each 16-byte AES block is
 * byte-swapped straight into a message register.
 */
#define PDF6_G512 2             /* SHA-384/512 streams per interleaved compression (1: -11 %, 4: -2 %, 8: -14 %) */

/* AES-128 key schedule. SubWord is AESE with a zero key on four copies of the word (ShiftRows then moves nothing). */
ARMCE static void aes128_expand(uint8x16_t* rk, const uint8_t* key)
{
    static const uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
    uint32_t w[44];
    memcpy(w, key, 16);
    for (int i = 4; i < 44; i++)
    {
        uint32_t t = w[i - 1];
        if (i % 4 == 0)
        {
            uint8x16_t s = vaeseq_u8(vreinterpretq_u8_u32(vdupq_n_u32(t)), vdupq_n_u8(0));
            t = ror32(vgetq_lane_u32(vreinterpretq_u32_u8(s), 0), 8) ^ rcon[i / 4 - 1];
        }
        w[i] = w[i - 4] ^ t;
    }
    for (int r = 0; r < 11; r++) rk[r] = vld1q_u8((const uint8_t*)(w + 4 * r));
}

/* Sets up round `l->round` for K = l->k: key schedule, E block 0, and the lane's bin. */
ARMCE static int pdf6_prep(pdf6_lane* l, const uint8_t* pw, int len)
{
    int p = len + l->kl;
    memcpy(l->pk, pw, (size_t)len);
    memcpy(l->pk + len, l->k, (size_t)l->kl);
    memcpy(l->pk + p, l->pk, (size_t)p);
    aes128_expand(l->rk, l->k);
    uint8x16_t x = veorq_u8(vld1q_u8(l->pk), vld1q_u8(l->k + 16));
    for (int r = 0; r < 9; r++) x = vaesmcq_u8(vaeseq_u8(x, l->rk[r]));
    x = veorq_u8(vaeseq_u8(x, l->rk[9]), l->rk[10]);
    l->e0 = l->c = x;
    int sum = vaddlvq_u8(x);
    return (sum % 3) * 3 + (l->kl == 32 ? 0 : l->kl == 48 ? 1 : 2);
}

/* One SHA-256 block for four streams: s0 = ABCD, s1 = EFGH; m[l] = message words 0..15 (overwritten). */
ARMCE static inline __attribute__((always_inline)) void sha256ce_x4(uint32x4_t* s0, uint32x4_t* s1, uint32x4_t (*m)[4])
{
    uint32x4_t a0[4], b0[4];
    for (int l = 0; l < 4; l++) { a0[l] = s0[l]; b0[l] = s1[l]; }
#pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++)
    {
        const uint32x4_t k = vld1q_u32(SHA256_K + 4 * i);
#pragma clang loop unroll(full)
        for (int l = 0; l < 4; l++)
        {
            if (i >= 4) m[l][i & 3] = vsha256su1q_u32(vsha256su0q_u32(m[l][i & 3], m[l][(i + 1) & 3]), m[l][(i + 2) & 3], m[l][(i + 3) & 3]);
            uint32x4_t wk = vaddq_u32(m[l][i & 3], k), t = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], t, wk);
        }
    }
    for (int l = 0; l < 4; l++) { s0[l] = vaddq_u32(s0[l], a0[l]); s1[l] = vaddq_u32(s1[l], b0[l]); }
}

/*
 * One SHA-512 block for PDF6_G512 streams: s[l] = AB CD EF GH; m[l] = message words 0..15 in pairs.
 * Two rounds per step; the four state registers take turns in each role.
 */
ARMCE static inline __attribute__((always_inline)) void sha512ce_g(uint64x2_t (*s)[4], uint64x2_t (*m)[8])
{
    uint64x2_t sv[PDF6_G512][4];
    for (int l = 0; l < PDF6_G512; l++) for (int j = 0; j < 4; j++) sv[l][j] = s[l][j];
#pragma clang loop unroll(full)
    for (int i = 0; i < 40; i++)
    {
        const uint64x2_t k = vld1q_u64(SHA512_K + 2 * i);
        const int ab = (4 - (i & 3)) & 3, cd = (5 - (i & 3)) & 3, ef = (6 - (i & 3)) & 3, gh = (7 - (i & 3)) & 3;
#pragma clang loop unroll(full)
        for (int l = 0; l < PDF6_G512; l++)
        {
            uint64x2_t* r = s[l];
            uint64x2_t mk = vaddq_u64(m[l][i & 7], k);
            uint64x2_t t1 = vaddq_u64(vextq_u64(mk, mk, 1), r[gh]);
            uint64x2_t t0 = vsha512hq_u64(t1, vextq_u64(r[ef], r[gh], 1), vextq_u64(r[cd], r[ef], 1));
            r[gh] = vsha512h2q_u64(t0, r[cd], r[ab]);
            r[cd] = vaddq_u64(r[cd], t0);
            if (i < 32)
                m[l][i & 7] = vsha512su1q_u64(vsha512su0q_u64(m[l][i & 7], m[l][(i + 1) & 7]), m[l][(i + 7) & 7],
                                              vextq_u64(m[l][(i + 4) & 7], m[l][(i + 5) & 7], 1));
        }
    }
    for (int l = 0; l < PDF6_G512; l++) for (int j = 0; j < 4; j++) s[l][j] = vaddq_u64(s[l][j], sv[l][j]);
}

/* One round for eight lanes of bin `bin`, as the AVX2 version: E is hashed as it is produced. */
ARMCE static void pdf6_round(pdf6_lane** g, int bin, int len)
{
    const int fn = bin / 3, kl = 32 + 16 * (bin % 3), p = len + kl;
    const int T = 64 * p, nchunks = T / 16;
    const int bsz = fn == 0 ? 64 : 128, cpb = bsz / 16;
    const int nb = (T + (fn == 0 ? 9 : 17) + bsz - 1) / bsz;
    uint8x16_t c[8], blk[8][8];
    uint32x4_t s0[8], s1[8];
    uint64x2_t s5[8][4];
    for (int l = 0; l < 8; l++) c[l] = g[l]->c;
    if (fn == 0)
        for (int l = 0; l < 8; l++) { s0[l] = vld1q_u32(SHA256_IV); s1[l] = vld1q_u32(SHA256_IV + 4); }
    else
        for (int l = 0; l < 8; l++)
            for (int j = 0; j < 4; j++) s5[l][j] = vld1q_u64((fn == 1 ? SHA384_IV : SHA512_IV) + 2 * j);
    int off = 16, q = 0;
    for (int b = 0; b < nb; b++)
    {
        for (int ci = 0; ci < cpb; ci++, q++)
        {
            if (q == 0) { for (int l = 0; l < 8; l++) blk[l][ci] = g[l]->e0; continue; }
            if (q < nchunks)
            {
                uint8x16_t x[8];
                for (int l = 0; l < 8; l++) x[l] = veorq_u8(vld1q_u8(g[l]->pk + off), c[l]);
                for (int r = 0; r < 9; r++)
                    for (int l = 0; l < 8; l++) x[l] = vaesmcq_u8(vaeseq_u8(x[l], g[l]->rk[r]));
                for (int l = 0; l < 8; l++) c[l] = blk[l][ci] = veorq_u8(vaeseq_u8(x[l], g[l]->rk[9]), g[l]->rk[10]);
                off += 16;
                if (off >= p) off -= p;
            }
            else
            {
                /* Padding: 0x80 right after E, zeros, the bit length in the block's last 8 bytes. */
                uint8_t pad[16] = { 0 };
                if (q == nchunks) pad[0] = 0x80;
                if (b == nb - 1 && ci == cpb - 1)
                {
                    uint64_t bits = (uint64_t)T * 8;
                    for (int i = 0; i < 8; i++) pad[15 - i] = (uint8_t)(bits >> (8 * i));
                }
                for (int l = 0; l < 8; l++) blk[l][ci] = vld1q_u8(pad);
            }
        }
        if (fn == 0)
            for (int h = 0; h < 8; h += 4)
            {
                uint32x4_t m[4][4];
                for (int l = 0; l < 4; l++)
                    for (int j = 0; j < 4; j++) m[l][j] = vreinterpretq_u32_u8(vrev32q_u8(blk[h + l][j]));
                sha256ce_x4(s0 + h, s1 + h, m);
            }
        else
            for (int h = 0; h < 8; h += PDF6_G512)
            {
                uint64x2_t m[PDF6_G512][8];
                for (int l = 0; l < PDF6_G512; l++)
                    for (int j = 0; j < 8; j++) m[l][j] = vreinterpretq_u64_u8(vrev64q_u8(blk[h + l][j]));
                sha512ce_g(s5 + h, m);
            }
    }
    /* New K per lane: the state words, big-endian. */
    int nkl = fn == 0 ? 32 : fn == 1 ? 48 : 64;
    for (int l = 0; l < 8; l++)
    {
        uint8_t kb[64];
        if (fn == 0)
        {
            vst1q_u8(kb, vrev32q_u8(vreinterpretq_u8_u32(s0[l])));
            vst1q_u8(kb + 16, vrev32q_u8(vreinterpretq_u8_u32(s1[l])));
        }
        else
            for (int j = 0; j < 4; j++) vst1q_u8(kb + 16 * j, vrev64q_u8(vreinterpretq_u8_u64(s5[l][j])));
        memcpy(g[l]->k, kb, (size_t)nkl);
        g[l]->kl = nkl;
        g[l]->c = c[l];
        g[l]->round++;
    }
}
#endif

#if RK_VEC
/* Keeps a pool of candidates and runs whichever (hash, |K|) bin has the most lanes ready. */
PDF6FN static int pdf6_pool(const uint8_t* u48, const uint8_t* pws, int len, int n, int* hits, int maxh)
{
    void* raw;
    pdf6_lane* lanes = (pdf6_lane*)aligned_buf(sizeof(pdf6_lane) * (PDF6_POOL + 8), &raw);
    if (!lanes) return -1;
    pdf6_lane* scratch = lanes + PDF6_POOL;     /* lane copies that pad a partial group */
    int bins[9][PDF6_POOL], bc[9] = { 0 };
    uint8_t init[PDF6_MAXLEN + 8];
    int next = 0, active = 0, nh = 0;
    for (int i = 0; i < PDF6_POOL && next < n; i++, next++, active++)
    {
        pdf6_lane* l = &lanes[i];
        const uint8_t* pw = pws + (size_t)next * len;
        memcpy(init, pw, (size_t)len); memcpy(init + len, u48 + 32, 8);
        sha256_short(init, len + 8, l->k);
        l->kl = 32; l->round = 0; l->idx = next;
        int b = pdf6_prep(l, pw, len);
        bins[b][bc[b]++] = i;
    }
    while (active > 0)
    {
        int b = 0;
        for (int i = 1; i < 9; i++) if (bc[i] > bc[b]) b = i;
        int m = bc[b] < 8 ? bc[b] : 8;
        int ids[8];
        pdf6_lane* g[8];
        for (int i = 0; i < m; i++) { ids[i] = bins[b][--bc[b]]; g[i] = &lanes[ids[i]]; }
        for (int i = m; i < 8; i++) { scratch[i] = *g[0]; g[i] = &scratch[i]; }
        pdf6_round(g, b, len);
        for (int i = 0; i < m; i++)
        {
            pdf6_lane* l = g[i];
            int elast = V128_LAST(l->c);
            if (l->round >= 64 && elast <= l->round - 32)
            {
                if (memcmp(l->k, u48, 32) == 0) nh = add_hit(hits, nh, maxh, l->idx);
                if (next >= n) { active--; continue; }
                const uint8_t* pw = pws + (size_t)next * len;
                memcpy(init, pw, (size_t)len); memcpy(init + len, u48 + 32, 8);
                sha256_short(init, len + 8, l->k);
                l->kl = 32; l->round = 0; l->idx = next++;
            }
            int nbin = pdf6_prep(l, pws + (size_t)l->idx * len, len);
            bins[nbin][bc[nbin]++] = ids[i];
        }
    }
    free(raw);
    return nh;
}
#endif

/*
 * PDF R6 user-password check: n packed candidates of length len against /U (48 bytes: hash,
 * validation salt, key salt). Returns the number of exact matches written to hits, or -1 when this
 * CPU has no fast path.
 */
RK_EXPORT int rk_pdf6_search(const uint8_t* u48, const uint8_t* pws, int len, int n, int* hits, int maxh)
{
#if RK_X64
    if ((features() & RK_FEAT_AVX2) && (features() & RK_FEAT_AESNI) && len >= 0 && len <= PDF6_MAXLEN && n > 0)
        return pdf6_pool(u48, pws, len, n, hits, maxh);
#elif RK_ARM64
    const int need = RK_FEAT_ARM_AES | RK_FEAT_ARM_SHA2 | RK_FEAT_ARM_SHA512;
    if ((features() & need) == need && len >= 0 && len <= PDF6_MAXLEN && n > 0)
        return pdf6_pool(u48, pws, len, n, hits, maxh);
#endif
    (void)u48; (void)pws; (void)len; (void)n; (void)hits; (void)maxh;
    return -1;
}

/*
 * Candidate filters for the RC4 formats. Each tests n passwords of length len (packed) and writes
 * the indices that pass the 32-bit check to hits (up to maxh); returns the number found, or -1 when
 * this CPU has no fast path (the caller then uses its own kernel). Hits are re-verified by the caller.
 */
RK_EXPORT int rk_office97_search(const uint8_t* salt16, const uint8_t* enc32, const uint8_t* pws, int len, int n, int* hits, int maxh)
{
#if RK_VEC
    if ((features() & RK_FEAT_VEC) && len >= 1 && len <= 15) return office97_vec(salt16, enc32, pws, len, n, hits, maxh);
#endif
    (void)salt16; (void)enc32; (void)pws; (void)len; (void)n; (void)hits; (void)maxh;
    return -1;
}

RK_EXPORT int rk_office2003_search(const uint8_t* salt16, const uint8_t* enc36, const uint8_t* pws, int len, int n, int* hits, int maxh)
{
#if RK_VEC
    if ((features() & RK_FEAT_VEC) && len >= 1 && len <= 15) return office2003_vec(salt16, enc36, pws, len, n, hits, maxh);
#endif
    (void)salt16; (void)enc36; (void)pws; (void)len; (void)n; (void)hits; (void)maxh;
    return -1;
}

RK_EXPORT int rk_pdf_search(const rk_pdf_params* params, const uint8_t* pws, int len, int n, int* hits, int maxh)
{
#if RK_VEC
    if ((features() & RK_FEAT_VEC) && len >= 1 && len <= 32 && params->keylen >= 5 && params->keylen <= 16 &&
        (params->r != 2 || params->keylen == 5))
        return pdf_vec(params, pws, len, n, hits, maxh);
#endif
    (void)params; (void)pws; (void)len; (void)n; (void)hits; (void)maxh;
    return -1;
}

/* ------------------------------------------------------------------------------------------ */
/* PBKDF2-HMAC-SHA256, many candidates at once                                                */
/*                                                                                            */
/* Per candidate the HMAC inner and outer states (SHA-256 after key ^ ipad / key ^ opad) and   */
/* U1 are computed once, in scalar code. Every further iteration is two SHA-256 compressions    */
/* of a 32-byte message, run on a lane per candidate: 16 lanes with AVX-512, 8 with AVX2 or     */
/* NEON (sha256_lanes.h, one source for all widths), or 8 interleaved streams of the ARMv8      */
/* SHA-256 instructions. pbkdf2_sha256() is the entry point for the kernels.                  */
/* ------------------------------------------------------------------------------------------ */

#define PBKDF2_MAXLANES 16

/* SHA-256 over m[0..n) continuing state s, after `prefix` bytes already hashed (a multiple of 64). */
static void sha256_tail(uint32_t s[8], const uint8_t* m, size_t n, uint64_t prefix)
{
    uint8_t b[128];
    while (n >= 64) { sha256_block(s, m); m += 64; n -= 64; prefix += 64; }
    memset(b, 0, sizeof b);
    memcpy(b, m, n);
    b[n] = 0x80;
    int nb = n + 9 <= 64 ? 1 : 2;
    uint64_t bits = (prefix + n) * 8;
    for (int i = 0; i < 8; i++) b[nb * 64 - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (int i = 0; i < nb; i++) sha256_block(s, b + 64 * i);
}

/* HMAC-SHA256 key setup: states after the key block xor ipad / opad (keys over 64 bytes are hashed first). */
static void hmac_sha256_states(const uint8_t* key, size_t klen, uint32_t ist[8], uint32_t ost[8])
{
    uint8_t k[64] = { 0 }, b[64];
    if (klen > 64)
    {
        uint32_t s[8];
        memcpy(s, SHA256_IV, sizeof s);
        sha256_tail(s, key, klen, 0);
        for (int i = 0; i < 8; i++) put_be32(k + 4 * i, s[i]);
    }
    else if (klen) memcpy(k, key, klen);
    for (int i = 0; i < 64; i++) b[i] = (uint8_t)(k[i] ^ 0x36);
    memcpy(ist, SHA256_IV, 32);
    sha256_block(ist, b);
    for (int i = 0; i < 64; i++) b[i] = (uint8_t)(k[i] ^ 0x5c);
    memcpy(ost, SHA256_IV, 32);
    sha256_block(ost, b);
}

/* U1 = HMAC(key, salt || INT(block)) from the key's states. */
static void pbkdf2_sha256_u1(const uint32_t ist[8], const uint32_t ost[8], const uint8_t* salt, size_t slen, uint32_t block, uint32_t u[8])
{
    uint8_t buf[256], *m = slen + 4 <= sizeof buf ? buf : (uint8_t*)malloc(slen + 4), d[32];
    if (!m) { memset(u, 0, 32); return; }
    if (slen) memcpy(m, salt, slen);
    put_be32(m + slen, block);
    uint32_t s[8];
    memcpy(s, ist, 32);
    sha256_tail(s, m, slen + 4, 64);
    if (m != buf) free(m);
    for (int i = 0; i < 8; i++) put_be32(d + 4 * i, s[i]);
    memcpy(u, ost, 32);
    sha256_tail(u, d, 32, 64);
}

#define PS_SUFFIX _1
#define PS_V uint32_t
#define PS_L 1
#define PS_FN
#define PS_LANE(v, l) (v)
#include "sha256_lanes.h"

#if RK_X64
typedef uint32_t v8u __attribute__((vector_size(32)));
typedef uint32_t v16u __attribute__((vector_size(64)));
#define PS_SUFFIX _avx2
#define PS_V v8u
#define PS_L 8
#define PS_FN AVX2
#include "sha256_lanes.h"
#define PS_SUFFIX _avx512
#define PS_V v16u
#define PS_L 16
#define PS_FN AVX512
#include "sha256_lanes.h"
#elif RK_ARM64
typedef uint32_t v8u __attribute__((vector_size(32)));
#define PS_SUFFIX _neon
#define PS_V v8u
#define PS_L 8
#define PS_FN
#include "sha256_lanes.h"

/*
 * ARMv8 SHA-256 instructions: one message per register set, so the lanes are independent streams,
 * interleaved to cover the instruction latency. Words 8..15 of every message are the constant
 * padding of a 32-byte message after one 64-byte block.
 */
#ifndef PBKDF2_CE_STREAMS
#define PBKDF2_CE_STREAMS 8         /* 4: -2 %; the hash instructions, not their latency, are the limit (M1 Pro) */
#endif

ARMCE static inline __attribute__((always_inline)) void sha256ce_c32(const uint32x4_t (*st)[2], uint32x4_t (*x)[2])
{
    static const uint32_t pad[8] = { 0x80000000u, 0, 0, 0, 0, 0, 0, 768 };
    uint32x4_t m[PBKDF2_CE_STREAMS][4], s0[PBKDF2_CE_STREAMS], s1[PBKDF2_CE_STREAMS];
    for (int l = 0; l < PBKDF2_CE_STREAMS; l++)
    {
        m[l][0] = x[l][0]; m[l][1] = x[l][1]; m[l][2] = vld1q_u32(pad); m[l][3] = vld1q_u32(pad + 4);
        s0[l] = st[l][0]; s1[l] = st[l][1];
    }
#pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++)
    {
        const uint32x4_t k = vld1q_u32(SHA256_K + 4 * i);
#pragma clang loop unroll(full)
        for (int l = 0; l < PBKDF2_CE_STREAMS; l++)
        {
            if (i >= 4) m[l][i & 3] = vsha256su1q_u32(vsha256su0q_u32(m[l][i & 3], m[l][(i + 1) & 3]), m[l][(i + 2) & 3], m[l][(i + 3) & 3]);
            uint32x4_t wk = vaddq_u32(m[l][i & 3], k), t = s0[l];
            s0[l] = vsha256hq_u32(s0[l], s1[l], wk);
            s1[l] = vsha256h2q_u32(s1[l], t, wk);
        }
    }
    for (int l = 0; l < PBKDF2_CE_STREAMS; l++) { x[l][0] = vaddq_u32(s0[l], st[l][0]); x[l][1] = vaddq_u32(s1[l], st[l][1]); }
}

ARMCE static void pbkdf2_sha256_iter_ce(const uint32_t (*ist)[8], const uint32_t (*ost)[8], uint32_t (*u)[8], uint32_t iter)
{
    uint32x4_t is[PBKDF2_CE_STREAMS][2], os[PBKDF2_CE_STREAMS][2], x[PBKDF2_CE_STREAMS][2], t[PBKDF2_CE_STREAMS][2];
    for (int l = 0; l < PBKDF2_CE_STREAMS; l++)
        for (int h = 0; h < 2; h++)
        {
            is[l][h] = vld1q_u32(ist[l] + 4 * h); os[l][h] = vld1q_u32(ost[l] + 4 * h);
            t[l][h] = x[l][h] = vld1q_u32(u[l] + 4 * h);
        }
    for (uint32_t i = 1; i < iter; i++)
    {
        sha256ce_c32(is, x);
        sha256ce_c32(os, x);
        for (int l = 0; l < PBKDF2_CE_STREAMS; l++) { t[l][0] = veorq_u32(t[l][0], x[l][0]); t[l][1] = veorq_u32(t[l][1], x[l][1]); }
    }
    for (int l = 0; l < PBKDF2_CE_STREAMS; l++) { vst1q_u32(u[l], t[l][0]); vst1q_u32(u[l] + 4, t[l][1]); }
}
#endif

typedef void (*pbkdf2_iter_fn)(const uint32_t (*)[8], const uint32_t (*)[8], uint32_t (*)[8], uint32_t);

#include "pbkdf2_sha256_selftest.h"

#if RK_X64
static int pbkdf2_wide_ok(void)
{
    if (wide_switched_off("RECOVERKIT_RAR5_AVX512")) return 0;
    int state = atomic_load(&g_pbkdf2_wide_test);
    if (state == 0 && atomic_compare_exchange_strong(&g_pbkdf2_wide_test, &state, 1))
    {
        state = pbkdf2_sha256_selftest(pbkdf2_sha256_iter_avx512) ? 2 : 3;
        atomic_store(&g_pbkdf2_wide_test, state);
    }
    return state == 2;
}
#endif

/* The fastest iteration path this CPU (and the feature mask) allows, and its lane count. */
static pbkdf2_iter_fn pbkdf2_sha256_path(int* lanes)
{
    int f = features();
    (void)f;
#if RK_X64
    if ((f & RK_FEAT_AVX512) && pbkdf2_wide_ok()) { *lanes = 16; return pbkdf2_sha256_iter_avx512; }
    if (f & RK_FEAT_AVX2) { *lanes = 8; return pbkdf2_sha256_iter_avx2; }
#elif RK_ARM64
    if (f & RK_FEAT_ARM_SHA2) { *lanes = PBKDF2_CE_STREAMS; return pbkdf2_sha256_iter_ce; }
    if (f & RK_FEAT_NEON) { *lanes = 8; return pbkdf2_sha256_iter_neon; }
#endif
    *lanes = 1;
    return pbkdf2_sha256_iter_1;
}

/*
 * PBKDF2-HMAC-SHA256 (RFC 8018) for n candidates: candidate l is pws + l * stride, lens[l] bytes
 * long (stride bytes when lens is NULL). dk + l * dklen receives its dklen-byte key. iter >= 1.
 */
static void pbkdf2_sha256(const uint8_t* pws, int stride, const int* lens, int n, const uint8_t* salt, int slen,
                          uint32_t iter, uint8_t* dk, int dklen)
{
    int L;
    pbkdf2_iter_fn fn = pbkdf2_sha256_path(&L);
    int path = RK_PATH_SCALAR;
#if RK_X64
    if (iter > 1 && fn == pbkdf2_sha256_iter_avx512) path = RK_PATH_AVX512;
    else if (iter > 1 && fn == pbkdf2_sha256_iter_avx2) path = RK_PATH_AVX2;
#elif RK_ARM64
    if (iter > 1 && fn == pbkdf2_sha256_iter_ce) path = RK_PATH_ARM_SHA256;
    else if (iter > 1 && fn == pbkdf2_sha256_iter_neon) path = RK_PATH_NEON;
#endif
    if (n > 0) atomic_fetch_or(&g_pbkdf2_paths, path);
    uint32_t ist[PBKDF2_MAXLANES][8], ost[PBKDF2_MAXLANES][8], u[PBKDF2_MAXLANES][8];
    for (int i0 = 0; i0 < n; i0 += L)
    {
        int m = n - i0 < L ? n - i0 : L;
        for (int l = 0; l < m; l++)
            hmac_sha256_states(pws + (size_t)(i0 + l) * stride, (size_t)(lens ? lens[i0 + l] : stride), ist[l], ost[l]);
        for (int l = m; l < L; l++) { memcpy(ist[l], ist[0], 32); memcpy(ost[l], ost[0], 32); }   /* idle lanes repeat lane 0 */
        for (int b = 0; b * 32 < dklen; b++)
        {
            for (int l = 0; l < L; l++) pbkdf2_sha256_u1(ist[l], ost[l], salt, (size_t)slen, (uint32_t)b + 1, u[l]);
            if (iter > 1) fn(ist, ost, u, iter);
            int take = dklen - 32 * b < 32 ? dklen - 32 * b : 32;
            for (int l = 0; l < m; l++)
            {
                uint8_t w[32];
                for (int j = 0; j < 8; j++) put_be32(w + 4 * j, u[l][j]);
                memcpy(dk + (size_t)(i0 + l) * dklen + 32 * b, w, (size_t)take);
            }
        }
    }
}

/* Lanes per group of the PBKDF2-SHA256 path in use (for logs and batch sizes). */
RK_EXPORT int rk_pbkdf2_sha256_lanes(void) { int L; pbkdf2_sha256_path(&L); return L; }

/* PBKDF2-HMAC-SHA256 of n packed candidates (see pbkdf2_sha256); for tests. Returns 0, or -1 on bad arguments. */
RK_EXPORT int rk_pbkdf2_sha256(const uint8_t* pws, int stride, const int* lens, int n, const uint8_t* salt, int slen,
                               uint32_t iter, uint8_t* dk, int dklen)
{
    if (n < 0 || stride < 0 || slen < 0 || iter < 1 || dklen < 1) return -1;
    if (lens) for (int i = 0; i < n; i++) if (lens[i] < 0 || lens[i] > stride) return -1;
    pbkdf2_sha256(pws, stride, lens, n, salt, slen, iter, dk, dklen);
    return 0;
}

/*
 * RAR 5 password check (hashcat 13000). The archive's KDF runs PBKDF2-HMAC-SHA256 with 2^lg2
 * iterations for the key and continues to 2^lg2 + 32 for the password check value: the 32-byte
 * value folded to 8 bytes (byte i xored into byte i % 8) must equal check8. n packed candidates of
 * length len; returns the number of matches written to hits.
 */
RK_EXPORT int rk_rar5_search(const uint8_t* salt16, int lg2, const uint8_t* check8, const uint8_t* pws, int len, int n, int* hits, int maxh)
{
    if (lg2 < 1 || lg2 > 24 || len < 0 || n < 0) return -1;
    uint8_t dk[PBKDF2_MAXLANES * 32];
    int nh = 0;
    for (int i0 = 0; i0 < n; i0 += PBKDF2_MAXLANES)
    {
        int m = n - i0 < PBKDF2_MAXLANES ? n - i0 : PBKDF2_MAXLANES;
        pbkdf2_sha256(pws + (size_t)i0 * len, len, NULL, m, salt16, 16, (1u << lg2) + 32, dk, 32);
        for (int l = 0; l < m; l++)
        {
            const uint8_t* v = dk + 32 * l;
            int ok = 1;
            for (int i = 0; i < 8 && ok; i++) ok = (v[i] ^ v[i + 8] ^ v[i + 16] ^ v[i + 24]) == check8[i];
            if (ok) nh = add_hit(hits, nh, maxh, i0 + l);
        }
    }
    return nh;
}

#if RK_X64
static inline uint64_t rk_tsc(void) { unsigned lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); return ((uint64_t)hi << 32) | lo; }
#elif RK_ARM64
static inline uint64_t rk_tsc(void) { uint64_t t; __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t)); return t; }    /* 24 MHz on Apple */
#else
static inline uint64_t rk_tsc(void) { return 0; }
#endif

/* Micro-benchmarks: timestamp-counter ticks per item for primitive `which`. */
RK_EXPORT double rk_bench(int which, int reps)
{
    static uint8_t S[8 * 256] __attribute__((aligned(64)));
    uint8_t K[8 * 16];
    for (int i = 0; i < 128; i++) K[i] = (uint8_t)(i * 37 + 11);
    uint64_t t0 = rk_tsc();
    long items = 0;
    for (int r = 0; r < reps; r++)
    {
        K[0] = (uint8_t)r; K[16] = (uint8_t)(r >> 1);
        switch (which)
        {
            case 0: rc4_ksa16x4(S, K); items += 4; break;
            case 1: rc4_ksa16x8(S, K); items += 8; break;
            case 2: rc4_ksa_n(S, K, 16, 5, 4); items += 4; break;
            case 3: rc4_ksa8_16_c(S, K); items += 8; break;
            case 4: rc4_ksa8_16(S, K); items += 8; break;
            case 5: rc4_ksa8_16z5(S, K); items += 8; break;
            default: return -1;
        }
    }
    uint64_t t1 = rk_tsc();
    volatile uint8_t sink = S[K[0]]; (void)sink;
    return (double)(t1 - t0) / (double)items;
}

#include "whirlpool.h"

/* ZipCrypto header filter. Keys after the shared prefix come from the managed worker. */
static const uint32_t zip_crc[256] = {
    0x00000000u, 0x77073096u, 0xee0e612cu, 0x990951bau, 0x076dc419u, 0x706af48fu, 0xe963a535u, 0x9e6495a3u,
    0x0edb8832u, 0x79dcb8a4u, 0xe0d5e91eu, 0x97d2d988u, 0x09b64c2bu, 0x7eb17cbdu, 0xe7b82d07u, 0x90bf1d91u,
    0x1db71064u, 0x6ab020f2u, 0xf3b97148u, 0x84be41deu, 0x1adad47du, 0x6ddde4ebu, 0xf4d4b551u, 0x83d385c7u,
    0x136c9856u, 0x646ba8c0u, 0xfd62f97au, 0x8a65c9ecu, 0x14015c4fu, 0x63066cd9u, 0xfa0f3d63u, 0x8d080df5u,
    0x3b6e20c8u, 0x4c69105eu, 0xd56041e4u, 0xa2677172u, 0x3c03e4d1u, 0x4b04d447u, 0xd20d85fdu, 0xa50ab56bu,
    0x35b5a8fau, 0x42b2986cu, 0xdbbbc9d6u, 0xacbcf940u, 0x32d86ce3u, 0x45df5c75u, 0xdcd60dcfu, 0xabd13d59u,
    0x26d930acu, 0x51de003au, 0xc8d75180u, 0xbfd06116u, 0x21b4f4b5u, 0x56b3c423u, 0xcfba9599u, 0xb8bda50fu,
    0x2802b89eu, 0x5f058808u, 0xc60cd9b2u, 0xb10be924u, 0x2f6f7c87u, 0x58684c11u, 0xc1611dabu, 0xb6662d3du,
    0x76dc4190u, 0x01db7106u, 0x98d220bcu, 0xefd5102au, 0x71b18589u, 0x06b6b51fu, 0x9fbfe4a5u, 0xe8b8d433u,
    0x7807c9a2u, 0x0f00f934u, 0x9609a88eu, 0xe10e9818u, 0x7f6a0dbbu, 0x086d3d2du, 0x91646c97u, 0xe6635c01u,
    0x6b6b51f4u, 0x1c6c6162u, 0x856530d8u, 0xf262004eu, 0x6c0695edu, 0x1b01a57bu, 0x8208f4c1u, 0xf50fc457u,
    0x65b0d9c6u, 0x12b7e950u, 0x8bbeb8eau, 0xfcb9887cu, 0x62dd1ddfu, 0x15da2d49u, 0x8cd37cf3u, 0xfbd44c65u,
    0x4db26158u, 0x3ab551ceu, 0xa3bc0074u, 0xd4bb30e2u, 0x4adfa541u, 0x3dd895d7u, 0xa4d1c46du, 0xd3d6f4fbu,
    0x4369e96au, 0x346ed9fcu, 0xad678846u, 0xda60b8d0u, 0x44042d73u, 0x33031de5u, 0xaa0a4c5fu, 0xdd0d7cc9u,
    0x5005713cu, 0x270241aau, 0xbe0b1010u, 0xc90c2086u, 0x5768b525u, 0x206f85b3u, 0xb966d409u, 0xce61e49fu,
    0x5edef90eu, 0x29d9c998u, 0xb0d09822u, 0xc7d7a8b4u, 0x59b33d17u, 0x2eb40d81u, 0xb7bd5c3bu, 0xc0ba6cadu,
    0xedb88320u, 0x9abfb3b6u, 0x03b6e20cu, 0x74b1d29au, 0xead54739u, 0x9dd277afu, 0x04db2615u, 0x73dc1683u,
    0xe3630b12u, 0x94643b84u, 0x0d6d6a3eu, 0x7a6a5aa8u, 0xe40ecf0bu, 0x9309ff9du, 0x0a00ae27u, 0x7d079eb1u,
    0xf00f9344u, 0x8708a3d2u, 0x1e01f268u, 0x6906c2feu, 0xf762575du, 0x806567cbu, 0x196c3671u, 0x6e6b06e7u,
    0xfed41b76u, 0x89d32be0u, 0x10da7a5au, 0x67dd4accu, 0xf9b9df6fu, 0x8ebeeff9u, 0x17b7be43u, 0x60b08ed5u,
    0xd6d6a3e8u, 0xa1d1937eu, 0x38d8c2c4u, 0x4fdff252u, 0xd1bb67f1u, 0xa6bc5767u, 0x3fb506ddu, 0x48b2364bu,
    0xd80d2bdau, 0xaf0a1b4cu, 0x36034af6u, 0x41047a60u, 0xdf60efc3u, 0xa867df55u, 0x316e8eefu, 0x4669be79u,
    0xcb61b38cu, 0xbc66831au, 0x256fd2a0u, 0x5268e236u, 0xcc0c7795u, 0xbb0b4703u, 0x220216b9u, 0x5505262fu,
    0xc5ba3bbeu, 0xb2bd0b28u, 0x2bb45a92u, 0x5cb36a04u, 0xc2d7ffa7u, 0xb5d0cf31u, 0x2cd99e8bu, 0x5bdeae1du,
    0x9b64c2b0u, 0xec63f226u, 0x756aa39cu, 0x026d930au, 0x9c0906a9u, 0xeb0e363fu, 0x72076785u, 0x05005713u,
    0x95bf4a82u, 0xe2b87a14u, 0x7bb12baeu, 0x0cb61b38u, 0x92d28e9bu, 0xe5d5be0du, 0x7cdcefb7u, 0x0bdbdf21u,
    0x86d3d2d4u, 0xf1d4e242u, 0x68ddb3f8u, 0x1fda836eu, 0x81be16cdu, 0xf6b9265bu, 0x6fb077e1u, 0x18b74777u,
    0x88085ae6u, 0xff0f6a70u, 0x66063bcau, 0x11010b5cu, 0x8f659effu, 0xf862ae69u, 0x616bffd3u, 0x166ccf45u,
    0xa00ae278u, 0xd70dd2eeu, 0x4e048354u, 0x3903b3c2u, 0xa7672661u, 0xd06016f7u, 0x4969474du, 0x3e6e77dbu,
    0xaed16a4au, 0xd9d65adcu, 0x40df0b66u, 0x37d83bf0u, 0xa9bcae53u, 0xdebb9ec5u, 0x47b2cf7fu, 0x30b5ffe9u,
    0xbdbdf21cu, 0xcabac28au, 0x53b39330u, 0x24b4a3a6u, 0xbad03605u, 0xcdd70693u, 0x54de5729u, 0x23d967bfu,
    0xb3667a2eu, 0xc4614ab8u, 0x5d681b02u, 0x2a6f2b94u, 0xb40bbe37u, 0xc30c8ea1u, 0x5a05df1bu, 0x2d02ef8du,
};
#define Z_SUFFIX _scalar
#define Z_V uint32_t
#define Z_L 1
#define Z_G 4
#define Z_FN
#define Z_LANE(v,l) (v)
#define Z_CRC(k,p) (((k) >> 8) ^ zip_crc[((k) ^ (p)) & 255u])
#include "zip_lanes.h"

#if RK_X64
AVX2 static inline __attribute__((always_inline)) v8u zip_lookup8(v8u x)
{
    return (v8u)_mm256_i32gather_epi32((const int*)zip_crc, (__m256i)(x & 255u), 4);
}
AVX512 static inline __attribute__((always_inline)) v16u zip_lookup16(v16u x)
{
    return (v16u)_mm512_i32gather_epi32((__m512i)(x & 255u), (const void*)zip_crc, 4);
}
#define Z_SUFFIX _avx2
#define Z_V v8u
#define Z_L 8
#define Z_G 3
#define Z_FN AVX2
#define Z_CRC(k,p) (((k) >> 8) ^ zip_lookup8((k) ^ (p)))
#include "zip_lanes.h"
#define Z_SUFFIX _avx512
#define Z_V v16u
#define Z_L 16
#define Z_G 3
#define Z_FN AVX512
#define Z_CRC(k,p) (((k) >> 8) ^ zip_lookup16((k) ^ (p)))
#include "zip_lanes.h"
#elif RK_ARM64
#include <arm_acle.h>
/* Nibble tables fit in two four-register TBL operands. */
static inline __attribute__((always_inline)) uint32x4_t zip_lookup4(uint32x4_t x)
{
    uint8x16x4_t lo, hi;
    for (int i = 0; i < 4; i++)
    {
        lo.val[i] = vreinterpretq_u8_u32(vld1q_u32(zip_crc + 4 * i));
        uint32_t h[4];
        for (int j = 0; j < 4; j++) h[j] = zip_crc[(4 * i + j) << 4];
        hi.val[i] = vreinterpretq_u8_u32(vld1q_u32(h));
    }
    uint32x4_t il = (x & 15u) * 0x04040404u + 0x03020100u;
    uint32x4_t ih = ((x >> 4) & 15u) * 0x04040404u + 0x03020100u;
    return vreinterpretq_u32_u8(veorq_u8(vqtbl4q_u8(lo, vreinterpretq_u8_u32(il)), vqtbl4q_u8(hi, vreinterpretq_u8_u32(ih))));
}
#define Z_SUFFIX _neon
#define Z_V uint32x4_t
#define Z_L 4
#define Z_G 4
#define Z_FN
#define Z_CRC(k,p) (((k) >> 8) ^ zip_lookup4((k) ^ (p)))
#include "zip_lanes.h"
#define Z_SUFFIX _armcrc
#define Z_V uint32_t
#define Z_L 1
#define Z_G 8
#define Z_FN __attribute__((target("crc")))
#define Z_LANE(v,l) (v)
#define Z_CRC(k,p) __crc32b((k), (uint8_t)(p))
#include "zip_lanes.h"
#endif

/* 0 auto, 1 scalar, 2 NEON, 3 AVX2, 4 AVX-512, 5 ARM CRC. -1 means unsupported. */
RK_EXPORT int rk_zip_path(int requested)
{
    int f = features();
    if (requested < 0 || requested > 5) return -1;
    if (requested == 1) return 1;
#if RK_X64
    if ((requested == 0 || requested == 4) && (f & RK_FEAT_AVX512)) return 4;
    if ((requested == 0 || requested == 3) && (f & RK_FEAT_AVX2)) return 3;
#elif RK_ARM64
    if ((requested == 0 || requested == 5) && (f & RK_FEAT_ARM_CRC)) return 5;
    if ((requested == 0 || requested == 2) && (f & RK_FEAT_NEON)) return 2;
#endif
    return requested == 0 ? 1 : -1;
}

RK_EXPORT int rk_zip_search(const uint8_t* header, uint8_t c1, uint8_t c2,
    uint32_t p0, uint32_t p1, uint32_t p2, const uint8_t* last, int n, int* hits, int cap, int path)
{
    if (!header || n < 0 || cap < 0 || (n && !last) || (cap && !hits)) return -1;
    switch (rk_zip_path(path))
    {
#if RK_X64
        case 4: return zip_search_avx512(header, c1, c2, p0, p1, p2, last, n, hits, cap);
        case 3: return zip_search_avx2(header, c1, c2, p0, p1, p2, last, n, hits, cap);
#elif RK_ARM64
        case 5: return zip_search_armcrc(header, c1, c2, p0, p1, p2, last, n, hits, cap);
        case 2: return zip_search_neon(header, c1, c2, p0, p1, p2, last, n, hits, cap);
#endif
        case 1: return zip_search_scalar(header, c1, c2, p0, p1, p2, last, n, hits, cap);
        default: return -1;
    }
}

RK_EXPORT int rk_zip_search_batch(const uint8_t* header, uint8_t c1, uint8_t c2,
    const uint32_t* keys, const uint8_t* last, int n, int* hits, int cap, int path)
{
    if (!header || n < 0 || n > INT32_MAX / 3 || cap < 0 || (n && (!last || !keys)) || (cap && !hits)) return -1;
    switch (rk_zip_path(path))
    {
#if RK_X64
        case 4: return zip_search_batch_avx512(header, c1, c2, keys, last, n, hits, cap);
        case 3: return zip_search_batch_avx2(header, c1, c2, keys, last, n, hits, cap);
#elif RK_ARM64
        case 5: return zip_search_batch_armcrc(header, c1, c2, keys, last, n, hits, cap);
        case 2: return zip_search_batch_neon(header, c1, c2, keys, last, n, hits, cap);
#endif
        case 1: return zip_search_batch_scalar(header, c1, c2, keys, last, n, hits, cap);
        default: return -1;
    }
}

#include "rar3_decode.c"
