/* One candidate per 64-bit lane. The eight 2 KB tables fit in L1; gathers keep the
 * existing scalar transform and need only AVX-512F, without a byte-shuffle ISA. */
typedef uint64_t whirl_v8 __attribute__((vector_size(64)));

static AVX512 inline void whirl_round8(whirl_v8 y[8], const whirl_v8 x[8], const uint64_t t[8][256])
{
    const whirl_v8 mask = (whirl_v8)_mm512_set1_epi64(255);
#define WG(j, i, shift) (whirl_v8)_mm512_i64gather_epi64((__m512i)((x[(i)] >> (shift)) & mask), t[(j)], 8)
    #pragma unroll
    for (int i = 0; i < 8; i++)
        y[i] = WG(0, i, 56) ^ WG(1, (i+7)&7, 48) ^ WG(2, (i+6)&7, 40) ^ WG(3, (i+5)&7, 32)
            ^ WG(4, (i+4)&7, 24) ^ WG(5, (i+3)&7, 16) ^ WG(6, (i+2)&7, 8) ^ WG(7, (i+1)&7, 0);
#undef WG
}

static AVX512 void whirl_compress8(whirl_v8 h[8], const whirl_v8 m[8], const uint64_t t[8][256], const whirl_v8 keys[10][8])
{
    whirl_v8 k[8], s[8], v[8], q[8];
    for (int i = 0; i < 8; i++) { k[i] = h[i]; s[i] = m[i] ^ h[i]; }
    for (int r = 0; r < 10; r++)
    {
        if (keys) memcpy(k, keys[r], sizeof k);
        else
        {
            whirl_round8(q, k, t);
            q[0] ^= (whirl_v8)_mm512_set1_epi64(whirl_rc(r));
            memcpy(k, q, sizeof k);
        }
        whirl_round8(v, s, t);
        for (int i = 0; i < 8; i++) s[i] = v[i] ^ k[i];
    }
    for (int i = 0; i < 8; i++) h[i] ^= s[i] ^ m[i];
}

static AVX512 int whirl_avx512(const uint8_t* salt, const uint8_t* pws, int len, int n, uint8_t* out)
{
    uint64_t t[8][256] __attribute__((aligned(64)));
    whirl_tables(t);
    uint64_t sm[8]; for (int i = 0; i < 8; i++) sm[i] = whirl_load(salt + 8*i);
    const uint64_t first_pad[8] = { 0x0000000180000000ULL, 0, 0, 0, 0, 0, 0, 1056 };
    const uint64_t pad[8] = { 0x8000000000000000ULL, 0, 0, 0, 0, 0, 0, 1024 };
    whirl_v8 vp[8];
    for (int i = 0; i < 8; i++) vp[i] = (whirl_v8)_mm512_set1_epi64(pad[i]);
    for (int c = 0; c < n;)
    {
        int take = n - c < 8 ? n - c : 8;
        whirl_v8 ip[8] = {0}, op[8] = {0}, ik[10][8] = {0}, ok[10][8] = {0}, u[8] = {0}, dk[8];
        /* Setup and U1 are only 1/1000 of PBKDF2. Transpose once, then keep the
         * 999 dependent HMAC iterations in registers and cached vector keys. */
        for (int l = 0; l < take; l++)
        {
            uint8_t pw[64] = {0}; if (len) memcpy(pw, pws + (size_t)(c+l)*len, len);
            uint64_t is[8] = {0}, os[8] = {0}, m[8], ki[10][8], ko[10][8], h[8], first[8];
            for (int i = 0; i < 8; i++) m[i] = whirl_load(pw+8*i) ^ 0x3636363636363636ULL;
            whirl_compress(is, m, t, NULL);
            for (int i = 0; i < 8; i++) m[i] ^= 0x6a6a6a6a6a6a6a6aULL;
            whirl_compress(os, m, t, NULL);
            whirl_keys(ki, is, t); whirl_keys(ko, os, t);
            memcpy(h, is, 64);
            whirl_compress(h, sm, t, ki); whirl_compress(h, first_pad, t, NULL);
            memcpy(first, os, 64);
            whirl_compress(first, h, t, ko); whirl_compress(first, pad, t, NULL);
            for (int i = 0; i < 8; i++)
            {
                ip[i][l] = is[i]; op[i][l] = os[i]; u[i][l] = first[i];
                for (int r = 0; r < 10; r++) { ik[r][i][l] = ki[r][i]; ok[r][i][l] = ko[r][i]; }
            }
        }
        memcpy(dk, u, sizeof dk);
        for (int r = 1; r < 1000; r++)
        {
            whirl_v8 h[8], next[8]; memcpy(h, ip, sizeof h);
            whirl_compress8(h, u, t, ik); whirl_compress8(h, vp, t, NULL);
            memcpy(next, op, sizeof next);
            whirl_compress8(next, h, t, ok); whirl_compress8(next, vp, t, NULL);
            for (int i = 0; i < 8; i++) { u[i] = next[i]; dk[i] ^= next[i]; }
        }
        for (int l = 0; l < take; l++)
            for (int i = 0; i < 8; i++) whirl_store(out + (size_t)(c+l)*64 + 8*i, dk[i][l]);
        c += take;
    }
    return n;
}
