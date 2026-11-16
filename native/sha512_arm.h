/* Interleaved SHA-512 streams using ARMv8.2 SHA-512 instructions. Numeric word pairs. */
#ifndef SHA512_CE_STREAMS
#define SHA512_CE_STREAMS 2
#endif
ARMCE static inline __attribute__((always_inline)) void sha512_ce_compress(uint64x2_t (*s)[4], uint64x2_t (*m)[8])
{
    uint64x2_t sv[SHA512_CE_STREAMS][4];
    for (int l = 0; l < SHA512_CE_STREAMS; l++) for (int j = 0; j < 4; j++) sv[l][j] = s[l][j];
#pragma clang loop unroll(full)
    for (int i = 0; i < 40; i++)
    {
        const uint64x2_t k = vld1q_u64(SHA512_K + 2 * i);
        const int ab = (4 - (i & 3)) & 3, cd = (5 - (i & 3)) & 3, ef = (6 - (i & 3)) & 3, gh = (7 - (i & 3)) & 3;
#pragma clang loop unroll(full)
        for (int l = 0; l < SHA512_CE_STREAMS; l++)
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
    for (int l = 0; l < SHA512_CE_STREAMS; l++) for (int j = 0; j < 4; j++) s[l][j] = vaddq_u64(s[l][j], sv[l][j]);
}
