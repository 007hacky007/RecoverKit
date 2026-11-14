/* Included per width. AVX2 and AVX-512 differ only in vector width and lookup intrinsic.
 * Z_G independent groups hide the dependency latency of CRC lookups and the k1 multiply.
 * No key update is needed after header byte 11: only its plaintext is checked here.
 */
#define Z_CAT_(a,b) a##b
#define Z_CAT(a,b) Z_CAT_(a,b)
#define Z_F(n) Z_CAT(n,Z_SUFFIX)
#ifndef Z_LANE
#define Z_LANE(v,l) (v)[l]
#endif
Z_FN static inline __attribute__((always_inline)) int Z_F(zip_filter)(const uint8_t* header, uint8_t c1, uint8_t c2,
    uint32_t p0, uint32_t p1, uint32_t p2, const uint8_t* last, int n, int* hits, int cap, const uint32_t* keys)
{
    int nh = 0;
    const Z_V zero = {0};
    for (int i = 0; i < n; i += Z_L * Z_G)
    {
        Z_V k0[Z_G], k1[Z_G], k2[Z_G], plain[Z_G];
#pragma clang loop unroll(full)
        for (int g = 0; g < Z_G; g++)
        {
            k0[g] = zero + p0; k1[g] = zero + p1; k2[g] = zero + p2;
            for (int l = 0; l < Z_L; l++)
            {
                int idx = i + g * Z_L + l;
                Z_LANE(plain[g], l) = idx < n ? last[idx] : 0;
                if (keys)
                {
                    int at = idx < n ? idx : n - 1;
                    Z_LANE(k0[g], l) = keys[at];
                    Z_LANE(k1[g], l) = keys[n + at];
                    Z_LANE(k2[g], l) = keys[2 * n + at];
                }
            }
        }
        for (int j = 0; j < 12; j++)
        {
#pragma clang loop unroll(full)
            for (int g = 0; g < Z_G; g++)
            {
                k0[g] = Z_CRC(k0[g], plain[g]);
                k1[g] = (k1[g] + (k0[g] & 255u)) * 134775813u + 1u;
                k2[g] = Z_CRC(k2[g], k1[g] >> 24);
                Z_V t = k2[g] | 2u;
                plain[g] = (((t * (t ^ 1u)) >> 8) & 255u) ^ header[j];
            }
        }
        /* Scan in candidate order, including across interleaved groups; ignore tail lanes. */
        for (int g = 0; g < Z_G; g++)
        for (int l = 0; l < Z_L; l++)
        {
            int idx = i + g * Z_L + l;
            uint32_t p = Z_LANE(plain[g], l);
            if (idx < n && (p == c1 || p == c2))
            {
                if (nh < cap) hits[nh] = idx;
                nh++;
            }
        }
    }
    return nh;
}
Z_FN static int Z_F(zip_search)(const uint8_t* header, uint8_t c1, uint8_t c2,
    uint32_t p0, uint32_t p1, uint32_t p2, const uint8_t* last, int n, int* hits, int cap)
{
    return Z_F(zip_filter)(header, c1, c2, p0, p1, p2, last, n, hits, cap, NULL);
}

/* Three arrays of n prefix keys, one key state per candidate before its last character. */
Z_FN static int Z_F(zip_search_batch)(const uint8_t* header, uint8_t c1, uint8_t c2,
    const uint32_t* keys, const uint8_t* last, int n, int* hits, int cap)
{
    return Z_F(zip_filter)(header, c1, c2, 0, 0, 0, last, n, hits, cap, keys);
}
#undef Z_SUFFIX
#undef Z_V
#undef Z_L
#undef Z_G
#undef Z_FN
#undef Z_LANE
#undef Z_CRC
#undef Z_F
#undef Z_CAT
#undef Z_CAT_
