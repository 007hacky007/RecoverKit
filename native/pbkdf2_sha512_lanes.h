/* Repeated HMACs use the reusable SHA-512 compression in sha512_lanes.h. */
#include "sha512_lanes.h"
S5_FN static void S5_F(pbkdf2_sha512_iter)(const uint64_t (*ist)[8], const uint64_t (*ost)[8], uint64_t (*u)[8], uint32_t iter)
{
    S5_V is[8], os[8], x[8], t[8];
    for (int j = 0; j < 8; j++)
    {
        for (int l = 0; l < S5_L; l++)
        {
            S5_LANE(is[j], l) = ist[l][j]; S5_LANE(os[j], l) = ost[l][j]; S5_LANE(x[j], l) = u[l][j];
        }
        t[j] = x[j];
    }
    for (uint32_t i = 1; i < iter; i++)
    {
        S5_V inner[8];
        S5_F(sha512_c64)(is, x, inner);
        S5_F(sha512_c64)(os, inner, x);
        for (int j = 0; j < 8; j++) t[j] ^= x[j];
    }
    for (int j = 0; j < 8; j++) for (int l = 0; l < S5_L; l++) u[l][j] = S5_LANE(t[j], l);
}
#undef S5_SUFFIX
#undef S5_V
#undef S5_L
#undef S5_FN
#undef S5_LANE
#undef S5_F
#undef S5_CAT
#undef S5_CAT2
