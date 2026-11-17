#if RK_X64
#define O7_SHANI __attribute__((target("sha,sse2")))
#define O7_SHA_STREAMS 2
O7_SHANI static void office2007_iter_shani(uint32_t (*hash)[5], uint32_t spins)
{
    __m128i x[O7_SHA_STREAMS], xe[O7_SHA_STREAMS];
    const __m128i iv=_mm_set_epi32(0x67452301u,0xefcdab89u,0x98badcfeu,0x10325476u);
    const __m128i ive=_mm_set_epi32(0xc3d2e1f0u,0,0,0);
    for (int l=0;l<O7_SHA_STREAMS;l++)
    {
        x[l]=_mm_set_epi32(hash[l][0],hash[l][1],hash[l][2],hash[l][3]);
        xe[l]=_mm_set_epi32(hash[l][4],0,0,0);
    }
    for (uint32_t i=0;i<spins;i++)
    {
        __m128i m[O7_SHA_STREAMS][4], abcd[O7_SHA_STREAMS], previous[O7_SHA_STREAMS];
        for (int l=0;l<O7_SHA_STREAMS;l++)
        {
            m[l][0]=_mm_or_si128(_mm_srli_si128(x[l],4),_mm_set_epi32(__builtin_bswap32(i),0,0,0));
            m[l][1]=_mm_or_si128(_mm_slli_si128(x[l],12),_mm_srli_si128(xe[l],4));
            m[l][1]=_mm_or_si128(m[l][1],_mm_set_epi32(0,0,0x80000000u,0));
            m[l][2]=_mm_setzero_si128(); m[l][3]=_mm_set_epi32(0,0,0,192);
            abcd[l]=iv; previous[l]=ive;
        }
#pragma clang loop unroll(full)
        for (int g=0;g<20;g++)
        {
#pragma clang loop unroll(full)
            for (int l=0;l<O7_SHA_STREAMS;l++)
            {
                if (g>=4) m[l][g&3]=_mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(m[l][g&3],m[l][(g+1)&3]),m[l][(g+2)&3]),m[l][(g+3)&3]);
                __m128i e=g==0 ? _mm_add_epi32(ive,m[l][0]) : _mm_sha1nexte_epu32(previous[l],m[l][g&3]);
                previous[l]=abcd[l];
                if (g<5) abcd[l]=_mm_sha1rnds4_epu32(abcd[l],e,0);
                else if (g<10) abcd[l]=_mm_sha1rnds4_epu32(abcd[l],e,1);
                else if (g<15) abcd[l]=_mm_sha1rnds4_epu32(abcd[l],e,2);
                else abcd[l]=_mm_sha1rnds4_epu32(abcd[l],e,3);
            }
        }
        for (int l=0;l<O7_SHA_STREAMS;l++)
        {
            x[l]=_mm_add_epi32(abcd[l],iv);
            xe[l]=_mm_sha1nexte_epu32(previous[l],ive);
        }
    }
    for (int l=0;l<O7_SHA_STREAMS;l++)
    {
        uint32_t out[4]; _mm_storeu_si128((__m128i*)out,x[l]);
        for (int j=0;j<4;j++) hash[l][j]=out[3-j];
        hash[l][4]=(uint32_t)_mm_cvtsi128_si32(_mm_srli_si128(xe[l],12));
    }
}
#elif RK_ARM64
#define O7_SHA_STREAMS 4
__attribute__((target("sha2"))) static void office2007_iter_armsha1(uint32_t (*hash)[5], uint32_t spins)
{
    uint32x4_t x[O7_SHA_STREAMS]; uint32_t xe[O7_SHA_STREAMS];
    const uint32x4_t iv=vld1q_u32(SHA1_IV);
    for (int l=0;l<O7_SHA_STREAMS;l++) { x[l]=vld1q_u32(hash[l]); xe[l]=hash[l][4]; }
    for (uint32_t i=0;i<spins;i++)
    {
        uint32x4_t m[O7_SHA_STREAMS][4], abcd[O7_SHA_STREAMS]; uint32_t e[O7_SHA_STREAMS];
        for (int l=0;l<O7_SHA_STREAMS;l++)
        {
            m[l][0]=vextq_u32(vdupq_n_u32(__builtin_bswap32(i)),x[l],3);
            uint32_t tail[4]={vgetq_lane_u32(x[l],3),xe[l],0x80000000u,0};
            m[l][1]=vld1q_u32(tail); m[l][2]=vdupq_n_u32(0);
            m[l][3]=vsetq_lane_u32(192,vdupq_n_u32(0),3);
            abcd[l]=iv; e[l]=SHA1_IV[4];
        }
#pragma clang loop unroll(full)
        for (int g=0;g<20;g++)
        {
            uint32_t k=g<5?0x5a827999u:g<10?0x6ed9eba1u:g<15?0x8f1bbcdcu:0xca62c1d6u;
#pragma clang loop unroll(full)
            for (int l=0;l<O7_SHA_STREAMS;l++)
            {
                if (g>=4) m[l][g&3]=vsha1su1q_u32(vsha1su0q_u32(m[l][g&3],m[l][(g+1)&3],m[l][(g+2)&3]),m[l][(g+3)&3]);
                uint32x4_t wk=vaddq_u32(m[l][g&3],vdupq_n_u32(k));
                uint32_t next=vsha1h_u32(vgetq_lane_u32(abcd[l],0));
                if (g<5) abcd[l]=vsha1cq_u32(abcd[l],e[l],wk);
                else if (g<10 || g>=15) abcd[l]=vsha1pq_u32(abcd[l],e[l],wk);
                else abcd[l]=vsha1mq_u32(abcd[l],e[l],wk);
                e[l]=next;
            }
        }
        for (int l=0;l<O7_SHA_STREAMS;l++) { x[l]=vaddq_u32(abcd[l],iv); xe[l]=e[l]+SHA1_IV[4]; }
    }
    for (int l=0;l<O7_SHA_STREAMS;l++) { vst1q_u32(hash[l],x[l]); hash[l][4]=xe[l]; }
}
#endif
