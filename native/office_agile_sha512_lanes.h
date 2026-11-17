/* Fixed 68-byte LE counter + SHA512 digest, using the existing compression. */
#define A5_CAT2(a,b) a##b
#define A5_CAT(a,b) A5_CAT2(a,b)
#define A5_F(name) A5_CAT(name,A5_SUFFIX)
#ifndef A5_LANE
#define A5_LANE(v,l) (v)[l]
#endif
A5_FN static void A5_F(office_agile_iter)(uint64_t (*hash)[8], uint32_t spins)
{
    const A5_V z = {0};
    A5_V x[8], iv[8];
    for (int j=0;j<8;j++)
    {
        iv[j]=z+SHA512_IV[j];
        for (int l=0;l<A5_L;l++) A5_LANE(x[j],l)=hash[l][j];
    }
    for (uint32_t i=0;i<spins;i++)
    {
        A5_V w[16];
        w[0]=(z+((uint64_t)__builtin_bswap32(i)<<32)) | (x[0]>>32);
        for (int j=1;j<8;j++) w[j]=(x[j-1]<<32) | (x[j]>>32);
        w[8]=(x[7]<<32) | (z+UINT64_C(0x80000000));
        for (int j=9;j<15;j++) w[j]=z;
        w[15]=z+544;
        A5_F(sha512_compress)(iv,w,x);
    }
    for (int j=0;j<8;j++) for (int l=0;l<A5_L;l++) hash[l][j]=A5_LANE(x[j],l);
}
#undef A5_SUFFIX
#undef A5_V
#undef A5_L
#undef A5_FN
#undef A5_LANE
#undef A5_F
#undef A5_CAT
#undef A5_CAT2
