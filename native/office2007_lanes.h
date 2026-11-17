/* One fixed 24-byte SHA1 message per lane; keep the digest in registers across spins. */
#define O7_CAT2(a,b) a##b
#define O7_CAT(a,b) O7_CAT2(a,b)
#define O7_F(a) O7_CAT(a,O7_SUFFIX)
#ifndef O7_LANE
#define O7_LANE(v,l) (v)[l]
#endif
#define O7_ROL(x,n) (((x) << (n)) | ((x) >> (32-(n))))
O7_FN static void O7_F(office2007_iter)(uint32_t (*hash)[5], uint32_t spins)
{
    const O7_V z = {0};
    O7_V x[5];
    for (int j=0;j<5;j++) for (int l=0;l<O7_L;l++) O7_LANE(x[j],l)=hash[l][j];
    for (uint32_t i=0;i<spins;i++)
    {
        O7_V w[16];
        w[0]=z+__builtin_bswap32(i);
        for (int j=0;j<5;j++) w[j+1]=x[j];
        w[6]=z+0x80000000u;
        for (int j=7;j<15;j++) w[j]=z;
        w[15]=z+192u;
        O7_V a=z+0x67452301u,b=z+0xefcdab89u,c=z+0x98badcfeu,d=z+0x10325476u,e=z+0xc3d2e1f0u;
#pragma clang loop unroll(full)
        for (int t=0;t<80;t++)
        {
            if (t>=16) w[t&15]=O7_ROL(w[(t-3)&15]^w[(t-8)&15]^w[(t-14)&15]^w[t&15],1);
            O7_V f; uint32_t k;
            if (t<20) { f=d^(b&(c^d)); k=0x5a827999u; }
            else if (t<40) { f=b^c^d; k=0x6ed9eba1u; }
            else if (t<60) { f=(b&c)|(d&(b|c)); k=0x8f1bbcdcu; }
            else { f=b^c^d; k=0xca62c1d6u; }
            O7_V v=O7_ROL(a,5)+f+e+w[t&15]+k;
            e=d; d=c; c=O7_ROL(b,30); b=a; a=v;
        }
        x[0]=a+0x67452301u; x[1]=b+0xefcdab89u; x[2]=c+0x98badcfeu;
        x[3]=d+0x10325476u; x[4]=e+0xc3d2e1f0u;
    }
    for (int j=0;j<5;j++) for (int l=0;l<O7_L;l++) hash[l][j]=O7_LANE(x[j],l);
}
#undef O7_SUFFIX
#undef O7_V
#undef O7_L
#undef O7_FN
#undef O7_LANE
#undef O7_ROL
