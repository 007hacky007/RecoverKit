/* Independent Python hashlib answers for salt 00..0f and distinct UTF16LE inputs. */
static const int O7_TEST_LENGTHS[16] = {0, 2, 8, 16, 38, 40, 54, 56, 64, 80, 100, 126, 128, 200, 256, 512};
static const uint32_t O7_TEST_ANSWERS[16][5] = {
    { 0xa7dafbafu, 0xcc5c54eeu, 0xc6c44c55u, 0x0b8db8bcu, 0x9fd1df79u },
    { 0x096d0818u, 0x08a72004u, 0xa47b6ac2u, 0x6a30c551u, 0x1a2f8258u },
    { 0x76e09dbeu, 0x18f5d582u, 0x35c72754u, 0x5cdd45c7u, 0x41855d49u },
    { 0xdf002b9bu, 0x1710cc25u, 0xb38736b9u, 0x9bfaeba5u, 0x09e19cb2u },
    { 0xfc9da0c6u, 0x24f039f5u, 0x8fc95d95u, 0xa26f56f5u, 0x96f8e760u },
    { 0x091d1bf8u, 0x9ffcec32u, 0xd7c05dbdu, 0xf641034cu, 0x85ccde71u },
    { 0x04617fd9u, 0xd1241013u, 0x3c18fd35u, 0x070545b6u, 0xf1910d05u },
    { 0x867e9114u, 0xe4d7e188u, 0xa766c99eu, 0x4251b285u, 0x5e17468au },
    { 0x5f2ff3e5u, 0xfb15837au, 0x3ddb822cu, 0x96490493u, 0xbaa40880u },
    { 0x38e3882bu, 0x465dce6cu, 0xd950b30cu, 0xc87b3ca1u, 0x4fafd467u },
    { 0x55e0a21fu, 0xced8991cu, 0x6ca17a86u, 0x0151391fu, 0x19d9697bu },
    { 0x7dad1d8cu, 0x88823728u, 0xf79078beu, 0x140b1261u, 0x8d066530u },
    { 0x6b749b40u, 0x56283e79u, 0x69cb448cu, 0xa1459735u, 0x57d8b72du },
    { 0x6db10a1cu, 0x6d6cfe4eu, 0xf039a1fcu, 0xf543d959u, 0x16661a37u },
    { 0x17155b98u, 0xc493c38bu, 0x8d798ddcu, 0xc32630e9u, 0x8f433ed2u },
    { 0xfbb393abu, 0x95fac09eu, 0xffcfb700u, 0xa859a544u, 0x50436a60u },
};

static int office2007_selftest(office2007_iter_fn fn, int lanes)
{
    uint8_t pw[512], salt[16]; uint32_t h[16][5];
    for (int j=0;j<16;j++) salt[j]=(uint8_t)j;
    for (int b=0;b<16;b+=lanes)
    {
        int m=16-b<lanes?16-b:lanes;
        for (int l=0;l<lanes;l++)
        {
            int ql=b+(l<m?l:0);
            for (int q=0;q<O7_TEST_LENGTHS[ql];q++) pw[q]=(uint8_t)(q%2==0?33+(ql*17+q*7)%94:0);
            office2007_initial(pw,O7_TEST_LENGTHS[ql],salt,h[l]);
        }
        fn(h,50000);
        for (int l=0;l<m;l++) if (memcmp(h[l],O7_TEST_ANSWERS[b+l],20)!=0) return 0;
    }
    return 1;
}
