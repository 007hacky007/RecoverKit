/* Fixed hashlib.pbkdf2_hmac SHA1 answers: distinct lanes, lengths around HMAC boundaries. */
static const int P1_TEST_LENGTHS[16] = { 0, 1, 8, 15, 16, 31, 32, 55, 56, 63, 64, 65, 80, 100, 127, 256 };
static const uint32_t P1_TEST_ANSWERS[2][16][5] = {
    {
        { 0x20e144c7u, 0xdd1eab24u, 0xeb870ed1u, 0x1c78743eu, 0x6feb87f9u },
        { 0x016ec27eu, 0xd329c8f6u, 0x17f48352u, 0x82ca039eu, 0x25807b0cu },
        { 0x72344040u, 0xbcec4427u, 0x4cf1935du, 0xde7defe7u, 0xda3f767au },
        { 0xa2d2bc72u, 0x1874cc17u, 0xcd7755fbu, 0x6d1abf68u, 0xd2c905e1u },
        { 0x446928bau, 0xfb0362a5u, 0x4df7a113u, 0x8913818bu, 0x992bf80au },
        { 0x0b82e210u, 0x81695f47u, 0x8eee6767u, 0x776c2f19u, 0x56014cccu },
        { 0x5d99d0d4u, 0xfeeb52d9u, 0xd38765d2u, 0x32159699u, 0xb42aa750u },
        { 0x0ebabc6fu, 0x451644c0u, 0xa190ccedu, 0x3be375eeu, 0xe7d24c7cu },
        { 0xcdf6d84fu, 0x647fc64eu, 0x0f031997u, 0x9088e1c2u, 0x59133d55u },
        { 0x92c14ec5u, 0xbf786231u, 0x5e7c5126u, 0xc8fdd3d4u, 0xabf4fa7du },
        { 0xf22355f7u, 0x4163fbfdu, 0xa18d6eb7u, 0x4ca4b8a5u, 0x081b45b6u },
        { 0xabb1191au, 0xf1a50b0bu, 0xa845be4fu, 0xdc984abdu, 0xd69fc070u },
        { 0xa778756cu, 0xd3f7b594u, 0x4a9c3735u, 0x162bafe9u, 0xdccc8397u },
        { 0xf51b64d3u, 0x286fc098u, 0xbbfacae2u, 0x28ab71fau, 0x5faa9c6du },
        { 0xea3074d5u, 0xa3a7dfd8u, 0xd90f9f2cu, 0x4ba2e19au, 0xb45eea74u },
        { 0xd933c0abu, 0x831431cfu, 0x0cc765b9u, 0x36a3881au, 0x7b697d11u },
    },
    {
        { 0x26d4d2efu, 0x23a4dc6fu, 0xd21cc20au, 0xacbcf3c8u, 0x28cb0349u },
        { 0xd5faead0u, 0x3fe719aeu, 0x9e823211u, 0x385fef7eu, 0x1089c69cu },
        { 0xe80e3109u, 0x3b40651fu, 0xcb50efb7u, 0xb8712c1cu, 0xc7c99280u },
        { 0xf04e77a1u, 0x8aa16e04u, 0xb3a5c71cu, 0x5b8a1ca9u, 0x4b78754eu },
        { 0x5a926e4cu, 0x3f987324u, 0xd17658b2u, 0x96d77bceu, 0x63225683u },
        { 0x973ba6c6u, 0x17348ce9u, 0x42a0efa8u, 0x70493fe5u, 0x894311d1u },
        { 0xefe6c09eu, 0xcfe3629fu, 0xc7c510bau, 0xa57edb0bu, 0xfc8abb75u },
        { 0x28154dfbu, 0x720de769u, 0x14d9ff2fu, 0xe9762d49u, 0x4f71d6ccu },
        { 0xb54ab05fu, 0x1fe80502u, 0x987340e6u, 0x44975d51u, 0x6d23e3dfu },
        { 0xff370554u, 0x5c92e276u, 0x9696f39du, 0xd74dba2eu, 0x2884c8fbu },
        { 0xf1dc7995u, 0x3fd29aa4u, 0x410b813eu, 0x5065b47du, 0xa179215du },
        { 0x0c93c637u, 0xdfc19d4eu, 0x80cc09d9u, 0xbc909d8du, 0xe5e56ce0u },
        { 0x15833228u, 0xce8cff8eu, 0xf707c3ebu, 0x41ea83f1u, 0x9095f13eu },
        { 0xd23d69beu, 0x49136430u, 0xeb59e1b7u, 0x27a8b629u, 0x57c02727u },
        { 0x53abd8c3u, 0x54678f5eu, 0xbf46f519u, 0x3fb54fc2u, 0xbf0e516fu },
        { 0xb3379a08u, 0xaf6796b4u, 0x5057bec0u, 0x78f94d9au, 0x2a7e2f6fu },
    },
};

static int pbkdf2_sha1_selftest(pbkdf2_sha1_iter_fn iterate)
{
    uint8_t pw[256], salt[16];
    uint32_t ist[16][5], ost[16][5], u[16][5];
    for (int j = 0; j < 16; j++) salt[j] = (uint8_t)j;
    for (int b = 0; b < 2; b++)
    {
        for (int l = 0; l < 16; l++)
        {
            for (int q = 0; q < P1_TEST_LENGTHS[l]; q++) pw[q] = (uint8_t)(0x21 + (l * 17 + q * 7) % 94);
            hmac_sha1_states(pw, (size_t)P1_TEST_LENGTHS[l], ist[l], ost[l]);
            pbkdf2_sha1_u1(ist[l], ost[l], salt, 16, b ? 4 : 1, u[l]);
        }
        iterate(ist, ost, u, 7);
        if (memcmp(u, P1_TEST_ANSWERS[b], sizeof u) != 0) return 0;
    }
    return 1;
}
