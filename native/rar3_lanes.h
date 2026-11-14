/* RAR 3 stream hashing, included for 8 lanes (AVX2 / NEON) and 16 lanes (AVX-512).
 * R3_V is a uint32_t clang vector, R3_L its width, R3_FN its target attribute.
 * Each call interleaves two groups; all candidates in a call have the same password length.
 */
#define R3_CAT_(a, b) a##b
#define R3_CAT(a, b) R3_CAT_(a, b)
#define R3_F(n) R3_CAT(n, R3_SUFFIX)
#define R3_ADD(a, b) ((a) + (b))
#define R3_XOR(a, b) ((a) ^ (b))
#define R3_AND(a, b) ((a) & (b))
#define R3_OR(a, b) ((a) | (b))
#define R3_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define R3_ZERO ((R3_V){ 0 })
#define R3_SET1(x) (R3_ZERO + (uint32_t)(x))
#define R3_SLLV(x, s) ((x) << (s))
#define R3_LOAD(p) (*(const R3_V*)(p))
#define R3_STORE(p, v) (*(R3_V*)(p) = (v))
#define R3_LOADU(p) R3_F(rar3_loadu)(p)
R3_FN static inline R3_V R3_F(rar3_loadu)(const void* p)
{
    R3_V v;
    memcpy(&v, p, sizeof v);
    return v;
}

#define R3_F1(b, c, d) R3_XOR(d, R3_AND(b, R3_XOR(c, d)))
#define R3_F2(b, c, d) R3_XOR(R3_XOR(b, c), d)
#define R3_F3(b, c, d) R3_OR(R3_AND(b, c), R3_AND(d, R3_OR(b, c)))

/* Plain lane-generic SHA-1 block with its own schedule (rare paths). */
R3_FN static void R3_F(sha1_block)(R3_V st[5], const R3_V* m)
{
    R3_V w[80];
    for (int j = 0; j < 16; j++) w[j] = m[j];
    for (int t = 16; t < 80; t++) w[t] = R3_ROTL(R3_XOR(R3_XOR(w[t - 3], w[t - 8]), R3_XOR(w[t - 14], w[t - 16])), 1);
    R3_V a = st[0], b = st[1], c = st[2], d = st[3], e = st[4];
    for (int t = 0; t < 80; t++)
    {
        R3_V f, k;
        if (t < 20) { f = R3_F1(b, c, d); k = R3_SET1(0x5A827999); }
        else if (t < 40) { f = R3_F2(b, c, d); k = R3_SET1(0x6ED9EBA1); }
        else if (t < 60) { f = R3_F3(b, c, d); k = R3_SET1(0x8F1BBCDCu); }
        else { f = R3_F2(b, c, d); k = R3_SET1(0xCA62C1D6u); }
        R3_V tmp = R3_ADD(R3_ADD(R3_ROTL(a, 5), f), R3_ADD(R3_ADD(e, k), w[t]));
        e = d; d = c; c = R3_ROTL(b, 30); b = a; a = tmp;
    }
    st[0] = R3_ADD(st[0], a); st[1] = R3_ADD(st[1], b); st[2] = R3_ADD(st[2], c); st[3] = R3_ADD(st[3], d); st[4] = R3_ADD(st[4], e);
}

/* Schedule expansion of the shared words, R3_L blocks per vector. */
R3_FN static void R3_F(rar3_expand)(const rar3_layout* L, uint32_t* S)
{
    const int n = RAR3_NBP, cols = (L->nb + R3_L - 1) & ~(R3_L - 1);
    for (int t = 16; t < 80; t++)
        for (int b = 0; b < cols; b += R3_L)
        {
            R3_V x = R3_XOR(R3_XOR(R3_LOAD(S + (t - 3) * n + b), R3_LOAD(S + (t - 8) * n + b)),
                          R3_XOR(R3_LOAD(S + (t - 14) * n + b), R3_LOAD(S + (t - 16) * n + b)));
            R3_STORE(S + t * n + b, R3_ROTL(x, 1));
        }
    /* Rows 80..95: words 0..15 with the round constant already added, for the rounds whose word
       does not involve the last character (the same for every candidate). */
    const R3_V k1 = R3_SET1(0x5A827999);
    for (int t = 0; t < 16; t++)
        for (int b = 0; b < cols; b += R3_L)
            R3_STORE(S + (80 + t) * n + b, R3_ADD(R3_LOAD(S + t * n + b), k1));
}

/* One round for both groups: W = broadcast(shared word) ^ per-group last-character word. */
#define R3_RND(F, K, t, a, b, c, d, e)                                                     \
    do {                                                                                \
        R3_V ws_ = R3_SET1(Sb[(t) * RAR3_NBP]);                                           \
        e##0 = R3_ADD(R3_ADD(e##0, R3_ADD(K, R3_XOR(ws_, Va[t]))), R3_ADD(R3_ROTL(a##0, 5), F(b##0, c##0, d##0))); \
        e##1 = R3_ADD(R3_ADD(e##1, R3_ADD(K, R3_XOR(ws_, Vb[t]))), R3_ADD(R3_ROTL(a##1, 5), F(b##1, c##1, d##1))); \
        b##0 = R3_ROTL(b##0, 30);                                                         \
        b##1 = R3_ROTL(b##1, 30);                                                         \
    } while (0)

/* Rounds 0..15: when word t is shared by all lanes, W + K is one broadcast. */
#define R3_RNDE(t, a, b, c, d, e)                                                          \
    do {                                                                                \
        if (lcm & (1u << (t))) R3_RND(R3_F1, k1, t, a, b, c, d, e);                           \
        else {                                                                          \
            R3_V wk_ = R3_SET1(Sb[(80 + (t)) * RAR3_NBP]);                                \
            e##0 = R3_ADD(R3_ADD(e##0, wk_), R3_ADD(R3_ROTL(a##0, 5), R3_F1(b##0, c##0, d##0)));   \
            e##1 = R3_ADD(R3_ADD(e##1, wk_), R3_ADD(R3_ROTL(a##1, 5), R3_F1(b##1, c##1, d##1)));   \
            b##0 = R3_ROTL(b##0, 30);                                                     \
            b##1 = R3_ROTL(b##1, 30);                                                     \
        }                                                                               \
    } while (0)

#define R3_R5E(t)                              \
    R3_RNDE((t), a, b, c, d, e);               \
    R3_RNDE((t) + 1, e, a, b, c, d);           \
    R3_RNDE((t) + 2, d, e, a, b, c);           \
    R3_RNDE((t) + 3, c, d, e, a, b);           \
    R3_RNDE((t) + 4, b, c, d, e, a)

#define R3_R5(F, K, t)                         \
    R3_RND(F, K, (t), a, b, c, d, e);          \
    R3_RND(F, K, (t) + 1, e, a, b, c, d);      \
    R3_RND(F, K, (t) + 2, d, e, a, b, c);      \
    R3_RND(F, K, (t) + 3, c, d, e, a, b);      \
    R3_RND(F, K, (t) + 4, b, c, d, e, a)

/* One block for two groups of R3_L candidates. Sb points at the block's column of S (stride nbp). */
R3_FN static inline void R3_F(rar3_block2)(R3_V* st0, R3_V* st1, const uint32_t* Sb, uint32_t lcm, const R3_V* Va, const R3_V* Vb)
{
    R3_V a0 = st0[0], b0 = st0[1], c0 = st0[2], d0 = st0[3], e0 = st0[4];
    R3_V a1 = st1[0], b1 = st1[1], c1 = st1[2], d1 = st1[3], e1 = st1[4];
    const R3_V k1 = R3_SET1(0x5A827999), k2 = R3_SET1(0x6ED9EBA1);
    const R3_V k3 = R3_SET1(0x8F1BBCDCu), k4 = R3_SET1(0xCA62C1D6u);
    R3_R5E(0); R3_R5E(5); R3_R5E(10); R3_RNDE(15, a, b, c, d, e); R3_RND(R3_F1, k1, 16, e, a, b, c, d);
    R3_RND(R3_F1, k1, 17, d, e, a, b, c); R3_RND(R3_F1, k1, 18, c, d, e, a, b); R3_RND(R3_F1, k1, 19, b, c, d, e, a);
    R3_R5(R3_F2, k2, 20); R3_R5(R3_F2, k2, 25); R3_R5(R3_F2, k2, 30); R3_R5(R3_F2, k2, 35);
    R3_R5(R3_F3, k3, 40); R3_R5(R3_F3, k3, 45); R3_R5(R3_F3, k3, 50); R3_R5(R3_F3, k3, 55);
    R3_R5(R3_F2, k4, 60); R3_R5(R3_F2, k4, 65); R3_R5(R3_F2, k4, 70); R3_R5(R3_F2, k4, 75);
    st0[0] = R3_ADD(st0[0], a0); st0[1] = R3_ADD(st0[1], b0); st0[2] = R3_ADD(st0[2], c0); st0[3] = R3_ADD(st0[3], d0); st0[4] = R3_ADD(st0[4], e0);
    st1[0] = R3_ADD(st1[0], a1); st1[1] = R3_ADD(st1[1], b1); st1[2] = R3_ADD(st1[2], c1); st1[3] = R3_ADD(st1[3], d1); st1[4] = R3_ADD(st1[4], e1);
}

/* Return whether vector code ran, so a self-test cannot validate the scalar allocation fallback. */
R3_FN static int R3_F(rar3_vec)(const rar3_layout* L, const uint8_t* pws, int n, uint8_t* out)
{
    int nb = L->nb, nbp = L->nbp, p = L->p;
    void *rawS, *rawV;
    uint32_t* S = (uint32_t*)aligned_buf(96 * (size_t)nbp * 4, &rawS);
    R3_V* V = (R3_V*)aligned_buf(2 * (size_t)nb * 80 * sizeof(R3_V), &rawV);
    if (!S || !V) { free(rawS); free(rawV); rar3_scalar(L, pws, n, out); return 0; }
    int cutOff = p % 64;
    int len = L->len;
    uint32_t lanes[R3_L];
    R3_V pb[RAR3_MAXLEN];

    for (int i = 0; i < n; i += 2 * R3_L)
    {
        /* Per-group schedule of the lane bytes, per block. */
        for (int g = 0; g < 2; g++)
        {
            for (int q = 0; q < len; q++)
            {
                for (int l = 0; l < R3_L; l++)
                {
                    int idx = i + R3_L * g + l;
                    lanes[l] = pws[(idx < n ? idx : n - 1) * len + q];
                }
                pb[q] = R3_LOADU(lanes);
            }
            for (int blk = 0; blk < nb; blk++)
            {
                R3_V* w = V + ((size_t)g * nb + blk) * 80;
                for (int j = 0; j < 16; j++)
                {
                    int wi = blk * 16 + j;
                    R3_V v = R3_ZERO;
                    for (int k = 0; k < L->nent[wi]; k++)
                        v = R3_OR(v, R3_SLLV(pb[L->entq[wi][k]], R3_SET1(L->ents[wi][k])));
                    w[j] = v;
                }
                for (int t = 16; t < 80; t++) w[t] = R3_ROTL(R3_XOR(R3_XOR(w[t - 3], w[t - 8]), R3_XOR(w[t - 14], w[t - 16])), 1);
            }
        }
        R3_V st[2][5];
        for (int g = 0; g < 2; g++)
            for (int q = 0; q < 5; q++) st[g][q] = R3_SET1(SHA1_IV[q]);
        uint8_t iv[2 * R3_L][16];
        memset(iv, 0, sizeof iv);

        rar3_template_words(L, S);
        for (int s = 0; s < RAR3_PERIODS; s++)
        {
            rar3_period_words(L, s, S);
            R3_F(rar3_expand)(L, S);
            if ((s & 255) == 0)
            {
                /* IV byte: SHA-1 final of a copy after the first round of this period (inside block 0). */
                for (int g = 0; g < 2; g++)
                {
                    R3_V cs[5], m[16];
                    memcpy(cs, st[g], sizeof cs);
                    const R3_V* Vg = V + (size_t)g * nb * 80;
                    for (int j = 0; j < 16; j++)
                    {
                        R3_V v = R3_XOR(R3_SET1(S[j * nbp]), Vg[j]);
                        int start = 4 * j;
                        if (start >= cutOff) v = R3_ZERO;
                        else if (start + 4 > cutOff) v = R3_AND(v, R3_SET1(0xffffffffu << (8 * (start + 4 - cutOff))));
                        m[j] = v;
                    }
                    m[cutOff / 4] = R3_OR(m[cutOff / 4], R3_SET1(0x80u << (8 * (3 - cutOff % 4))));
                    uint64_t bits = ((uint64_t)(64 * s) + 1) * (uint64_t)p * 8;
                    if (cutOff > 55)
                    {
                        R3_F(sha1_block)(cs, m);
                        for (int j = 0; j < 14; j++) m[j] = R3_ZERO;
                    }
                    m[14] = R3_SET1((uint32_t)(bits >> 32));
                    m[15] = R3_SET1((uint32_t)bits);
                    R3_F(sha1_block)(cs, m);
                    uint32_t ev[R3_L];
                    memcpy(ev, &cs[4], sizeof cs[4]);
                    for (int l = 0; l < R3_L; l++) iv[R3_L * g + l][s >> 8] = (uint8_t)ev[l];
                }
            }
            for (int blk = 0; blk < nb; blk++)
                R3_F(rar3_block2)(st[0], st[1], S + blk, L->lcm[blk], V + (size_t)blk * 80, V + ((size_t)nb + blk) * 80);
        }
        /* Final padding block: the total length is a multiple of 64 bytes. */
        R3_V m[16];
        for (int j = 0; j < 16; j++) m[j] = R3_ZERO;
        uint64_t total = (uint64_t)RAR3_ROUNDS * (uint64_t)p * 8;
        m[0] = R3_SET1(0x80000000u);
        m[14] = R3_SET1((uint32_t)(total >> 32));
        m[15] = R3_SET1((uint32_t)total);
        for (int g = 0; g < 2; g++)
        {
            R3_F(sha1_block)(st[g], m);
            uint32_t sv[5][R3_L];
            for (int q = 0; q < 5; q++) memcpy(sv[q], &st[g][q], sizeof st[g][q]);
            for (int l = 0; l < R3_L; l++)
            {
                int idx = i + R3_L * g + l;
                if (idx >= n) continue;
                for (int q = 0; q < 5; q++) put_be32(out + 36 * idx + 4 * q, sv[q][l]);
                memcpy(out + 36 * idx + 20, iv[R3_L * g + l], 16);
            }
        }
    }
    free(rawS); free(rawV);
    return 1;
}

#undef R3_CAT_
#undef R3_CAT
#undef R3_F
#undef R3_ADD
#undef R3_XOR
#undef R3_AND
#undef R3_OR
#undef R3_ROTL
#undef R3_ZERO
#undef R3_SET1
#undef R3_SLLV
#undef R3_LOAD
#undef R3_STORE
#undef R3_LOADU
#undef R3_F1
#undef R3_F2
#undef R3_F3
#undef R3_RND
#undef R3_RNDE
#undef R3_R5E
#undef R3_R5
#undef R3_V
#undef R3_L
#undef R3_FN
#undef R3_SUFFIX
