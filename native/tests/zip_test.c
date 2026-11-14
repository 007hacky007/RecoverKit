/* Standalone differential test, also executable under Rosetta for AVX2 correctness.
 * cc -O2 native/rknative.c native/tests/zip_test.c -o /tmp/rk-zip-test
 * Use -fsanitize=address,undefined for a host build, or zig cc -target x86_64-macos
 * on Apple silicon followed by arch -x86_64 /tmp/rk-zip-test.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int rk_version(void);
int rk_zip_path(int);
int rk_zip_search(const uint8_t*, uint8_t, uint8_t, uint32_t, uint32_t, uint32_t, const uint8_t*, int, int*, int, int);

int rk_zip_search_batch(const uint8_t*, uint8_t, uint8_t, const uint32_t*, const uint8_t*, int, int*, int, int);

static uint32_t state = 17210;
static uint32_t random32(void)
{
    state ^= state << 13; state ^= state >> 17; state ^= state << 5;
    return state;
}
static uint32_t crc(uint32_t x, uint8_t b)
{
    x ^= b;
    for (int i = 0; i < 8; i++) x = (x >> 1) ^ (0xedb88320u & (0u - (x & 1u)));
    return x;
}
static void step(uint32_t* a, uint32_t* b, uint32_t* c, uint8_t p)
{
    *a = crc(*a, p); *b = (*b + (*a & 255u)) * 134775813u + 1u; *c = crc(*c, *b >> 24);
}
int main(void)
{
    assert(rk_version() == 11);
    int paths = 0;
    for (int path = 1; path <= 5; path++)
    {
        if (rk_zip_path(path) != path) continue;
        paths++;
        for (int trial = 0; trial < 1000; trial++)
        {
            uint8_t header[12], last[256];
            for (int i = 0; i < 12; i++) header[i] = random32();
            for (int i = 0; i < 256; i++) last[i] = random32();
            int n = trial % 257, hits[256], want[256], nw = 0;
            uint32_t a = random32(), b = random32(), c = random32();
            uint8_t c1 = random32(), c2 = trial & 1 ? c1 : random32();
            for (int i = 0; i < n; i++)
            {
                uint32_t x = a, y = b, z = c;
                step(&x, &y, &z, last[i]);
                uint8_t p = 0;
                for (int j = 0; j < 12; j++)
                {
                    uint32_t t = (z | 2u) & 65535u;
                    p = header[j] ^ (uint8_t)((t * (t ^ 1u)) >> 8);
                    step(&x, &y, &z, p);
                }
                if (p == c1 || p == c2) want[nw++] = i;
            }
            assert(rk_zip_search(header, c1, c2, a, b, c, last, n, hits, 256, path) == nw);
            for (int i = 0; i < nw; i++) assert(hits[i] == want[i]);
            assert(rk_zip_search(header, c1, c2, a, b, c, last, n, NULL, 0, path) == nw);
        }
        for (int trial = 0; trial < 1000; trial++)
        {
            uint8_t header[12], last[257];
            uint32_t keys[3 * 257];
            for (int i = 0; i < 12; i++) header[i] = random32();
            int n = trial % 258, hits[257], want[257], nw = 0;
            for (int i = 0; i < n; i++)
            {
                last[i] = random32();
                keys[i] = random32(); keys[n + i] = random32(); keys[2 * n + i] = random32();
            }
            uint8_t c1 = random32(), c2 = trial & 1 ? c1 : random32();
            for (int i = 0; i < n; i++)
            {
                uint32_t x = keys[i], y = keys[n + i], z = keys[2 * n + i];
                step(&x, &y, &z, last[i]);
                uint8_t p = 0;
                for (int j = 0; j < 12; j++)
                {
                    uint32_t t = (z | 2u) & 65535u;
                    p = header[j] ^ (uint8_t)((t * (t ^ 1u)) >> 8);
                    step(&x, &y, &z, p);
                }
                if (p == c1 || p == c2) want[nw++] = i;
            }
            assert(rk_zip_search_batch(header, c1, c2, keys, last, n, hits, n, path) == nw);
            for (int i = 0; i < nw; i++) assert(hits[i] == want[i]);
            assert(rk_zip_search_batch(header, c1, c2, keys, last, n, NULL, 0, path) == nw);
            hits[1] = -42;
            assert(rk_zip_search_batch(header, c1, c2, keys, last, n, hits, 1, path) == nw);
            if (nw) assert(hits[0] == want[0]);
            assert(hits[1] == -42);
        }
        printf("path %d: 1000 random headers and masks plus 1000 per-lane key batches passed\n", path);
    }
    assert(paths > 0);
    return 0;
}
