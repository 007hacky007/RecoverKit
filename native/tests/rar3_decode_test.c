/* Decoder regressions. Build with clang -I native native/tests/rar3_decode_test.c. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#define RK_EXPORT
#include "rar3_decode.c"

typedef struct
{
  u8 packed[64];
  size_t pos;
  int fail;
  rar3_arena_t arena;
} ppm_source_t;

static int ppm_read(void *opaque, u8 *buffer, int count)
{
  ppm_source_t *s = (ppm_source_t *) opaque;
  size_t n = sizeof(s->packed) - s->pos;
  if (n > (size_t)count) n = (size_t)count;
  memcpy(buffer, s->packed + s->pos, n);
  s->pos += n;
  return (int)n;
}

static void *ppm_allocate(void *opaque, size_t size)
{
  ppm_source_t *s = (ppm_source_t *) opaque;
  if (s->fail) { s->fail = 0; return NULL; }
  return rar3_arena_alloc(&s->arena.vt, size);
}

int main(void)
{
  rar3_arena_t arena = {0};
  void *first = rar3_arena_alloc (&arena.vt, 1 << 20);
  assert(first);
  memset(first, 0xa5, 1 << 20);
  assert(rar3_arena_alloc (&arena.vt, 1 << 20) == first);
  assert(rar3_arena_alloc (&arena.vt, 1 << 19) == first);
  free(arena.base);

  // A reset PPM stream with 33 output bytes and an independently verified CRC.
  ppm_source_t source = {{
    0xa5, 0x03, 0x02, 0x04, 0x23, 0xde, 0xac, 0x9b, 0x4f, 0x42, 0x4a, 0x4d,
    0x1d, 0xae, 0xa7, 0xfc, 0x5e, 0x62, 0x6a, 0x08, 0x5e, 0x53, 0x89, 0xf1,
    0x82, 0x09, 0xa0, 0x06, 0x3a, 0x16, 0x06, 0x2a, 0x83, 0xe6, 0x7d, 0xf0,
    0xe9, 0x82, 0x94, 0x17, 0x2d, 0x7d, 0x00, 0x00, 0xbf, 0x88, 0x67, 0xf6,
    0xa9, 0xff, 0xd4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  }, 0, 1, {0}};
  int stage;
  assert(rk_rar3_decode_stream_alloc(ppm_read, &source, 64, 33, 65536, 0x46755231, &stage, ppm_allocate) == -3);
  // Failure cannot poison a later retry or expose another candidate's model state.
  for (int i = 0; i < 256; i++)
  {
    source.pos = 0;
    source.packed[1] = (u8)i;
    int result = rk_rar3_decode_stream_alloc(ppm_read, &source, 64, 33, 65536, 0x46755231, &stage, ppm_allocate);
    if (result != 1) fprintf(stderr, "PPM model %d result %d stage %d\n", i + 1, result, stage);
    assert(result == 1);
    assert(stage == 3);
  }
  source.pos = 0;
  source.packed[0] &= ~0x20; // No model exists at the start of a new candidate.
  assert(rk_rar3_decode_stream_alloc(ppm_read, &source, 64, 33, 65536, 0x46755231, &stage, ppm_allocate) == 0);
  assert(source.arena.capacity == 256u << 20);
  free(source.arena.base);

  const u32 starts[] = { 0x2000000, 0x81000000, 0xfffffff0 };
  const u32 values[] = { 0xfe800000, 0xff800000, 0x00000020, 0x40000000, 0x90000000 };
  for (unsigned e9 = 0; e9 < 2; e9++)
    for (unsigned i = 0; i < sizeof(starts)/sizeof(starts[0]); i++)
      for (unsigned j = 0; j < sizeof(values)/sizeof(values[0]); j++)
      {
        u8 bytes[5] = { e9 ? 0xe9 : 0xe8 };
        u32 v = values[j], offset = starts[i] + 1, expected = v;
        for (unsigned k = 0; k < 4; k++) bytes[k+1] = (u8)(v >> (k*8));
        if (v & 0x80000000u)
        {
          if (((v + offset) & 0x80000000u) == 0) expected = v + 0x1000000;
        }
        else if (((v - 0x1000000u) & 0x80000000u) != 0) expected = v - offset;
        rar3_filter_x86(bytes, 5, starts[i], e9);
        u32 actual = (u32)bytes[1] | ((u32)bytes[2]<<8) | ((u32)bytes[3]<<16) | ((u32)bytes[4]<<24);
        assert(actual == expected);
      }
  for (u32 i = 0; i < sizeof(RAR3_PROGRAMS)/sizeof(RAR3_PROGRAMS[0]); i++)
  {
    const rar3_program_t *p = &RAR3_PROGRAMS[i];
    assert(rar3_filter_of(p->bytes, p->size) == p->filter);
    u8 corrupt[256]; memcpy(corrupt, p->bytes, p->size); corrupt[0] ^= 1;
    assert(rar3_filter_of(corrupt, p->size) == RAR3_FILTER_NONE);
    corrupt[1] ^= 1; // Restore the XOR checksum while changing the program CRC.
    assert(rar3_filter_of(corrupt, p->size) == RAR3_FILTER_NONE);
  }
  u8 itanium[33] = {0}, expected[33] = {0};
  itanium[16] = expected[16] = 0x10;
  itanium[31] = expected[31] = 0x50;
  rar3_filter_itanium(itanium, sizeof(itanium), 0);
  assert(memcmp(itanium, expected, sizeof(itanium)) == 0);

  u8 audio[4096], scratch[4096];
  u32 seed = 13;
  for (u32 i = 0; i < sizeof(audio); i++)
  {
    seed = 1664525u * seed + 1013904223u;
    audio[i] = (u8)(seed >> 24);
  }
  assert((rar3_crc32(0xffffffffu, audio, sizeof(audio)) ^ 0xffffffffu) == 0x5e70a751u);
  rar3_filter_audio(audio, sizeof(audio), 1, scratch);
  // Independent RAR 3 audio prediction model, checked before the filter fix.
  assert((rar3_crc32(0xffffffffu, audio, sizeof(audio)) ^ 0xffffffffu) == 0x7f63da21u);
  puts("RAR 3 standard filter regressions passed");
  return 0;
}
