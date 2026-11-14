/* Decoder regressions. Build with clang -I native native/tests/rar3_decode_test.c. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#define RK_EXPORT
#include "rar3_decode.c"

int main(void)
{
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
  // Independent unrar-compatible prediction model, checked before the filter fix.
  assert((rar3_crc32(0xffffffffu, audio, sizeof(audio)) ^ 0xffffffffu) == 0x7f63da21u);
  puts("RAR 3 standard filter regressions passed");
  return 0;
}
