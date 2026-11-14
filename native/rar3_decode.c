/**
 * Author......: hashcat project contributors; see RecoverKit NOTICE
 * License.....: MIT
 */

// Adapted from hashcat 8.0.0: bounded input, a wrapping dictionary, 64-bit output positions,
// and CRC32 output. The PPMd codec retains its public domain headers; see rar3/ppmd7/ORIGIN.txt.

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int (*rar3_read_fn)(void *opaque, u8 *buffer, int count);

#include "rar3/rar3_status.h"

#include "rar3/ppmd7/Ppmd7.c"
#include "rar3/ppmd7/Ppmd7aDec.c"


// How much is decrypted before the first attempt. The rest follows only if the decode wants more.

#define RAR3_FIRST_CHUNK 4096

// Input refills after the first trial are bounded independently of the file size.
#define RAR3_INPUT_SIZE 65536

// A filter is applied to at most this many bytes at a time.

#define RAR3_FILTER_SIZE 0x40000

// Bound the pending filter queue; consumed blocks are reused as the stream advances.

#define RAR3_FILTER_MAX 4096

// The PPM header bounds model memory to at most 256 MiB.

// The LZ block header. 2 flag bits, then 20 code lengths of 4 bits, with 15 escaping a run of zeros.

#define RAR3_PRE_TABLE_SIZE   20
#define RAR3_PRE_TABLE_BITS    4
#define RAR3_PRE_TABLE_ESCAPE 15

// The 4 tables a block describes, in the order their code lengths appear.

#define RAR3_TABLE_MAIN  299
#define RAR3_TABLE_DIST   60
#define RAR3_TABLE_LOW    17
#define RAR3_TABLE_REP    28

#define RAR3_TABLE_TOTAL (RAR3_TABLE_MAIN + RAR3_TABLE_DIST + RAR3_TABLE_LOW + RAR3_TABLE_REP)

#define RAR3_MAX_TABLE RAR3_TABLE_MAIN

#define RAR3_MAX_CODE_LEN 15

// The symbols of the first table that are not literals.

#define RAR3_END_OF_BLOCK   256
#define RAR3_FILTER_RECORD  257
#define RAR3_REPEAT_SAME    258
#define RAR3_REPEAT_FIRST   259
#define RAR3_REPEAT_LAST    262
#define RAR3_SHORT_FIRST    263
#define RAR3_LENGTH_FIRST   271

// How many distances a block remembers, and where a match runs 1 byte longer than its symbol says.

#define RAR3_OLD_DIST  4
#define RAR3_LONG_DIST   0x2000
#define RAR3_LONGER_DIST 0x40000

// The third table's 17th entry takes a distance's low 4 bits from the match before, for 16 matches.

#define RAR3_LOW_REPEAT_SYMBOL 16
#define RAR3_LOW_REPEAT_COUNT  15

#define RAR3_DIST_LOW_BITS 4

// The lengths a match symbol names, and how many extra bits each reads.

static const u16 RAR3_LENGTH_BASE[RAR3_TABLE_REP] =
{
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
  35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227,
};

static const u8 RAR3_LENGTH_EXTRA[RAR3_TABLE_REP] =
{
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
  3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
};

// A match exactly 2 bytes long has 8 symbols of its own and never touches the distance table.

static const u16 RAR3_SHORT_BASE[8] = { 1, 5, 9, 17, 33, 65, 129, 193 };

static const u8  RAR3_SHORT_EXTRA[8] = { 2, 2, 3, 4, 5, 6, 6, 6 };

// The filter programs, one per filter, taken out of records the encoders wrote.

#include "rar3/rar3_programs.c"

typedef enum rar3_filter
{
  RAR3_FILTER_NONE    = 0,
  RAR3_FILTER_X86     = 1,
  RAR3_FILTER_ITANIUM = 2,
  RAR3_FILTER_DELTA   = 3,
  RAR3_FILTER_RGB     = 4,
  RAR3_FILTER_AUDIO   = 5,
  RAR3_FILTER_E8E9    = 6,

} rar3_filter_t;

typedef struct rar3_program
{
  rar3_filter_t  filter;
  const u8      *bytes;
  u32            size;

} rar3_program_t;

static const rar3_program_t RAR3_PROGRAMS[] =
{
  { RAR3_FILTER_X86,     RAR3_PROGRAM_X86,     sizeof (RAR3_PROGRAM_X86)     },
  { RAR3_FILTER_E8E9,    RAR3_PROGRAM_E8E9,    sizeof (RAR3_PROGRAM_E8E9)    },
  { RAR3_FILTER_ITANIUM, RAR3_PROGRAM_ITANIUM, sizeof (RAR3_PROGRAM_ITANIUM) },
  { RAR3_FILTER_DELTA,   RAR3_PROGRAM_DELTA,   sizeof (RAR3_PROGRAM_DELTA)   },
  { RAR3_FILTER_RGB,     RAR3_PROGRAM_RGB,     sizeof (RAR3_PROGRAM_RGB)     },
  { RAR3_FILTER_AUDIO,   RAR3_PROGRAM_AUDIO,   sizeof (RAR3_PROGRAM_AUDIO)   },
};

typedef struct rar3_block
{
  rar3_filter_t filter;

  u64 start;
  u32 length;

  u32 param[2];
  u32 params;

} rar3_block_t;

// A canonical Huffman code, handed out shortest first and, within one length, in symbol order.

typedef struct rar3_huff
{
  u32 count[RAR3_MAX_CODE_LEN + 1];
  u32 first_code[RAR3_MAX_CODE_LEN + 1];
  u32 first_index[RAR3_MAX_CODE_LEN + 1];

  u16 symbol[RAR3_MAX_TABLE];

} rar3_huff_t;

typedef struct rar3_ctx rar3_ctx_t;
typedef struct rar3_byte_in
{
  IByteIn vt;
  rar3_ctx_t *ctx;
} rar3_byte_in_t;

struct rar3_ctx
{
  rar3_read_fn read;
  void *opaque;
  u8 in[RAR3_INPUT_SIZE];
  u64 input_start;
  u32 input_count;
  u64 in_bits;
  u64 bit;
  int read_error;
  int trial_passed;
  int tables_ok;
  u32 window_size;
  u32 window_mask;

  u8 *win;
  u64 produced;

  u8 *filter_buf;

  // The filter block queue, caller owned because it is too large for the stack.

  rar3_block_t *blocks;
  u32           block_cnt;
  u32           block_at;

  // Where the filter that is being collected started, and how far into it the output has come.

  u32 collecting;
  u32 collected;

  u32 crc;

  u64 dest_size;

  u8 lengths[RAR3_TABLE_TOTAL];

  rar3_huff_t huff[4];

  void *ppm_arena;
  CPpmd7 ppm;
  rar3_byte_in_t ppm_reader;
  int ppm_mode;
  u8 ppm_escape;
  u32 last_low;
  u32 low_repeat;

  int status;

};

// CRC32, the ordinary reflected one the RAR file header carries.

static const u32 rar3_crc32_table[256] = {
  0x00000000u, 0x77073096u, 0xee0e612cu, 0x990951bau, 0x076dc419u, 0x706af48fu, 0xe963a535u, 0x9e6495a3u,
  0x0edb8832u, 0x79dcb8a4u, 0xe0d5e91eu, 0x97d2d988u, 0x09b64c2bu, 0x7eb17cbdu, 0xe7b82d07u, 0x90bf1d91u,
  0x1db71064u, 0x6ab020f2u, 0xf3b97148u, 0x84be41deu, 0x1adad47du, 0x6ddde4ebu, 0xf4d4b551u, 0x83d385c7u,
  0x136c9856u, 0x646ba8c0u, 0xfd62f97au, 0x8a65c9ecu, 0x14015c4fu, 0x63066cd9u, 0xfa0f3d63u, 0x8d080df5u,
  0x3b6e20c8u, 0x4c69105eu, 0xd56041e4u, 0xa2677172u, 0x3c03e4d1u, 0x4b04d447u, 0xd20d85fdu, 0xa50ab56bu,
  0x35b5a8fau, 0x42b2986cu, 0xdbbbc9d6u, 0xacbcf940u, 0x32d86ce3u, 0x45df5c75u, 0xdcd60dcfu, 0xabd13d59u,
  0x26d930acu, 0x51de003au, 0xc8d75180u, 0xbfd06116u, 0x21b4f4b5u, 0x56b3c423u, 0xcfba9599u, 0xb8bda50fu,
  0x2802b89eu, 0x5f058808u, 0xc60cd9b2u, 0xb10be924u, 0x2f6f7c87u, 0x58684c11u, 0xc1611dabu, 0xb6662d3du,
  0x76dc4190u, 0x01db7106u, 0x98d220bcu, 0xefd5102au, 0x71b18589u, 0x06b6b51fu, 0x9fbfe4a5u, 0xe8b8d433u,
  0x7807c9a2u, 0x0f00f934u, 0x9609a88eu, 0xe10e9818u, 0x7f6a0dbbu, 0x086d3d2du, 0x91646c97u, 0xe6635c01u,
  0x6b6b51f4u, 0x1c6c6162u, 0x856530d8u, 0xf262004eu, 0x6c0695edu, 0x1b01a57bu, 0x8208f4c1u, 0xf50fc457u,
  0x65b0d9c6u, 0x12b7e950u, 0x8bbeb8eau, 0xfcb9887cu, 0x62dd1ddfu, 0x15da2d49u, 0x8cd37cf3u, 0xfbd44c65u,
  0x4db26158u, 0x3ab551ceu, 0xa3bc0074u, 0xd4bb30e2u, 0x4adfa541u, 0x3dd895d7u, 0xa4d1c46du, 0xd3d6f4fbu,
  0x4369e96au, 0x346ed9fcu, 0xad678846u, 0xda60b8d0u, 0x44042d73u, 0x33031de5u, 0xaa0a4c5fu, 0xdd0d7cc9u,
  0x5005713cu, 0x270241aau, 0xbe0b1010u, 0xc90c2086u, 0x5768b525u, 0x206f85b3u, 0xb966d409u, 0xce61e49fu,
  0x5edef90eu, 0x29d9c998u, 0xb0d09822u, 0xc7d7a8b4u, 0x59b33d17u, 0x2eb40d81u, 0xb7bd5c3bu, 0xc0ba6cadu,
  0xedb88320u, 0x9abfb3b6u, 0x03b6e20cu, 0x74b1d29au, 0xead54739u, 0x9dd277afu, 0x04db2615u, 0x73dc1683u,
  0xe3630b12u, 0x94643b84u, 0x0d6d6a3eu, 0x7a6a5aa8u, 0xe40ecf0bu, 0x9309ff9du, 0x0a00ae27u, 0x7d079eb1u,
  0xf00f9344u, 0x8708a3d2u, 0x1e01f268u, 0x6906c2feu, 0xf762575du, 0x806567cbu, 0x196c3671u, 0x6e6b06e7u,
  0xfed41b76u, 0x89d32be0u, 0x10da7a5au, 0x67dd4accu, 0xf9b9df6fu, 0x8ebeeff9u, 0x17b7be43u, 0x60b08ed5u,
  0xd6d6a3e8u, 0xa1d1937eu, 0x38d8c2c4u, 0x4fdff252u, 0xd1bb67f1u, 0xa6bc5767u, 0x3fb506ddu, 0x48b2364bu,
  0xd80d2bdau, 0xaf0a1b4cu, 0x36034af6u, 0x41047a60u, 0xdf60efc3u, 0xa867df55u, 0x316e8eefu, 0x4669be79u,
  0xcb61b38cu, 0xbc66831au, 0x256fd2a0u, 0x5268e236u, 0xcc0c7795u, 0xbb0b4703u, 0x220216b9u, 0x5505262fu,
  0xc5ba3bbeu, 0xb2bd0b28u, 0x2bb45a92u, 0x5cb36a04u, 0xc2d7ffa7u, 0xb5d0cf31u, 0x2cd99e8bu, 0x5bdeae1du,
  0x9b64c2b0u, 0xec63f226u, 0x756aa39cu, 0x026d930au, 0x9c0906a9u, 0xeb0e363fu, 0x72076785u, 0x05005713u,
  0x95bf4a82u, 0xe2b87a14u, 0x7bb12baeu, 0x0cb61b38u, 0x92d28e9bu, 0xe5d5be0du, 0x7cdcefb7u, 0x0bdbdf21u,
  0x86d3d2d4u, 0xf1d4e242u, 0x68ddb3f8u, 0x1fda836eu, 0x81be16cdu, 0xf6b9265bu, 0x6fb077e1u, 0x18b74777u,
  0x88085ae6u, 0xff0f6a70u, 0x66063bcau, 0x11010b5cu, 0x8f659effu, 0xf862ae69u, 0x616bffd3u, 0x166ccf45u,
  0xa00ae278u, 0xd70dd2eeu, 0x4e048354u, 0x3903b3c2u, 0xa7672661u, 0xd06016f7u, 0x4969474du, 0x3e6e77dbu,
  0xaed16a4au, 0xd9d65adcu, 0x40df0b66u, 0x37d83bf0u, 0xa9bcae53u, 0xdebb9ec5u, 0x47b2cf7fu, 0x30b5ffe9u,
  0xbdbdf21cu, 0xcabac28au, 0x53b39330u, 0x24b4a3a6u, 0xbad03605u, 0xcdd70693u, 0x54de5729u, 0x23d967bfu,
  0xb3667a2eu, 0xc4614ab8u, 0x5d681b02u, 0x2a6f2b94u, 0xb40bbe37u, 0xc30c8ea1u, 0x5a05df1bu, 0x2d02ef8du,
};

static u32 rar3_crc32 (u32 crc, const u8 *buf, const u32 len)
{
  for (u32 i = 0; i < len; i++)
  {
    crc = rar3_crc32_table[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
  }

  return crc;
}

// The bit reader. Bits come out most significant first, from bytes read in order.

static u8 rar3_input_byte (rar3_ctx_t *ctx, const u64 pos)
{
  if (pos >= ctx->in_bits / 8) return 0;
  while (pos >= ctx->input_start + ctx->input_count)
  {
    ctx->input_start += ctx->input_count;
    ctx->input_count = 0;
    const u64 left = ctx->in_bits / 8 - ctx->input_start;
    const int size = ctx->input_start == 0 ? RAR3_FIRST_CHUNK : RAR3_INPUT_SIZE;
    const int count = left < (u64) size ? (int) left : size;
    const int n = ctx->read (ctx->opaque, ctx->in, count);
    if (n <= 0 || n > count)
    {
      ctx->read_error = 1;
      return 0;
    }
    ctx->input_count = (u32) n;
    if (ctx->input_start >= RAR3_FIRST_CHUNK) ctx->trial_passed = 1;
  }
  if (pos < ctx->input_start || pos >= ctx->input_start + ctx->input_count)
  {
    ctx->read_error = 1;
    return 0;
  }
  return ctx->in[pos - ctx->input_start];
}

static u32 rar3_bit (rar3_ctx_t *ctx)
{
  if (ctx->bit >= ctx->in_bits || ctx->read_error)
  {
    ctx->bit = ctx->in_bits + 1;
    return 0;
  }
  const u32 v = (rar3_input_byte (ctx, ctx->bit >> 3) >> (7 - (ctx->bit & 7))) & 1;
  ctx->bit++;
  return v;
}

static u32 rar3_bits (rar3_ctx_t *ctx, const u32 count)
{
  u32 v = 0;

  for (u32 i = 0; i < count; i++)
  {
    v = (v << 1) | rar3_bit (ctx);
  }

  return v;
}

static int rar3_ended (const rar3_ctx_t *ctx)
{
  return (ctx->bit > ctx->in_bits || ctx->read_error) ? 1 : 0;
}

static int rar3_huff_build (rar3_huff_t *h, const u8 *lengths, const u32 size)
{
  memset (h, 0, sizeof (rar3_huff_t));

  for (u32 i = 0; i < size; i++)
  {
    h->count[lengths[i]]++;
  }

  h->count[0] = 0;

  u32 code  = 0;
  u32 index = 0;

  for (u32 len = 1; len <= RAR3_MAX_CODE_LEN; len++)
  {
    h->first_code[len]  = code;
    h->first_index[len] = index;

    code  += h->count[len];
    index += h->count[len];

    code <<= 1;
  }

  u32 next[RAR3_MAX_CODE_LEN + 1];

  for (u32 len = 0; len <= RAR3_MAX_CODE_LEN; len++) next[len] = h->first_index[len];

  for (u32 i = 0; i < size; i++)
  {
    const u32 len = lengths[i];

    if (len == 0) continue;

    h->symbol[next[len]] = (u16) i;

    next[len]++;
  }

  return 0;
}

// Incomplete prefix codes are valid; only oversubscribed tables are impossible.

static int rar3_huff_complete (const u8 *lengths, const u32 size)
{
  int left = 1;
  for (u32 len = 1; len <= RAR3_MAX_CODE_LEN; len++)
  {
    left *= 2;
    for (u32 i = 0; i < size; i++)
      if (lengths[i] == len) left--;
    if (left < 0) return 0;
  }
  return 1;
}

static int rar3_decode_symbol (rar3_ctx_t *ctx, const rar3_huff_t *h)
{
  u32 code = 0;

  for (u32 len = 1; len <= RAR3_MAX_CODE_LEN; len++)
  {
    code = (code << 1) | rar3_bit (ctx);

    if (h->count[len] == 0) continue;

    const u32 offset = code - h->first_code[len];

    if (offset < h->count[len]) return (int) h->symbol[h->first_index[len] + offset];
  }

  return -1;
}

static int rar3_read_pre_table (rar3_ctx_t *ctx, u8 *pre)
{
  u32 n = 0;

  while (n < RAR3_PRE_TABLE_SIZE)
  {
    const u32 length = rar3_bits (ctx, RAR3_PRE_TABLE_BITS);

    if (length != RAR3_PRE_TABLE_ESCAPE)
    {
      pre[n] = (u8) length;

      n++;

      continue;
    }

    const u32 zeros = rar3_bits (ctx, RAR3_PRE_TABLE_BITS);

    if (zeros == 0)
    {
      pre[n] = RAR3_PRE_TABLE_ESCAPE;

      n++;

      continue;
    }

    for (u32 i = 0; i < (zeros + 2); i++)
    {
      if (n >= RAR3_PRE_TABLE_SIZE) break;

      pre[n] = 0;

      n++;
    }
  }

  return rar3_ended (ctx);
}

// One block's 4 tables. Flag bit 2 set means a plain length is a difference against the previous block's, modulo 16.

static int rar3_init_ppm (rar3_ctx_t *ctx);

static int rar3_read_tables (rar3_ctx_t *ctx)
{
  ctx->bit = (ctx->bit + 7) & ~(u64) 7;
  if ((rar3_input_byte (ctx, ctx->bit / 8) & 0x80) != 0) return rar3_init_ppm (ctx);
  rar3_bit (ctx);
  ctx->ppm_mode = 0;
  ctx->last_low = 0;
  ctx->low_repeat = 0;

  const u32 keep = rar3_bit (ctx);

  if (keep == 0) memset (ctx->lengths, 0, sizeof (ctx->lengths));

  u8 pre[RAR3_PRE_TABLE_SIZE];

  if (rar3_read_pre_table (ctx, pre) != 0) return -1;

  if (rar3_huff_complete (pre, RAR3_PRE_TABLE_SIZE) == 0) return -1;

  rar3_huff_t code;

  rar3_huff_build (&code, pre, RAR3_PRE_TABLE_SIZE);

  u32 n = 0;

  while (n < RAR3_TABLE_TOTAL)
  {
    const int sym = rar3_decode_symbol (ctx, &code);

    if (sym < 0) return -1;

    if (rar3_ended (ctx) != 0) return -1;

    if (sym < 16)
    {
      ctx->lengths[n] = (u8) ((sym + ctx->lengths[n]) & 15);

      n++;

      continue;
    }

    u32 width = 0;
    u32 bias  = 0;
    u32 fill  = 0;

    if (sym == 16) { width = 3; bias =  3; fill = 1; }
    if (sym == 17) { width = 7; bias = 11; fill = 1; }
    if (sym == 18) { width = 3; bias =  3; fill = 0; }
    if (sym == 19) { width = 7; bias = 11; fill = 0; }

    if (sym > 19) return -1;

    const u32 count = bias + rar3_bits (ctx, width);

    for (u32 i = 0; i < count; i++)
    {
      if (n >= RAR3_TABLE_TOTAL) break;

      ctx->lengths[n] = ((fill == 1) && (n > 0)) ? ctx->lengths[n - 1] : 0;

      n++;
    }
  }

  const u8 *at = ctx->lengths;

  const u32 sizes[4] = { RAR3_TABLE_MAIN, RAR3_TABLE_DIST, RAR3_TABLE_LOW, RAR3_TABLE_REP };

  for (u32 t = 0; t < 4; t++)
  {
    if (rar3_huff_complete (at, sizes[t]) == 0) return -1;

    rar3_huff_build (&ctx->huff[t], at, sizes[t]);

    at += sizes[t];
  }

  return 0;
}

static void rar3_filter_x86 (u8 *data, const u32 len, const u32 start, const int with_e9)
{
  // At every 0xE8 the 4 bytes after it are a little endian value. Below 2^24 it is an address and the
  // file has it minus its own position in the whole file. Within 2^24 of the top it is an offset.

  if (len < 5) return;

  const u32 span = 1 << 24;

  u32 i = 0;

  while (i < (len - 4))
  {
    // E8E9 rewrites a jump, 0xE9, the same way. rar picks it for 64 bit code and x86 for 32 bit.

    const int mark = (data[i] == 0xe8) || ((with_e9 == 1) && (data[i] == 0xe9));

    if (mark == 0)
    {
      i++;

      continue;
    }

    const u32 pos = start + i + 1;

    const u32 v = (u32) data[i + 1] | ((u32) data[i + 2] << 8) | ((u32) data[i + 3] << 16) | ((u32) data[i + 4] << 24);

    u32 w = v;

    // Test signs after 32-bit unsigned arithmetic, including offsets above 2 GiB.
    if ((v & 0x80000000u) != 0)
    {
      if (((v + pos) & 0x80000000u) == 0) w = v + span;
    }
    else if (((v - span) & 0x80000000u) != 0)
    {
      w = v - pos;
    }

    data[i + 1] = (u8) (w >>  0);
    data[i + 2] = (u8) (w >>  8);
    data[i + 3] = (u8) (w >> 16);
    data[i + 4] = (u8) (w >> 24);

    i += 5;
  }
}

// An IA-64 bundle is 16 bytes: 5 bits of template and 3 slots of 41 bits. A slot is a branch when its template says so and bits 37-40 hold 5.

static const u8 RAR3_ITANIUM_SLOTS[32] =
{
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0,
};

static u64 rar3_bundle_get (const u64 lo, const u64 hi, const u32 at, const u32 count)
{
  u64 v = 0;

  for (u32 i = 0; i < count; i++)
  {
    const u32 p = at + i;

    const u64 b = (p < 64) ? ((lo >> p) & 1) : ((hi >> (p - 64)) & 1);

    v |= b << i;
  }

  return v;
}

static void rar3_bundle_set (u64 *lo, u64 *hi, const u32 at, const u32 count, const u64 value)
{
  for (u32 i = 0; i < count; i++)
  {
    const u32 p = at + i;

    const u64 b = (value >> i) & 1;

    if (p < 64)
    {
      *lo = (*lo & ~(1ULL << p)) | (b << p);
    }
    else
    {
      *hi = (*hi & ~(1ULL << (p - 64))) | (b << (p - 64));
    }
  }
}

static void rar3_filter_itanium (u8 *data, const u32 len, const u32 start)
{
  // The target is 20 bits at bit 13, minus the bundle number in the whole file. The last is untouched.

  if (len < 21) return;
  u32 pos = 0;

  while (pos < len - 21)
  {
    u64 lo = 0;
    u64 hi = 0;

    for (u32 i = 0; i < 8; i++) lo |= ((u64) data[pos + i]) << (i * 8);
    for (u32 i = 0; i < 8; i++) hi |= ((u64) data[pos + 8 + i]) << (i * 8);

    const u32 mask = RAR3_ITANIUM_SLOTS[lo & 0x1f];

    for (u32 slot = 0; slot < 3; slot++)
    {
      if ((mask & (1u << slot)) == 0) continue;

      const u32 base = 5 + (41 * slot);

      if (rar3_bundle_get (lo, hi, base + 37, 4) != 5) continue;

      const u64 imm = rar3_bundle_get (lo, hi, base + 13, 20);

      const u64 want = (imm - ((start + pos) / 16)) & 0xfffff;

      rar3_bundle_set (&lo, &hi, base + 13, 20, want);
    }

    for (u32 i = 0; i < 8; i++) data[pos + i]     = (u8) (lo >> (i * 8));
    for (u32 i = 0; i < 8; i++) data[pos + 8 + i] = (u8) (hi >> (i * 8));

    pos += 16;
  }
}

static void rar3_filter_delta (u8 *data, const u32 len, const u32 channels, u8 *scratch)
{
  // The channels arrive separated out, each byte being the sample before it minus the sample itself.

  if (channels == 0) return;

  // A channel past the end of the block holds no bytes, so a count above the length is capped to it.

  const u32 lanes = (channels > len) ? len : channels;

  u32 j = 0;

  for (u32 c = 0; c < lanes; c++)
  {
    u8 prev = 0;

    for (u32 i = c; i < len; i += channels)
    {
      prev = (u8) (prev - data[j]);

      scratch[i] = prev;

      j++;
    }
  }

  memcpy (data, scratch, len);
}

// The audio filter. Each channel is the sample before plus a weighted sum of the last 3 differences,
// shifted down by 3. Every 32 samples the cheapest of 7 weight moves is taken, ties going to no move.

#define RAR3_AUDIO_BLOCK 32
#define RAR3_AUDIO_MOVES 7

static const int RAR3_AUDIO_MOVE[RAR3_AUDIO_MOVES][3] =
{
  {  0,  0,  0 },
  { -1,  0,  0 },
  {  1,  0,  0 },
  {  0, -1,  0 },
  {  0,  1,  0 },
  {  0,  0, -1 },
  {  0,  0,  1 },
};

static int rar3_audio_signed (const u8 v)
{
  const int out = (v >= 128) ? ((int) v - 256) : (int) v;

  return out;
}

static void rar3_filter_audio (u8 *data, const u32 len, const u32 channels, u8 *scratch)
{
  if (channels == 0) return;

  const u32 lanes = (channels > len) ? len : channels;

  u8 *out = scratch;

  u32 at = 0;

  for (u32 c = 0; c < lanes; c++)
  {
    int k[3];

    k[0] = 0;
    k[1] = 0;
    k[2] = 0;

    int cost[RAR3_AUDIO_MOVES];

    for (u32 m = 0; m < RAR3_AUDIO_MOVES; m++) cost[m] = 0;

    int d1 = 0;
    int d2 = 0;
    int d3 = 0;

    int last = 0;

    u32 n = 0;

    for (u32 i = c; i < len; i += channels)
    {
      const int t1 = d1;
      const int t2 = d1 - d2;
      const int t3 = d2 - d3;

      const int q = ((k[0] * t1) + (k[1] * t2) + (k[2] * t3)) >> 3;

      const u8 written = data[at + n];

      const u8 sample = (u8) ((last + q) - written);

      out[i] = sample;

      const int e = rar3_audio_signed (written);

      for (u32 m = 0; m < RAR3_AUDIO_MOVES; m++)
      {
        const int d = (RAR3_AUDIO_MOVE[m][0] * t1) + (RAR3_AUDIO_MOVE[m][1] * t2) + (RAR3_AUDIO_MOVE[m][2] * t3);

        const int v = (8 * e) + d;

        cost[m] += (v < 0) ? -v : v;
      }

      d3 = d2;
      d2 = d1;
      d1 = rar3_audio_signed ((u8) (sample - last));

      last = sample;

      // The first look is after 1 sample and every 32 after that.

      if ((n % RAR3_AUDIO_BLOCK) == 0)
      {
        u32 best = 0;

        for (u32 m = 1; m < RAR3_AUDIO_MOVES; m++)
        {
          if (cost[m] < cost[best]) best = m;
        }

        for (u32 j = 0; j < 3; j++)
        {
          const int move = RAR3_AUDIO_MOVE[best][j];
          if ((move < 0 && k[j] >= -16) || (move > 0 && k[j] < 16)) k[j] += move;
        }

        for (u32 m = 0; m < RAR3_AUDIO_MOVES; m++) cost[m] = 0;
      }

      n++;
    }

    at += n;
  }

  memcpy (data, out, len);
}

static int rar3_paeth (const int left, const int upper, const int upperleft)
{
  const int p = left + upper - upperleft;

  const int a = abs (p - left);
  const int b = abs (p - upper);
  const int c = abs (p - upperleft);

  if ((a <= b) && (a <= c)) return left;

  if (b <= c) return upper;

  return upperleft;
}

static int rar3_rgb_offset (const u32 c, const u32 ref)
{
  // The nearest byte of the reference channel: 1 before for the channel after it, 1 after for the one before.

  int d = (int) ref - (int) c;

  if (d < -1) d += 3;
  if (d >  1) d -= 3;

  return d;
}

static void rar3_filter_rgb (u8 *data, const u32 len, const u32 width, const u32 ref, u8 *scratch)
{
  // A channel is read from one run and written back interleaved, so this cannot be done in place.

  u8 *out = scratch;
  u8 *seq = scratch + RAR3_FILTER_SIZE;

  u32 counts[3];
  u32 at[3];

  u32 off = 0;

  for (u32 c = 0; c < 3; c++)
  {
    counts[c] = (len > c) ? (((len - c) + 2) / 3) : 0;

    at[c] = off;

    off += counts[c];
  }

  const u32 order[3] = { ref, (ref + 1) % 3, (ref + 2) % 3 };

  for (u32 k = 0; k < 3; k++)
  {
    const u32 c = order[k];

    const int d = rar3_rgb_offset (c, ref);

    for (u32 i = 0; i < counts[c]; i++)
    {
      const int left = (i >= 1) ? seq[i - 1] : 0;
      const int up   = (i >  width) ? seq[i - width] : 0;
      const int ul   = (i >  width) ? seq[i - width - 1] : 0;

      const u8 v = (u8) (rar3_paeth (left, up, ul) - data[at[c] + i]);

      seq[i] = v;

      const u32 p = (i * 3) + c;

      u8 byte = v;

      if (c != ref)
      {
        const int q = (int) p + d;

        // The reference byte is used only at index 1 or later and at least 2 bytes before the end.

        if ((q >= 1) && (q < ((int) len - 1))) byte = (u8) (v + out[q]);
      }

      out[p] = byte;
    }
  }

  memcpy (data, out, len);
}

static rar3_filter_t rar3_filter_of (const u8 *program, const u32 size)
{
  if (size == 0) return RAR3_FILTER_NONE;
  u8 checksum = 0;
  for (u32 i = 1; i < size; i++) checksum ^= program[i];
  if (checksum != program[0]) return RAR3_FILTER_NONE;
  const u32 crc = rar3_crc32 (0xffffffffu, program, size) ^ 0xffffffffu;
  // Standard filter signatures, identified by length and CRC as in unrar 5+.
  const u32 sizes[] = { 53, 57, 120, 29, 149, 216 };
  const u32 crcs[] = { 0xad576887u, 0x3cd7e57eu, 0x3769893fu, 0x0e06077du, 0x1c2c5dc8u, 0xbc85e701u };
  const rar3_filter_t filters[] = { RAR3_FILTER_X86, RAR3_FILTER_E8E9, RAR3_FILTER_ITANIUM,
      RAR3_FILTER_DELTA, RAR3_FILTER_RGB, RAR3_FILTER_AUDIO };
  for (u32 i = 0; i < 6; i++)
    if (size == sizes[i] && crc == crcs[i]) return filters[i];
  return RAR3_FILTER_NONE;
}

// A number in a record body is 2 bits saying how wide it is and then that many bits.

typedef struct rar3_body
{
  const u8 *buf;
  u32       len;
  u32       pos;
  int       over;

} rar3_body_t;

static u32 rar3_body_bit (rar3_body_t *b)
{
  if (b->pos >= (b->len * 8))
  {
    b->over = 1;

    return 0;
  }

  const u32 v = (b->buf[b->pos >> 3] >> (7 - (b->pos & 7))) & 1;

  b->pos++;

  return v;
}

static u32 rar3_body_bits (rar3_body_t *b, const u32 count)
{
  u32 v = 0;

  for (u32 i = 0; i < count; i++) v = (v << 1) | rar3_body_bit (b);

  return v;
}

static u32 rar3_body_number (rar3_body_t *b)
{
  const u32 sel = rar3_body_bits (b, 2);
  if (sel == 0) return rar3_body_bits (b, 4);
  if (sel == 1)
  {
    const u32 high = rar3_body_bits (b, 4);
    if (high == 0) return 0xffffff00u | rar3_body_bits (b, 8);
    return (high << 4) | rar3_body_bits (b, 4);
  }
  return rar3_body_bits (b, sel == 2 ? 16 : 32);
}

// Reading a filter setup record. The flags byte says which fields the body holds.

#define RAR3_REC_HAS_NUMBER 0x80

#define RAR3_REC_FAR_START  0x40

#define RAR3_REC_HAS_LENGTH 0x20
#define RAR3_REC_HAS_PARAMS 0x10
#define RAR3_REC_UNKNOWN    0x08

// How many filters one stream may set up. Naming one past the end is refused.

#define RAR3_SLOT_MAX 64

typedef struct rar3_slots
{
  // What each filter is, and the length and parameters its last block had. A record may leave any out.

  rar3_filter_t filter[RAR3_SLOT_MAX];

  u32 length[RAR3_SLOT_MAX];
  int has_length[RAR3_SLOT_MAX];

  u32 param[RAR3_SLOT_MAX][2];
  u32 params[RAR3_SLOT_MAX];

  u32 count;
  u32 last;
  int has_last;

} rar3_slots_t;

// -1 is not a record at all, which is what noise gives. -2 read cleanly and asks for the unimplemented.

#define RAR3_RECORD_MALFORMED   -1
#define RAR3_RECORD_UNSUPPORTED -2

static int rar3_record_byte (rar3_ctx_t *ctx)
{
  return ctx->ppm_mode ? Ppmd7a_DecodeSymbol (&ctx->ppm) : (int) rar3_bits (ctx, 8);
}

static int rar3_read_record (rar3_ctx_t *ctx, rar3_slots_t *slots)
{
  const int first_byte = rar3_record_byte (ctx);
  if (first_byte < 0) return RAR3_RECORD_MALFORMED;
  const u32 first = (u32) first_byte;
  u32 size = (first & 7) + 1;
  if (size >= 7)
  {
    const int a = rar3_record_byte (ctx);
    if (a < 0) return RAR3_RECORD_MALFORMED;
    if (size == 7) size = (u32) a + 7;
    else
    {
      const int b = rar3_record_byte (ctx);
      if (b < 0) return RAR3_RECORD_MALFORMED;
      size = (u32) a * 256 + (u32) b;
    }
  }
  if (size == 0) return RAR3_RECORD_MALFORMED;
  u8 body[65536];
  for (u32 i = 0; i < size; i++)
  {
    const int byte = rar3_record_byte (ctx);
    if (byte < 0) return RAR3_RECORD_MALFORMED;
    body[i] = (u8) byte;
  }
  if (rar3_ended (ctx)) return RAR3_RECORD_MALFORMED;

  rar3_body_t b;

  b.buf  = body;
  b.len  = size;
  b.pos  = 0;
  b.over = 0;

  // The number names filter n - 1, and 0 and 1 both name the first. No number means the last one used.

  u32 idx = 0;
  int reset_filters = 0;

  if ((first & RAR3_REC_HAS_NUMBER) != 0)
  {
    const u32 which = rar3_body_number (&b);

    if (which == 0)
    {
      reset_filters = slots->count > 0;
      memset (slots, 0, sizeof (*slots));
    }
    idx = (which == 0) ? 0 : (which - 1);
  }
  else
  {
    idx = slots->last;
  }

  if (idx > slots->count) return RAR3_RECORD_MALFORMED;

  if (idx >= RAR3_SLOT_MAX) return RAR3_RECORD_UNSUPPORTED;

  const int is_new = (idx == slots->count) ? 1 : 0;

  const u32 start = rar3_body_number (&b);

  u32 length = 0;

  int has_length = 0;

  if ((first & RAR3_REC_HAS_LENGTH) != 0)
  {
    length = rar3_body_number (&b);

    has_length = 1;
  }

  u32 regs[7] = { 0, 0, 0, 0, length, 0, 0 };
  u32 mask = 0;
  if ((first & RAR3_REC_HAS_PARAMS) != 0)
  {
    mask = rar3_body_bits (&b, 7);
    for (u32 i = 0; i < 7; i++)
      if (mask & (1u << i)) regs[i] = rar3_body_number (&b);
  }
  u32 param[2] = { regs[0], regs[1] };
  u32 params = 2;

  rar3_filter_t filter = RAR3_FILTER_NONE;

  u8  program[256];
  u32 program_size = 0;

  if (is_new)
  {
    program_size = rar3_body_number (&b);
    if (b.over || program_size == 0 || program_size > (b.len * 8 - b.pos) / 8)
      return RAR3_RECORD_MALFORMED;
    // No other VM program can be extracted by unrar 5+ either.
    if (program_size > sizeof (program)) return RAR3_RECORD_MALFORMED;
    for (u32 i = 0; i < program_size; i++) program[i] = (u8) rar3_body_bits (&b, 8);
    filter = rar3_filter_of (program, program_size);
    if (filter == RAR3_FILTER_NONE || b.over) return RAR3_RECORD_MALFORMED;
    slots->count++;
    slots->has_length[idx] = 0;
    slots->filter[idx] = filter;
  }
  else filter = slots->filter[idx];
  if (b.over) return RAR3_RECORD_MALFORMED;
  if (reset_filters)
  {
    // A reset also discards pending filters. After output, unrar's window flush timing matters.
    if (ctx->produced > 0)
    {
      ctx->status = -7;
      return RAR3_RECORD_UNSUPPORTED;
    }
    ctx->block_cnt = ctx->block_at = 0;
    ctx->collecting = ctx->collected = 0;
  }

  slots->last     = idx;
  slots->has_last = 1;

  // Retire consumed records so the queue does not grow with the file.
  if (ctx->block_at > 0)
  {
    ctx->block_cnt -= ctx->block_at;
    memmove (ctx->blocks, ctx->blocks + ctx->block_at, ctx->block_cnt * sizeof (rar3_block_t));
    ctx->block_at = 0;
  }
  if (ctx->block_cnt >= RAR3_FILTER_MAX) return RAR3_RECORD_UNSUPPORTED;

  // Where the block starts. The field carries it, and bit 6 of the flags byte says to add 258.

  const u64 at = ctx->produced + (u64) start + (((first & RAR3_REC_FAR_START) != 0) ? 258 : 0);

  // Noncanonical offsets can wrap the dictionary or refer to a deferred window in unrar.
  // Preserve the candidate when this forward-only queue cannot place its filter safely.
  if ((u64) start + (((first & RAR3_REC_FAR_START) != 0) ? 258u : 0u) >= ctx->window_size ||
      at < ctx->produced || at > ctx->dest_size)
  {
    ctx->status = -4;
    return RAR3_RECORD_UNSUPPORTED;
  }

  // A record with no length takes the one the last block of that same filter had, not of any filter.

  if (has_length == 0)
  {
    if (slots->has_length[idx] == 0) return RAR3_RECORD_MALFORMED;

    length = slots->length[idx];
  }

  slots->length[idx]     = length;
  slots->has_length[idx] = 1;

  if (length == 0 || length > ctx->dest_size - at) return RAR3_RECORD_UNSUPPORTED;
  if (length > RAR3_FILTER_SIZE) return RAR3_RECORD_UNSUPPORTED;
  if ((mask & (1u << 4)) != 0 && regs[4] != length)
  {
    ctx->status = -6;
    return RAR3_RECORD_UNSUPPORTED;
  }
  if (filter == RAR3_FILTER_DELTA || filter == RAR3_FILTER_AUDIO || filter == RAR3_FILTER_RGB)
  {
    if (length > RAR3_FILTER_SIZE / 2) return RAR3_RECORD_UNSUPPORTED;
    if ((filter != RAR3_FILTER_RGB && (param[0] == 0 || param[0] > 128)) ||
        (filter == RAR3_FILTER_RGB && (length < 3 || param[0] - 3 > length || param[1] > 2)))
    {
      // Unrar may pass the raw block through for these parameters; do not guess its VM state.
      ctx->status = -6;
      return RAR3_RECORD_UNSUPPORTED;
    }
    if (filter == RAR3_FILTER_RGB && param[0] % 3 != 0)
    {
      ctx->status = -6;
      return RAR3_RECORD_UNSUPPORTED;
    }
  }

  rar3_block_t *block = &ctx->blocks[ctx->block_cnt];

  block->filter = filter;
  block->start  = at;
  block->length = length;
  block->params = params;

  block->param[0] = (params > 0) ? param[0] : 0;
  block->param[1] = (params > 1) ? param[1] : 0;

  ctx->block_cnt++;

  return 0;
}

static void rar3_run_filter (rar3_ctx_t *ctx, const rar3_block_t *block, u8 *scratch)
{
  u8 *data = ctx->filter_buf;

  const u32 len = block->length;

  if (block->filter == RAR3_FILTER_X86)     rar3_filter_x86     (data, len, block->start, 0);
  if (block->filter == RAR3_FILTER_E8E9)    rar3_filter_x86     (data, len, block->start, 1);
  if (block->filter == RAR3_FILTER_ITANIUM) rar3_filter_itanium (data, len, block->start);
  if (block->filter == RAR3_FILTER_DELTA)   rar3_filter_delta   (data, len, block->param[0], scratch);
  if (block->filter == RAR3_FILTER_AUDIO)   rar3_filter_audio   (data, len, block->param[0], scratch);

  if (block->filter == RAR3_FILTER_RGB)
  {
    // 3 times one more than the row width, and the reference channel less 1 modulo 3.

    const u32 width = (block->param[0] / 3) - 1;
    const u32 ref   = (block->param[1] + 1) % 3;

    rar3_filter_rgb (data, len, width, ref, scratch);
  }

}

// A filter block has all its bytes, so it runs and the queue moves on.

static void rar3_finish_block (rar3_ctx_t *ctx, u8 *scratch)
{
  const u64 start = ctx->blocks[ctx->block_at].start;
  const u32 length = ctx->blocks[ctx->block_at].length;
  do
  {
    rar3_run_filter (ctx, &ctx->blocks[ctx->block_at], scratch);
    ctx->block_at++;
  }
  while (ctx->block_at < ctx->block_cnt && ctx->blocks[ctx->block_at].start == start &&
      ctx->blocks[ctx->block_at].length == length);
  ctx->crc = rar3_crc32 (ctx->crc, ctx->filter_buf, length);
  ctx->collecting = 0;
  ctx->collected = 0;
  if (ctx->block_at < ctx->block_cnt && ctx->blocks[ctx->block_at].start < ctx->produced)
    ctx->status = -5;
}

static void rar3_emit (rar3_ctx_t *ctx, const u8 byte, u8 *scratch)
{
  // Poll even when a tiny compressed input expands for a long time without another refill.
  if ((ctx->produced & 0xffff) == 0 && ctx->read (ctx->opaque, ctx->in, 0) < 0)
  {
    ctx->read_error = 1;
    return;
  }
  ctx->win[ctx->produced & ctx->window_mask] = byte;

  const u64 at = ctx->produced;

  ctx->produced++;

  if (ctx->collecting == 1)
  {
    ctx->filter_buf[ctx->collected] = byte;

    ctx->collected++;

    if (ctx->collected >= ctx->blocks[ctx->block_at].length) rar3_finish_block (ctx, scratch);

    return;
  }

  if ((ctx->block_at < ctx->block_cnt) && (at > ctx->blocks[ctx->block_at].start))
  {
    // Output past a filter's block that was never collected would reach the CRC32 untransformed.

    ctx->status = HC_RAR3_UNPACK_UNSUPPORTED;

    return;
  }

  if ((ctx->block_at < ctx->block_cnt) && (at == ctx->blocks[ctx->block_at].start))
  {
    ctx->collecting = 1;
    ctx->collected  = 1;

    ctx->filter_buf[0] = byte;

    if (ctx->blocks[ctx->block_at].length <= 1) rar3_finish_block (ctx, scratch);

    return;
  }

  ctx->crc = rar3_crc32 (ctx->crc, &byte, 1);
}

// Copying a match out of the window. Returns the last byte emitted, which the PPM path needs, and
// last unchanged when the output ran out before anything was copied.

static u8 rar3_copy_match (rar3_ctx_t *ctx, const u32 dist, const u32 length, const u8 last, u8 *scratch)
{
  u8 out = last;

  for (u32 i = 0; i < length; i++)
  {
    if (ctx->produced >= ctx->dest_size) break;

    out = ctx->win[(ctx->produced - dist) & ctx->window_mask];

    rar3_emit (ctx, out, scratch);
  }

  return out;
}

// Distance slots use pairs up to 15 bits, fourteen 16-bit slots, then twelve 18-bit slots.

static u32 rar3_dist_extra (const u32 sym)
{
  if (sym < 4) return 0;
  if (sym >= 48) return 18;

  const u32 e = (sym - 2) / 2;

  if (e >= 16) return 16;

  return e;
}

static int rar3_ppm_step (rar3_ctx_t *ctx, rar3_slots_t *slots, u8 *scratch);

static void rar3_unpack (rar3_ctx_t *ctx, u8 *scratch)
{
  if (rar3_read_tables (ctx) != 0)
  {
    if (ctx->status == HC_RAR3_UNPACK_OK) ctx->status = HC_RAR3_UNPACK_REJECTED_LZ;

    return;
  }

  ctx->tables_ok = 1;

  rar3_slots_t slots;

  memset (&slots, 0, sizeof (slots));

  u32 history[RAR3_OLD_DIST];
  u32 history_cnt = 0;

  u32 last_length = 0;

  while (ctx->produced < ctx->dest_size && ctx->status == HC_RAR3_UNPACK_OK && !rar3_ended (ctx))
  {
    if (ctx->ppm_mode)
    {
      if (rar3_ppm_step (ctx, &slots, scratch) != 0) return;
      continue;
    }
    const int sym = rar3_decode_symbol (ctx, &ctx->huff[0]);

    if (sym < 0) return;

    if (rar3_ended (ctx) != 0) return;

    if (sym < 256)
    {
      rar3_emit (ctx, (u8) sym, scratch);

      continue;
    }

    if (sym == RAR3_FILTER_RECORD)
    {
      const int ok = rar3_read_record (ctx, &slots);

      if (ok == RAR3_RECORD_UNSUPPORTED)
      {
        if (ctx->status == HC_RAR3_UNPACK_OK) ctx->status = HC_RAR3_UNPACK_UNSUPPORTED;

        return;
      }

      if (ok != 0) return;

      continue;
    }

    if (sym == RAR3_END_OF_BLOCK)
    {
      // A zero starts the next file; a one introduces byte-aligned tables in this file.
      if (rar3_bit (ctx) == 0) return;
      ctx->bit = (ctx->bit + 7) & ~(u64) 7;

      if (rar3_read_tables (ctx) != 0) return;

      continue;
    }

    u32 length = 0;
    u32 dist   = 0;

    int remember = 1;

    if (sym == RAR3_REPEAT_SAME)
    {
      if (history_cnt == 0) return;

      length = last_length;

      dist = history[0];

      remember = 0;
    }
    else if ((sym >= RAR3_REPEAT_FIRST) && (sym <= RAR3_REPEAT_LAST))
    {
      const u32 j = (u32) sym - RAR3_REPEAT_FIRST;

      if (j >= history_cnt) return;

      dist = history[j];

      const int lsym = rar3_decode_symbol (ctx, &ctx->huff[3]);

      if (lsym < 0) return;

      if (lsym >= RAR3_TABLE_REP) return;

      // The fourth table's 28 entries are the 28 length symbols with every base 1 lower.

      length = (RAR3_LENGTH_BASE[lsym] - 1) + rar3_bits (ctx, RAR3_LENGTH_EXTRA[lsym]);

      // Naming an older distance moves it back to the front.

      for (u32 k = j; k > 0; k--) history[k] = history[k - 1];

      history[0] = dist;

      remember = 0;
    }
    else if (sym >= RAR3_LENGTH_FIRST)
    {
      const u32 k = (u32) sym - RAR3_LENGTH_FIRST;

      if (k >= RAR3_TABLE_REP) return;

      length = RAR3_LENGTH_BASE[k] + rar3_bits (ctx, RAR3_LENGTH_EXTRA[k]);

      const int dsym = rar3_decode_symbol (ctx, &ctx->huff[1]);

      if (dsym < 0) return;

      if (dsym >= RAR3_TABLE_DIST) return;

      // Once a distance symbol reads 4 or more extra bits, its low 4 come from the third table.

      const u32 e = rar3_dist_extra ((u32) dsym);

      u32 base = 1;

      for (u32 i = 0; i < (u32) dsym; i++) base += 1u << rar3_dist_extra (i);

      u32 off = 0;

      if (e >= RAR3_DIST_LOW_BITS)
      {
        const u32 high = (e > RAR3_DIST_LOW_BITS) ? rar3_bits (ctx, e - RAR3_DIST_LOW_BITS) : 0;

        u32 low = 0;

        if (ctx->low_repeat > 0)
        {
          ctx->low_repeat--;

          low = ctx->last_low;
        }
        else
        {
          const int lsym = rar3_decode_symbol (ctx, &ctx->huff[2]);

          if (lsym < 0) return;

          if (lsym == RAR3_LOW_REPEAT_SYMBOL)
          {
            low = ctx->last_low;

            ctx->low_repeat = RAR3_LOW_REPEAT_COUNT;
          }
          else if (lsym >= (1 << RAR3_DIST_LOW_BITS))
          {
            return;
          }
          else
          {
            low = (u32) lsym;

            ctx->last_low = low;
          }
        }

        off = (high << RAR3_DIST_LOW_BITS) | low;
      }
      else
      {
        off = (e > 0) ? rar3_bits (ctx, e) : 0;
      }

      dist = base + off;

      if (dist >= RAR3_LONGER_DIST) length += 2;
      else if (dist >= RAR3_LONG_DIST) length += 1;
    }
    else if (sym >= RAR3_SHORT_FIRST)
    {
      const u32 k = (u32) sym - RAR3_SHORT_FIRST;

      length = 2;

      dist = RAR3_SHORT_BASE[k] + rar3_bits (ctx, RAR3_SHORT_EXTRA[k]);
    }
    else
    {
      return;
    }

    if ((dist == 0) || (dist > ctx->produced)) return;

    if (dist > ctx->window_size) return;

    if (remember == 1)
    {
      for (u32 k = RAR3_OLD_DIST - 1; k > 0; k--) history[k] = history[k - 1];

      history[0] = dist;

      if (history_cnt < RAR3_OLD_DIST) history_cnt++;
    }

    last_length = length;

    rar3_copy_match (ctx, dist, length, 0, scratch);
  }
}

// The public-domain PPM model persists across table transitions, including non-reset headers.

static Byte rar3_byte_in_read (IByteInPtr pp)
{
  rar3_byte_in_t *p = Z7_CONTAINER_FROM_VTBL (pp, rar3_byte_in_t, vt);
  return (Byte) rar3_bits (p->ctx, 8);
}

typedef struct rar3_arena
{
  ISzAlloc vt;
  void *base;
} rar3_arena_t;

static void *rar3_arena_alloc (ISzAllocPtr pp, size_t size)
{
  rar3_arena_t *p = (rar3_arena_t *) pp;
  p->base = malloc (size);
  return p->base;
}

static void rar3_arena_free (ISzAllocPtr pp, void *address)
{
  (void) pp;
  (void) address;
}

static int rar3_init_ppm (rar3_ctx_t *ctx)
{
  const u32 flags = rar3_bits (ctx, 8);
  const int reset = (flags & 0x20) != 0;
  const u32 memory = reset ? rar3_bits (ctx, 8) + 1 : 0;
  if (flags & 0x40) ctx->ppm_escape = (u8) rar3_bits (ctx, 8);
  if (reset)
  {
    const u32 n = (flags & 31) + 1;
    const u32 order = n > 16 ? 16 + 3 * (n - 16) : n;
    if (order == 1) return -1;
    free (ctx->ppm_arena);
    ctx->ppm_arena = NULL;
    Ppmd7_Construct (&ctx->ppm);
    rar3_arena_t arena;
    arena.vt.Alloc = rar3_arena_alloc;
    arena.vt.Free = rar3_arena_free;
    arena.base = NULL;
    if (!Ppmd7_Alloc (&ctx->ppm, memory << 20, &arena.vt))
    {
      ctx->status = -3;
      return -1;
    }
    ctx->ppm_arena = arena.base;
    Ppmd7_Init (&ctx->ppm, order);
  }
  else if (!ctx->ppm_arena) return -1;
  ctx->ppm_reader.vt.Read = rar3_byte_in_read;
  ctx->ppm_reader.ctx = ctx;
  ctx->ppm.rc.dec.Stream = &ctx->ppm_reader.vt;
  if (!Ppmd7a_RangeDec_Init (&ctx->ppm.rc.dec) || rar3_ended (ctx)) return -1;
  ctx->ppm_mode = 1;
  ctx->tables_ok = 1;
  return 0;
}

static int rar3_ppm_step (rar3_ctx_t *ctx, rar3_slots_t *slots, u8 *scratch)
{
  const int sym = Ppmd7a_DecodeSymbol (&ctx->ppm);
  if (sym < 0 || rar3_ended (ctx)) return -1;
  if (sym != ctx->ppm_escape)
  {
    rar3_emit (ctx, (u8) sym, scratch);
    return 0;
  }
  const int cmd = Ppmd7a_DecodeSymbol (&ctx->ppm);
  if (cmd < 0 || rar3_ended (ctx)) return -1;
  if (cmd == 0) return rar3_read_tables (ctx);
  if (cmd == 2) return -1;
  if (cmd == 3)
  {
    const int result = rar3_read_record (ctx, slots);
    if (result == RAR3_RECORD_UNSUPPORTED && ctx->status == HC_RAR3_UNPACK_OK) ctx->status = HC_RAR3_UNPACK_UNSUPPORTED;
    return result;
  }
  if (cmd == 4 || cmd == 5)
  {
    u32 distance = 1;
    if (cmd == 4)
    {
      distance = 0;
      for (u32 i = 0; i < 3; i++)
      {
        const int b = Ppmd7a_DecodeSymbol (&ctx->ppm);
        if (b < 0) return -1;
        distance = (distance << 8) | (u32) b;
      }
      distance += 2;
    }
    const int n = Ppmd7a_DecodeSymbol (&ctx->ppm);
    if (n < 0 || distance > ctx->produced || distance > ctx->window_size || rar3_ended (ctx)) return -1;
    rar3_copy_match (ctx, distance, (u32) n + (cmd == 4 ? 32 : 4), 0, scratch);
    return 0;
  }
  // All remaining escape commands write the escape byte, as unrar does.
  rar3_emit (ctx, ctx->ppm_escape, scratch);
  return 0;
}

/* read returns decrypted bytes, 0 at EOF or -1 on error/cancellation. A zero-count call polls
 * cancellation without consuming input. A successful check
 * requires the expected output length and CRC, never just the first-chunk trial. */
RK_EXPORT int rk_rar3_decode_stream (rar3_read_fn read, void *opaque, u64 packed, u64 unpacked,
    u32 window_size, u32 expected_crc, int *stage)
{
  if (stage) *stage = 0;
  if (!read || !stage || packed == 0 || packed > UINT64_MAX / 8 || unpacked == 0 ||
      window_size < 0x10000 || window_size > 0x400000 || (window_size & (window_size - 1))) return -1;
  rar3_ctx_t *ctx = (rar3_ctx_t *) calloc (1, sizeof (*ctx));
  if (!ctx) return -3;
  ctx->read = read;
  ctx->opaque = opaque;
  ctx->in_bits = packed * 8;
  ctx->dest_size = unpacked;
  ctx->window_size = window_size;
  ctx->window_mask = window_size - 1;
  ctx->crc = 0xffffffff;
  ctx->ppm_escape = 2;
  ctx->win = (u8 *) malloc (window_size);
  ctx->filter_buf = (u8 *) malloc (RAR3_FILTER_SIZE);
  ctx->blocks = (rar3_block_t *) malloc (RAR3_FILTER_MAX * sizeof (rar3_block_t));
  u8 *scratch = (u8 *) malloc (RAR3_FILTER_SIZE * 2);
  int result = -3;
  if (ctx->win && ctx->filter_buf && ctx->blocks && scratch)
  {
    rar3_unpack (ctx, scratch);
    *stage = (ctx->trial_passed || ctx->produced == unpacked) ? 2 : ctx->tables_ok ? 1 : 0;
    result = 0;
    if (ctx->read_error) result = -2;
    else if (ctx->status == HC_RAR3_UNPACK_UNSUPPORTED) result = -1;
    else if (ctx->status < 0) result = ctx->status;
    else if (ctx->status == HC_RAR3_UNPACK_OK && !rar3_ended (ctx) &&
        ctx->produced == unpacked && !ctx->collecting && ctx->block_at == ctx->block_cnt &&
        (ctx->crc ^ 0xffffffff) == expected_crc)
    {
      result = 1;
      *stage = 3;
    }
  }
  free (ctx->ppm_arena);
  free (ctx->win);
  free (ctx->filter_buf);
  free (ctx->blocks);
  free (scratch);
  free (ctx);
  return result;
}
