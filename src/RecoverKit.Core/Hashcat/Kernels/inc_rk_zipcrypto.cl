/*
 * RecoverKit ZipCrypto helpers for the PKZIP kernels (modes 17200, 17210), hashcat 8.0.0 kernel ABI.
 *
 * Installed by RecoverKit into hashcat's OpenCL folder next to its replacement m17200/m17210
 * kernels. The pkzip_t layout, the key update and the deflate pre-checks follow the PKZIP Kernels
 * for Hashcat (c) 2018 European Union (Joint Research Centre, author Sein Coray), MIT License;
 * see the license text in the kernel files.
 *
 * Why these kernels exist: hashcat's PKZIP kernels decrypt and check the whole file (CRC, or a full
 * inflate) inside the candidate loop whenever the 1-byte header check passes, which happens for 1 in
 * 128 to 1 in 256 candidates. On a GPU the other 31 threads of the SIMD group wait for it, so the cost
 * grows with the file size: a 1 KB entry runs about 13 times slower than a 17-byte one. Here the
 * candidate loop only runs the key schedule and the 12-byte header; candidates that pass the check
 * byte are queued in local memory, and every thread of the work-group then verifies one queued
 * candidate, so the full-file work is spread evenly and is done for 1/128 of the candidates only.
 *
 * This file has the shared definitions; the kernel bodies are in inc_rk_zip_a3.cl (brute-force and
 * mask) and inc_rk_zip_a0.cl (dictionary and rules).
 */

#ifndef INC_RK_ZIPCRYPTO
#define INC_RK_ZIPCRYPTO

#define RK_ZIP_VERSION 1

#define MAX_DATA (320 * 1024)

#ifndef MAX_LOCAL
#define MAX_LOCAL 64
#endif

// Survivors of the header check queued per work-group before they are verified together.
#define RK_QUEUE 1024

// Without the packed attribute the compiler lays data[] out at offset 40 of pkzip_t (hashcat 8).

struct pkzip_hash
{
  u8  data_type_enum;
  u8  magic_type_enum;
  u32 compressed_length;
  u32 uncompressed_length;
  u32 crc32;
  u32 offset;
  u32 additional_offset;
  u8  compression_type;
  u32 data_length;
  u16 checksum_from_crc;
  u16 checksum_from_timestamp;
  u32 data[MAX_DATA / 4];

};

typedef struct pkzip_hash pkzip_hash_t;

struct pkzip
{
  u8 hash_count;
  u8 checksum_size;
  u8 version;

  pkzip_hash_t hash;

};

typedef struct pkzip pkzip_t;

#define RK_MIN(a,b) (((a) < (b)) ? (a) : (b))
#define RK_MAX(a,b) (((a) > (b)) ? (a) : (b))

#define RK_KEY_CONST 0x08088405u

#define RK_CRC(x,c) (((x) >> 8) ^ l_crc32tab[((x) ^ (c)) & 0xff])

#define RK_UPDATE(k0,k1,k2,c)                    \
{                                                \
  (k0) = RK_CRC ((k0), (c));                     \
  (k1) = ((k1) + ((k0) & 0xff)) * RK_KEY_CONST + 1; \
  (k2) = RK_CRC ((k2), (k1) >> 24);              \
}

#define RK_KEY3(k2) (((((k2) | 2) & 0xffff) * ((((k2) | 2) & 0xffff) ^ 1) >> 8) & 0xff)

#define RK_BYTE(w,n) (((w) >> ((n) * 8)) & 0xff)

// decrypt one byte of word w and feed the plaintext back into the keys
#define RK_DECRYPT(k0,k1,k2,w,n,plain) \
{                                      \
  (plain) = RK_BYTE ((w), (n)) ^ RK_KEY3 (k2); \
  RK_UPDATE ((k0), (k1), (k2), (plain));       \
}

// atomic increment of a work-group (local) counter, returns the old value

#if defined IS_CUDA || defined IS_HIP
#define RK_LOCAL_INC(p) atomicAdd ((p), 1u)
#elif defined IS_METAL
#define RK_LOCAL_INC(p) atomic_fetch_add_explicit ((volatile threadgroup atomic_uint *) (p), 1u, memory_order_relaxed)
#else
#define RK_LOCAL_INC(p) atomic_inc (p)
#endif

#if defined IS_CUDA || defined IS_HIP
#define RK_LOCAL_OR(p,v) atomicOr ((p), (v))
#elif defined IS_METAL
#define RK_LOCAL_OR(p,v) atomic_fetch_or_explicit ((volatile threadgroup atomic_uint *) (p), (v), memory_order_relaxed)
#else
#define RK_LOCAL_OR(p,v) atomic_or ((p), (v))
#endif

// RK_AMP_CACHE 1: the key states after the amplifier's characters (one per il_pos) are computed
// once per work-group into local memory (12 KB). On the Apple M1 Pro this made the kernel slower,
// so it is off; recoverkit-cli bench-zip measures it as well on other GPUs.
#define RK_AMP_CACHE 0
#define RK_PFX 1024

// the 32-bit word j of the entry data, from the local copy when it holds it
#define RK_DATA(j) (((j) < MAX_LOCAL) ? l_data[(j)] : esalt_bufs[DIGESTS_OFFSET_HOST].hash.data[(j)])

// Key schedule of the password: the first word comes from w0, words 1-3 from registers and anything
// past 16 characters straight from the candidate buffer.

#define RK_PW_WORD(k0,k1,k2,w,base,len)                              \
{                                                                     \
  if ((len) > (base) + 0) RK_UPDATE ((k0), (k1), (k2), RK_BYTE ((w), 0)); \
  if ((len) > (base) + 1) RK_UPDATE ((k0), (k1), (k2), RK_BYTE ((w), 1)); \
  if ((len) > (base) + 2) RK_UPDATE ((k0), (k1), (k2), RK_BYTE ((w), 2)); \
  if ((len) > (base) + 3) RK_UPDATE ((k0), (k1), (k2), RK_BYTE ((w), 3)); \
}

#define RK_PW_KEYS(k0,k1,k2,w0,w1,w2,w3,len,pwbuf)                   \
{                                                                     \
  (k0) = 0x12345678;                                                  \
  (k1) = 0x23456789;                                                  \
  (k2) = 0x34567890;                                                  \
  RK_PW_TAIL ((k0), (k1), (k2), (w0), (w1), (w2), (w3), (len), (pwbuf), 0); \
}

// The same from character `from` (0..4) on, with the keys already holding the state before it.

#define RK_PW_TAIL(k0,k1,k2,w0,w1,w2,w3,len,pwbuf,from)              \
{                                                                     \
  if ((from) <= 0 && (len) > 0) RK_UPDATE ((k0), (k1), (k2), RK_BYTE ((w0), 0)); \
  if ((from) <= 1 && (len) > 1) RK_UPDATE ((k0), (k1), (k2), RK_BYTE ((w0), 1)); \
  if ((from) <= 2 && (len) > 2) RK_UPDATE ((k0), (k1), (k2), RK_BYTE ((w0), 2)); \
  if ((from) <= 3 && (len) > 3) RK_UPDATE ((k0), (k1), (k2), RK_BYTE ((w0), 3)); \
  if ((len) > 4)                                                      \
  {                                                                   \
    RK_PW_WORD ((k0), (k1), (k2), (w1),  4, (len));                   \
    RK_PW_WORD ((k0), (k1), (k2), (w2),  8, (len));                   \
    RK_PW_WORD ((k0), (k1), (k2), (w3), 12, (len));                   \
    for (u32 rk_i = 16; rk_i < (len); rk_i++)                         \
    {                                                                 \
      const u32 rk_c = RK_BYTE ((pwbuf)[rk_i / 4], rk_i & 3);         \
      RK_UPDATE ((k0), (k1), (k2), rk_c);                             \
    }                                                                 \
  }                                                                   \
}

// The 12-byte encryption header in h0..h2. Leaves the keys after the header and evaluates to false
// when the check byte (and with checksum_size 2 the byte before it) does not match.

#define RK_HEADER(k0,k1,k2,h0,h1,h2,ok)                               \
{                                                                     \
  u32 rk_p;                                                           \
  RK_DECRYPT ((k0), (k1), (k2), (h0), 0, rk_p);                       \
  RK_DECRYPT ((k0), (k1), (k2), (h0), 1, rk_p);                       \
  RK_DECRYPT ((k0), (k1), (k2), (h0), 2, rk_p);                       \
  RK_DECRYPT ((k0), (k1), (k2), (h0), 3, rk_p);                       \
  RK_DECRYPT ((k0), (k1), (k2), (h1), 0, rk_p);                       \
  RK_DECRYPT ((k0), (k1), (k2), (h1), 1, rk_p);                       \
  RK_DECRYPT ((k0), (k1), (k2), (h1), 2, rk_p);                       \
  RK_DECRYPT ((k0), (k1), (k2), (h1), 3, rk_p);                       \
  RK_DECRYPT ((k0), (k1), (k2), (h2), 0, rk_p);                       \
  RK_DECRYPT ((k0), (k1), (k2), (h2), 1, rk_p);                       \
  rk_p = RK_BYTE ((h2), 2) ^ RK_KEY3 (k2);                            \
  (ok) = (checksum_size != 2) || (rk_p == (checksum_from_crc & 0xff)) || (rk_p == (checksum_from_timestamp & 0xff)); \
  RK_UPDATE ((k0), (k1), (k2), rk_p);                                 \
  rk_p = RK_BYTE ((h2), 3) ^ RK_KEY3 (k2);                            \
  (ok) = (ok) && ((rk_p == (checksum_from_crc >> 8)) || (rk_p == (checksum_from_timestamp >> 8))); \
  RK_UPDATE ((k0), (k1), (k2), rk_p);                                 \
}

// Report a verified candidate. rk_gid and rk_il name the candidate, which may belong to another
// thread of the work-group than the one that verified it.

#define RK_REPORT_S(r0,rk_gid,rk_il)                                  \
{                                                                     \
  if ((r0) == search0)                                                \
  {                                                                   \
    const u32 final_hash_pos = DIGESTS_OFFSET_HOST + 0;               \
                                                                      \
    if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)           \
    {                                                                 \
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, final_hash_pos, (rk_gid), (rk_il), 0, 0); \
    }                                                                 \
  }                                                                   \
}

#define RK_REPORT_M(r0,rk_gid,rk_il)                                  \
{                                                                     \
  const u32 digest_tp0[4] = { (r0), 0, 0, 0 };                        \
                                                                      \
  if (check (digest_tp0,                                              \
             bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, \
             bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, \
             BITMAP_MASK))                                            \
  {                                                                   \
    const u32 digest_pos = find_hash (digest_tp0, DIGESTS_CNT, &digests_buf[DIGESTS_OFFSET_HOST]); \
                                                                      \
    if (digest_pos != (u32) -1)                                       \
    {                                                                 \
      const u32 final_hash_pos = DIGESTS_OFFSET_HOST + digest_pos;    \
                                                                      \
      if (hc_atomic_inc (&hashes_shown[final_hash_pos]) == 0)         \
      {                                                               \
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, final_hash_pos, (rk_gid), (rk_il), 0, 0); \
      }                                                               \
    }                                                                 \
  }                                                                   \
}

// Key schedule of a candidate in a private buffer (dictionary attacks).

#define RK_PW_KEYS_BUF(k0,k1,k2,pwbuf,len)                           \
{                                                                     \
  (k0) = 0x12345678;                                                  \
  (k1) = 0x23456789;                                                  \
  (k2) = 0x34567890;                                                  \
  for (u32 rk_i = 0; rk_i < (len); rk_i++)                            \
  {                                                                   \
    const u32 rk_c = RK_BYTE ((pwbuf)[rk_i / 4], rk_i & 3);           \
    RK_UPDATE ((k0), (k1), (k2), rk_c);                               \
  }                                                                   \
}

#endif // INC_RK_ZIPCRYPTO
