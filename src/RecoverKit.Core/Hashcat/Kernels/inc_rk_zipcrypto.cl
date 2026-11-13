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
  RK_PW_WORD ((k0), (k1), (k2), (w0),  0, (len));                     \
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

// The brute-force (-a 3) kernel body. The kernel defines RK_VERIFY (k0, k1, k2, r0): the full check
// of a candidate whose keys after the 12-byte header are k0..k2, leaving the value compared with the
// digest in r0. REPORT is RK_REPORT_S or RK_REPORT_M.
//
// The candidate loop runs in rounds. In a round each thread tests up to `chunk` candidates and queues
// those that pass the header check. The queue holds about twice what a round is expected to produce;
// should it still fill up, a thread starts its next round at the first candidate it could not queue
// (verifying inline instead would put the long verification loop into the candidate loop, and on
// Apple GPUs that alone halves the speed; candidates queued after that one are tested twice, which
// is harmless). After each round all threads of the work-group
// verify the queue together. Every thread takes part in the barriers, also those past GID_CNT, which
// only help with the verification. The candidate loop must not be unrolled (register pressure).

#define RK_A3_BODY(REPORT)                                            \
  const u64 gid = get_global_id (0);                                  \
  const u64 lid = get_local_id (0);                                   \
  const u64 lsz = get_local_size (0);                                 \
                                                                      \
  LOCAL_VK u32 l_crc32tab[256];                                       \
                                                                      \
  for (u64 i = lid; i < 256; i += lsz)                                \
  {                                                                   \
    l_crc32tab[i] = crc32tab[i];                                      \
  }                                                                   \
                                                                      \
  LOCAL_VK u32 l_data[MAX_LOCAL];                                     \
                                                                      \
  for (u64 i = lid; i < MAX_LOCAL; i += lsz)                          \
  {                                                                   \
    l_data[i] = esalt_bufs[DIGESTS_OFFSET_HOST].hash.data[i];         \
  }                                                                   \
                                                                      \
  LOCAL_VK u32 l_qpos[RK_QUEUE];                                      \
  LOCAL_VK u32 l_qcnt;                                                \
  LOCAL_VK u32 l_more;                                                \
                                                                      \
  if (lid == 0) l_qcnt = 0;                                           \
                                                                      \
  SYNC_THREADS ();                                                    \
                                                                      \
  const u32 search0                 = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0]; \
  const u32 checksum_size           = esalt_bufs[DIGESTS_OFFSET_HOST].checksum_size; \
  const u32 checksum_from_crc       = esalt_bufs[DIGESTS_OFFSET_HOST].hash.checksum_from_crc; \
  const u32 checksum_from_timestamp = esalt_bufs[DIGESTS_OFFSET_HOST].hash.checksum_from_timestamp; \
  const u32 data_length             = esalt_bufs[DIGESTS_OFFSET_HOST].hash.data_length; \
                                                                      \
  const u32 h0 = l_data[0];                                           \
  const u32 h1 = l_data[1];                                           \
  const u32 h2 = l_data[2];                                           \
                                                                      \
  const bool active = (gid < GID_CNT);                                \
                                                                      \
  const u32 pw_len = (active) ? pws[gid].pw_len : 0;                  \
  const u32 w0l    = (active) ? pws[gid].i[0] : 0;                    \
  const u32 w1     = (active) ? pws[gid].i[1] : 0;                    \
  const u32 w2     = (active) ? pws[gid].i[2] : 0;                    \
  const u32 w3     = (active) ? pws[gid].i[3] : 0;                    \
                                                                      \
  /* about RK_QUEUE / 2 survivors per round at the usual 1 in 128 */  \
  const u32 chunk = (u32) RK_MAX ((u64) 1, (u64) (RK_QUEUE * 64) / lsz); \
                                                                      \
  u32 il_next = (active) ? 0 : (u32) IL_CNT;                          \
                                                                      \
  for (;;)                                                            \
  {                                                                   \
    const u32 il_stop = RK_MIN (il_next + chunk, (u32) IL_CNT);       \
                                                                      \
    u32 il_retry = il_stop;                                           \
                                                                      \
    _Pragma ("unroll 1")                                              \
    for (u32 il_pos = il_next; il_pos < il_stop; il_pos++)            \
    {                                                                 \
      const u32 w0 = w0l | words_buf_r[il_pos];                       \
                                                                      \
      u32 key0;                                                       \
      u32 key1;                                                       \
      u32 key2;                                                       \
                                                                      \
      RK_PW_KEYS (key0, key1, key2, w0, w1, w2, w3, pw_len, pws[gid].i); \
                                                                      \
      bool ok;                                                        \
                                                                      \
      RK_HEADER (key0, key1, key2, h0, h1, h2, ok);                   \
                                                                      \
      if (ok == false) continue;                                      \
                                                                      \
      const u32 slot = RK_LOCAL_INC (&l_qcnt);                        \
                                                                      \
      if (slot < RK_QUEUE)                                            \
      {                                                               \
        l_qpos[slot] = ((u32) lid << 22) | il_pos;                    \
      }                                                               \
      else                                                            \
      {                                                               \
        il_retry = RK_MIN (il_retry, il_pos);                         \
      }                                                               \
    }                                                                 \
                                                                      \
    il_next = il_retry;                                               \
                                                                      \
    if (lid == 0) l_more = 0;                                         \
                                                                      \
    SYNC_THREADS ();                                                  \
                                                                      \
    if (il_next < IL_CNT) l_more = 1;                                 \
                                                                      \
    const u32 qn = RK_MIN (l_qcnt, (u32) RK_QUEUE);                   \
                                                                      \
    for (u32 q = (u32) lid; q < qn; q += (u32) lsz)                   \
    {                                                                 \
      /* the queue holds only the position: the keys are computed again */ \
      const u32 q_gid = (u32) (gid - lid) + (l_qpos[q] >> 22);        \
      const u32 q_il  = l_qpos[q] & 0x3fffff;                         \
                                                                      \
      u32 key0;                                                       \
      u32 key1;                                                       \
      u32 key2;                                                       \
                                                                      \
      RK_PW_KEYS (key0, key1, key2, pws[q_gid].i[0] | words_buf_r[q_il], pws[q_gid].i[1], pws[q_gid].i[2], pws[q_gid].i[3], pws[q_gid].pw_len, pws[q_gid].i); \
                                                                      \
      bool ok;                                                        \
                                                                      \
      RK_HEADER (key0, key1, key2, h0, h1, h2, ok);                   \
                                                                      \
      u32 r0;                                                         \
      RK_VERIFY (key0, key1, key2, r0);                               \
      REPORT (r0, q_gid, q_il);                                       \
    }                                                                 \
                                                                      \
    SYNC_THREADS ();                                                  \
                                                                      \
    const u32 more = l_more;                                          \
                                                                      \
    if (lid == 0) l_qcnt = 0;                                         \
                                                                      \
    SYNC_THREADS ();                                                  \
                                                                      \
    if (more == 0) break;                                             \
  }

#endif // INC_RK_ZIPCRYPTO
