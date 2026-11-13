/*
 * RecoverKit ZipCrypto kernels for hashcat 8.0.0: body of the brute-force (-a 3) kernels, included
 * inside the kernel functions of m17200_a3-pure.cl and m17210_a3-pure.cl, once with RK_REPORT set
 * to RK_REPORT_S and once to RK_REPORT_M. The kernel file defines RK_VERIFY (k0, k1, k2, r0): the
 * full check of a candidate whose keys after the 12-byte header are k0..k2, leaving the value to
 * compare with the digest in r0. Helpers, settings and the license are in inc_rk_zipcrypto.cl.
 *
 * The body is plain code rather than one big macro: Apple's OpenCL compiler ran the same code at
 * less than half the speed when it came from a macro.
 *
 * The candidate loop runs in rounds. In a round each thread tests up to `chunk` candidates and
 * queues those that pass the header check. The queue holds about twice what a round is expected to
 * produce; should it still fill up, a thread starts its next round at the first candidate it could
 * not queue (candidates queued after that one are tested twice, which is harmless). Verifying
 * inline instead puts the long verification loop into the candidate loop, which cost half the speed
 * on the Apple GPU. After each round all threads of the work-group verify the queue together, one
 * candidate each, with the keys computed again from the position. Every thread takes part in the
 * barriers, also those past GID_CNT, which only help with the verification.
 */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 l_crc32tab[256];

  for (u64 i = lid; i < 256; i += lsz)
  {
    l_crc32tab[i] = crc32tab[i];
  }

  LOCAL_VK u32 l_data[MAX_LOCAL];

  for (u64 i = lid; i < MAX_LOCAL; i += lsz)
  {
    l_data[i] = esalt_bufs[DIGESTS_OFFSET_HOST].hash.data[i];
  }

  LOCAL_VK u32 l_qpos[RK_QUEUE];
  LOCAL_VK u32 l_qcnt;
  LOCAL_VK u32 l_more;

  if (lid == 0) l_qcnt = 0;

  SYNC_THREADS ();

  const u32 search0                 = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0];
  const u32 checksum_size           = esalt_bufs[DIGESTS_OFFSET_HOST].checksum_size;
  const u32 checksum_from_crc       = esalt_bufs[DIGESTS_OFFSET_HOST].hash.checksum_from_crc;
  const u32 checksum_from_timestamp = esalt_bufs[DIGESTS_OFFSET_HOST].hash.checksum_from_timestamp;
  const u32 data_length             = esalt_bufs[DIGESTS_OFFSET_HOST].hash.data_length;

  const u32 h0 = l_data[0];
  const u32 h1 = l_data[1];
  const u32 h2 = l_data[2];

  const bool active = (gid < GID_CNT);

  const u32 pw_len = (active) ? pws[gid].pw_len : 0;
  const u32 w0l    = (active) ? pws[gid].i[0] : 0;
  const u32 w1     = (active) ? pws[gid].i[1] : 0;
  const u32 w2     = (active) ? pws[gid].i[2] : 0;
  const u32 w3     = (active) ? pws[gid].i[3] : 0;

  /* hashcat puts the first 1-4 characters (the amplifier, il_pos) in words_buf_r and the rest */
  /* in pws[gid], with zero bytes where the other part goes. The bytes that are zero in every   */
  /* w0l of the work-group come from words_buf_r alone, so the keys after them depend on il_pos */
  /* only and are computed once per work-group.                                                 */
  u32 pfx = 0;

  #if RK_AMP_CACHE
  LOCAL_VK u32 l_pk0[RK_PFX];
  LOCAL_VK u32 l_pk1[RK_PFX];
  LOCAL_VK u32 l_pk2[RK_PFX];
  LOCAL_VK u32 l_w0or;

  if (lid == 0) l_w0or = 0;

  SYNC_THREADS ();

  if (active && w0l != 0) RK_LOCAL_OR (&l_w0or, w0l);

  SYNC_THREADS ();

  const u32 w0or = l_w0or;

  if (IL_CNT <= RK_PFX)
  {
    if ((w0or & 0x000000ff) == 0) pfx = 1;
    if ((w0or & 0x0000ffff) == 0) pfx = 2;
    if ((w0or & 0x00ffffff) == 0) pfx = 3;
    if (w0or == 0)                pfx = 4;
  }

  if (pfx > 0)
  {
    for (u32 i = (u32) lid; i < IL_CNT; i += (u32) lsz)
    {
      const u32 wr = words_buf_r[i];
      u32 k0 = 0x12345678;
      u32 k1 = 0x23456789;
      u32 k2 = 0x34567890;
      for (u32 b = 0; b < pfx; b++) RK_UPDATE (k0, k1, k2, RK_BYTE (wr, b));
      l_pk0[i] = k0;
      l_pk1[i] = k1;
      l_pk2[i] = k2;
    }
  }

  SYNC_THREADS ();
  #endif

  /* a password shorter than the shared part takes the full key schedule */
  const u32 from = (pw_len >= pfx) ? pfx : 0;

  /* about RK_QUEUE / 2 survivors per round at the usual 1 in 128 */
  const u32 chunk = (u32) RK_MAX ((u64) 1, (u64) (RK_QUEUE * 64) / lsz);

  u32 il_next = (active) ? 0 : (u32) IL_CNT;

  for (;;)
  {
    const u32 il_stop = RK_MIN (il_next + chunk, (u32) IL_CNT);

    u32 il_retry = il_stop;

    #pragma unroll 1
    for (u32 il_pos = il_next; il_pos < il_stop; il_pos++)
    {
      const u32 w0 = w0l | words_buf_r[il_pos];

      u32 key0;
      u32 key1;
      u32 key2;

      #if RK_AMP_CACHE
      if (from > 0)
      {
        key0 = l_pk0[il_pos];
        key1 = l_pk1[il_pos];
        key2 = l_pk2[il_pos];
      }
      else
      #endif
      {
        key0 = 0x12345678;
        key1 = 0x23456789;
        key2 = 0x34567890;
      }

      RK_PW_TAIL (key0, key1, key2, w0, w1, w2, w3, pw_len, pws[gid].i, from);

      bool ok;

      RK_HEADER (key0, key1, key2, h0, h1, h2, ok);

      if (ok == false) continue;

      const u32 slot = RK_LOCAL_INC (&l_qcnt);

      if (slot < RK_QUEUE)
      {
        l_qpos[slot] = ((u32) lid << 22) | il_pos;
      }
      else
      {
        il_retry = RK_MIN (il_retry, il_pos);
      }
    }

    il_next = il_retry;

    if (lid == 0) l_more = 0;

    SYNC_THREADS ();

    if (il_next < IL_CNT) l_more = 1;

    const u32 qn = RK_MIN (l_qcnt, (u32) RK_QUEUE);

    for (u32 q = (u32) lid; q < qn; q += (u32) lsz)
    {
      /* the queue holds only the position: the keys are computed again */
      const u32 q_gid = (u32) (gid - lid) + (l_qpos[q] >> 22);
      const u32 q_il  = l_qpos[q] & 0x3fffff;

      u32 key0;
      u32 key1;
      u32 key2;

      RK_PW_KEYS (key0, key1, key2, pws[q_gid].i[0] | words_buf_r[q_il], pws[q_gid].i[1], pws[q_gid].i[2], pws[q_gid].i[3], pws[q_gid].pw_len, pws[q_gid].i);

      bool ok;

      RK_HEADER (key0, key1, key2, h0, h1, h2, ok);

      u32 r0;
      RK_VERIFY (key0, key1, key2, r0);
      RK_REPORT (r0, q_gid, q_il);
    }

    SYNC_THREADS ();

    const u32 more = l_more;

    if (lid == 0) l_qcnt = 0;

    SYNC_THREADS ();

    if (more == 0) break;
  }
