/*
 * RecoverKit ZipCrypto kernels for hashcat 8.0.0: body of the dictionary (-a 0) kernels, included
 * inside the kernel functions of m17200_a0-pure.cl and m17210_a0-pure.cl, once with RK_REPORT set
 * to RK_REPORT_S and once to RK_REPORT_M, after the kernel file has defined RK_VERIFY. The
 * candidate is pws[gid] with rule il_pos applied. Same rounds and queue as inc_rk_zip_a3.cl; the
 * queue verification applies the rule again.
 */

#if ATTACK_MODE == 9

// Association attacks (-a 9) give every thread its own hash, so nothing is shared in the
// work-group: every candidate is verified on the spot, as in hashcat's kernel.

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 l_crc32tab[256];

  for (u64 i = lid; i < 256; i += lsz)
  {
    l_crc32tab[i] = crc32tab[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  GLOBAL_AS const u32 *l_data = esalt_bufs[DIGESTS_OFFSET_HOST].hash.data;

  const u32 search0                 = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0];
  const u32 checksum_size           = esalt_bufs[DIGESTS_OFFSET_HOST].checksum_size;
  const u32 checksum_from_crc       = esalt_bufs[DIGESTS_OFFSET_HOST].hash.checksum_from_crc;
  const u32 checksum_from_timestamp = esalt_bufs[DIGESTS_OFFSET_HOST].hash.checksum_from_timestamp;
  const u32 data_length             = esalt_bufs[DIGESTS_OFFSET_HOST].hash.data_length;

  const u32 h0 = l_data[0];
  const u32 h1 = l_data[1];
  const u32 h2 = l_data[2];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = pws[gid];

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 key0;
    u32 key1;
    u32 key2;

    RK_PW_KEYS_BUF (key0, key1, key2, tmp.i, tmp.pw_len);

    bool ok;

    RK_HEADER (key0, key1, key2, h0, h1, h2, ok);

    if (ok == false) continue;

    u32 r0;
    RK_VERIFY (key0, key1, key2, r0);
    RK_REPORT (r0, gid, il_pos);
  }

#else

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

  const pw_t pw = pws[(active) ? gid : 0];

  const u32 chunk = (u32) RK_MAX ((u64) 1, (u64) (RK_QUEUE * 64) / lsz);

  u32 il_next = (active) ? 0 : (u32) IL_CNT;

  for (;;)
  {
    const u32 il_stop = RK_MIN (il_next + chunk, (u32) IL_CNT);

    u32 il_retry = il_stop;

    #pragma unroll 1
    for (u32 il_pos = il_next; il_pos < il_stop; il_pos++)
    {
      pw_t tmp = pw;

      tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

      u32 key0;
      u32 key1;
      u32 key2;

      RK_PW_KEYS_BUF (key0, key1, key2, tmp.i, tmp.pw_len);

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
      const u32 q_gid = (u32) (gid - lid) + (l_qpos[q] >> 22);
      const u32 q_il  = l_qpos[q] & 0x3fffff;

      pw_t tmp = pws[q_gid];

      tmp.pw_len = apply_rules (rules_buf[q_il].cmds, tmp.i, tmp.pw_len);

      u32 key0;
      u32 key1;
      u32 key2;

      RK_PW_KEYS_BUF (key0, key1, key2, tmp.i, tmp.pw_len);

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

#endif
