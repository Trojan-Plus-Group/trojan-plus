# Chrome transport image: patch build-tree copy only, after recovery patch.
set(_header "${NGTCP2_PATCHED_DIR}/lib/includes/ngtcp2/ngtcp2.h")
file(READ "${_header}" _text)
string(FIND "${_text}" "} ngtcp2_transport_params;" _pos)
if(_pos EQUAL -1)
    message(FATAL_ERROR "ngtcp2 fingerprint patch: transport parameters changed")
endif()
string(REPLACE "} ngtcp2_transport_params;" "  /* Trojan Plus client-only wire profile; never serialized as a field. */\n  uint8_t tp_chrome_fingerprint;\n} ngtcp2_transport_params;" _text "${_text}")
file(WRITE "${_header}" "${_text}")

set(_source "${NGTCP2_PATCHED_DIR}/lib/ngtcp2_conn.c")
file(READ "${_source}" _text)
set(_old [=[  return ngtcp2_transport_params_encode(dest, destlen,
                                        &conn->local.transport_params);]=])
set(_new [=[  /* Keep native encoding unchanged for servers and the "none" profile.
     Crumbling/PING/PADDING remain owned by ngtcp2's Initial machinery. */
  uint8_t wire[1024], *p, *q;
  const uint8_t *cursor, *end, *start;
  struct { const uint8_t *base; size_t len; } fields[32], tmp;
  size_t count = 0, i, j, n, extra;
  uint64_t id, len, grease;
  ngtcp2_ssize encoded;
  ngtcp2_pcg32 random = conn->pcg;

  if (conn->server || !conn->local.transport_params.tp_chrome_fingerprint) {
    return ngtcp2_transport_params_encode(dest, destlen,
                                          &conn->local.transport_params);
  }

  /* Local PRNG copy keeps sizing and encoding calls identical without
     consuming connection randomness or allocating handshake storage. */
  /* ponytail: 1024-byte profile ceiling; grow or allocate if profile expands. */
  encoded = ngtcp2_transport_params_encode(wire, sizeof(wire) - 32,
                                            &conn->local.transport_params);
  if (encoded < 0) {
    return encoded;
  }
  p = wire + encoded;
  p = ngtcp2_put_uvarint(p, 0x3128);
  p = ngtcp2_put_uvarint(p, 4);
  p = ngtcp2_cpymem(p, "ORIG", 4);
  grease = ((uint64_t)ngtcp2_pcg32_rand(&random) << 32) |
           ngtcp2_pcg32_rand(&random);
  grease = 31 * (grease % (UINT64_C(1) << 57)) + 27;
  p = ngtcp2_put_uvarint(p, grease);
  extra = ngtcp2_pcg32_rand_n(&random, 9);
  p = ngtcp2_put_uvarint(p, extra);
  for (i = 0; i < extra; ++i) {
    *p++ = (uint8_t)ngtcp2_pcg32_rand(&random);
  }
  end = p;
  cursor = wire;
  while (cursor < end) {
    start = cursor;
    n = (size_t)1 << (*cursor >> 6);
    if ((size_t)(end - cursor) < n) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    cursor = ngtcp2_get_uvarint(&id, cursor);
    if (cursor == end) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    n = (size_t)1 << (*cursor >> 6);
    if ((size_t)(end - cursor) < n) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    cursor = ngtcp2_get_uvarint(&len, cursor);
    if (len > (uint64_t)(end - cursor) || count == 32) {
      return NGTCP2_ERR_INVALID_ARGUMENT;
    }
    cursor += (size_t)len;
    fields[count].base = start;
    fields[count++].len = (size_t)(cursor - start);
  }
  for (i = count; i > 1; --i) {
    j = ngtcp2_pcg32_rand_n(&random, (uint32_t)i);
    tmp = fields[i - 1];
    fields[i - 1] = fields[j];
    fields[j] = tmp;
  }
  n = (size_t)(end - wire);
  if (dest == NULL) {
    return (ngtcp2_ssize)n;
  }
  if (destlen < n) {
    return NGTCP2_ERR_NOBUF;
  }
  q = dest;
  for (i = 0; i < count; ++i) {
    q = ngtcp2_cpymem(q, fields[i].base, fields[i].len);
  }
  return (ngtcp2_ssize)n;]=])
string(FIND "${_text}" "${_old}" _pos)
if(_pos EQUAL -1)
    message(FATAL_ERROR "ngtcp2 fingerprint patch: local encoder changed")
endif()
string(REPLACE "${_old}" "${_new}" _text "${_text}")
# First-flight scheduling state owns no storage: pending ranges stay in streamfrq.
set(_conn_header "${NGTCP2_PATCHED_DIR}/lib/ngtcp2_conn.h")
file(READ "${_conn_header}" _conn_text)
string(FIND "${_conn_text}" "struct ngtcp2_conn {" _pos)
if(_pos EQUAL -1)
    message(FATAL_ERROR "ngtcp2 fingerprint patch: connection layout changed")
endif()
string(REPLACE "struct ngtcp2_conn {" "struct ngtcp2_conn {\n  uint8_t tp_initial_prepared;" _conn_text "${_conn_text}")
file(WRITE "${_conn_header}" "${_conn_text}")
unset(_conn_text)

set(_old_flight [=[/*
 * conn_crumble_initial_crypto splits CRYPTO frame (*pfrc)->fr.stream]=])
set(_new_flight [=[/* Chrome 156, 2026-11-06: 36 independent primary captures (30 fresh
   browser runs plus 6 supplied captures), not the 160-connection background-
   inclusive sample. CRYPTO count median 14.5, normalized inversions 0.5197.
   Provenance: logs/s3/chrome-primary-2.json, ci/fp/s3_layout.py (external).
   Split the whole queued ClientHello before choosing packet contents. Never
   reorder streamfrq keys: native pop relies on ascending, contiguous offsets.
   Every wire range has its own native frame chain for ACK/loss bookkeeping. */
static int conn_tp_prepare_initial(ngtcp2_conn *conn, ngtcp2_strm *strm) {
  ngtcp2_frame_chain *frc, *frames[NGTCP2_MAX_STREAM_DATACNT];
  ngtcp2_vec data[NGTCP2_MAX_STREAM_DATACNT];
  uint64_t offsets[NGTCP2_MAX_STREAM_DATACNT];
  size_t datacnt, i, j, target, len;
  int rv;

  /* ponytail: one contiguous Initial flight below 16 KiB; larger or fragmented
     submissions retain native crumbling. Extend only with capture evidence. */
  if (strm->tx.offset == 0 || strm->tx.offset >= 16384 ||
      ngtcp2_ksl_len(strm->tx.streamfrq) != 1) {
    return 0;
  }
  frc = ngtcp2_strm_streamfrq_top(strm);
  if (frc->fr.stream.offset != 0 || frc->fr.stream.datacnt != 1 ||
      frc->fr.stream.data[0].len != strm->tx.offset) {
    return 0;
  }

  data[0] = frc->fr.stream.data[0];
  offsets[0] = 0;
  target = 8 + ngtcp2_pcg32_rand_n(&conn->pcg, 13);
  datacnt = 1;
  for (i = 1; i < target; ++i) {
    j = ngtcp2_pcg32_rand_n(&conn->pcg, (uint32_t)datacnt);
    if (data[j].len < 2) {
      continue;
    }
    len = 1 + ngtcp2_pcg32_rand_n(&conn->pcg, (uint32_t)data[j].len - 1);
    offsets[datacnt] = offsets[j] + len;
    ngtcp2_vec_split_at(&data[datacnt++], &data[j], len);
  }

  /* Allocate everything before changing queue ownership. Allocation failure
     leaves the original queued range intact; inserted ranges belong to strm. */
  for (i = 0; i < datacnt; ++i) {
    rv = ngtcp2_frame_chain_stream_datacnt_objalloc_new(
      &frames[i], 1, &conn->frc_objalloc, conn->mem);
    if (rv != 0) {
      for (j = 0; j < i; ++j) {
        ngtcp2_frame_chain_objalloc_del(frames[j], &conn->frc_objalloc, conn->mem);
      }
      return rv;
    }
    frames[i]->fr.stream = (ngtcp2_stream){
      .type = NGTCP2_FRAME_CRYPTO,
      .offset = offsets[i],
      .datacnt = 1,
      .data = frames[i]->fr.stream.data,
    };
    frames[i]->fr.stream.data[0] = data[i];
  }

  ngtcp2_ksl_remove(strm->tx.streamfrq, NULL, &frc->fr.stream.offset);
  ngtcp2_frame_chain_objalloc_del(frc, &conn->frc_objalloc, conn->mem);
  for (i = 0; i < datacnt; ++i) {
    rv = ngtcp2_strm_streamfrq_push(strm, frames[i]);
    if (rv != 0) {
      /* Like native pop, insertion failure is fatal. Do not leak the ranges
         not yet transferred to the queue. */
      for (j = i; j < datacnt; ++j) {
        ngtcp2_frame_chain_objalloc_del(frames[j], &conn->frc_objalloc, conn->mem);
      }
      return rv;
    }
  }
  conn->tp_initial_prepared = 1;
  return 0;
}

static ngtcp2_ssize
conn_tp_crumble_initial(ngtcp2_conn *conn, ngtcp2_frame_chain **pfrc,
                        ngtcp2_vec *data, uint64_t *offsets,
                        ngtcp2_strm *strm, size_t left) {
  ngtcp2_frame_chain *frc, *sent, **tail = pfrc;
  ngtcp2_ksl_it it;
  uint64_t offset;
  size_t datacnt = 0, i, n, len, budget = 50 + ngtcp2_pcg32_rand_n(&conn->pcg, 61);
  size_t pings = 3 + ngtcp2_pcg32_rand_n(&conn->pcg, 6);
  /* Adjacent padding vectors coalesce into one observable run after shuffle. */
  size_t pads = 4 + ngtcp2_pcg32_rand_n(&conn->pcg, 4);
  int rv;

  *pfrc = NULL;
  if (left <= budget + 5) {
    return 0;
  }
  left -= budget;
  while (!ngtcp2_strm_streamfrq_empty(strm) &&
         datacnt < NGTCP2_MAX_STREAM_DATACNT - pings - pads) {
    n = ngtcp2_ksl_len(strm->tx.streamfrq);
    i = ngtcp2_pcg32_rand_n(&conn->pcg, (uint32_t)n);
    it = ngtcp2_ksl_begin(strm->tx.streamfrq);
    for (; i; --i) {
      ngtcp2_ksl_it_next(&it);
    }
    frc = ngtcp2_ksl_it_get(&it);
    assert(frc->next == NULL && frc->fr.stream.datacnt == 1);
    offset = frc->fr.stream.offset;
    len = ngtcp2_pkt_crypto_max_datalen(offset, frc->fr.stream.data[0].len, left);
    if (len == (size_t)-1 || len == 0) {
      break;
    }
    if (len < frc->fr.stream.data[0].len) {
      rv = ngtcp2_frame_chain_stream_datacnt_objalloc_new(
        &sent, 1, &conn->frc_objalloc, conn->mem);
      if (rv != 0) {
        ngtcp2_frame_chain_list_objalloc_del(*pfrc, &conn->frc_objalloc, conn->mem);
        *pfrc = NULL;
        return rv;
      }
      sent->fr.stream = (ngtcp2_stream){
        .type = NGTCP2_FRAME_CRYPTO,
        .offset = offset,
        .datacnt = 1,
        .data = sent->fr.stream.data,
      };
      sent->fr.stream.data[0] = (ngtcp2_vec){
        .base = frc->fr.stream.data[0].base, .len = len,
      };
      /* New key stays strictly inside this range, before its successor.
         update_key allocates nothing; residual bytes never leave the queue. */
      frc->fr.stream.offset += len;
      ngtcp2_ksl_update_key(strm->tx.streamfrq, &offset, &frc->fr.stream.offset);
      ngtcp2_vec_drop(&frc->fr.stream.data[0], len);
    } else {
      ngtcp2_ksl_remove_hint(strm->tx.streamfrq, NULL, &it, &offset);
      sent = frc;
    }
    *tail = sent;
    tail = &sent->next;
    data[datacnt] = sent->fr.stream.data[0];
    offsets[datacnt++] = offset;
    left -= len + 1 + ngtcp2_put_uvarintlen(offset) + ngtcp2_put_uvarintlen(len);
  }
  if (ngtcp2_strm_streamfrq_empty(strm)) {
    conn->tp_initial_prepared = 2;
  }
  if (datacnt == 0) {
    return 0;
  }

  /* Put final-packet slack into interleaved padding, not extra CRYPTO/PING.
     Exact encoded lengths above leave budget + left bytes available. */
  budget += left;
  assert(budget >= pings + pads);
  for (i = 0; i < pings; ++i) {
    offsets[datacnt] = 0;
    data[datacnt++] = (ngtcp2_vec){.base = NULL, .len = 0};
  }
  budget -= pings;
  for (i = pads; i; --i) {
    n = i == 1 ? budget : 1 + ngtcp2_pcg32_rand_n(
      &conn->pcg, (uint32_t)(budget - i + 1));
    offsets[datacnt] = 0;
    data[datacnt++] = (ngtcp2_vec){.base = NULL, .len = n};
    budget -= n;
  }
  /* Native permutation excludes the identity choice; use Fisher-Yates here. */
  for (i = datacnt; i > 1; --i) {
    ngtcp2_vec v;
    uint64_t o;
    n = ngtcp2_pcg32_rand_n(&conn->pcg, (uint32_t)i);
    v = data[i - 1]; data[i - 1] = data[n]; data[n] = v;
    o = offsets[i - 1]; offsets[i - 1] = offsets[n]; offsets[n] = o;
  }
  return (ngtcp2_ssize)datacnt;
}

/*
 * conn_crumble_initial_crypto splits CRYPTO frame (*pfrc)->fr.stream]=])
string(FIND "${_text}" "${_old_flight}" _pos)
if(_pos EQUAL -1)
    message(FATAL_ERROR "ngtcp2 fingerprint patch: Initial crumbling changed")
endif()
string(REPLACE "${_old_flight}" "${_new_flight}" _text "${_text}")
set(_old_dispatch [=[  if (left <= total_crypto_overhead) {
    return 0;
  }]=])
set(_new_dispatch [=[  /* Only fresh, unacknowledged client flight. Permanently retire scheduling
     on recovery or peer response; native pop owns ACK trimming and retries. */
  if (conn->tp_initial_prepared == 1 &&
      (conn->cstat.pto_count || conn->in_pktns->rtb.probe_pkt_left ||
       conn->in_pktns->rtb.largest_acked_tx_pkt_num != -1 ||
       crypto_strm->tx.cont_acked_offset || crypto_strm->tx.acked_offset ||
       (conn->flags & (NGTCP2_CONN_FLAG_RECV_RETRY |
                       NGTCP2_CONN_FLAG_INITIAL_PKT_PROCESSED)))) {
    conn->tp_initial_prepared = 2;
  }
  if (!conn->server && conn->local.transport_params.tp_chrome_fingerprint &&
      conn->tp_initial_prepared != 2 && conn->cstat.pto_count == 0 &&
      !conn->in_pktns->rtb.probe_pkt_left &&
      !(conn->flags & (NGTCP2_CONN_FLAG_RECV_RETRY |
                       NGTCP2_CONN_FLAG_INITIAL_PKT_PROCESSED)) &&
      conn->in_pktns->rtb.largest_acked_tx_pkt_num == -1 &&
      crypto_strm->tx.cont_acked_offset == 0 && !crypto_strm->tx.acked_offset) {
    if (!conn->tp_initial_prepared &&
        conn->in_pktns->tx.last_pkt_num == conn->local.settings.initial_pkt_num - 1) {
      rv = conn_tp_prepare_initial(conn, crypto_strm);
      if (rv != 0) {
        return rv;
      }
    }
    if (conn->tp_initial_prepared) {
      return conn_tp_crumble_initial(conn, pfrc, data, offsets, crypto_strm, left);
    }
  }

  if (left <= total_crypto_overhead) {
    return 0;
  }]=])
string(FIND "${_text}" "${_old_dispatch}" _pos)
if(_pos EQUAL -1)
    message(FATAL_ERROR "ngtcp2 fingerprint patch: Initial dispatch changed")
endif()
string(REPLACE "${_old_dispatch}" "${_new_dispatch}" _text "${_text}")

# Recovery and unsupported flight shapes retain native crumbling unchanged.
file(WRITE "${_source}" "${_text}")
unset(_text)
