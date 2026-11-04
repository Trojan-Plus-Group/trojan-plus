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
file(WRITE "${_source}" "${_text}")
unset(_text)
