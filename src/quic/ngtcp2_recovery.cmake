# Patch the build-tree copy only; keep the ngtcp2 submodule unchanged.
set(_conn_source "${NGTCP2_PATCHED_DIR}/lib/ngtcp2_conn.c")
file(READ "${_conn_source}" _conn)
set(_recv_end "  conn_restart_timer_on_read(conn, ts);\n\n  ngtcp2_qlog_metrics_updated(&conn->qlog, &conn->cstat);\n\n  return conn->state == NGTCP2_CS_DRAINING ? NGTCP2_ERR_DRAINING")
set(_recovery_recv [=[  /* A returning authenticated peer can reach us while our download waits
     for a backed-off PTO. Grant the normal two-packet PTO probe allowance
     once per ACK-progress epoch, not once per incoming packet. Restart PTO
     backoff at the real receive timestamp; preserve cwnd and RTT estimates.
     Clear stale pacing debt so these bounded recovery probes can leave now. */
  if (conn->server && hd.type == NGTCP2_PKT_1RTT && require_ack &&
      !conn->cstat.peer_return_probe_used && conn->cstat.pto_count > 0 &&
      pktns->rtb.num_retransmittable) {
    conn->cstat.peer_return_probe_used = 1;
    conn->cstat.pto_count = 0;
    conn->cstat.loss_detection_timer = ts;
    rv = ngtcp2_conn_on_loss_detection_timer(conn, ts);
    if (rv != 0) {
      return rv;
    }
    conn->tx.pacing.next_ts = UINT64_MAX;
    conn->tx.pacing.compensation = 0;
    ngtcp2_log_info(&conn->log, NGTCP2_LOG_EVENT_LDC,
                   "peer return resumed backed-off PTO probes");
  }

  conn_restart_timer_on_read(conn, ts);

  ngtcp2_qlog_metrics_updated(&conn->qlog, &conn->cstat);

  return conn->state == NGTCP2_CS_DRAINING ? NGTCP2_ERR_DRAINING]=])
string(FIND "${_conn}" "${_recv_end}" _recv_pos REVERSE)
if(_recv_pos EQUAL -1)
    message(FATAL_ERROR "ngtcp2 recovery patch no longer matches; review upstream packet handling")
endif()
string(SUBSTRING "${_conn}" 0 ${_recv_pos} _prefix)
string(LENGTH "${_recv_end}" _recv_len)
math(EXPR _suffix_pos "${_recv_pos} + ${_recv_len}")
string(SUBSTRING "${_conn}" ${_suffix_pos} -1 _suffix)
set(_conn "${_prefix}${_recovery_recv}${_suffix}")
string(REPLACE "  cstat->pto_count = 0;" "  cstat->pto_count = 0;\n  cstat->peer_return_probe_used = 0;" _conn "${_conn}")
file(WRITE "${_conn_source}" "${_conn}")
unset(_conn)

# Re-arm only when a retransmittable packet is ACKed (including a data probe).
# Acknowledging a pure PING must not refresh this allowance.
set(_stat_source "${NGTCP2_PATCHED_DIR}/lib/ngtcp2_conn_stat.h")
file(READ "${_stat_source}" _stat)
string(FIND "${_stat}" "size_t pto_count;" _pto_pos)
if(_pto_pos EQUAL -1)
    message(FATAL_ERROR "ngtcp2 recovery patch no longer matches PTO statistics")
endif()
string(REPLACE "size_t pto_count;" "size_t pto_count;\n  int peer_return_probe_used;" _stat "${_stat}")
file(WRITE "${_stat_source}" "${_stat}")

set(_rtb_source "${NGTCP2_PATCHED_DIR}/lib/ngtcp2_rtb.c")
file(READ "${_rtb_source}" _rtb)
string(FIND "${_rtb}" "  ngtcp2_rst_update_rate_sample(rtb->rst, ent, ts);" _ack_pos)
if(_ack_pos EQUAL -1)
    message(FATAL_ERROR "ngtcp2 recovery patch no longer matches ACK progress handling")
endif()
string(REPLACE "  ngtcp2_rst_update_rate_sample(rtb->rst, ent, ts);" "  if (ent->flags & NGTCP2_RTB_ENTRY_FLAG_RETRANSMITTABLE) {\n    cstat->pto_count = 0;\n    cstat->peer_return_probe_used = 0;\n  }\n  ngtcp2_rst_update_rate_sample(rtb->rst, ent, ts);" _rtb "${_rtb}")
file(WRITE "${_rtb_source}" "${_rtb}")
