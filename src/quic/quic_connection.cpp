/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

// Preserve historical logical lines for log/allocator metadata and OFF object equality.
#include "quic_connection.h"
#include "core/utils.h"

#include <chrono>
#if TROJAN_QUIC_STATS
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#endif
#line 15
#include "mem/memallocator.h"

static void *tj_ngtcp2_malloc(size_t size, void *user_data) {
    (void)user_data;
    return tp::get_tj_mem_allocator().malloc(size, "ngtcp2", 0);
}

static void tj_ngtcp2_free(void *ptr, void *user_data) {
    (void)user_data;
    tp::get_tj_mem_allocator().free(ptr);
}

static void *tj_ngtcp2_calloc(size_t nmemb, size_t size, void *user_data) {
    (void)user_data;
    size_t real_size = nmemb * size;
    void *ptr = tp::get_tj_mem_allocator().malloc(real_size, "ngtcp2", 0);
    if (ptr) {
        std::memset(ptr, 0, real_size);
    }
    return ptr;
}

static void *tj_ngtcp2_realloc(void *ptr, size_t size, void *user_data) {
    (void)user_data;
    return tp::get_tj_mem_allocator().realloc(ptr, size, "ngtcp2", 0);
}

static const ngtcp2_mem tj_ngtcp2_mem = {
    nullptr,
    tj_ngtcp2_malloc,
    tj_ngtcp2_free,
    tj_ngtcp2_calloc,
    tj_ngtcp2_realloc
};
#include <cstddef>
#include <cstring>

#include "h1_upstream/quic_to_http3_connect.h"
#include "h1_upstream/quic_session_upstream.h"
#include "core/config.h"

#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <openssl/rand.h>
#include <openssl/x509.h>

#include "core/log.h"
#include "quic_endpoint.h"
#include "quic_tls_ctx.h"
#include "core/utils.h"

// ---- helpers ----------------------------------------------------------------
#if TROJAN_QUIC_STATS

namespace {

// Cached once. Unset or empty means off: callers do one bool check and nothing else.
bool quic_stats_enabled() {
    static const bool enabled = [] {
        const char* path = std::getenv("TROJAN_QUIC_STATS");
        return path != nullptr && path[0] != '\0';
    }();
    return enabled;
}

// bbr is the historical default. Unknown values warn once and stay on BBR.
ngtcp2_cc_algo quic_cc_from_env() {
    static const ngtcp2_cc_algo algo = [] {
        const char* value = std::getenv("TROJAN_QUIC_CC");
        if (value == nullptr || value[0] == '\0' || std::strcmp(value, "bbr") == 0) {
            return NGTCP2_CC_ALGO_BBR;
        }
        if (std::strcmp(value, "cubic") == 0) {
            return NGTCP2_CC_ALGO_CUBIC;
        }
        if (std::strcmp(value, "reno") == 0) {
            return NGTCP2_CC_ALGO_RENO;
        }
        _log_with_date_time(tp::string("TROJAN_QUIC_CC unknown value, keeping BBR: ") + value, Log::WARN);
        return NGTCP2_CC_ALGO_BBR;
    }();
    return algo;
}

// One process-wide CSV. Connection methods run on a single io_context thread.
class QuicStatsFile {
  public:
    void write(const char* line, bool force_flush) {
        if (!ensure_open()) {
            return;
        }
        m_out << line << '\n';
        const auto now = std::chrono::steady_clock::now();
        if (force_flush || now - m_last_flush >= std::chrono::seconds(1)) {
            m_out.flush();
            m_last_flush = now;
        }
    }

  private:
    bool ensure_open() {
        if (m_out.is_open()) {
            return true;
        }
        if (m_failed) {
            return false;
        }
        const char* path = std::getenv("TROJAN_QUIC_STATS");
        if (path == nullptr || path[0] == '\0') {
            m_failed = true;
            return false;
        }
        bool nonempty = false;
        {
            std::ifstream existing(path, std::ios::binary);
            nonempty = existing.good() && existing.peek() != std::char_traits<char>::eof();
        }
        m_out.open(path, std::ios::app);
        if (!m_out) {
            m_failed = true;
            _log_with_date_time(tp::string("TROJAN_QUIC_STATS open failed: ") + path, Log::WARN);
            return false;
        }
        if (!nonempty) {
            m_out << "t_ms,role,cwnd,ssthresh,bytes_in_flight,latest_rtt,min_rtt,smoothed_rtt,rttvar,"
                     "pkt_sent,bytes_sent,pkt_recv,bytes_recv,pkt_lost,bytes_lost,pkt_discarded,"
                     "max_data_left,streams_bidi_left,max_stream_data_left,app_queue_bytes,"
                     "stream_data_blocked,write_more,zero_len_send,udp_send_errors,"
                     "pump_other,data_other,vecs_other,udp_sent_other,"
                     "pump_ack,data_ack,vecs_ack,udp_sent_ack,"
                     "pump_retry,data_retry,vecs_retry,udp_sent_retry,"
                     "pump_loss,data_loss,vecs_loss,udp_sent_loss,"
                     "pump_application,data_application,vecs_application,udp_sent_application,"
                     "pump_flow,data_flow,vecs_flow,udp_sent_flow,"
                     "retry_arms,retry_expires_bytes,retry_expires_empty,open_packet_gap_max_ms,"
                     "zero_write_expiry_ms,zero_write_expiry_max_ms\n";
        }
        m_last_flush = std::chrono::steady_clock::now();
        return true;
    }

    std::ofstream m_out;
    std::chrono::steady_clock::time_point m_last_flush{};
    bool m_failed{false};
};

QuicStatsFile& quic_stats_file() {
    static QuicStatsFile file;
    return file;
}

} // namespace
#endif
#line 68

static ngtcp2_tstamp now_nanos() {
    return static_cast<ngtcp2_tstamp>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            QuicClock::now().time_since_epoch())
            .count());
}

static void fill_sockaddr_union(const boost::asio::ip::udp::endpoint& ep,
                                ngtcp2_sockaddr_union& su, ngtcp2_socklen& len) {
    std::memset(&su, 0, sizeof(su));
    if (ep.address().is_v4()) {
        su.in.sin_family = AF_INET;
        su.in.sin_port   = htons(ep.port());
        auto bytes       = ep.address().to_v4().to_bytes();
        std::memcpy(&su.in.sin_addr, bytes.data(), 4);
        len = sizeof(ngtcp2_sockaddr_in);
    } else {
        su.in6.sin6_family = AF_INET6;
        su.in6.sin6_port   = htons(ep.port());
        auto bytes         = ep.address().to_v6().to_bytes();
        std::memcpy(&su.in6.sin6_addr, bytes.data(), 16);
        len = sizeof(ngtcp2_sockaddr_in6);
    }
}

// ---- static callbacks -------------------------------------------------------

ngtcp2_conn* QuicConnection::get_conn_cb(ngtcp2_crypto_conn_ref* ref) {
    return static_cast<QuicConnection*>(ref->user_data)->m_conn;
}

int QuicConnection::cb_recv_client_initial(ngtcp2_conn* conn, const ngtcp2_cid* dcid,
                                           void* /*user_data*/) {
    return ngtcp2_crypto_recv_client_initial_cb(conn, dcid, nullptr);
}

int QuicConnection::cb_recv_crypto_data(ngtcp2_conn* conn, ngtcp2_encryption_level level,
                                        uint64_t offset, const uint8_t* data, size_t datalen,
                                        void* user_data) {
    int rv = ngtcp2_crypto_recv_crypto_data_cb(conn, level, offset, data, datalen, nullptr);
    if (rv != 0) {
        auto* self = static_cast<QuicConnection*>(user_data);
        long error = SSL_get_verify_result(self->m_ssl);
        if (error == X509_V_ERR_HOSTNAME_MISMATCH || error == X509_V_ERR_IP_ADDRESS_MISMATCH) {
            _log_with_date_time("QUIC: certificate hostname verification failed (hostname/IP SAN mismatch)",
                                Log::ERROR);
        }
    }
    return rv;
}

int QuicConnection::cb_handshake_completed(ngtcp2_conn* /*conn*/, void* user_data) {
    static_cast<QuicConnection*>(user_data)->on_handshake_completed_impl();
    return 0;
}

int QuicConnection::cb_recv_stream_data(ngtcp2_conn* /*conn*/, uint32_t flags, int64_t stream_id,
                                        uint64_t /*offset*/, const uint8_t* data, size_t datalen,
                                        void* user_data, void* /*stream_user_data*/) {

    auto* self = static_cast<QuicConnection*>(user_data);
    bool fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;

    // extend connection window at very first to make sure connection will be never stuck
    self->conn_extend_window(datalen);

    auto it = self->m_stream_handlers.find(stream_id);
    if (it != self->m_stream_handlers.end()) {
        // server will use handlers
        auto handler = it->second;
        handler->on_stream_data(data, datalen, fin);
    } else if (self->on_stream_data_cb) {
        // client will use cb 
        self->on_stream_data_cb(stream_id, data, datalen, fin);
    }

    return 0;
}

int QuicConnection::cb_acked_stream_data_offset(ngtcp2_conn* /*conn*/, int64_t stream_id,
                                                uint64_t offset, uint64_t datalen,
                                                void* user_data, void* /*stream_user_data*/) {
    auto* self = static_cast<QuicConnection*>(user_data);

    QUIC_STAT(
        if (self->m_stats.m_stats_enabled && self->m_in_read_pkt) self->m_stats.m_stats_read_ack = true;
        StatsReasonScope reason(*self, SendReason::ack);
    )
#line 153
    // Notify H3 engine to free internal buffers and release backpressure.
    if (self->m_h3) {
        self->m_h3->acked_stream_data(stream_id, static_cast<std::size_t>(datalen));
    }

    // Release ACKed buffers maintained at connection level
    auto it_buf = self->m_conn_unacked_bufs.find(stream_id);
    if (it_buf != self->m_conn_unacked_bufs.end()) {
        auto& bufs = it_buf->second;
        uint64_t ack_start = offset;
        uint64_t ack_end = offset + datalen;

        auto it = bufs->buffers.begin();
        while (it != bufs->buffers.end()) {
            auto& buf = *it;
            uint64_t buf_start = buf->m_ack_offset;
            uint64_t buf_end = buf_start + buf->m_sending_offset;

            // Calculate intersection
            uint64_t intersect_start = std::max(ack_start, buf_start);
            uint64_t intersect_end = std::min(ack_end, buf_end);

            if (intersect_start < intersect_end) {
                buf->m_bytes_acked += (intersect_end - intersect_start);
            }

            if (buf->m_buf && buf->m_sending_offset >= buf->m_buf->size() && buf->m_bytes_acked >= buf->m_buf->size()) {
                _log_with_date_time_ALL("cb_acked_stream_data_offset stream_id=" + tp::to_string(stream_id) + 
                    " buf_size=" + tp::to_string(buf->m_buf->size()));

                buf->cancel_timer();
                it = bufs->buffers.erase(it);
            } else {
                ++it;
            }
        }
    }

    return 0;
}

int QuicConnection::cb_stream_open(ngtcp2_conn* /*conn*/, int64_t stream_id, void* user_data) {
    auto* self = static_cast<QuicConnection*>(user_data);
    if (self->on_stream_open_cb) {
        self->on_stream_open_cb(stream_id);
    }
    return 0;
}

int QuicConnection::cb_stream_close(ngtcp2_conn* /*conn*/, uint32_t /*flags*/, int64_t stream_id,
                                    uint64_t app_error_code, void* user_data,
                                    void* /*stream_user_data*/) {
    auto* self = static_cast<QuicConnection*>(user_data);

    if (self->m_h3) {
        self->m_h3->close_stream(stream_id, app_error_code);
    }

    auto it = self->m_stream_handlers.find(stream_id);
    if (it != self->m_stream_handlers.end()) {
        auto handler = it->second;
        handler->on_stream_close();
        self->m_stream_handlers.erase(stream_id);
    } else if (self->on_stream_close_cb) {
        self->on_stream_close_cb(stream_id);
    }

    self->fail_unacked_buffers(stream_id, boost::asio::error::broken_pipe);

    if (!ngtcp2_conn_is_local_stream2(self->m_conn, stream_id)) {
        if (ngtcp2_is_bidi_stream(stream_id)) {
            ngtcp2_conn_extend_max_streams_bidi(self->m_conn, 1);
        } else {
            ngtcp2_conn_extend_max_streams_uni(self->m_conn, 1);
        }
        if (!self->m_in_read_pkt && !self->m_in_pump_write) {
            self->on_pump_write("cb_stream_close");
        }
    }

    return 0;
}

int QuicConnection::cb_extend_max_stream_data(ngtcp2_conn* /*conn*/, int64_t stream_id,
                                              uint64_t max_data, void* user_data,
                                              void* /*stream_user_data*/) {
    auto* self = static_cast<QuicConnection*>(user_data);
    self->on_extend_max_stream_data(stream_id, max_data);
    return 0;
}

void QuicConnection::cb_rand(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* /*ctx*/) {
    RAND_bytes(dest, static_cast<int>(destlen));
}

int QuicConnection::cb_get_new_connection_id(ngtcp2_conn* /*conn*/, ngtcp2_cid* cid,
                                             ngtcp2_stateless_reset_token* token,
                                             size_t cidlen, void* user_data) {
    cid->datalen = cidlen;
    RAND_bytes(cid->data, static_cast<int>(cidlen));

    auto* self = static_cast<QuicConnection*>(user_data);

    // Derive a deterministic Stateless Reset token from the new CID and the
    // per-process endpoint secret.  This token is advertised to the peer via
    // NEW_CONNECTION_ID, so when we later send a Stateless Reset (using the
    // same derivation), the peer will recognise and honour it.
    const uint8_t* secret = self->m_endpoint.stateless_reset_secret();
    if (ngtcp2_crypto_generate_stateless_reset_token(
            reinterpret_cast<uint8_t*>(token),
            secret, kStatelessResetSecretLen, cid) != 0) {
        // Fallback to random on unexpected failure (should never happen).
        RAND_bytes(reinterpret_cast<uint8_t*>(token),
                           NGTCP2_STATELESS_RESET_TOKENLEN);
    }

    if (self->on_new_connection_id_cb) {
        self->on_new_connection_id_cb(cid);
    }

    return 0;
}

int QuicConnection::cb_update_key(ngtcp2_conn* conn, uint8_t* rx_secret, uint8_t* tx_secret,
                                  ngtcp2_crypto_aead_ctx* rx_aead_ctx, uint8_t* rx_iv,
                                  ngtcp2_crypto_aead_ctx* tx_aead_ctx, uint8_t* tx_iv,
                                  const uint8_t* current_rx_secret,
                                  const uint8_t* current_tx_secret, size_t secretlen,
                                  void* /*user_data*/) {
    return ngtcp2_crypto_update_key_cb(conn, rx_secret, tx_secret, rx_aead_ctx, rx_iv,
                                       tx_aead_ctx, tx_iv, current_rx_secret, current_tx_secret,
                                       secretlen, nullptr);
}

int QuicConnection::cb_extend_max_local_streams_bidi(ngtcp2_conn* /*conn*/,
                                                     uint64_t max_streams,
                                                     void* user_data) {
    auto* self = static_cast<QuicConnection*>(user_data);
    _log_with_date_time("cb_extend_max_local_streams_bidi: max_streams=" + tp::to_string(max_streams), Log::ALL);
    if (self->on_extend_max_streams_cb) {
        boost::asio::post(self->m_endpoint.io_context(), [self = self->shared_from_this()]() {
            if (self->on_extend_max_streams_cb && !self->m_closed) {
                QUIC_STAT(
                    StatsReasonScope reason(*self, SendReason::flow);
                )
#line 295
                self->on_extend_max_streams_cb();
            }
        });
    }
    return 0;
}

// ---- constructor / destructor -----------------------------------------------

QuicConnection::QuicConnection(QuicEndpoint& endpoint, std::shared_ptr<QuicTlsCtx> tls_ctx,
                               const boost::asio::ip::udp::endpoint& peer)
    : m_endpoint(endpoint),
      m_tls_ctx(std::move(tls_ctx)),
      m_peer(peer),
      m_loss_timer(endpoint.io_context()),
      m_write_buf(std::max<std::size_t>(NGTCP2_MAX_UDP_PAYLOAD_SIZE, 1250)),
      m_in_read_pkt(false),
      m_in_pump_write(false) {
    QUIC_STAT(
        static const bool announced = [] {
            _log_with_date_time("quic stats: compiled in", Log::INFO);
            return true;
        }();
        (void)announced;
        m_stats.m_stats_enabled = quic_stats_enabled();
    )
#line 313
    _log_with_date_time("QuicConnection: QuicConnection constructed for peer " + 
                        tp::string(peer.address().to_string().c_str()) + ":" + 
                        tp::to_string(peer.port()), Log::INFO);
    s_live_count.fetch_add(1, std::memory_order_relaxed);
}

QuicConnection::~QuicConnection() {
    QUIC_STAT(
        if (m_stats.m_stats_armed) {
            m_stats.m_stats_timer->cancel();
            write_stats_sample(true);
        }
    )
#line 320
    _log_with_date_time("QuicConnection counters peer=" +
                        tp::string(m_peer.address().to_string().c_str()) + ":" +
                        tp::to_string(m_peer.port()) + " partial_write_retries=" +
                        tp::to_string(m_partial_write_retries) + " write_more=" +
                        tp::to_string(m_write_more_count) + " stream_data_blocked=" +
                        tp::to_string(m_stream_data_blocked_count), Log::INFO);
    _log_with_date_time("QuicConnection: ~QuicConnection destructed for peer " + 
                        tp::string(m_peer.address().to_string().c_str()) + ":" + 
                        tp::to_string(m_peer.port()), Log::INFO);
    if (m_conn) {
        ngtcp2_conn_del(m_conn);
    }
    if (m_ssl) {
        SSL_free(m_ssl);
    }
    s_live_count.fetch_sub(1, std::memory_order_relaxed);
}

// ---- path helper ------------------------------------------------------------

ngtcp2_path QuicConnection::make_path(const boost::asio::ip::udp::endpoint& local_ep,
                                      const boost::asio::ip::udp::endpoint& remote_ep) {
    fill_sockaddr_union(local_ep, m_local_su, m_local_len);
    fill_sockaddr_union(remote_ep, m_remote_su, m_remote_len);
    ngtcp2_path path;
    path.local.addr     = &m_local_su.sa;
    path.local.addrlen  = m_local_len;
    path.remote.addr    = &m_remote_su.sa;
    path.remote.addrlen = m_remote_len;
    return path;
}

// ---- server init ------------------------------------------------------------

bool QuicConnection::init_server(const uint8_t* data, std::size_t datalen,
                                 const boost::asio::ip::udp::endpoint& local_ep,
                                 const boost::asio::ip::udp::endpoint& remote_ep,
                                 const ngtcp2_cid* dcid, const ngtcp2_cid* scid,
                                 uint32_t version,
                                 ngtcp2_cid* out_sv_scid) {
    m_is_server = true;

    m_ssl = m_tls_ctx->create_ssl();
    if (!m_ssl) {
        return false;
    }

    // Wire up conn_ref so TLS crypto callbacks can reach our ngtcp2_conn.
    m_conn_ref.get_conn  = &QuicConnection::get_conn_cb;
    m_conn_ref.user_data = this;
    SSL_set_app_data(m_ssl, &m_conn_ref);

    ngtcp2_callbacks callbacks;
    std::memset(&callbacks, 0, sizeof(callbacks));
    callbacks.recv_client_initial      = cb_recv_client_initial;
    callbacks.recv_crypto_data         = cb_recv_crypto_data;
    callbacks.handshake_completed      = cb_handshake_completed;
    callbacks.encrypt                  = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt                  = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask                  = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_stream_data         = cb_recv_stream_data;
    callbacks.stream_open              = cb_stream_open;
    callbacks.stream_close             = cb_stream_close;
    callbacks.rand                     = cb_rand;
    callbacks.update_key               = cb_update_key;
    callbacks.delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.version_negotiation      = ngtcp2_crypto_version_negotiation_cb;
    callbacks.get_new_connection_id2   = cb_get_new_connection_id;
    callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
    callbacks.acked_stream_data_offset = cb_acked_stream_data_offset;
    callbacks.extend_max_stream_data   = cb_extend_max_stream_data;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.cc_algo = QUIC_CC_ALGO;
#line 396
    settings.initial_ts = now_nanos();
    const auto handshake_timeout = m_endpoint.config().get_ssl().handshake_timeout;
    settings.handshake_timeout = handshake_timeout
        ? static_cast<ngtcp2_duration>(handshake_timeout) * NGTCP2_SECONDS
        : UINT64_MAX;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local  = 512 * 1024; // max cache size in one stream
    params.initial_max_stream_data_bidi_remote = 512 * 1024;
    params.initial_max_data                    = 32 * 1024 * 1024; // max cache size in all streams
    uint32_t srv_cfg_streams                   = m_endpoint.config().get_quic().max_concurrent_streams;
    params.initial_max_streams_bidi            = srv_cfg_streams > 0 ? std::max(1000U, srv_cfg_streams) : 1000;
    params.initial_max_stream_data_uni         = 64 * 1024;
    params.initial_max_streams_uni             = 200;
    params.max_idle_timeout = static_cast<ngtcp2_duration>(
        m_endpoint.config().get_quic().max_idle_timeout_ms) * 1'000'000ULL;
    params.original_dcid         = *dcid;
    params.original_dcid_present = 1;

    auto path = make_path(local_ep, remote_ep);

    // Choose a new SCID for the server.
    ngtcp2_cid sv_scid;
    sv_scid.datalen = kServerScidLen;
    RAND_bytes(sv_scid.data, static_cast<int>(kServerScidLen));
    params.stateless_reset_token_present =
        ngtcp2_crypto_generate_stateless_reset_token(params.stateless_reset_token,
            m_endpoint.stateless_reset_secret(), kStatelessResetSecretLen, &sv_scid) == 0;

    // ngtcp2_conn_server_new(conn, dcid, scid, path, version, ...):
    //   dcid = the client's SCID (server uses it as its destination CID)
    //   scid = the server's own SCID (newly generated sv_scid)
    int rv = ngtcp2_conn_server_new(&m_conn, scid ? scid : dcid, &sv_scid, &path, version,
                                    &callbacks, &settings, &params, &tj_ngtcp2_mem, this);
    if (rv != 0) {
        _log_with_date_time(
            "QuicConnection::init_server: ngtcp2_conn_server_new: " + tp::string(ngtcp2_strerror(rv)),
            Log::ERROR);
        SSL_free(m_ssl);
        m_ssl = nullptr;
        return false;
    }

    ngtcp2_conn_set_tls_native_handle(m_conn, m_ssl);

    // Export the chosen SCID so the caller can add a routing table entry for it.
    // Post-handshake packets from the client use sv_scid as DCID.
    if (out_sv_scid) {
        *out_sv_scid = sv_scid;
    }

    // Process the first packet to kick off the handshake.
    rv = ngtcp2_conn_read_pkt(m_conn, &path, nullptr, data, datalen, now_nanos());
    if (rv != 0 && rv != NGTCP2_ERR_RETRY) {
        _log_with_date_time(
            "QuicConnection::init_server: initial ngtcp2_conn_read_pkt: " + tp::string(ngtcp2_strerror(rv)),
            Log::WARN);
        if (rv == NGTCP2_ERR_CRYPTO) {
            // Initial TLS failures must reach the peer as QUIC crypto alerts, not silent drops.
            ngtcp2_ccerr ccerr;
            ngtcp2_ccerr_set_tls_alert(&ccerr, ngtcp2_conn_get_tls_alert(m_conn), nullptr, 0);
            ngtcp2_path_storage ps;
            ngtcp2_path_storage_zero(&ps);
            ngtcp2_pkt_info pi{};
            const auto written = ngtcp2_conn_write_connection_close(m_conn, &ps.path, &pi,
              m_write_buf.data(), m_write_buf.size(), &ccerr, now_nanos());
            if (written > 0) {
                QUIC_SEND(m_peer, m_write_buf.data(), static_cast<std::size_t>(written));
#line 465
            }
        }
        return false;
    }

    QUIC_STAT(
        start_stats_sampler();
    )
#line 470
    pump_write(FUNC_NAME);
    reschedule_loss_timer();
    return true;
}

// ---- client init ------------------------------------------------------------

bool QuicConnection::init_client(const boost::asio::ip::udp::endpoint& local_ep,
                                 const boost::asio::ip::udp::endpoint& remote_ep) {
    m_is_server = false;
    m_peer      = remote_ep;

    m_ssl = m_tls_ctx->create_ssl();
    if (!m_ssl) {
        return false;
    }

    m_conn_ref.get_conn  = &QuicConnection::get_conn_cb;
    m_conn_ref.user_data = this;
    SSL_set_app_data(m_ssl, &m_conn_ref);

    const auto& ssl_cfg = m_endpoint.config().get_ssl();
    const auto& expected_host = !ssl_cfg.sni.empty() ? ssl_cfg.sni : m_endpoint.config().get_remote_addr();
    // Verify certificate identity independently of SNI configuration.
    if (ssl_cfg.verify && ssl_cfg.verify_hostname) {
        boost::system::error_code ec;
        boost::asio::ip::make_address(expected_host.c_str(), ec);
        auto* param = SSL_get0_param(m_ssl);
        int rc = ec ? X509_VERIFY_PARAM_set1_host(param, expected_host.c_str(), expected_host.size())
                    : X509_VERIFY_PARAM_set1_ip_asc(param, expected_host.c_str());
        if (expected_host.empty() || rc != 1) {
            _log_with_date_time("QUIC: failed to configure certificate hostname verification", Log::ERROR);
            return false;
        }
    }
    if (!expected_host.empty()) {
        if (SSL_set_tlsext_host_name(m_ssl, expected_host.c_str()) != 1) {
            _log_with_date_time("QUIC: failed to configure SNI", Log::ERROR);
            return false;
        }
    }

    ngtcp2_callbacks callbacks;
    std::memset(&callbacks, 0, sizeof(callbacks));
    callbacks.client_initial                = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data              = cb_recv_crypto_data;
    callbacks.handshake_completed           = cb_handshake_completed;
    callbacks.recv_version_negotiation      = nullptr;
    callbacks.encrypt                       = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt                       = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask                       = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_stream_data              = cb_recv_stream_data;
    callbacks.stream_close                  = cb_stream_close;
    callbacks.recv_retry                    = ngtcp2_crypto_recv_retry_cb;
    callbacks.recv_stateless_reset2 = [](ngtcp2_conn*, const ngtcp2_pkt_stateless_reset2*, void*) {
        _log_with_date_time("QuicConnection: stateless reset received", Log::INFO);
        return 0;
    };
    callbacks.extend_max_local_streams_bidi = cb_extend_max_local_streams_bidi;
    callbacks.rand                          = cb_rand;
    callbacks.update_key                    = cb_update_key;
    callbacks.handshake_confirmed           = cb_handshake_completed;
    callbacks.delete_crypto_aead_ctx        = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx      = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.version_negotiation           = ngtcp2_crypto_version_negotiation_cb;
    callbacks.get_new_connection_id2        = cb_get_new_connection_id;
    callbacks.get_path_challenge_data2      = ngtcp2_crypto_get_path_challenge_data2_cb;
    callbacks.acked_stream_data_offset      = cb_acked_stream_data_offset;
    callbacks.extend_max_stream_data        = cb_extend_max_stream_data;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.cc_algo = QUIC_CC_ALGO;
#line 543
    settings.initial_ts = now_nanos();

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_data                    = 32 * 1024 * 1024; // max cache size in all streams
    uint32_t cli_cfg_streams                   = m_endpoint.config().get_quic().max_concurrent_streams;
    params.initial_max_streams_bidi            = cli_cfg_streams > 0 ? cli_cfg_streams : 100;
    params.initial_max_stream_data_uni         = 64 * 1024;
    params.initial_max_streams_uni             = 100;
    params.initial_max_stream_data_bidi_local  = 1 * 1024 * 1024;  // max cache size in one stream
    params.initial_max_stream_data_bidi_remote = 1 * 1024 * 1024;  // max cache size in one stream
    params.max_idle_timeout = static_cast<ngtcp2_duration>(
        m_endpoint.config().get_quic().max_idle_timeout_ms) * 1'000'000ULL;

    const bool chrome = ssl_cfg.fingerprint == "chrome";
    uint32_t versions[] = {NGTCP2_PROTO_VER_V1, 0};
    if (chrome) {
        // Start at 1 for Chrome wire parity: observers can decrypt Initial packets.
        settings.initial_pkt_num = 1;
        uint32_t random_version;
        if (RAND_bytes(reinterpret_cast<uint8_t*>(&random_version), sizeof(random_version)) != 1) {
            return false;
        }
        versions[1] = (random_version & 0xf0f0f0f0U) | 0x0a0a0a0aU;
        settings.available_versions = versions;
        settings.available_versionslen = 2;
        settings.max_tx_udp_payload_size = 1250;
        settings.no_tx_udp_payload_size_shaping = 1;
        params.tp_chrome_fingerprint = 1;
        params.initial_max_data = 15 * 1024 * 1024;
        params.initial_max_stream_data_bidi_local = 6 * 1024 * 1024;
        params.initial_max_stream_data_bidi_remote = 6 * 1024 * 1024;
        params.initial_max_stream_data_uni = 6 * 1024 * 1024;
        params.initial_max_streams_bidi = 100;
        params.initial_max_streams_uni = 103;
        params.max_idle_timeout = 30 * NGTCP2_SECONDS;
        params.max_udp_payload_size = 1472;
        params.max_datagram_frame_size = 65536;
    }

    ngtcp2_cid dcid, scid;
    dcid.datalen = chrome ? 8 : 18;
    scid.datalen = chrome ? 0 : 17;
    if (RAND_bytes(dcid.data, static_cast<int>(dcid.datalen)) != 1 ||
        RAND_bytes(scid.data, static_cast<int>(scid.datalen)) != 1) {
        return false;
    }

    auto path = make_path(local_ep, remote_ep);

    int rv = ngtcp2_conn_client_new(&m_conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                                    &callbacks, &settings, &params, &tj_ngtcp2_mem, this);
    if (rv != 0) {
        _log_with_date_time(
            "QuicConnection::init_client: ngtcp2_conn_client_new: " + tp::string(ngtcp2_strerror(rv)),
            Log::ERROR);
        SSL_free(m_ssl);
        m_ssl = nullptr;
        return false;
    }

    ngtcp2_conn_set_tls_native_handle(m_conn, m_ssl);

    QUIC_STAT(
        start_stats_sampler();
    )
#line 606
    pump_write(FUNC_NAME);
    reschedule_loss_timer();
    return true;
}

// ---- packet receive ---------------------------------------------------------

void QuicConnection::on_packet(const uint8_t* data, std::size_t datalen,
                               const boost::asio::ip::udp::endpoint& local_ep,
                               const boost::asio::ip::udp::endpoint& remote_ep) {
    if (m_closed || !m_conn) {
        return;
    QUIC_STAT(
        }
        StatsReasonScope reason(*this, SendReason::other);
        uint64_t credit_before = 0;
        if (m_stats.m_stats_enabled) credit_before = ngtcp2_conn_get_max_data_left2(m_conn);
        if (m_stats.m_stats_enabled) {
            m_stats.m_stats_read_flow = false;
            m_stats.m_stats_read_ack = false;
    )
#line 618
    }
    m_in_read_pkt = true;
    auto path = make_path(local_ep, remote_ep);
    ngtcp2_conn_info before{};
    ngtcp2_conn_get_conn_info2(m_conn, &before);
    int  rv   = ngtcp2_conn_read_pkt(m_conn, &path, nullptr, data, datalen, now_nanos());
    m_in_read_pkt = false;
    if (rv != 0) {
        if (rv != NGTCP2_ERR_DRAINING && rv != NGTCP2_ERR_DROP_CONN) {
            _log_with_date_time(
                "QuicConnection::on_packet: ngtcp2_conn_read_pkt: " + tp::string(ngtcp2_strerror(rv)),
                Log::WARN);
        }
        if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CRYPTO) {
            close();
            return;
        }
    }
    if (!m_closed && m_conn) {
        ngtcp2_conn_info after{};
        ngtcp2_conn_get_conn_info2(m_conn, &after);
        // read_pkt can return success for discarded garbage; only authenticated
        // peer packets prove liveness, not arbitrary datagrams on the socket.
        if (rv == 0 && after.pkt_recv > before.pkt_recv) {
            m_last_packet_received = QuicClock::now();
        }
        QUIC_STAT(
            // Window evidence wins over ACK evidence; unclassified receives stay other.
            if (m_stats.m_stats_enabled) {
                if (m_stats.m_stats_read_flow || ngtcp2_conn_get_max_data_left2(m_conn) > credit_before)
                    m_stats.m_stats_reason = SendReason::flow;
                else if (m_stats.m_stats_read_ack || after.bytes_in_flight < before.bytes_in_flight)
                    m_stats.m_stats_reason = SendReason::ack;
            }
        )
#line 644
        // ACKs release congestion credit; MAX_DATA and MAX_STREAM_DATA release
        // flow credit. Retry only after read_pkt returns, never inside callbacks.
        schedule_send_wakeup();
        on_pump_write(FUNC_NAME);
    }
}

void QuicConnection::probe() {
    if (m_closed || !m_conn || !m_handshake_done) return;
    // ngtcp2 exposes no submit_ping API. An expired keep-alive queues a PING
    // through its normal packet writer without inventing transport frames.
    ngtcp2_conn_set_keep_alive_timeout(m_conn, 1);
    on_pump_write(FUNC_NAME);
    ngtcp2_conn_set_keep_alive_timeout(m_conn,
        static_cast<ngtcp2_duration>(m_endpoint.config().get_quic().ping_interval_ms) * 1'000'000ULL);
    reschedule_loss_timer();
}

void QuicConnection::schedule_send_wakeup() {
    if (m_closed || m_send_wakeup_pending || m_conn_unacked_bufs.empty()) return;
    QUIC_STAT(
        if (m_stats.m_stats_enabled) m_stats.m_stats_wakeup_reason = m_stats.m_stats_reason;
    )
#line 664
    m_send_wakeup_pending = true;
    // One socket drain can accept many ACKs. Coalesce their wake-ups rather
    // than scanning queues and cancelling/rearming timers for every datagram;
    // that churn starves H3 and other connections under concurrent load.
    boost::asio::post(m_endpoint.io_context(), tp::bind_mem_alloc([this, self = shared_from_this()]() {
        QUIC_STAT(
            StatsReasonScope reason(*this, m_stats.m_stats_enabled ? m_stats.m_stats_wakeup_reason : SendReason::other);
        )
#line 669
        m_send_wakeup_pending = false;
        if (m_closed) return;
        resume_blocked_sends();
        on_pump_write(FUNC_NAME);
    }));
}

void QuicConnection::resume_blocked_sends() {
    // Batch the connection pump too: pumping after every stream sends tiny
    // control packets and inflates retransmission bookkeeping during a wake-up.
    m_resuming_sends = true;
    // Sending can complete application callbacks and erase queues. Snapshot only
    // queue heads so no iterator survives a send and per-stream ordering holds.
    tp::vector<std::shared_ptr<UnackedBuf>> pending;
    for (auto& [id, queue] : m_conn_unacked_bufs) {
        for (auto& buf : queue->buffers) {
            if (buf->is_sending()) {
                pending.push_back(buf);
                break;
            }
        }
    }
    for (auto& buf : pending) {
        if (m_closed) break;
        // Earlier completion callbacks can remove another stream's queue.
        auto it = m_conn_unacked_bufs.find(buf->m_stream_id);
        if (it == m_conn_unacked_bufs.end() || !buf->is_sending() ||
            std::find(it->second->buffers.begin(), it->second->buffers.end(), buf) == it->second->buffers.end()) {
            continue;
        }
        buf->cancel_timer();
        buf->send();
    }
    m_resuming_sends = false;
}

void QuicConnection::on_pump_write(const char* debug_path) {
    if (m_closed || !m_conn || m_in_read_pkt) {
        return;
    }
    if (m_endpoint.udp_gso_enabled() && m_close_waiting) return;

    if (m_in_pump_write) {
        return;
    }
    m_in_pump_write = true;
    
    pump_write(debug_path);

    if (m_closed) {
        m_in_pump_write = false;
        return;
    }

    if (m_h3) {
        m_h3->pump_h3_response(debug_path);
    }

    // Give handlers a chance to retry buffered data (e.g. if QPACK was unblocked)
    for (auto& [id, handler] : m_stream_handlers) {
        handler->on_connection_pump();
    }

    m_in_pump_write = false;
    reschedule_loss_timer();
}

// ---- pump_write : send ACK/Control/handshake packet without stream id --------------------------

void QuicConnection::pump_write(const char* debug_path) {
    if (m_endpoint.udp_gso_enabled() && m_conn && !m_closed) {
        bool accepted = false;
        send_gso(-1, nullptr, 0, false, accepted);
        return;
    }
    QUIC_STAT(
        if (m_stats.m_stats_enabled) {
            ++m_stats.m_reason_stats[static_cast<unsigned>(m_stats.m_stats_reason)].pump;
            stats_observe_gap(false);
        }
    )
#line 738
    if (m_closed || !m_conn) {
        return;
    }

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi{};

    std::size_t batch_bytes = 0;
    auto send_quantum = ngtcp2_conn_get_send_quantum2(m_conn);
    auto flush_batch = [&]() {
        if (batch_bytes == 0) return;
        ngtcp2_conn_update_pkt_tx_time(m_conn, now_nanos());
        batch_bytes = 0;
        send_quantum = ngtcp2_conn_get_send_quantum2(m_conn);
    };
    auto record_packet = [&](std::size_t len) {
        batch_bytes += len;
        if (batch_bytes >= send_quantum) flush_batch();
    };
    auto prepare_packet = [&]() {
        // Start a new batch before the next full-sized datagram could exceed it.
        if (send_quantum - batch_bytes <
            std::min(m_write_buf.size(), ngtcp2_conn_get_max_tx_udp_payload_size2(m_conn))) {
            flush_batch();
        }
    };
    struct BatchGuard {
        decltype(flush_batch)& flush;
        ~BatchGuard() { flush(); }
    } batch_guard{flush_batch};

    bool ppe_pending = false;
    for (;;) {
        QUIC_STAT(
            if (m_stats.m_stats_enabled) stats_observe_gap(false);
        )
#line 772
        if (!ppe_pending) prepare_packet();
        auto ts = now_nanos();
        auto nwrite = ngtcp2_conn_write_pkt(m_conn, &ps.path, &pi, m_write_buf.data(), m_write_buf.size(), ts);
        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE) {
                ppe_pending = true;
                continue;
            }
            if (ppe_pending) {
                auto flush_ts = now_nanos();
                auto flush_nwrite = ngtcp2_conn_write_pkt(m_conn, &ps.path, &pi, m_write_buf.data(),
                                                          m_write_buf.size(), flush_ts);
                if (flush_nwrite > 0) {
                    QUIC_SEND(m_peer, m_write_buf.data(), static_cast<std::size_t>(flush_nwrite));
#line 786
                    record_packet(static_cast<std::size_t>(flush_nwrite));
                }
            }
            _log_with_date_time(
                "QuicConnection::pump_write: " + tp::string(ngtcp2_strerror(static_cast<int>(nwrite))) + 
                " path" + tp::string(debug_path),
                Log::WARN);
            flush_batch();
            if (nwrite == NGTCP2_ERR_CLOSING || nwrite == NGTCP2_ERR_DRAINING) {
                close();
            }
            return;
        }
        ppe_pending = false;
        if (nwrite == 0) {
            QUIC_STAT(
                if (m_stats.m_stats_enabled) stats_zero_write_expiry();
            )
#line 801
            break;
        }
        // Determine destination from the path returned by ngtcp2.
        boost::asio::ip::udp::endpoint dest = m_peer;
        if (ps.path.remote.addrlen == sizeof(sockaddr_in)) {
            auto* sin = reinterpret_cast<sockaddr_in*>(ps.path.remote.addr);
            dest      = boost::asio::ip::udp::endpoint(
                boost::asio::ip::address_v4(ntohl(sin->sin_addr.s_addr)), ntohs(sin->sin_port));
        } else if (ps.path.remote.addrlen == sizeof(sockaddr_in6)) {
            auto* sin6 = reinterpret_cast<sockaddr_in6*>(ps.path.remote.addr);
            boost::asio::ip::address_v6::bytes_type bytes;
            std::memcpy(bytes.data(), &sin6->sin6_addr, 16);
            dest = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6(bytes),
                                                  ntohs(sin6->sin6_port));
        }
        QUIC_SEND(dest, m_write_buf.data(), static_cast<std::size_t>(nwrite));
#line 817
        record_packet(static_cast<std::size_t>(nwrite));
    }
}

// ---- send_stream_data -------------------------------------------------------

void QuicConnection::send_stream_data(int64_t stream_id, std::shared_ptr<ReadBufWithGuard> buf, bool fin, IoHandler sent_cb){
    QUIC_STAT(
        // Preserve synchronous transport trigger; untriggered submissions are application.
        StatsReasonScope reason(*this, m_stats.m_stats_enabled && m_stats.m_stats_reason != SendReason::other
                                          ? m_stats.m_stats_reason : SendReason::application);
    )
#line 824
    if (m_closed || !m_conn) {
        if(sent_cb){
            sent_cb(boost::asio::error::broken_pipe, 0);
        }
        return;
    }

    if (m_in_read_pkt) {
        auto self = shared_from_this();
        QUIC_STAT(const auto trigger = m_stats.m_stats_enabled ? m_stats.m_stats_reason : SendReason::other;)
        boost::asio::post(m_endpoint.io_context(), [this, self, stream_id, buf, fin, sent_cb QUIC_STAT(, trigger)]() {
            QUIC_STAT(StatsReasonScope reason(*this, trigger);)
#line 834
            send_stream_data(stream_id, buf, fin, sent_cb);
        });
        return;
    }

    if(!buf || buf->size() == 0){
        bool accepted = false;
        auto sent = send_stream_vecs_impl(stream_id, nullptr, 0, fin, accepted, FUNC_NAME);
        if (sent >= 0 && fin && !accepted) {
            // Zero bytes written can mean pacing rejected the empty FIN, not
            // that FIN was accepted. Losing it retains ngtcp2 stream state for
            // the connection lifetime, visible as T16 allocator growth.
            auto timer = TP_MAKE_SHARED(boost::asio::steady_timer, m_endpoint.io_context());
            QUIC_STAT(
                if (m_stats.m_stats_enabled) ++m_stats.m_retry_arms;
            )
#line 847
            timer->expires_after(std::chrono::milliseconds(10));
            timer->async_wait(tp::bind_mem_alloc(
              [this, self = shared_from_this(), timer, stream_id, buf, fin, sent_cb = std::move(sent_cb)](
                const boost::system::error_code& ec) mutable {
                  if (!ec) {
                      // Public submission normally starts application attribution;
                      // this timer is an empty-FIN retry instead.
                      QUIC_STAT(StatsReasonScope reason(*this, SendReason::retry);)
                      QUIC_STAT(const auto before = m_stats.m_stats_enabled ? m_stats.m_stats_udp_sent : 0;)
                      send_stream_data(stream_id, buf, fin, std::move(sent_cb));
                      QUIC_STAT(if (m_stats.m_stats_enabled) {
                          if (m_stats.m_stats_udp_sent > before) ++m_stats.m_retry_expires_bytes;
                          else ++m_stats.m_retry_expires_empty;
                      })
                  }
#line 852
                  else if (sent_cb) sent_cb(ec, 0);
              }));
            return;
        }
        if(sent < 0){
            if(sent_cb){
                sent_cb(boost::asio::error::broken_pipe, 0);
            }
        }else{
            if(sent_cb){
                sent_cb({}, 0);
            }
        }
        return;
    }

    _log_with_date_time("[QuicConnection::send_stream_data] stream_id=" + tp::to_string(stream_id) + 
        " buf_size=" + tp::to_string(buf ? buf->size() : 0) + " fin=" + tp::to_string(fin), Log::ALL);

    // cache the data for ack
    auto it = m_conn_unacked_bufs.find(stream_id);
    std::shared_ptr<UnackedBuffers> ptr;
    if(it == m_conn_unacked_bufs.end()){
        ptr = TP_MAKE_SHARED(UnackedBuffers);
        m_conn_unacked_bufs[stream_id] = ptr;
    } else {
        ptr = it->second;
    }

    auto& list = ptr->buffers;
    auto unacked_ptr = TP_MAKE_SHARED(UnackedBuf, m_endpoint.io_context());
    unacked_ptr->m_stream_id = stream_id;
    unacked_ptr->m_buf = buf;
    unacked_ptr->m_fin = fin;
    unacked_ptr->m_ack_offset = ptr->curr_written;
    unacked_ptr->m_bytes_acked = 0;
    unacked_ptr->m_sent_cb = std::move(sent_cb);
    unacked_ptr->m_conn = shared_from_this();
    
    list.emplace_back(unacked_ptr);

    ptr->curr_written += buf ? buf->size() : 0;

    if(!ptr->m_sending){
        ptr->m_sending = true;
        unacked_ptr->send();
    }
    
}

bool QuicConnection::UnackedBuf::is_sending() const {
    return m_sending_offset < m_buf->size();
}

void QuicConnection::UnackedBuf::cancel_timer() {
    if (!m_timer_running) return;
    m_timer_running = false;
    ++m_timer_generation;
    m_write_timer.cancel();
}

void QuicConnection::UnackedBuf::complete(const boost::system::error_code& ec, std::size_t n) {
    auto cb = std::move(m_sent_cb);
    if (cb) {
        cb(ec, n);
    }
}

void QuicConnection::UnackedBuf::send(){
    auto self = shared_from_this(); // Completion callbacks can erase the owning queue.
    auto conn = m_conn.lock();
    if(!conn){
        complete(boost::asio::error::broken_pipe, 0);
        return;
    }

    const auto& data = m_buf->to_string_view();
    const uint8_t* ptr = (const uint8_t*)data.data() + m_sending_offset;
    std::size_t len = data.length() - m_sending_offset;

    auto sent = conn->send_stream_data_impl(m_stream_id, ptr, len, m_fin);
    if(sent < 0){
        cancel_timer();
        conn->fail_unacked_buffers(m_stream_id, boost::asio::error::broken_pipe);
    }else if((std::size_t)sent >= len){
        // finished, and wait for ack since now
        m_sending_offset += sent;
        complete({}, m_sending_offset);

        cancel_timer();
        conn->send_next_unacked_buff(m_stream_id, this);
    }else{
        // wait for a while and send again
        m_sending_offset += sent;
        ++conn->m_partial_write_retries;

        // 93e7e8e backed off 50..3000 ms and failed streams; e3c29a5 used
        // fixed 10 ms polling to avoid that failure. ACK/window events now wake
        // sends directly. Keep 100 ms only for pacing or a missed wake-up.
        m_retry_delay_ms = 100;

        if (!m_timer_running) {
            QUIC_STAT(
                if (conn->m_stats.m_stats_enabled) ++conn->m_stats.m_retry_arms;
            )
#line 956
            m_timer_running = true;
            m_write_timer.expires_after(std::chrono::milliseconds(m_retry_delay_ms));
            m_write_timer.async_wait(
                [unacked = this->shared_from_this(), sent, generation = ++m_timer_generation
                 QUIC_STAT(, stats_enabled = conn->m_stats.m_stats_enabled)](boost::system::error_code ec){
#line 960
                    // aa0f39b removed event wake-ups because cancelling this
                    // wait completed the send with an error and wiped its queue.
                    // A cancelled old wait must not touch a newly armed timer.
                    // A successful expiry may already be queued when cancelled.
                    if (ec == boost::asio::error::operation_aborted ||
                        generation != unacked->m_timer_generation) return;
                    unacked->m_timer_running = false;
                    if(ec){
                        unacked->complete(boost::asio::error::operation_aborted, unacked->m_sending_offset);
                        return;
                    }

                    _log_with_date_time("UnackedBuf retry send stream_id=" + 
                        tp::to_string(unacked->m_stream_id) + " sent=" + tp::to_string(sent) + 
                        " offset=" + tp::to_string(unacked->m_sending_offset) + 
                        " fin=" + tp::to_string(unacked->m_fin) + " buf_size=" + 
                        tp::to_string(unacked->m_buf ? unacked->m_buf->size() : 0), 
                        Log::ALL);

                    QUIC_STAT(
                        if (stats_enabled) {
                            auto conn = unacked->m_conn.lock();
                            if (conn) {
                                const auto before = conn->m_stats.m_stats_udp_sent;
                                StatsReasonScope reason(*conn, SendReason::retry);
                                unacked->send();
                                if (conn->m_stats.m_stats_udp_sent > before) ++conn->m_stats.m_retry_expires_bytes;
                                else ++conn->m_stats.m_retry_expires_empty;
                                return;
                            }
                        }
                    )
#line 979
                    unacked->send();
                }
            );
        }
    }

    if(sent > 0 && !conn->m_resuming_sends){
        conn->on_pump_write(FUNC_NAME);
    }
}

void QuicConnection::send_next_unacked_buff(int64_t stream_id, UnackedBuf* /*buf_finished*/){
    auto stream_id_it = m_conn_unacked_bufs.find(stream_id);
    if(stream_id_it != m_conn_unacked_bufs.end()){
        auto queue = stream_id_it->second;
        for(auto buf : queue->buffers){
            if(buf->m_buf && buf->m_sending_offset < buf->m_buf->size()){
                buf->send();
                return; // Sending can erase the stream and its queue.
            }
        }
        queue->m_sending = false;
    }
}
void QuicConnection::fail_unacked_buffers(int64_t stream_id, const boost::system::error_code& ec) {
    auto it = m_conn_unacked_bufs.find(stream_id);
    if (it == m_conn_unacked_bufs.end()) {
        return;
    }
    auto bufs = std::move(it->second);
    m_conn_unacked_bufs.erase(it);
    for (auto& buf : bufs->buffers) {
        buf->cancel_timer();
        buf->complete(ec, buf->m_sending_offset);
    }
}

void QuicConnection::fail_all_unacked_buffers(const boost::system::error_code& ec) {
    auto pending = std::move(m_conn_unacked_bufs);
    m_conn_unacked_bufs.clear();
    for (auto& [id, bufs] : pending) {
        for (auto& buf : bufs->buffers) {
            buf->cancel_timer();
            buf->complete(ec, buf->m_sending_offset);
        }
    }
}

int64_t QuicConnection::send_stream_vecs(int64_t stream_id, 
    const ngtcp2_vec* datav, std::size_t datavcnt, bool fin, bool& accepted, const char* debug_path){
    QUIC_STAT(
        StatsReasonScope reason(*this, m_stats.m_stats_enabled && m_stats.m_stats_reason != SendReason::other
                                          ? m_stats.m_stats_reason : SendReason::application);
    )
#line 1029
    return send_stream_vecs_impl(stream_id, datav, datavcnt, fin, accepted, debug_path);
}

int64_t QuicConnection::send_stream_data_impl(int64_t stream_id, const uint8_t* data, std::size_t datalen,
                                      bool fin) {
    QUIC_STAT(
        if (m_stats.m_stats_enabled) ++m_stats.m_reason_stats[static_cast<unsigned>(m_stats.m_stats_reason)].data;
    )
#line 1034
    if (m_closed || !m_conn) {
        return -1;
    QUIC_STAT(
        }
        if (m_stats.m_stats_enabled) {
            stats_observe_gap(false);
            m_stats.m_stats_have_stream = true;
            m_stats.m_stats_stream_id = stream_id;
    )
#line 1036
    }

    if (m_endpoint.udp_gso_enabled()) {
        ngtcp2_vec vec{const_cast<uint8_t*>(data), datalen};
        bool accepted = false;
        return send_gso(stream_id, &vec, 1, fin, accepted);
    }

    _log_with_date_time("send_stream_data_impl enter: stream_id=" + tp::to_string(stream_id) + 
                    " datalen=" + tp::to_string(datalen) + " fin=" + tp::to_string(fin), Log::ALL);

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi{};

    std::size_t batch_bytes = 0;
    auto send_quantum = ngtcp2_conn_get_send_quantum2(m_conn);
    auto flush_batch = [&]() {
        if (batch_bytes == 0) return;
        ngtcp2_conn_update_pkt_tx_time(m_conn, now_nanos());
        batch_bytes = 0;
        send_quantum = ngtcp2_conn_get_send_quantum2(m_conn);
    };
    auto record_packet = [&](std::size_t len) {
        batch_bytes += len;
        if (batch_bytes >= send_quantum) flush_batch();
    };
    auto prepare_packet = [&]() {
        // Start a new batch before the next full-sized datagram could exceed it.
        if (send_quantum - batch_bytes <
            std::min(m_write_buf.size(), ngtcp2_conn_get_max_tx_udp_payload_size2(m_conn))) {
            flush_batch();
        }
    };
    struct BatchGuard {
        decltype(flush_batch)& flush;
        ~BatchGuard() { flush(); }
    } batch_guard{flush_batch};

    std::size_t written = 0;
    bool ppe_pending = false;  // true when WRITE_MORE was returned, ngtcp2 PPE_PENDING flag is set
    ngtcp2_tstamp packet_ts = 0;  // WRITE_MORE continuations must retain the packet timestamp.

    // Flush PPE on any exit path to ensure PPE_PENDING is cleared before read_pkt can be called.
    // ngtcp2 asserts PPE_PENDING==0 at the top of ngtcp2_conn_read_pkt_versioned.
    // IMPORTANT: must reuse the same ps/pi/buf as the WRITE_MORE call per ngtcp2 contract.
    auto flush_ppe = [&]() {
        if (!ppe_pending) return;
        ppe_pending = false;
        auto flush_nwrite = ngtcp2_conn_writev_stream(m_conn, &ps.path, &pi, m_write_buf.data(), m_write_buf.size(),
                                                      nullptr, 0, -1, nullptr, 0, packet_ts);
        if (flush_nwrite > 0) {
            QUIC_SEND(m_peer, m_write_buf.data(), static_cast<std::size_t>(flush_nwrite));
#line 1083
            record_packet(static_cast<std::size_t>(flush_nwrite));
        }
    };

    for (;;) {
        QUIC_STAT(
            if (m_stats.m_stats_enabled) stats_observe_gap(false);
        )
#line 1088
        if (!ppe_pending) {
            prepare_packet();
            packet_ts = now_nanos();
        }
        std::size_t remain = datalen - written;
        ngtcp2_vec vec;
        vec.base = const_cast<uint8_t*>(data + written);
        vec.len  = remain;
        ngtcp2_ssize pdatalen = -1;

        uint32_t flags = 0;
        if (fin) {
            // mark fin tag for all data, ngtcp2 will process correctly
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        } else {
            flags |= NGTCP2_WRITE_STREAM_FLAG_MORE;
        }

        if (flags & NGTCP2_WRITE_STREAM_FLAG_MORE) {
            ppe_pending = true;
        }

        auto nwrite = ngtcp2_conn_writev_stream(m_conn, &ps.path, &pi, m_write_buf.data(), m_write_buf.size(),
                                                &pdatalen, flags, stream_id, &vec, 1, packet_ts);

        QUIC_STAT(
            if (m_stats.m_stats_enabled && nwrite == 0) stats_zero_write_expiry();
        )
#line 1113
        if (nwrite == NGTCP2_ERR_WRITE_MORE) {
            ++m_write_more_count;
            _log_with_date_time("send_stream_data_impl: WRITE_MORE stream=" + 
                tp::to_string(stream_id) + " pdatalen=" + tp::to_string(pdatalen), Log::ALL);
            ppe_pending = true;
            if (pdatalen > 0) written += pdatalen;
            if (written == datalen && !fin) {
                break;
            }
            continue;
        }

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                ++m_stream_data_blocked_count;
                _log_with_date_time("send_stream_data_impl: STREAM_DATA_BLOCKED stream=" + tp::to_string(stream_id) + 
                    " written=" + tp::to_string(written), Log::ALL);
                // PPE_PENDING may be set from a previous WRITE_MORE; must flush before returning.
                flush_ppe();
                flush_batch();
                reschedule_loss_timer();
                return static_cast<int64_t>(written);
            }
            _log_with_date_time(
                "send_stream_data_impl error=" + tp::string(ngtcp2_strerror(static_cast<int>(nwrite))) +
                " stream=" + tp::to_string(stream_id) + " written=" + tp::to_string(written),
                Log::ALL);
            if (nwrite != NGTCP2_ERR_STREAM_SHUT_WR) {
                _log_with_date_time(
                    "send_stream_data_impl error=" + tp::string(ngtcp2_strerror(static_cast<int>(nwrite))) +
                    " stream=" + tp::to_string(stream_id),
                    Log::WARN);
            }
            flush_ppe();
            flush_batch();
            reschedule_loss_timer();
            if (written > 0) return static_cast<int64_t>(written);
            return -1;
        }

        ppe_pending = false;  // successful writev clears internal PPE_PENDING
        if (nwrite > 0) {
            QUIC_SEND(m_peer, m_write_buf.data(), static_cast<std::size_t>(nwrite));
#line 1156
            record_packet(static_cast<std::size_t>(nwrite));
        }

        if (pdatalen > 0) {
            written += pdatalen;
        }

        if (written == datalen) {
            break;
        }

        if (pdatalen <= 0) {
            QUIC_STAT(
                if (m_stats.m_stats_enabled) {
                    ++m_stats.m_zero_len_sends;
                }
            )
#line 1168
            _log_with_date_time("send_stream_data_impl: loop break due to pdatalen<=0 stream=" + tp::to_string(stream_id) + 
                " written=" + tp::to_string(written), Log::ALL);
            // Flow control, congestion control, or no more data for this stream in current packets.
            // DO NOT loop if we didn't send any stream data, to avoid infinite loop on connection-level frames.
            break;
        }
    }

    flush_ppe();
    flush_batch();
    _log_with_date_time("send_stream_data_impl leave: stream_id=" + tp::to_string(stream_id) + " written=" + tp::to_string(written), Log::ALL);
    reschedule_loss_timer();
    return static_cast<int64_t>(written);
}


int64_t QuicConnection::send_stream_vecs_impl(int64_t stream_id,
                                          const ngtcp2_vec* datav,
                                          std::size_t datavcnt, bool fin, bool& accepted, const char* debug_path) {
    QUIC_STAT(
        if (m_stats.m_stats_enabled) ++m_stats.m_reason_stats[static_cast<unsigned>(m_stats.m_stats_reason)].vecs;
    )
#line 1187
    accepted = false;
    if (m_closed || !m_conn) {
        return -1;
    QUIC_STAT(
        }
        if (m_stats.m_stats_enabled) {
            stats_observe_gap(false);
            m_stats.m_stats_have_stream = true;
            m_stats.m_stats_stream_id = stream_id;
    )
#line 1190
    }

    _log_with_date_time("send_stream_vecs_impl enter: stream_id=" + tp::to_string(stream_id) + 
                    " datavcnt=" + tp::to_string(datavcnt) + " fin=" + tp::to_string(fin) + 
                    " path=" + tp::string(debug_path), Log::ALL);

    if (m_endpoint.udp_gso_enabled()) return send_gso(stream_id, datav, datavcnt, fin, accepted);

    // Calculate total data length across all vectors
    std::size_t total_len = 0;
    for (std::size_t i = 0; i < datavcnt; ++i) {
        total_len += datav[i].len;
    }

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi{};

    std::size_t batch_bytes = 0;
    auto send_quantum = ngtcp2_conn_get_send_quantum2(m_conn);
    auto flush_batch = [&]() {
        if (batch_bytes == 0) return;
        ngtcp2_conn_update_pkt_tx_time(m_conn, now_nanos());
        batch_bytes = 0;
        send_quantum = ngtcp2_conn_get_send_quantum2(m_conn);
    };
    auto record_packet = [&](std::size_t len) {
        batch_bytes += len;
        if (batch_bytes >= send_quantum) flush_batch();
    };
    auto prepare_packet = [&]() {
        // Start a new batch before the next full-sized datagram could exceed it.
        if (send_quantum - batch_bytes <
            std::min(m_write_buf.size(), ngtcp2_conn_get_max_tx_udp_payload_size2(m_conn))) {
            flush_batch();
        }
    };
    struct BatchGuard {
        decltype(flush_batch)& flush;
        ~BatchGuard() { flush(); }
    } batch_guard{flush_batch};

    std::size_t written = 0;
    bool ppe_pending = false;  // true when WRITE_MORE was returned, ngtcp2 PPE_PENDING flag is set
    ngtcp2_tstamp packet_ts = 0;  // WRITE_MORE continuations must retain the packet timestamp.

    // Flush PPE on any exit path to ensure PPE_PENDING is cleared before read_pkt can be called.
    // ngtcp2 asserts PPE_PENDING==0 at the top of ngtcp2_conn_read_pkt_versioned.
    // IMPORTANT: must reuse the same ps/pi/buf as the WRITE_MORE call per ngtcp2 contract.
    auto flush_ppe = [&]() {
        if (!ppe_pending) return;
        ppe_pending = false;
        auto flush_nwrite = ngtcp2_conn_writev_stream(m_conn, &ps.path, &pi, m_write_buf.data(), m_write_buf.size(),
                                                      nullptr, 0, -1, nullptr, 0, packet_ts);
        if (flush_nwrite > 0) {
            QUIC_SEND(m_peer, m_write_buf.data(), static_cast<std::size_t>(flush_nwrite));
#line 1244
            record_packet(static_cast<std::size_t>(flush_nwrite));
        }
    };

    for (;;) {
        QUIC_STAT(
            if (m_stats.m_stats_enabled) stats_observe_gap(false);
        )
#line 1249
        if (!ppe_pending) {
            prepare_packet();
            packet_ts = now_nanos();
        }
        // Calculate the slice of active vecs for this iteration
        std::size_t skip = written;
        std::size_t start_idx = 0;
        std::size_t first_vec_offset = 0;
        bool found = false;

        for (std::size_t i = 0; i < datavcnt; ++i) {
            if (skip < datav[i].len) {
                start_idx = i;
                first_vec_offset = skip;
                found = true;
                break;
            }
            skip -= datav[i].len;
        }

        tp::vector<ngtcp2_vec> active_vecs;
        if (found) {
            active_vecs.reserve(datavcnt - start_idx);
            
            // Slice the first vector to skip already sent bytes
            ngtcp2_vec first_vec;
            first_vec.base = datav[start_idx].base + first_vec_offset;
            first_vec.len = datav[start_idx].len - first_vec_offset;
            active_vecs.push_back(first_vec);

            // Copy subsequent unsent vectors
            for (std::size_t i = start_idx + 1; i < datavcnt; ++i) {
                active_vecs.push_back(datav[i]);
            }
        } else {
            // If all data was sent but we still need to send the fin tag, 
            // push an empty vector to match send_stream_data_impl behavior.
            ngtcp2_vec empty_vec;
            empty_vec.base = nullptr;
            empty_vec.len = 0;
            active_vecs.push_back(empty_vec);
        }

        ngtcp2_ssize pdatalen = -1;

        uint32_t flags = 0;
        if (fin) {
            // mark fin tag for all data, ngtcp2 will process correctly
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        } else {
            flags |= NGTCP2_WRITE_STREAM_FLAG_MORE;
        }

        if (flags & NGTCP2_WRITE_STREAM_FLAG_MORE) {
            ppe_pending = true;
        }

        auto nwrite = ngtcp2_conn_writev_stream(m_conn, &ps.path, &pi, m_write_buf.data(), m_write_buf.size(),
                                                &pdatalen, flags, stream_id, active_vecs.data(), active_vecs.size(), packet_ts);

        // pdatalen == 0 accepts an empty FIN; -1 means no stream frame was accepted.
        if (pdatalen >= 0 && (nwrite >= 0 || nwrite == NGTCP2_ERR_WRITE_MORE)) accepted = true;

        QUIC_STAT(
            if (m_stats.m_stats_enabled && nwrite == 0) stats_zero_write_expiry();
        )
#line 1312
        if (nwrite == NGTCP2_ERR_WRITE_MORE) {
            ++m_write_more_count;
            _log_with_date_time("send_stream_vecs_impl: WRITE_MORE stream=" + 
                tp::to_string(stream_id) + " pdatalen=" + tp::to_string(pdatalen) + 
                " path=" + tp::string(debug_path), Log::ALL);
            ppe_pending = true;
            if (pdatalen > 0) written += pdatalen;
            if (written == total_len && !fin) {
                break;
            }
            continue;
        }

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                ++m_stream_data_blocked_count;
                _log_with_date_time("send_stream_vecs_impl: STREAM_DATA_BLOCKED stream=" + tp::to_string(stream_id) + 
                    " written=" + tp::to_string(written) + 
                    " path=" + tp::string(debug_path), Log::ALL);
                // PPE_PENDING may be set from a previous WRITE_MORE; must flush before returning.
                flush_ppe();
                flush_batch();
                reschedule_loss_timer();
                return static_cast<int64_t>(written);
            }
            _log_with_date_time(
                "send_stream_vecs_impl error=" + tp::string(ngtcp2_strerror(static_cast<int>(nwrite))) +
                " stream=" + tp::to_string(stream_id) + " written=" + tp::to_string(written) + 
                " path=" + tp::string(debug_path),
                Log::ALL);
            if (nwrite != NGTCP2_ERR_STREAM_SHUT_WR) {
                _log_with_date_time(
                    "send_stream_vecs_impl error=" + tp::string(ngtcp2_strerror(static_cast<int>(nwrite))) +
                    " stream=" + tp::to_string(stream_id) + " path=" + tp::string(debug_path),
                    Log::WARN);
            }
            flush_ppe();
            flush_batch();
            reschedule_loss_timer();
            if (written > 0) return static_cast<int64_t>(written);
            return -1;
        }

        ppe_pending = false;  // successful writev clears internal PPE_PENDING
        if (nwrite > 0) {
            QUIC_SEND(m_peer, m_write_buf.data(), static_cast<std::size_t>(nwrite));
#line 1358
            record_packet(static_cast<std::size_t>(nwrite));
        }

        if (pdatalen > 0) {
            written += pdatalen;
        }

        if (written == total_len) {
            break;
        }

        if (pdatalen <= 0) {
            QUIC_STAT(
                if (m_stats.m_stats_enabled) {
                    ++m_stats.m_zero_len_sends;
                }
            )
#line 1370
            _log_with_date_time("send_stream_vecs_impl: loop break due to pdatalen<=0 stream=" + tp::to_string(stream_id) + 
                " written=" + tp::to_string(written) + 
                " path=" + tp::string(debug_path), Log::ALL);
            // Flow control, congestion control, or no more data for this stream in current packets.
            // DO NOT loop if we didn't send any stream data, to avoid infinite loop on connection-level frames.
            break;
        }
    }

    flush_ppe();
    flush_batch();
    _log_with_date_time("send_stream_vecs_impl leave: stream_id=" + tp::to_string(stream_id) + 
    " written=" + tp::to_string(written) + 
                    " path=" + tp::string(debug_path), Log::ALL);
    reschedule_loss_timer();
    return static_cast<int64_t>(written);
}

void QuicConnection::on_socket_writable() {
    if (!m_endpoint.send_available()) {
        close(m_close_waiting ? m_close_waiting_error : 0);
        return;
    }
    if (m_close_waiting) {
        m_close_waiting = false;
        close(m_close_waiting_error);
        return;
    }
    if (m_closed || !m_conn) return;
    resume_blocked_sends();
    on_pump_write(FUNC_NAME);
}

int64_t QuicConnection::send_gso(int64_t stream_id, const ngtcp2_vec* vecs,
                                std::size_t count, bool fin, bool& accepted) {
    accepted = false;
    if (m_close_waiting) return 0;
    // Reserve queue capacity before ngtcp2 consumes plaintext or creates ciphertext.
    if (!m_endpoint.aggregate_capacity(*this)) return 0;
    struct Context {
        int64_t id;
        tp::vector<ngtcp2_vec>& vecs;
        std::size_t written{0};
        bool fin;
        bool accepted{false};
        std::size_t encrypted{0};
        int error{0};
    } context{stream_id, m_gso_vecs, 0, fin};
    assert(!m_gso_context); // Connection sends stay on this endpoint's event loop.
    m_gso_vecs.clear();
    if (count) context.vecs.assign(vecs, vecs + count);
    m_gso_context = &context;
    auto callback = [](ngtcp2_conn* conn, ngtcp2_path* path, ngtcp2_pkt_info* pi,
                       uint8_t* dest, size_t size, ngtcp2_tstamp ts, void* user) -> ngtcp2_ssize {
        auto* self = static_cast<QuicConnection*>(user);
        auto& c = *static_cast<Context*>(self->m_gso_context);
        ngtcp2_ssize consumed = -1;
        auto n = ngtcp2_conn_writev_stream(conn, path, pi, dest, size, &consumed,
            NGTCP2_WRITE_STREAM_FLAG_PADDING | (c.fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0),
            c.id, c.vecs.data(), c.vecs.size(), ts);
        if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
            consumed = -1;
            n = ngtcp2_conn_write_pkt(conn, path, pi, dest, size, ts);
        }
        if (n < 0) {
            c.error = static_cast<int>(n);
            // Aggregate API discards its prefix on negative callback return.
            // Flush existing ciphertext first, then handle this error outside.
            return c.encrypted ? 0 : n;
        }
        if (n > 0) c.encrypted += static_cast<std::size_t>(n);
        if (n >= 0 && consumed >= 0) {
            c.accepted = true;
            c.written += static_cast<std::size_t>(consumed);
            auto left = static_cast<std::size_t>(consumed);
            bool empty = true;
            for (auto& v : c.vecs) {
                auto take = std::min(left, v.len);
                if (take) v.base += take;
                v.len -= take;
                left -= take;
                empty = empty && v.len == 0;
            }
            if (empty) { c.id = -1; c.fin = false; c.vecs.clear(); }
        }
        return n;
    };
    auto buffer = m_endpoint.acquire_aggregate_buffer();
    assert(buffer); // Queue capacity reserves room for this in-flight writer.
    ngtcp2_path_storage path;
    ngtcp2_path_storage_zero(&path);
    ngtcp2_pkt_info pi{};
    std::size_t segment = 0;
    // ngtcp2 clamps aggregation to its send quantum and updates packet transmit time.
    auto n = ngtcp2_conn_write_aggregate_pkt(m_conn, &path.path, &pi, buffer.data(),
        quic_udp_gso::aggregate_limit(ngtcp2_conn_get_path_max_tx_udp_payload_size2(m_conn)),
        &segment, callback, now_nanos());
    m_gso_context = nullptr;
    if (n > 0) {
        auto peer = m_peer;
        if (path.path.remote.addr && path.path.remote.addrlen > 0 &&
            static_cast<std::size_t>(path.path.remote.addrlen) <= peer.capacity()) {
            std::memcpy(peer.data(), path.path.remote.addr, path.path.remote.addrlen);
            peer.resize(path.path.remote.addrlen);
        }
        buffer.resize(static_cast<std::size_t>(n));
        m_endpoint.send_aggregate(peer, std::move(buffer), segment);
    }
    const int error = context.error ? context.error : (n < 0 ? static_cast<int>(n) : 0);
    if (error) {
        _log_with_date_time("QUIC aggregate write: " + tp::string(ngtcp2_strerror(error)), Log::WARN);
        if (error == NGTCP2_ERR_CLOSING || error == NGTCP2_ERR_DRAINING) defer_close();
    }
    accepted = context.accepted;
    reschedule_loss_timer();
    if (error == NGTCP2_ERR_STREAM_SHUT_WR || error == NGTCP2_ERR_STREAM_NOT_FOUND) return -1;
    return n < 0 && !context.written ? -1 : static_cast<int64_t>(context.written);
}

// ---- open_bidi_stream -------------------------------------------------------

int QuicConnection::open_bidi_stream(int64_t& stream_id) {
    if (!m_conn || m_closed) {
        return NGTCP2_ERR_INVALID_STATE;
    }
    int rv = ngtcp2_conn_open_bidi_stream(m_conn, &stream_id, nullptr);
    if (rv != 0) {
        if (rv != NGTCP2_ERR_STREAM_ID_BLOCKED) {
            _log_with_date_time("QuicConnection::open_bidi_stream: ngtcp2 error " + tp::string(ngtcp2_strerror(rv)), Log::WARN);
        } else {
            _log_with_date_time("QuicConnection::open_bidi_stream: stream ID blocked by peer flow control", Log::ALL);
        }
    }
    return rv;
}

void QuicConnection::set_stream_handler(int64_t stream_id, std::shared_ptr<QuicStreamHandler> handler) {
    // Unregister any stale h3 mapping before overwriting, keeping m_streams consistent.
    if (m_h3) {
        m_h3->unregister_stream(stream_id);
    }
    m_stream_handlers[stream_id] = std::move(handler);
}

int64_t QuicConnection::open_uni_stream() {
    if (!m_conn) return -1;
    int64_t id = -1;
    if (ngtcp2_conn_open_uni_stream(m_conn, &id, nullptr) != 0) return -1;
    return id;
}

QuicToHttp3Connect& QuicConnection::get_or_create_h3() {
    if (!m_h3) {
        m_h3 = std::make_unique<QuicToHttp3Connect>(*this);
        if (m_h3->init() && m_handshake_done && m_is_server) {
            int64_t ctrl = open_uni_stream();
            int64_t qenc = open_uni_stream();
            int64_t qdec = open_uni_stream();
            if (ctrl >= 0 && qenc >= 0 && qdec >= 0) {
                m_h3->bind_control_streams(ctrl, qenc, qdec);
            }
            m_h3->pump_h3_response(FUNC_NAME);
            pump_write(FUNC_NAME);
        }
    }
    return *m_h3;
}

void QuicConnection::remove_stream_handler(int64_t stream_id) {
    m_stream_handlers.erase(stream_id);
}

bool QuicConnection::forward_to_h1_upstream(int64_t stream_id, const uint8_t* data, std::size_t len, bool fin) {
    if (m_conn_type == ConnType::unknown) {
        m_conn_type = ConnType::other;
    }
    const auto& config = m_endpoint.config();
    const auto& h1_cfg = config.get_quic().h1_upstream;
    tp::string host;
    tp::string port_str;

    if (!h1_cfg.empty()) {
        auto colon_pos = h1_cfg.rfind(':');
        host = (colon_pos == tp::string::npos) ? h1_cfg : h1_cfg.substr(0, colon_pos);
        port_str = (colon_pos == tp::string::npos) ? "80" : h1_cfg.substr(colon_pos + 1);
    } else if (!config.get_remote_addr().empty()) {
        host = config.get_remote_addr();
        port_str = tp::to_string(config.get_remote_port());
    } else {
        _log_with_date_time("QuicConnection: stream " + tp::to_string(stream_id) +
                                " h1_upstream not configured, dropping",
                            Log::WARN);
        return false;
    }

    _log_with_date_time("QuicConnection: stream " + tp::to_string(stream_id) +
                            " " + (h1_cfg.empty() ? "falling back to " : "forwarding to ") 
                            + "h1_upstream " + host + ":" + port_str,
                        Log::INFO);

    auto& h3_mgr = get_or_create_h3();
    if (!h3_mgr.is_valid()) {
        _log_with_date_time("QuicConnection: stream " + tp::to_string(stream_id) +
                                " h3 manager init failed, dropping",
                            Log::ERROR);
        return false;
    }

    auto h3_handler = TP_MAKE_SHARED(QuicUpstreamHandler, shared_from_this(), stream_id, m_endpoint.io_context(), host, port_str);

    // Call set_stream_handler FIRST, because it performs stale mapping cleanup
    // which includes calling h3_mgr->unregister_stream(stream_id).
    set_stream_handler(stream_id, h3_handler);
    h3_mgr.register_stream(stream_id, h3_handler);

    if (data && len > 0) {
        h3_handler->on_stream_data(data, len, fin);
    } else if (fin) {
        h3_handler->on_stream_data(nullptr, 0, true);
    }

    if (!is_closed() && !is_quic_client_uni_stream(stream_id)) {
        // data is error so that handler is destroyed in h3_handler->on_stream_data
        h3_handler->h1_start();
    }
    return true;
}

// ---- close ------------------------------------------------------------------

void QuicConnection::defer_close(uint64_t app_error_code) {
    if (m_closed) return;
    if (m_close_pending_error == 0) m_close_pending_error = app_error_code;
    if (m_close_pending) return;
    m_close_pending = true;
    boost::asio::post(m_endpoint.io_context(),
        [self = shared_from_this(), endpoint = m_endpoint.shared_from_this()]() {
        self->m_close_pending = false;
        const auto app_error_code = self->m_close_pending_error;
        self->m_close_pending_error = 0;
        self->close(app_error_code);
    });
}

void QuicConnection::close(uint64_t app_error_code) {
    if (m_closed) {
        return;
    }
    if (m_in_read_pkt) {
        defer_close(app_error_code);
        return;
    }
    auto self = shared_from_this(); // Close callbacks can release the endpoint's last reference.
    const bool send_available = m_endpoint.send_available();
    if (send_available && m_endpoint.udp_gso_enabled() &&
        !m_endpoint.aggregate_capacity(*this)) {
        m_close_waiting = true;
        m_close_waiting_error = app_error_code;
        return; // Do not create a close packet until its FIFO slot is available.
    }
    m_closed = true;
    m_loss_timer.cancel();
    QUIC_STAT(
        if (m_stats.m_stats_armed) {
            m_stats.m_stats_timer->cancel();
        }
    )
#line 1512

    fail_all_unacked_buffers(boost::asio::error::broken_pipe);

    if (on_close_cb && (!m_is_server || !send_available)) {
        auto cb = std::move(on_close_cb);
        cb(this);
    } else if (on_close_cb) {
        m_loss_timer.expires_after(std::chrono::seconds(5));
        auto self = shared_from_this();
        m_loss_timer.async_wait([this, self](const boost::system::error_code& ec) {
            if (!ec && on_close_cb) {
                auto cb = std::move(on_close_cb);
                cb(this);
            }
        });
    }
    
    
    _log_with_date_time("QuicConnection: closing connection with error code " + 
                            tp::to_string(app_error_code) + " to peer " + 
                            tp::string(m_peer.address().to_string().c_str()) + ":" + 
                            tp::to_string(m_peer.port()),
                        Log::INFO);

    if (m_conn && send_available) {
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi{};
        ngtcp2_ccerr    ccerr;
        if (app_error_code == 0 && ngtcp2_conn_get_tls_alert(m_conn)) {
            ngtcp2_ccerr_set_tls_alert(&ccerr, ngtcp2_conn_get_tls_alert(m_conn), nullptr, 0);
        } else if (app_error_code == 0) {
            ngtcp2_ccerr_default(&ccerr);
        } else {
            ccerr.type       = NGTCP2_CCERR_TYPE_APPLICATION;
            ccerr.error_code = app_error_code;
            ccerr.reasonlen  = 0;
            ccerr.reason     = nullptr;
        }
        auto nwrite = ngtcp2_conn_write_connection_close(m_conn, &ps.path, &pi, m_write_buf.data(),
                                                         m_write_buf.size(), &ccerr, now_nanos());
        if (nwrite > 0) {
            QUIC_SEND(m_peer, m_write_buf.data(), static_cast<std::size_t>(nwrite));
#line 1555
        }
    }
    QUIC_STAT(
        write_stats_sample(true);
    )
#line 1557
}

// ---- handshake_completed ----------------------------------------------------

void QuicConnection::on_handshake_completed_impl() {
    if (m_handshake_done) {
        return;
    }
    m_handshake_done = true;
    const unsigned char* alpn = nullptr;
    unsigned int alpnlen = 0;
    SSL_get0_alpn_selected(m_ssl, &alpn, &alpnlen);
    tp::string alpn_str = alpn ? tp::string(reinterpret_cast<const char*>(alpn), alpnlen) : "none";

    _log_with_date_time("QuicConnection: handshake completed (role=" +
                            tp::string(m_is_server ? "server" : "client") + ", peer=" +
                            tp::string(m_peer.address().to_string().c_str()) + ":" +
                            tp::to_string(m_peer.port()) + ", alpn=" + alpn_str + ")",
                        Log::INFO);

    (void)alpn;
    (void)alpnlen;

    if (on_handshake_completed_cb) {
        on_handshake_completed_cb();
    }
    if (!m_is_server) {
        uint32_t ping_ms = m_endpoint.config().get_quic().ping_interval_ms;
        if (ping_ms > 0) {
            ngtcp2_conn_set_keep_alive_timeout(m_conn,
                static_cast<ngtcp2_duration>(ping_ms) * 1'000'000ULL);
        }
    }
}

// ---- loss timer -------------------------------------------------------------

void QuicConnection::reschedule_loss_timer() {
    if (m_closed || !m_conn) {
        return;
    }

    auto expiry = ngtcp2_conn_get_expiry2(m_conn);
    if (expiry == UINT64_MAX) {
        if (m_last_timer_expiry != UINT64_MAX) {
            m_loss_timer.cancel();
            m_last_timer_expiry = UINT64_MAX;
        }
        return;
    }

    uint64_t now_ns;
    if (m_endpoint.udp_gso_enabled()) {
        now_ns = now_nanos();
        if (quic_udp_gso::keep_timer(m_last_timer_expiry, expiry, now_ns)) return;
    } else
    {
        if (expiry == m_last_timer_expiry) return;
        now_ns = now_nanos();
    }

    auto delay_ns  = expiry > now_ns ? expiry - now_ns : 0;
    auto delay_dur = std::chrono::nanoseconds(delay_ns);

    m_last_timer_expiry = expiry;

    m_loss_timer.expires_after(delay_dur);
    auto self = shared_from_this();
    m_loss_timer.async_wait([this, self](const boost::system::error_code& ec) {
        if (ec) {
            if (ec != boost::asio::error::operation_aborted) {
                _log_with_date_time("QuicConnection: loss timer wait error: " + tp::string(ec.message().c_str()), Log::WARN);
            }
            return;
        }
        if (m_closed) {
            return;
        }
        QUIC_STAT(
            // Aggregate ngtcp2 timer: includes loss/PTO, ACK, pacing and idle expiry.
            StatsReasonScope reason(*this, SendReason::loss);
        )
#line 1630
        auto now = now_nanos();
        m_last_timer_expiry = 0; // reset
        auto rv = ngtcp2_conn_handle_expiry(m_conn, now);
        if (rv != 0) {
            _log_with_date_time(
                "QuicConnection: ngtcp2_conn_handle_expiry: " + tp::string(ngtcp2_strerror(rv)),
                Log::WARN);
            if (rv == NGTCP2_ERR_IDLE_CLOSE || rv == NGTCP2_ERR_DROP_CONN || rv == NGTCP2_ERR_HANDSHAKE_TIMEOUT) {
                close();
                return;
            }
        }

        schedule_send_wakeup();
        on_pump_write(FUNC_NAME);
    });
}



void QuicConnection::stream_extend_window(int64_t stream_id, std::size_t n) {
    QUIC_STAT(
        StatsReasonScope reason(*this, SendReason::flow);
    )
#line 1651
    if (m_conn && !m_closed && n > 0) {
        ngtcp2_conn_extend_max_stream_offset(m_conn, stream_id, n);
        ngtcp2_conn_extend_max_offset(m_conn, n);
        // Trigger active pump write to immediately transmit window updates (MAX_DATA / MAX_STREAM_DATA) to prevent deadlock.
        // Note: ngtcp2 has internal coalescing and thresholds for window updates (usually 1/2 of initial window size).
        // It won't actually queue frames or generate UDP packets until the threshold is crossed, 
        // avoiding traffic waste from small incremental window updates.
        if (!m_in_read_pkt) {
            on_pump_write(FUNC_NAME);
        }
    }
}

void QuicConnection::conn_extend_window(std::size_t n) {
    QUIC_STAT(
        StatsReasonScope reason(*this, SendReason::flow);
    )
#line 1665
    if (m_conn && !m_closed && n > 0) {
        ngtcp2_conn_extend_max_offset(m_conn, n);
        // Trigger active pump write to immediately transmit window updates (MAX_DATA / MAX_STREAM_DATA) to prevent deadlock.
        // Note: ngtcp2 has internal coalescing and thresholds for window updates (usually 1/2 of initial window size).
        // It won't actually queue frames or generate UDP packets until the threshold is crossed, 
        // avoiding traffic waste from small incremental window updates.
        if (!m_in_read_pkt) {
            on_pump_write(FUNC_NAME);
        }
    }
}

void QuicConnection::reset_stream(int64_t stream_id, uint64_t app_error_code) {
    if (m_conn && !m_closed) {
        int rv = ngtcp2_conn_shutdown_stream(m_conn, 0, stream_id, app_error_code);
        if (rv != 0 && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
            _log_with_date_time("QuicConnection: ngtcp2_conn_shutdown_stream failed for stream " + 
                                tp::to_string(stream_id) + ": " + tp::string(ngtcp2_strerror(rv)), Log::WARN);
        }
        if (!m_in_read_pkt) {
            on_pump_write(FUNC_NAME);
        }
    }
}

void QuicConnection::stop_reading_stream(int64_t stream_id, uint64_t app_error_code) {
    if (m_conn && !m_closed) {
        int rv = ngtcp2_conn_shutdown_stream_read(m_conn, 0, stream_id, app_error_code);
        if (rv != 0) {
            _log_with_date_time("QuicConnection: ngtcp2_conn_shutdown_stream_read failed for stream " +
                                tp::to_string(stream_id) + ": " + tp::string(ngtcp2_strerror(rv)), Log::WARN);
        }
        if (!m_in_read_pkt && !m_in_pump_write) {
            on_pump_write(FUNC_NAME);
        }
    }
}

void QuicConnection::on_extend_max_stream_data(int64_t stream_id, uint64_t max_data) {
    QUIC_STAT(
        StatsReasonScope reason(*this, SendReason::flow);
        if (m_stats.m_stats_enabled && m_in_read_pkt) m_stats.m_stats_read_flow = true;
    )
#line 1704
    _log_with_date_time("on_extend_max_stream_data: stream=" + tp::to_string(stream_id) + 
                        " max_data=" + tp::to_string(max_data), Log::ALL);
    if (m_h3) {
        m_h3->unblock_stream(stream_id);
    }
    on_pump_write(FUNC_NAME);
}

bool QuicConnection::is_stream_flow_control_blocked(int64_t stream_id) const {
    if (!m_conn) return false;
    return ngtcp2_conn_get_max_stream_data_left(m_conn, stream_id) == 0;
}
#if TROJAN_QUIC_STATS

void QuicConnection::send_udp(const boost::asio::ip::udp::endpoint& dest, const uint8_t* data, std::size_t len) {
    if (!m_stats.m_stats_enabled) {
        m_endpoint.send_packet(dest, data, len);
        return;
    }
    const bool sent = m_endpoint.send_packet(dest, data, len);
    if (!sent) ++m_stats.m_udp_send_errors;
    if (sent && len != 0) {
        ++m_stats.m_stats_udp_sent;
        ++m_stats.m_reason_stats[static_cast<unsigned>(m_stats.m_stats_reason)].packets;
        stats_observe_gap(true);
    }
}

void QuicConnection::stats_zero_write_expiry() {
    const auto expiry = ngtcp2_conn_get_expiry2(m_conn);
    if (expiry == UINT64_MAX) {
        m_stats.m_zero_write_expiry_last = UINT64_MAX;
        return;
    }
    const auto now = now_nanos();
    m_stats.m_zero_write_expiry_last = expiry > now ? expiry - now : 0;
    m_stats.m_zero_write_expiry_max = std::max(m_stats.m_zero_write_expiry_max, m_stats.m_zero_write_expiry_last);
}

void QuicConnection::stats_observe_gap(bool sent) {
    if (!m_conn) return;
    ngtcp2_conn_info info{};
    ngtcp2_conn_get_conn_info2(m_conn, &info);
    bool open = false;
    if (info.bytes_in_flight < info.cwnd && ngtcp2_conn_get_max_data_left2(m_conn) != 0) {
        for (const auto& [id, queue] : m_conn_unacked_bufs) {
            if (ngtcp2_conn_get_max_stream_data_left2(m_conn, id) == 0) continue;
            for (const auto& buf : queue->buffers) {
                if (buf->m_buf && buf->m_sending_offset < buf->m_buf->size()) { open = true; break; }
            }
            if (open) break;
        }
    }
    const auto now = now_nanos();
    if (open && m_stats.m_open_gap_start != 0)
        m_stats.m_open_gap_max = std::max(m_stats.m_open_gap_max, now - m_stats.m_open_gap_start);
    m_stats.m_open_gap_start = open ? (sent || m_stats.m_open_gap_start == 0 ? now : m_stats.m_open_gap_start) : 0;
}

void QuicConnection::start_stats_sampler() {
    if (!m_stats.m_stats_enabled || m_stats.m_stats_armed || !m_conn) {
        return;
    }
    m_stats.m_stats_timer = TP_MAKE_UNIQUE(boost::asio::steady_timer, m_endpoint.io_context());
    m_stats.m_stats_armed = true;
    m_stats.m_stats_origin = std::chrono::steady_clock::now();
    arm_stats_timer();
}

void QuicConnection::arm_stats_timer() {
    auto weak = weak_from_this();
    m_stats.m_stats_timer->expires_after(std::chrono::milliseconds(100));
    m_stats.m_stats_timer->async_wait(tp::bind_mem_alloc([weak](const boost::system::error_code& ec) {
        auto self = weak.lock();
        if (!self || ec || self->m_closed || !self->m_conn) {
            return;
        }
        self->write_stats_sample(false);
        if (!self->m_closed) {
            self->arm_stats_timer();
        }
    }));
}

std::size_t QuicConnection::stats_app_queue_bytes(int64_t& stream_id, bool& have_stream) const {
    std::size_t bytes = 0;
    stream_id = m_stats.m_stats_stream_id;
    have_stream = m_stats.m_stats_have_stream;
    bool picked = false;
    std::size_t best = 0;
    for (const auto& [id, queue] : m_conn_unacked_bufs) {
        std::size_t pending = 0;
        for (const auto& buf : queue->buffers) {
            if (!buf->m_buf) {
                continue;
            }
            const auto size = buf->m_buf->size();
            if (buf->m_sending_offset < size) {
                pending += size - buf->m_sending_offset;
            }
        }
        bytes += pending;
        if (!picked || pending > best) {
            best = pending;
            stream_id = id;
            have_stream = true;
            picked = true;
        }
    }
    return bytes;
}

void QuicConnection::write_stats_sample(bool final_sample) {
    if (!m_stats.m_stats_enabled || !m_stats.m_stats_armed || !m_conn) {
        return;
    }
    if (final_sample) {
        if (m_stats.m_stats_final_written) {
            return;
        }
        m_stats.m_stats_final_written = true;
    }

    ngtcp2_conn_info info{};
    ngtcp2_conn_get_conn_info2(m_conn, &info);

    int64_t stream_id = -1;
    bool have_stream = false;
    const auto queue_bytes = stats_app_queue_bytes(stream_id, have_stream);

    char stream_credit[32] = "";
    if (have_stream) {
        std::snprintf(stream_credit, sizeof(stream_credit), "%llu",
          static_cast<unsigned long long>(ngtcp2_conn_get_max_stream_data_left2(m_conn, stream_id)));
    }

    const auto t_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - m_stats.m_stats_origin)
                        .count();

    stats_observe_gap(false);
    char line[2048];
    std::snprintf(line, sizeof(line),
      "%lld,%s,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%s,%llu,%llu,%llu,%llu,%llu",
      static_cast<long long>(t_ms), m_is_server ? "server" : "client",
      static_cast<unsigned long long>(info.cwnd), static_cast<unsigned long long>(info.ssthresh),
      static_cast<unsigned long long>(info.bytes_in_flight), static_cast<unsigned long long>(info.latest_rtt),
      static_cast<unsigned long long>(info.min_rtt), static_cast<unsigned long long>(info.smoothed_rtt),
      static_cast<unsigned long long>(info.rttvar), static_cast<unsigned long long>(info.pkt_sent),
      static_cast<unsigned long long>(info.bytes_sent), static_cast<unsigned long long>(info.pkt_recv),
      static_cast<unsigned long long>(info.bytes_recv), static_cast<unsigned long long>(info.pkt_lost),
      static_cast<unsigned long long>(info.bytes_lost), static_cast<unsigned long long>(info.pkt_discarded),
      static_cast<unsigned long long>(ngtcp2_conn_get_max_data_left2(m_conn)),
      static_cast<unsigned long long>(ngtcp2_conn_get_streams_bidi_left2(m_conn)), stream_credit,
      static_cast<unsigned long long>(queue_bytes), static_cast<unsigned long long>(m_stream_data_blocked_count),
      static_cast<unsigned long long>(m_write_more_count), static_cast<unsigned long long>(m_stats.m_zero_len_sends),
      static_cast<unsigned long long>(m_stats.m_udp_send_errors));
    // All added counts are cumulative; only gap maximum/baseline reset per row.
    std::size_t used = std::strlen(line);
    for (const auto& counts : m_stats.m_reason_stats) {
        used += static_cast<std::size_t>(std::snprintf(line + used, sizeof(line) - used,
            ",%llu,%llu,%llu,%llu", static_cast<unsigned long long>(counts.pump),
            static_cast<unsigned long long>(counts.data), static_cast<unsigned long long>(counts.vecs),
            static_cast<unsigned long long>(counts.packets)));
    }
    char expiry_ms[32] = "";
    if (m_stats.m_zero_write_expiry_last != UINT64_MAX)
        std::snprintf(expiry_ms, sizeof(expiry_ms), "%.6f", m_stats.m_zero_write_expiry_last / 1e6);
    std::snprintf(line + used, sizeof(line) - used, ",%llu,%llu,%llu,%.6f,%s,%.6f",
        static_cast<unsigned long long>(m_stats.m_retry_arms), static_cast<unsigned long long>(m_stats.m_retry_expires_bytes),
        static_cast<unsigned long long>(m_stats.m_retry_expires_empty), m_stats.m_open_gap_max / 1e6,
        expiry_ms, m_stats.m_zero_write_expiry_max / 1e6);
    quic_stats_file().write(line, final_sample);
    m_stats.m_open_gap_max = 0;
    m_stats.m_zero_write_expiry_last = UINT64_MAX;
    m_stats.m_zero_write_expiry_max = 0;
    if (m_stats.m_open_gap_start != 0) m_stats.m_open_gap_start = now_nanos();
}
#endif
