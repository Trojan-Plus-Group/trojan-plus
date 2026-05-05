/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_connection.h"

#include <chrono>
#include <cstring>

#include <ngtcp2/ngtcp2_crypto_wolfssl.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "core/log.h"
#include "quic_endpoint.h"
#include "quic_tls_ctx.h"

// ---- helpers ----------------------------------------------------------------

static ngtcp2_tstamp now_nanos() {
    return static_cast<ngtcp2_tstamp>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
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
                                        void* /*user_data*/) {
    return ngtcp2_crypto_recv_crypto_data_cb(conn, level, offset, data, datalen, nullptr);
}

int QuicConnection::cb_handshake_completed(ngtcp2_conn* /*conn*/, void* user_data) {
    static_cast<QuicConnection*>(user_data)->on_handshake_completed_impl();
    return 0;
}

int QuicConnection::cb_recv_stream_data(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id,
                                        uint64_t /*offset*/, const uint8_t* data, size_t datalen,
                                        void* user_data, void* /*stream_user_data*/) {
    auto* self = static_cast<QuicConnection*>(user_data);
    if (self->on_stream_data_cb) {
        bool fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
        self->on_stream_data_cb(stream_id, data, datalen, fin);
    }
    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(conn, datalen);
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
                                    uint64_t /*app_error_code*/, void* user_data,
                                    void* /*stream_user_data*/) {
    auto* self = static_cast<QuicConnection*>(user_data);
    if (self->on_stream_close_cb) {
        self->on_stream_close_cb(stream_id);
    }
    return 0;
}

void QuicConnection::cb_rand(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* /*ctx*/) {
    wolfSSL_RAND_bytes(dest, static_cast<int>(destlen));
}

int QuicConnection::cb_get_new_connection_id(ngtcp2_conn* /*conn*/, ngtcp2_cid* cid,
                                             ngtcp2_stateless_reset_token* token,
                                             size_t cidlen, void* user_data) {
    cid->datalen = cidlen;
    wolfSSL_RAND_bytes(cid->data, static_cast<int>(cidlen));
    wolfSSL_RAND_bytes(reinterpret_cast<uint8_t*>(token), NGTCP2_STATELESS_RESET_TOKENLEN);
    
    auto* self = static_cast<QuicConnection*>(user_data);
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
                                                     uint64_t /*max_streams*/,
                                                     void* /*user_data*/) {
    return 0;
}

// ---- constructor / destructor -----------------------------------------------

QuicConnection::QuicConnection(QuicEndpoint& endpoint, std::shared_ptr<QuicTlsCtx> tls_ctx,
                               const boost::asio::ip::udp::endpoint& peer)
    : m_endpoint(endpoint),
      m_tls_ctx(std::move(tls_ctx)),
      m_peer(peer),
      m_loss_timer(endpoint.io_context()),
      m_write_buf(NGTCP2_MAX_UDP_PAYLOAD_SIZE) {}

QuicConnection::~QuicConnection() {
    if (m_conn) {
        ngtcp2_conn_del(m_conn);
    }
    if (m_ssl) {
        wolfSSL_free(m_ssl);
    }
}

// ---- path helper ------------------------------------------------------------

ngtcp2_path QuicConnection::make_path(const boost::asio::ip::udp::endpoint& local_ep,
                                      const boost::asio::ip::udp::endpoint& remote_ep) {
    fill_sockaddr_union(local_ep, m_local_su, m_local_len);
    fill_sockaddr_union(remote_ep, m_remote_su, m_remote_len);
    return ngtcp2_path{
        .local  = {.addr = &m_local_su.sa, .addrlen = m_local_len},
        .remote = {.addr = &m_remote_su.sa, .addrlen = m_remote_len},
    };
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

    // Wire up conn_ref so wolfSSL crypto callbacks can reach our ngtcp2_conn.
    m_conn_ref.get_conn  = &QuicConnection::get_conn_cb;
    m_conn_ref.user_data = this;
    wolfSSL_set_app_data(m_ssl, &m_conn_ref);

    static constexpr ngtcp2_callbacks callbacks{
        .recv_client_initial       = cb_recv_client_initial,
        .recv_crypto_data          = cb_recv_crypto_data,
        .handshake_completed       = cb_handshake_completed,
        .encrypt                   = ngtcp2_crypto_encrypt_cb,
        .decrypt                   = ngtcp2_crypto_decrypt_cb,
        .hp_mask                   = ngtcp2_crypto_hp_mask_cb,
        .recv_stream_data          = cb_recv_stream_data,
        .stream_open               = cb_stream_open,
        .stream_close              = cb_stream_close,
        .rand                      = cb_rand,
        .get_new_connection_id2    = cb_get_new_connection_id,
        .update_key                = cb_update_key,
        .delete_crypto_aead_ctx    = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx  = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .version_negotiation       = ngtcp2_crypto_version_negotiation_cb,
        .get_path_challenge_data2  = ngtcp2_crypto_get_path_challenge_data2_cb,
    };

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_nanos();

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local  = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_data                    = 4 * 1024 * 1024;
    params.initial_max_streams_bidi            = 100;
    params.initial_max_streams_uni             = 0;
    params.max_idle_timeout = static_cast<ngtcp2_duration>(
        m_endpoint.config().get_quic().max_idle_timeout_ms) * 1'000'000ULL;
    params.original_dcid         = *dcid;
    params.original_dcid_present = 1;
    // No retry token for Phase 1.
    params.stateless_reset_token_present = 0;

    auto path = make_path(local_ep, remote_ep);

    // Choose a new SCID for the server.
    ngtcp2_cid sv_scid;
    sv_scid.datalen = kServerScidLen;
    wolfSSL_RAND_bytes(sv_scid.data, static_cast<int>(kServerScidLen));

    // ngtcp2_conn_server_new(conn, dcid, scid, path, version, ...):
    //   dcid = the client's SCID (server uses it as its destination CID)
    //   scid = the server's own SCID (newly generated sv_scid)
    int rv = ngtcp2_conn_server_new(&m_conn, scid ? scid : dcid, &sv_scid, &path, version,
                                    &callbacks, &settings, &params, nullptr, this);
    if (rv != 0) {
        _log_with_date_time(
            "QuicConnection::init_server: ngtcp2_conn_server_new: " + tp::string(ngtcp2_strerror(rv)),
            Log::ERROR);
        wolfSSL_free(m_ssl);
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
        return false;
    }

    pump_write();
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
    wolfSSL_set_app_data(m_ssl, &m_conn_ref);

    // Set SNI.
    const auto& ssl_cfg = m_endpoint.config().get_ssl();
    const auto& sni     = !ssl_cfg.sni.empty() ? ssl_cfg.sni : m_endpoint.config().get_remote_addr();
    if (!sni.empty()) {
        wolfSSL_UseSNI(m_ssl, WOLFSSL_SNI_HOST_NAME, sni.c_str(),
                       static_cast<uint16_t>(sni.size()));
    }

    static constexpr ngtcp2_callbacks callbacks{
        .client_initial               = ngtcp2_crypto_client_initial_cb,
        .recv_crypto_data             = cb_recv_crypto_data,
        .handshake_completed          = cb_handshake_completed,
        .recv_version_negotiation     = nullptr,
        .encrypt                      = ngtcp2_crypto_encrypt_cb,
        .decrypt                      = ngtcp2_crypto_decrypt_cb,
        .hp_mask                      = ngtcp2_crypto_hp_mask_cb,
        .recv_stream_data             = cb_recv_stream_data,
        .stream_close                 = cb_stream_close,
        .recv_retry                   = ngtcp2_crypto_recv_retry_cb,
        .extend_max_local_streams_bidi = cb_extend_max_local_streams_bidi,
        .rand                         = cb_rand,
        .get_new_connection_id2       = cb_get_new_connection_id,
        .update_key                   = cb_update_key,
        .handshake_confirmed          = cb_handshake_completed, // reuse for confirmed event
        .delete_crypto_aead_ctx       = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
        .delete_crypto_cipher_ctx     = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
        .version_negotiation          = ngtcp2_crypto_version_negotiation_cb,
        .get_path_challenge_data2     = ngtcp2_crypto_get_path_challenge_data2_cb,
    };

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_nanos();

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local  = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_data                    = 4 * 1024 * 1024;
    params.initial_max_streams_bidi            = 100;
    params.initial_max_streams_uni             = 0;
    params.max_idle_timeout = static_cast<ngtcp2_duration>(
        m_endpoint.config().get_quic().max_idle_timeout_ms) * 1'000'000ULL;

    ngtcp2_cid dcid, scid;
    dcid.datalen = 18;
    wolfSSL_RAND_bytes(dcid.data, 18);
    scid.datalen = 17;
    wolfSSL_RAND_bytes(scid.data, 17);

    auto path = make_path(local_ep, remote_ep);

    int rv = ngtcp2_conn_client_new(&m_conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                                    &callbacks, &settings, &params, nullptr, this);
    if (rv != 0) {
        _log_with_date_time(
            "QuicConnection::init_client: ngtcp2_conn_client_new: " + tp::string(ngtcp2_strerror(rv)),
            Log::ERROR);
        wolfSSL_free(m_ssl);
        m_ssl = nullptr;
        return false;
    }

    ngtcp2_conn_set_tls_native_handle(m_conn, m_ssl);

    pump_write();
    reschedule_loss_timer();
    return true;
}

// ---- packet receive ---------------------------------------------------------

void QuicConnection::on_packet(const uint8_t* data, std::size_t datalen,
                               const boost::asio::ip::udp::endpoint& local_ep,
                               const boost::asio::ip::udp::endpoint& remote_ep) {
    if (m_closed || !m_conn) {
        return;
    }
    auto path = make_path(local_ep, remote_ep);
    int  rv   = ngtcp2_conn_read_pkt(m_conn, &path, nullptr, data, datalen, now_nanos());
    if (rv != 0) {
        if (rv != NGTCP2_ERR_DRAINING && rv != NGTCP2_ERR_DROP_CONN) {
            _log_with_date_time(
                "QuicConnection::on_packet: ngtcp2_conn_read_pkt: " + tp::string(ngtcp2_strerror(rv)),
                Log::WARN);
        }
        if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CRYPTO) {
            close();
        }
        return;
    }
    pump_write();
    reschedule_loss_timer();
}

// ---- pump_write -------------------------------------------------------------

void QuicConnection::pump_write() {
    if (m_closed || !m_conn) {
        return;
    }

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi{};

    for (;;) {
        auto nwrite = ngtcp2_conn_write_pkt(m_conn, &ps.path, &pi, m_write_buf.data(), m_write_buf.size(),
                                            now_nanos());
        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE) {
                continue;
            }
            _log_with_date_time(
                "QuicConnection::pump_write: " + tp::string(ngtcp2_strerror(static_cast<int>(nwrite))),
                Log::WARN);
            if (nwrite == NGTCP2_ERR_CLOSING || nwrite == NGTCP2_ERR_DRAINING) {
                m_closed = true;
            }
            return;
        }
        if (nwrite == 0) {
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
        m_endpoint.send_packet(dest, m_write_buf.data(), static_cast<std::size_t>(nwrite));
    }
}

// ---- send_stream_data -------------------------------------------------------

int64_t QuicConnection::send_stream_data(int64_t stream_id, const uint8_t* data, std::size_t datalen,
                                      bool fin) {
    if (m_closed || !m_conn) {
        return -1;
    }

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_pkt_info pi{};

    std::size_t written = 0;
    bool fin_sent = false;

    for (;;) {
        std::size_t remain = datalen - written;
        ngtcp2_vec vec{.base = const_cast<uint8_t*>(data + written), .len = remain};
        ngtcp2_ssize pdatalen = -1;

        bool send_fin = fin && !fin_sent && (remain == 0 || written + remain == datalen);
        uint32_t flags = 0;
        if (send_fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

        auto nwrite = ngtcp2_conn_writev_stream(m_conn, &ps.path, &pi, m_write_buf.data(), m_write_buf.size(),
                                                &pdatalen, flags,
                                                stream_id, &vec, 1, now_nanos());

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                // Not a fatal error, just blocked. Return what we wrote so far (or 0).
                return static_cast<int64_t>(written);
            }
            if (nwrite != NGTCP2_ERR_STREAM_SHUT_WR) {
                _log_with_date_time(
                    "QuicConnection::send_stream_data: " + tp::string(ngtcp2_strerror(static_cast<int>(nwrite))),
                    Log::WARN);
            }
            if (written > 0) return static_cast<int64_t>(written);
            return -1;
        }

        if (nwrite > 0) {
            m_endpoint.send_packet(m_peer, m_write_buf.data(), static_cast<std::size_t>(nwrite));
        }

        if (pdatalen > 0) {
            written += pdatalen;
        }

        if (send_fin && pdatalen >= 0) {
            fin_sent = true;
        }

        if (written == datalen && (fin_sent || !fin)) {
            break;
        }

        if (nwrite == 0 && pdatalen <= 0) {
            // Flow control or congestion control blocked. Data may be lost if not buffered.
            break;
        }
    }
    return static_cast<int64_t>(written);
}

// ---- open_bidi_stream -------------------------------------------------------

int64_t QuicConnection::open_bidi_stream() {
    if (!m_conn) {
        return -1;
    }
    int64_t stream_id = -1;
    if (ngtcp2_conn_open_bidi_stream(m_conn, &stream_id, nullptr) != 0) {
        return -1;
    }
    return stream_id;
}

// ---- close ------------------------------------------------------------------

void QuicConnection::close() {
    if (m_closed) {
        return;
    }
    m_closed = true;
    m_loss_timer.cancel();
    if (m_conn) {
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi{};
        ngtcp2_ccerr    ccerr;
        ngtcp2_ccerr_default(&ccerr);
        ngtcp2_conn_write_connection_close(m_conn, &ps.path, &pi, m_write_buf.data(), m_write_buf.size(), &ccerr,
                                          now_nanos());
    }
}

// ---- handshake_completed ----------------------------------------------------

void QuicConnection::on_handshake_completed_impl() {
    if (m_handshake_done) {
        return;
    }
    m_handshake_done = true;
    _log_with_date_time("QuicConnection: handshake completed (role=" +
                            tp::string(m_is_server ? "server" : "client") + ", peer=" +
                            tp::string(m_peer.address().to_string().c_str()) + ":" +
                            tp::to_string(m_peer.port()),
                        Log::INFO);
    if (on_handshake_completed_cb) {
        on_handshake_completed_cb();
    }
}

// ---- loss timer -------------------------------------------------------------

void QuicConnection::reschedule_loss_timer() {
    if (m_closed || !m_conn) {
        return;
    }

    auto expiry = ngtcp2_conn_get_expiry2(m_conn);
    if (expiry == UINT64_MAX) {
        m_loss_timer.cancel();
        return;
    }

    auto now_ns    = now_nanos();
    auto delay_ns  = expiry > now_ns ? expiry - now_ns : 0;
    auto delay_dur = std::chrono::nanoseconds(delay_ns);

    m_loss_timer.expires_after(delay_dur);
    auto self = shared_from_this();
    m_loss_timer.async_wait([this, self](const boost::system::error_code& ec) {
        if (ec || m_closed) {
            return;
        }
        auto rv = ngtcp2_conn_handle_expiry(m_conn, now_nanos());
        if (rv != 0) {
            _log_with_date_time(
                "QuicConnection: ngtcp2_conn_handle_expiry: " + tp::string(ngtcp2_strerror(rv)),
                Log::WARN);
            if (rv == NGTCP2_ERR_IDLE_CLOSE) {
                close();
                return;
            }
        }
        pump_write();
        reschedule_loss_timer();
    });
}
