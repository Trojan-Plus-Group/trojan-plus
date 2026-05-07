/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _QUIC_CONNECTION_H_
#define _QUIC_CONNECTION_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "mem/memallocator.h"
#include "quic_stream_handler.h"

class QuicEndpoint;
class QuicTlsCtx;
class QuicProxySession;

struct WOLFSSL;

// One ngtcp2_conn + its per-connection WOLFSSL handle.
// All I/O is driven through the owning QuicEndpoint's UDP socket.
class QuicConnection : public std::enable_shared_from_this<QuicConnection> {
  public:
    QuicConnection(QuicEndpoint& endpoint, std::shared_ptr<QuicTlsCtx> tls_ctx,
                   const boost::asio::ip::udp::endpoint& peer);
    ~QuicConnection();

    QuicConnection(const QuicConnection&)            = delete;
    QuicConnection& operator=(const QuicConnection&) = delete;

    // Initialise as a server connection. First packet bytes must be passed so
    // that ngtcp2 can process the Client Initial. If out_sv_scid is non-null,
    // the server's chosen SCID (sv_scid) is written there; callers should also
    // insert the connection into their routing table under that key so that
    // post-handshake packets (DCID = sv_scid) are dispatched correctly.
    bool init_server(const uint8_t* data, std::size_t datalen,
                     const boost::asio::ip::udp::endpoint& local_ep,
                     const boost::asio::ip::udp::endpoint& remote_ep,
                     const ngtcp2_cid* dcid, const ngtcp2_cid* scid,
                     uint32_t version,
                     ngtcp2_cid* out_sv_scid = nullptr);

    // Initialise as a client connection and start the QUIC handshake.
    bool init_client(const boost::asio::ip::udp::endpoint& local_ep,
                     const boost::asio::ip::udp::endpoint& remote_ep);

    // Feed an incoming UDP datagram to ngtcp2.
    void on_packet(const uint8_t* data, std::size_t datalen,
                   const boost::asio::ip::udp::endpoint& local_ep,
                   const boost::asio::ip::udp::endpoint& remote_ep);

    // Write pending stream data (call after every read or timer event).
    void pump_write();

    // Send data on an existing bidi stream. Returns false on error.
    int64_t send_stream_data(int64_t stream_id, const uint8_t* data, std::size_t datalen, bool fin);

    // Open a new client-initiated bidi stream. Returns -1 on error.
    int64_t open_bidi_stream();

    // Handler management
    void set_stream_handler(int64_t stream_id, std::shared_ptr<QuicStreamHandler> handler);
    void remove_stream_handler(int64_t stream_id);

    // Gracefully close the connection.
    void close();

    [[nodiscard]] bool is_closed() const { return m_closed; }
    [[nodiscard]] bool is_handshake_done() const { return m_handshake_done; }
    [[nodiscard]] const boost::asio::ip::udp::endpoint& peer() const { return m_peer; }
    [[nodiscard]] ngtcp2_conn* native_handle() const { return m_conn; }

    static constexpr size_t kServerScidLen = 18;

    // Callback invoked on handshake completion (client: after server Finished).
    std::function<void()> on_handshake_completed_cb;
    // Callback invoked when stream data arrives (stream_id, data, len, fin).
    std::function<void(int64_t, const uint8_t*, std::size_t, bool)> on_stream_data_cb;
    // Callback invoked when a new remote-initiated stream is opened.
    std::function<void(int64_t)> on_stream_open_cb;
    // Callback invoked when a stream is closed.
    std::function<void(int64_t)> on_stream_close_cb;
    // Callback invoked when a new Connection ID is generated.
    std::function<void(const ngtcp2_cid*)> on_new_connection_id_cb;

  private:
    // ngtcp2 static callbacks — forward to instance methods.
    static int cb_recv_client_initial(ngtcp2_conn*, const ngtcp2_cid* dcid, void* user_data);
    static int cb_recv_crypto_data(ngtcp2_conn*, ngtcp2_encryption_level level,
                                   uint64_t offset, const uint8_t* data, size_t datalen, void* user_data);
    static int cb_handshake_completed(ngtcp2_conn*, void* user_data);
    static int cb_recv_stream_data(ngtcp2_conn*, uint32_t flags, int64_t stream_id,
                                   uint64_t offset, const uint8_t* data, std::size_t datalen,
                                   void* user_data, void* stream_user_data);
    static int cb_stream_open(ngtcp2_conn*, int64_t stream_id, void* user_data);
    static int cb_stream_close(ngtcp2_conn*, uint32_t flags, int64_t stream_id,
                               uint64_t app_error_code, void* user_data, void* stream_user_data);
    static void cb_rand(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx);
    static int cb_get_new_connection_id(ngtcp2_conn*, ngtcp2_cid* cid,
                                        ngtcp2_stateless_reset_token* token,
                                        size_t cidlen, void* user_data);
    static int cb_update_key(ngtcp2_conn*, uint8_t* rx_secret, uint8_t* tx_secret,
                             ngtcp2_crypto_aead_ctx* rx_aead_ctx, uint8_t* rx_iv,
                             ngtcp2_crypto_aead_ctx* tx_aead_ctx, uint8_t* tx_iv,
                             const uint8_t* current_rx_secret, const uint8_t* current_tx_secret,
                             size_t secretlen, void* user_data);
    static int cb_extend_max_local_streams_bidi(ngtcp2_conn*, uint64_t max_streams, void* user_data);

    // ngtcp2_crypto_conn_ref get_conn callback.
    static ngtcp2_conn* get_conn_cb(ngtcp2_crypto_conn_ref* ref);

    // Internal helpers.
    ngtcp2_path make_path(const boost::asio::ip::udp::endpoint& local_ep,
                          const boost::asio::ip::udp::endpoint& remote_ep);
    void reschedule_loss_timer();
    void on_handshake_completed_impl();

    QuicEndpoint& m_endpoint;
    std::shared_ptr<QuicTlsCtx> m_tls_ctx;
    boost::asio::ip::udp::endpoint m_peer;
    boost::asio::steady_timer m_loss_timer;

    ngtcp2_conn* m_conn{nullptr};
    WOLFSSL* m_ssl{nullptr};
    ngtcp2_crypto_conn_ref m_conn_ref{};

    // sockaddr storage for local/remote addresses (kept alive for path lifetime).
    ngtcp2_sockaddr_union m_local_su{};
    ngtcp2_sockaddr_union m_remote_su{};
    ngtcp2_socklen m_local_len{0};
    ngtcp2_socklen m_remote_len{0};

    bool m_closed{false};
    bool m_handshake_done{false};
    bool m_is_server{false};

    tp::unordered_map<int64_t, std::shared_ptr<QuicStreamHandler>> m_stream_handlers;
    tp::vector<uint8_t> m_write_buf;
};

#endif // _QUIC_CONNECTION_H_
