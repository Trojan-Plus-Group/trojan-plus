/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _QUIC_CLIENT_ENDPOINT_H_
#define _QUIC_CLIENT_ENDPOINT_H_

#include <functional>
#include <memory>

#include "quic_connection.h"
#include "quic_endpoint.h"

class ReadBufWithGuard;

// Client-side QUIC endpoint. Maintains one QuicConnection to the trojan
// server. Callers use open_bidi_stream() to get a stream_id, then call
// send_stream_data() / register on_stream_data_cb to communicate.
class QuicClientEndpoint : public QuicEndpoint {
  public:
    using IoHandler = std::function<void(boost::system::error_code, std::size_t)>;

    QuicClientEndpoint(boost::asio::io_context& io_ctx, const Config& config,
                       std::shared_ptr<QuicTlsCtx> tls_ctx);

    void start() override;

    using PendingStreamOpenId = uint64_t;

    PendingStreamOpenId open_bidi_stream(std::function<void(int64_t /*stream_id*/)> on_stream_ready);
    void cancel_pending_stream_open(PendingStreamOpenId id);

    // Send data on an open stream.
    void send_stream_data(int64_t stream_id, std::shared_ptr<ReadBufWithGuard> buf, bool fin, IoHandler sent_cb);

    // Register a per-stream data handler.
    void set_stream_data_handler(int64_t stream_id,
                                 std::function<void(const uint8_t*, std::size_t, bool)> handler);

    // Remove a per-stream data handler.
    void remove_stream_data_handler(int64_t stream_id);

    // Extend QUIC flow control window for a stream (call after consuming data).
    void stream_extend_window(int64_t stream_id, std::size_t n);

    // True after QUIC handshake with server completes.
    [[nodiscard]] bool is_connected() const;
    [[nodiscard]] bool is_connecting() const { return m_conn && !m_conn->is_closed() && !m_conn->is_handshake_done(); }
    [[nodiscard]] bool is_usable() const { return m_conn && !m_conn->is_closed(); }

    [[nodiscard]] bool is_known_unreachable() const { return m_known_unreachable; }
    void mark_unreachable();

  protected:
    void on_packet(const uint8_t* data, std::size_t len,
                   const boost::asio::ip::udp::endpoint& src) override;
    void on_pump_write(const char* debug_path) override;

  private:
    void connect_to_server();
    void drain_pending_stream_opens();
    void fail_all_pending_streams();

    std::shared_ptr<QuicConnection> m_conn;
    bool m_known_unreachable{false};
    bool m_connecting{false};
    boost::asio::steady_timer m_retry_timer;

    // Per-stream data handlers: stream_id → handler.
    tp::unordered_map<int64_t, std::function<void(const uint8_t*, std::size_t, bool)>>
        m_stream_data_cb;

    struct PendingStreamOpen {
        PendingStreamOpenId id;
        std::function<void(int64_t)> callback;
    };

    tp::deque<PendingStreamOpen> m_pending_stream_opens;
    PendingStreamOpenId m_next_pending_stream_open_id{1};

    boost::asio::ip::udp::endpoint m_server_ep;
};

#endif // _QUIC_CLIENT_ENDPOINT_H_
