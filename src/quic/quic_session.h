/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef QUIC_SESSION_H
#define QUIC_SESSION_H

#include <cstddef>
#include <memory>
#include <cstdint>
#include <functional>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <list>

#include <nghttp3/nghttp3.h>

#include "quic_stream_handler.h"
#include "mem/memallocator.h"

class QuicConnection;
class Config;
class QuicUpstreamHandler;

// Server-side per-stream proxy session. Buffers incoming stream bytes until a
// complete TrojanRequest header is received, then dials a TCP socket to the
// target and splices data bidirectionally.
class QuicProxySession : public QuicStreamHandler, public std::enable_shared_from_this<QuicProxySession> {
    friend class QuicUpstreamHandler;
  public:
    QuicProxySession(std::shared_ptr<QuicConnection> conn, int64_t stream_id,
                     const Config& config, boost::asio::io_context& io_ctx);
    ~QuicProxySession() override;

    void start();

    // QuicStreamHandler implementation
    void on_stream_data(const uint8_t* data, std::size_t len, bool fin) override;
    void on_stream_close() override;

    [[nodiscard]] int64_t stream_id() const { return m_stream_id; }

  private:
    void try_parse_request(std::string_view data, bool fin);
    void forward_to_h1_upstream(std::string_view data, bool fin);
    void connect_target(const tp::string& host, uint16_t port);
    void tcp_read();
    void write_to_target(tp::string data, bool fin = false);
    void do_tcp_write();
    void destroy(bool reset = false, uint64_t app_error_code = 0, bool from_close_cb = false);

    std::weak_ptr<QuicConnection> m_conn;
    int64_t m_stream_id;
    const Config& m_config;
    boost::asio::io_context& m_io_ctx;

    boost::asio::ip::tcp::socket m_tcp_socket;
    boost::asio::ip::tcp::resolver m_resolver;

    tp::string m_quic_recv_buf;    // accumulates stream bytes until request parsed
    std::list<std::pair<std::size_t, std::shared_ptr<tp::string>>> m_unacked_bufs; // unacked stream buffers
    std::shared_ptr<tp::string> m_tcp_pending_buf; // current pending write buffer

    void udp_read();
    void out_udp_sent();
    void out_udp_async_write(const std::string_view& data, const boost::asio::ip::udp::endpoint& endpoint);

    boost::asio::ip::udp::socket m_udp_socket;
    boost::asio::ip::udp::resolver m_udp_resolver;
    boost::asio::ip::udp::endpoint m_udp_remote_endpoint;
    tp::string m_udp_recv_buf; // reads from UDP socket
    tp::string m_udp_data_buf; // receives from QUIC stream
    tp::string m_udp_pending_stream_data; // pending data to be sent to QUIC stream
    bool m_is_udp{false};
    bool m_udp_fin_received{false};

    bool m_request_parsed{false};
    bool m_destroyed{false};
    std::size_t m_unacked_stream_bytes{0};

    static constexpr std::size_t kQuicRecvBufReserveSize = 2 * 1024;
    static constexpr std::size_t kTcpBufSize = 16 * 1024;
    boost::asio::steady_timer m_write_timer;

    struct TcpWriteBuffer {
        tp::string data;
        bool fin{false};
    };
    tp::deque<TcpWriteBuffer> m_tcp_write_queue;
    bool m_is_writing_to_tcp{false};
    bool m_tcp_write_blocked{false};
    std::size_t m_tcp_pending_offset{0};
    std::size_t m_tcp_pending_bytes{0};
    bool m_tcp_write_pending{false};
    bool m_udp_write_pending{false};
};

#endif // QUIC_SESSION_H
