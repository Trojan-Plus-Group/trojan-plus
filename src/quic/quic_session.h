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

#include <memory>
#include <cstdint>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

class QuicConnection;
class Config;

#include "mem/memallocator.h"

// Server-side per-stream proxy session. Buffers incoming stream bytes until a
// complete TrojanRequest header is received, then dials a TCP socket to the
// target and splices data bidirectionally.
class QuicProxySession : public std::enable_shared_from_this<QuicProxySession> {
  public:
    QuicProxySession(std::shared_ptr<QuicConnection> conn, int64_t stream_id,
                     const Config& config, boost::asio::io_context& io_ctx);
    ~QuicProxySession();

    void start();

    // Called by QuicConnection when data arrives on this stream.
    void on_stream_data(const uint8_t* data, std::size_t len, bool fin);
    // Called by QuicConnection when this stream is closed remotely.
    void on_stream_close();

    [[nodiscard]] int64_t stream_id() const { return m_stream_id; }

  private:
    void try_parse_request();
    void forward_to_h3_upstream();
    void connect_target(const tp::string& host, uint16_t port);
    void tcp_read();
    void flush_tcp_read_buf(std::size_t offset, std::size_t bytes);
    void write_to_target(tp::string data, bool fin = false);
    void do_tcp_write();
    void udp_read();
    void destroy();

    std::shared_ptr<QuicConnection> m_conn;
    int64_t m_stream_id;
    const Config& m_config;

    boost::asio::ip::tcp::socket m_tcp_socket;
    boost::asio::ip::tcp::resolver m_resolver;

    boost::asio::ip::udp::socket m_udp_socket;
    boost::asio::ip::udp::resolver m_udp_resolver;
    boost::asio::ip::udp::endpoint m_udp_remote_ep;

    tp::string m_recv_buf;    // accumulates stream bytes until request parsed
    tp::string m_tcp_buf;     // read buffer for upstream → stream direction
    tp::string m_udp_buf;     // read buffer for UDP upstream → stream direction
    bool m_request_parsed{false};
bool m_upstream_forwarding{false}; // forwarding non-trojan traffic to h3_upstream
    bool m_waiting_h3_response{false}; // waiting for h3_upstream UDP response
    bool m_stream_fin_received{false}; // client sent QUIC stream FIN
    bool m_destroyed{false};

    static constexpr std::size_t kTcpBufSize = 16 * 1024;
    boost::asio::steady_timer m_write_timer;

    struct TcpWriteBuffer {
        tp::string data;
        bool fin{false};
    };
    tp::deque<TcpWriteBuffer> m_tcp_write_queue;
    bool m_is_writing_to_tcp{false};
};

#endif // QUIC_SESSION_H
