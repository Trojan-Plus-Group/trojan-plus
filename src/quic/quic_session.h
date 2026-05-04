/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _QUIC_SESSION_H_
#define _QUIC_SESSION_H_

#include <cstdint>
#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "mem/memallocator.h"

class QuicConnection;
class Config;

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
    void stream_write(const tp::string& data);
    void destroy();

    std::shared_ptr<QuicConnection> m_conn;
    int64_t m_stream_id;
    const Config& m_config;
    boost::asio::io_context& m_io_ctx;

    boost::asio::ip::tcp::socket m_tcp_socket;
    boost::asio::ip::tcp::resolver m_resolver;

    tp::string m_recv_buf;    // accumulates stream bytes until request parsed
    tp::string m_payload;     // post-header payload forwarded to upstream
    tp::string m_tcp_buf;     // read buffer for upstream → stream direction
    bool m_request_parsed{false};
    bool m_upstream_forwarding{false}; // forwarding non-trojan traffic to h3_upstream
    bool m_destroyed{false};

    static constexpr std::size_t kTcpBufSize = 16 * 1024;
};

#endif // _QUIC_SESSION_H_
