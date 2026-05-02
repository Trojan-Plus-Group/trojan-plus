/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _QUIC_ENDPOINT_H_
#define _QUIC_ENDPOINT_H_

#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>

#include "mem/memallocator.h"

class Config;
class QuicConnection;
class QuicTlsCtx;

// Base class for both server and client QUIC endpoints. Owns the UDP socket
// and the connection table keyed by ngtcp2 destination connection ID.
//
// Phase 1 status: skeleton — opens / closes the UDP socket, runs an idle
// async_receive_from loop, and logs incoming datagrams. ngtcp2 wiring lands in
// the next iteration.
class QuicEndpoint : public std::enable_shared_from_this<QuicEndpoint> {
  public:
    QuicEndpoint(boost::asio::io_context& io_ctx, const Config& config,
                 std::shared_ptr<QuicTlsCtx> tls_ctx);
    virtual ~QuicEndpoint();

    QuicEndpoint(const QuicEndpoint&)            = delete;
    QuicEndpoint& operator=(const QuicEndpoint&) = delete;

    virtual void start() = 0;
    virtual void stop();

    boost::asio::io_context& io_context() { return m_io_context; }
    const Config& config() const { return m_config; }

  protected:
    void open_socket(const boost::asio::ip::udp::endpoint& bind_ep,
                     bool reuse_port);
    void async_recv();
    virtual void on_packet(const uint8_t* data, std::size_t len,
                           const boost::asio::ip::udp::endpoint& src) = 0;

    boost::asio::io_context& m_io_context;
    const Config& m_config;
    std::shared_ptr<QuicTlsCtx> m_tls_ctx;
    boost::asio::ip::udp::socket m_socket;
    boost::asio::ip::udp::endpoint m_recv_endpoint;
    tp::vector<uint8_t> m_recv_buf;
    bool m_running;
};

#endif // _QUIC_ENDPOINT_H_
