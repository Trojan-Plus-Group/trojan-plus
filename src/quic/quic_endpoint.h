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

#include <cstdint>
#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>

#include "mem/memallocator.h"

// Length of the per-process Stateless Reset secret (256-bit).
constexpr std::size_t kStatelessResetSecretLen = 32;

class Config;
class QuicConnection;
class QuicTlsCtx;

// Base class for both server and client QUIC endpoints. Owns the UDP socket
// and the connection table keyed by ngtcp2 destination connection ID.
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
    bool is_running() const { return m_running; }

    // Per-process secret for deterministic Stateless Reset token derivation.
    // Generated once at endpoint construction, shared across all connections.
    const uint8_t* stateless_reset_secret() const { return m_stateless_reset_secret; }

    // Send a UDP datagram to the given remote endpoint (called by QuicConnection::pump_write).
    void send_packet(const boost::asio::ip::udp::endpoint& dest,
                     const uint8_t* data, std::size_t len);

    // Local endpoint of the bound UDP socket (needed to build ngtcp2 path).
    boost::asio::ip::udp::endpoint local_endpoint() const;

  protected:
    void open_socket(const boost::asio::ip::udp::endpoint& bind_ep, bool reuse_port);
    void async_recv();
    virtual void on_packet(const uint8_t* data, std::size_t len,
                           const boost::asio::ip::udp::endpoint& src) = 0;
    virtual void on_pump_write(const char* debug_path) = 0;

    boost::asio::io_context& m_io_context;
    const Config& m_config;
    std::shared_ptr<QuicTlsCtx> m_tls_ctx;
    boost::asio::ip::udp::socket m_socket;
    boost::asio::ip::udp::endpoint m_recv_endpoint;
    tp::vector<uint8_t> m_recv_buf;
    bool m_running;
    // 256-bit secret randomised once per process lifetime.
    uint8_t m_stateless_reset_secret[kStatelessResetSecretLen];
};

#endif // _QUIC_ENDPOINT_H_
