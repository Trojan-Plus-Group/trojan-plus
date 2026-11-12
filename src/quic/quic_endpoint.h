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

#include <chrono>
#include <cstdint>
#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include "mem/memallocator.h"
#include <quic_stats_config.h>
#include "quic_udp_gso.h"

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
    bool send_available() const { return m_running && m_socket.is_open(); }

    // Per-process secret for deterministic Stateless Reset token derivation.
    // Generated once at endpoint construction, shared across all connections.
    const uint8_t* stateless_reset_secret() const { return m_stateless_reset_secret; }

    // Send a UDP datagram to the given remote endpoint (called by QuicConnection::pump_write).
    bool send_packet(const boost::asio::ip::udp::endpoint& dest,
                     const uint8_t* data, std::size_t len);

    using AggregatePool = quic_udp_gso::BufferPool<tp::tj_unique_ptr<uint8_t[]>>;
    using AggregateBuffer = AggregatePool::Buffer;
    bool udp_gso_enabled() const { return m_udp_gso; }
    bool aggregate_capacity(QuicConnection& connection);
    AggregateBuffer acquire_aggregate_buffer();
    void send_aggregate(const boost::asio::ip::udp::endpoint& dest,
                        AggregateBuffer&& bytes, std::size_t segment);

    // Local endpoint of the bound UDP socket (needed to build ngtcp2 path).
    boost::asio::ip::udp::endpoint local_endpoint() const;

  protected:
    void derive_stateless_reset_secret();
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
    struct PendingAggregate {
        boost::asio::ip::udp::endpoint dest;
        AggregateBuffer bytes;
        std::size_t segment;
        std::size_t offset{0};
    };
    void drain_aggregates();
    bool m_udp_gso{false}; // Probed once after opening each socket.
    AggregatePool m_aggregate_pool; // Must outlive queued leases.
    quic_udp_gso::Queue<tp::deque<PendingAggregate>> m_aggregate_queue;
    tp::vector<std::shared_ptr<QuicConnection>> m_aggregate_waiters;
    boost::asio::steady_timer m_send_retry{m_io_context};
    struct SendError {
        int error;
        uint64_t suppressed{0};
        std::chrono::steady_clock::time_point last{};
    };
    tp::vector<SendError> m_send_errors;
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
    uint64_t m_zero_port_drops{0};
#endif
    bool m_send_wait{false};
    // 256-bit secret randomised once per process lifetime.
    uint8_t m_stateless_reset_secret[kStatelessResetSecretLen];
};

#endif // _QUIC_ENDPOINT_H_
