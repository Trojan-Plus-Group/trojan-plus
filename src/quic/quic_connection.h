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

#include <memory>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include "mem/memallocator.h"

class QuicEndpoint;
class QuicTlsCtx;

// Wraps one ngtcp2_conn plus its WOLFSSL handle, send/recv pumps, and per-conn
// loss-detection timer. Phase 1 is a skeleton; Phase 2+ will fill in the ngtcp2
// callbacks and stream/datagram dispatch.
class QuicConnection : public std::enable_shared_from_this<QuicConnection> {
  public:
    QuicConnection(QuicEndpoint& endpoint, std::shared_ptr<QuicTlsCtx> tls_ctx,
                   const boost::asio::ip::udp::endpoint& peer);
    ~QuicConnection();

    QuicConnection(const QuicConnection&)            = delete;
    QuicConnection& operator=(const QuicConnection&) = delete;

    void close();

    [[nodiscard]] const boost::asio::ip::udp::endpoint& peer() const { return m_peer; }

  private:
    QuicEndpoint& m_endpoint;
    std::shared_ptr<QuicTlsCtx> m_tls_ctx;
    boost::asio::ip::udp::endpoint m_peer;
    boost::asio::steady_timer m_loss_timer;
};

#endif // _QUIC_CONNECTION_H_
