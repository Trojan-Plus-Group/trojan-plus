/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _OUTBOUND_TRANSPORT_H_
#define _OUTBOUND_TRANSPORT_H_

#include <cstdint>
#include <functional>
#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/system/error_code.hpp>

#include "mem/memallocator.h"

class Config;
class QuicClientEndpoint;
class ReadBufWithGuard;

// Uniform async outbound transport – either TLS-over-TCP or a QUIC bidi stream.
// ClientSession depends only on this interface for its server-facing connection.
class OutboundTransport {
  public:
    using IoHandler = std::function<void(boost::system::error_code, std::size_t)>;

    virtual ~OutboundTransport() = default;

    // Establish the connection (TCP+TLS handshake or QUIC stream open).
    // Calls on_success() or on_error() exactly once.
    // For QUIC, host/port identify the trojan server but the QUIC connection
    // is already being maintained by QuicClientEndpoint; they are used only
    // by the TLS transport.
    virtual void async_connect(const tp::string& host, uint16_t port,
                               std::function<void()> on_success,
                               std::function<void()> on_error) = 0;

    // Read some bytes into buf. Calls handler(ec, bytes_read).
    virtual void async_read_some(boost::asio::mutable_buffer buf, IoHandler handler) = 0;

    // Write all bytes in [data]. Caller must keep data valid until handler fires.
    virtual void async_write(std::shared_ptr<ReadBufWithGuard> buf, IoHandler handler) = 0;

    // Cancel all pending async operations.
    virtual void cancel() = 0;

    // Begin graceful shutdown (non-blocking).
    virtual void close() = 0;

    [[nodiscard]] virtual bool is_via_quic() const = 0;
};

// Create the appropriate transport for the given service configuration.
// If QUIC is enabled, preferred, and the QuicClientEndpoint has already
// completed the handshake, returns a QuicStreamTransport; otherwise returns
// a TlsOutboundTransport.
std::shared_ptr<OutboundTransport> create_outbound_transport(
    boost::asio::io_context&       io_ctx,
    boost::asio::ssl::context&     ssl_ctx,
    const Config&                  config,
    boost::asio::ip::tcp::endpoint in_ep,
    std::shared_ptr<QuicClientEndpoint> quic_client);

#endif // _OUTBOUND_TRANSPORT_H_
