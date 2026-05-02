/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_client_endpoint.h"

#include <boost/asio/ip/address.hpp>

#include "core/config.h"
#include "core/log.h"

QuicClientEndpoint::QuicClientEndpoint(boost::asio::io_context& io_ctx, const Config& config,
                                       std::shared_ptr<QuicTlsCtx> tls_ctx)
    : QuicEndpoint(io_ctx, config, std::move(tls_ctx)),
      m_known_unreachable(false) {}

void QuicClientEndpoint::start() {
    if (m_running) {
        return;
    }

    // Bind to an ephemeral local UDP port for outbound QUIC.
    boost::asio::ip::udp::endpoint bind_ep(boost::asio::ip::udp::v4(), 0);
    open_socket(bind_ep, false);
    if (!m_socket.is_open()) {
        return;
    }

    m_running = true;
    async_recv();
    _log_with_date_time("QuicClientEndpoint: ready (server target " +
                            m_config.get_remote_addr() + ":" +
                            tp::to_string(m_config.get_remote_port()) + ")",
                        Log::INFO);
}

void QuicClientEndpoint::on_packet(const uint8_t* /*data*/, std::size_t len,
                                   const boost::asio::ip::udp::endpoint& src) {
    // Phase 1: log and drop. ngtcp2 dispatch lands in the next iteration.
    _log_with_date_time("QuicClientEndpoint: dropped " + tp::to_string(len) + " bytes from " +
                            tp::string(src.address().to_string().c_str()) + ":" +
                            tp::to_string(src.port()) + " (Phase 1 stub)",
                        Log::INFO);
}
