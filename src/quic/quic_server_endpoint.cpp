/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_server_endpoint.h"

#include <boost/asio/ip/address.hpp>

#include "core/config.h"
#include "core/log.h"

QuicServerEndpoint::QuicServerEndpoint(boost::asio::io_context& io_ctx, const Config& config,
                                       std::shared_ptr<QuicTlsCtx> tls_ctx)
    : QuicEndpoint(io_ctx, config, std::move(tls_ctx)) {}

void QuicServerEndpoint::start() {
    if (m_running) {
        return;
    }

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(
        std::string(m_config.get_local_addr().c_str()), ec);
    if (ec) {
        _log_with_date_time(
            "QuicServerEndpoint: invalid local_addr '" + m_config.get_local_addr() + "': " +
                tp::string(ec.message().c_str()),
            Log::ERROR);
        return;
    }

    boost::asio::ip::udp::endpoint bind_ep(addr, m_config.get_local_port());
    open_socket(bind_ep, m_config.get_tcp().reuse_port);
    if (!m_socket.is_open()) {
        return;
    }

    m_running = true;
    async_recv();
    _log_with_date_time("QuicServerEndpoint: listening on UDP " +
                            m_config.get_local_addr() + ":" +
                            tp::to_string(m_config.get_local_port()),
                        Log::INFO);
}

void QuicServerEndpoint::on_packet(const uint8_t* /*data*/, std::size_t len,
                                   const boost::asio::ip::udp::endpoint& src) {
    // Phase 1: log and drop. ngtcp2 dispatch lands in the next iteration.
    _log_with_date_time("QuicServerEndpoint: dropped " + tp::to_string(len) + " bytes from " +
                            tp::string(src.address().to_string().c_str()) + ":" +
                            tp::to_string(src.port()) + " (Phase 1 stub)",
                        Log::INFO);
}
