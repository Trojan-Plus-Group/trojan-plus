/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_endpoint.h"

#include <boost/asio/socket_base.hpp>

#include "core/config.h"
#include "core/log.h"
#include "quic_tls_ctx.h"

namespace {
constexpr std::size_t kRecvBufBytes = 65536;
} // namespace

QuicEndpoint::QuicEndpoint(boost::asio::io_context& io_ctx, const Config& config,
                           std::shared_ptr<QuicTlsCtx> tls_ctx)
    : m_io_context(io_ctx),
      m_config(config),
      m_tls_ctx(std::move(tls_ctx)),
      m_socket(io_ctx),
      m_recv_buf(kRecvBufBytes, 0),
      m_running(false) {}

QuicEndpoint::~QuicEndpoint() {
    boost::system::error_code ec;
    if (m_socket.is_open()) {
        m_socket.close(ec);
    }
}

void QuicEndpoint::open_socket(const boost::asio::ip::udp::endpoint& bind_ep,
                               bool reuse_port) {
    boost::system::error_code ec;
    m_socket.open(bind_ep.protocol(), ec);
    if (ec) {
        _log_with_date_time("QuicEndpoint: socket.open failed: " + tp::string(ec.message().c_str()), Log::ERROR);
        return;
    }
    m_socket.set_option(boost::asio::socket_base::reuse_address(true), ec);
    (void)reuse_port; // SO_REUSEPORT handled by platform-specific code in Service.

    m_socket.bind(bind_ep, ec);
    if (ec) {
        _log_with_date_time("QuicEndpoint: socket.bind " +
                            tp::string(bind_ep.address().to_string().c_str()) + ":" +
                            tp::to_string(bind_ep.port()) + " failed: " +
                            tp::string(ec.message().c_str()),
                            Log::ERROR);
        return;
    }

    const auto& q = m_config.get_quic();
    if (q.recv_buffer_size > 0) {
        m_socket.set_option(
            boost::asio::socket_base::receive_buffer_size(static_cast<int>(q.recv_buffer_size)), ec);
    }
    if (q.send_buffer_size > 0) {
        m_socket.set_option(
            boost::asio::socket_base::send_buffer_size(static_cast<int>(q.send_buffer_size)), ec);
    }

    _log_with_date_time("QuicEndpoint: bound UDP " +
                        tp::string(bind_ep.address().to_string().c_str()) + ":" +
                        tp::to_string(bind_ep.port()),
                        Log::INFO);
}

void QuicEndpoint::async_recv() {
    if (!m_running || !m_socket.is_open()) {
        return;
    }
    auto self = shared_from_this();
    m_socket.async_receive_from(
        boost::asio::buffer(m_recv_buf.data(), m_recv_buf.size()),
        m_recv_endpoint,
        [this, self](const boost::system::error_code& ec, std::size_t bytes) {
            if (ec) {
                if (m_running) {
                    _log_with_date_time("QuicEndpoint: async_receive_from error: " +
                                        tp::string(ec.message().c_str()),
                                        Log::WARN);
                }
                return;
            }
            if (bytes > 0) {
                on_packet(m_recv_buf.data(), bytes, m_recv_endpoint);
            }
            async_recv();
        });
}

void QuicEndpoint::stop() {
    m_running = false;
    boost::system::error_code ec;
    if (m_socket.is_open()) {
        m_socket.cancel(ec);
        m_socket.close(ec);
    }
}

void QuicEndpoint::send_packet(const boost::asio::ip::udp::endpoint& dest,
                               const uint8_t* data, std::size_t len) {
    if (!m_socket.is_open() || len == 0) {
        return;
    }
    boost::system::error_code ec;
    m_socket.send_to(boost::asio::buffer(data, len), dest, 0, ec);
    if (ec) {
        _log_with_date_time("QuicEndpoint::send_packet: " + tp::string(ec.message().c_str()), Log::WARN);
    }
}

boost::asio::ip::udp::endpoint QuicEndpoint::local_endpoint() const {
    boost::system::error_code ec;
    return m_socket.local_endpoint(ec);
}
