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
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "core/config.h"
#include "core/log.h"
#include "mem/memallocator.h"
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
      m_running(false) {
    // Generate a per-process random secret for deterministic Stateless Reset
    // token derivation.  The same secret is used in cb_get_new_connection_id
    // (advertised to peer via NEW_CONNECTION_ID) and send_stateless_reset
    // (reconstructed from DCID + secret), so the token will match.
    wolfSSL_RAND_bytes(m_stateless_reset_secret,
                       static_cast<int>(kStatelessResetSecretLen));
}

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

    // Keep option, query, and non-blocking errors separate so each result remains observable.
    const auto& q = m_config.get_quic();
    if (q.recv_buffer_size > 0) {
        boost::system::error_code recv_ec;
        m_socket.set_option(
            boost::asio::socket_base::receive_buffer_size(static_cast<int>(q.recv_buffer_size)), recv_ec);
        if (recv_ec) {
            _log_with_date_time("QuicEndpoint: set receive buffer " +
                                    tp::to_string(q.recv_buffer_size) + " failed: " +
                                    tp::string(recv_ec.message().c_str()),
                                Log::WARN);
        }
    }
    if (q.send_buffer_size > 0) {
        boost::system::error_code send_ec;
        m_socket.set_option(
            boost::asio::socket_base::send_buffer_size(static_cast<int>(q.send_buffer_size)), send_ec);
        if (send_ec) {
            _log_with_date_time("QuicEndpoint: set send buffer " +
                                    tp::to_string(q.send_buffer_size) + " failed: " +
                                    tp::string(send_ec.message().c_str()),
                                Log::WARN);
        }
    }

    boost::asio::socket_base::receive_buffer_size actual_recv_buffer;
    boost::system::error_code recv_get_ec;
    m_socket.get_option(actual_recv_buffer, recv_get_ec);
    if (recv_get_ec) {
        _log_with_date_time("QuicEndpoint: get receive buffer failed: " +
                                tp::string(recv_get_ec.message().c_str()),
                            Log::WARN);
    }

    boost::asio::socket_base::send_buffer_size actual_send_buffer;
    boost::system::error_code send_get_ec;
    m_socket.get_option(actual_send_buffer, send_get_ec);
    if (send_get_ec) {
        _log_with_date_time("QuicEndpoint: get send buffer failed: " +
                                tp::string(send_get_ec.message().c_str()),
                            Log::WARN);
    }

    boost::system::error_code non_blocking_ec;
    m_socket.non_blocking(true, non_blocking_ec);
    if (non_blocking_ec) {
        _log_with_date_time("QuicEndpoint: set non-blocking failed: " +
                                tp::string(non_blocking_ec.message().c_str()),
                            Log::ERROR);
        return;
    }

    _log_with_date_time("QuicEndpoint: bound UDP " +
                            tp::string(bind_ep.address().to_string().c_str()) + ":" +
                            tp::to_string(bind_ep.port()) + " buffers requested recv=" +
                            tp::to_string(q.recv_buffer_size) + " send=" +
                            tp::to_string(q.send_buffer_size) + " actual recv=" +
                            (recv_get_ec ? tp::string("unknown")
                                         : tp::to_string(actual_recv_buffer.value())) +
                            " send=" +
                            (send_get_ec ? tp::string("unknown")
                                         : tp::to_string(actual_send_buffer.value())),
                        Log::INFO);
}

void QuicEndpoint::async_recv() {
    if (!m_running || !m_socket.is_open()) {
        return;
    }
    auto self = shared_from_this();
    m_socket.async_wait(boost::asio::ip::udp::socket::wait_read,
        [self, this](boost::system::error_code /*ec*/) {
            bool need_flush = false;


            int read_count = 0;
            const int MAX_READS_PER_EVENT = 64; // Or 128, 256, depending on the workload

            // ==========================================
            // Phase 1: Drain the NIC buffer (The Drain Loop)
            // ==========================================
            while (read_count++ < MAX_READS_PER_EVENT) {
                boost::system::error_code read_ec;
                // Read using synchronous non-blocking mode!
                size_t bytes_recvd = m_socket.receive_from(
                    boost::asio::buffer(m_recv_buf.data(), m_recv_buf.size()), 
                    m_recv_endpoint, 
                    0, // flags
                    read_ec
                );

                if (read_ec) {
                    if (read_ec == boost::asio::error::would_block || 
                        read_ec == boost::asio::error::try_again) {
                        break; // Normal drain completed (no more data to read)
                    }
                    // A real error occurred (e.g., connection_reset)
                    // Log the error or terminate the current connection
                    // log_error(read_ec);
                    if (m_running) {
                        _log_with_date_time("QuicEndpoint: async_receive_from error: " +
                                            tp::string(read_ec.message().c_str()),
                                            Log::WARN);
                    }
                    break;
                }

                if (bytes_recvd > 0) {
                    // on_packet will set the quic connection stream offset
                    on_packet(m_recv_buf.data(), bytes_recvd, m_recv_endpoint);
                    need_flush = true; // State changed, need to check if we should send packets later
                }
            }

            // ==========================================
            // Phase 2: Send accumulated data (The Send Phase)
            // ==========================================
            if (need_flush) {
                on_pump_write(FUNC_NAME);
            }

            if (m_running) {
                async_recv();
            }
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

bool QuicEndpoint::send_packet(const boost::asio::ip::udp::endpoint& dest,
                               const uint8_t* data, std::size_t len) {
    if (!m_socket.is_open() || len == 0) {
        return false;
    }
    boost::system::error_code ec;
    auto sent = m_socket.send_to(boost::asio::buffer(data, len), dest, 0, ec);
    if (ec) {
        _log_with_date_time("QuicEndpoint::send_packet to " + dest.address().to_string() + ":" +
                               tp::to_string(dest.port()) + " failed: " + tp::string(ec.message().c_str()),
                            Log::WARN);
        return false;
    }
    return sent == len;
}

boost::asio::ip::udp::endpoint QuicEndpoint::local_endpoint() const {
    boost::system::error_code ec;
    return m_socket.local_endpoint(ec);
}
