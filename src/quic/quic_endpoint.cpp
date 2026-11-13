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
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <chrono>
#if TROJAN_QUIC_STATS
#include <cstdlib>
#endif
#include <fstream>

#include "core/config.h"
#include "core/log.h"
#include "mem/memallocator.h"
#include "platform_exports.h"
#include "quic_tls_ctx.h"
#include "quic_connection.h"
#include <boost/asio/post.hpp>

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
    derive_stateless_reset_secret();
}

void QuicEndpoint::derive_stateless_reset_secret() {
    if (m_config.get_run_type() != Config::SERVER) {
        RAND_bytes(m_stateless_reset_secret, static_cast<int>(kStatelessResetSecretLen));
        return;
    }

    constexpr char context[] = "trojan-plus/stateless-reset/v1";
    SHA256_CTX sha;
    auto update = [&sha](const void* data, std::size_t len) {
        return SHA256_Update(&sha, data, len) == 1;
    };
    bool ok = SHA256_Init(&sha) == 1 && update(context, sizeof(context) - 1);
    const auto& configured_secret = m_config.get_quic().stateless_reset_secret;
    if (!configured_secret.empty()) {
        ok = ok && update(configured_secret.data(), configured_secret.size());
    } else {
        std::ifstream key(m_config.get_ssl().key.c_str(), std::ios::binary);
        std::array<char, 4096> buf;
        std::size_t bytes_read = 0;
        ok = ok && key.good();
        while (ok && key) {
            key.read(buf.data(), buf.size());
            auto len = key.gcount();
            if (len > 0) {
                bytes_read += static_cast<std::size_t>(len);
                ok = update(buf.data(), static_cast<std::size_t>(len));
            }
        }
        ok = ok && bytes_read > 0;
    }
    if (ok && SHA256_Final(m_stateless_reset_secret, &sha) == 1) {
        return;
    }

    RAND_bytes(m_stateless_reset_secret, static_cast<int>(kStatelessResetSecretLen));
    _log_with_date_time("QuicEndpoint: failed to derive persistent Stateless Reset secret", Log::WARN);
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

    android_protect_socket(static_cast<int>(m_socket.native_handle()));

    m_socket.bind(bind_ep, ec);
    if (ec) {
        _log_with_date_time("QuicEndpoint: socket.bind " +
                            tp::string(bind_ep.address().to_string().c_str()) + ":" +
                            tp::to_string(bind_ep.port()) + " failed: " +
                            tp::string(ec.message().c_str()),
                            Log::ERROR);
        return;
    }

    m_udp_gso = m_config.get_quic().udp_gso && quic_udp_gso::platform_supported() &&
                quic_udp_gso::probe(m_socket.native_handle());
    if (udp_gso_enabled()) {
        _log_with_date_time("QUIC UDP_SEGMENT enabled for socket", Log::INFO);
    } else if (m_config.get_quic().udp_gso) {
        _log_with_date_time("QUIC udp_gso unavailable: Linux UDP_SEGMENT support required", Log::WARN);
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
        [self, this](boost::system::error_code ec) {
            if (ec || !m_running) return;
            bool need_flush = false;


            int read_count = 0;
            const int MAX_READS_PER_EVENT = 64; // Or 128, 256, depending on the workload

            // ==========================================
            // Phase 1: Drain the NIC buffer (The Drain Loop)
            // ==========================================
            while (m_running && read_count++ < MAX_READS_PER_EVENT) {
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

                if (!quic_udp_gso::valid_source_port(m_recv_endpoint.port())) {
#if TROJAN_QUIC_STATS
                    ++m_zero_port_drops;
#endif
                    continue;
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
            if (m_running && need_flush) {
                on_pump_write(FUNC_NAME);
            }

            if (m_running) {
                async_recv();
            }
    });
}

void QuicEndpoint::stop() {
    m_running = false;
#if TROJAN_QUIC_STATS
    const char* stats_path = std::getenv("TROJAN_QUIC_STATS");
    if (udp_gso_enabled() && stats_path && stats_path[0]) {
        const auto counters = "gso_attempts=" + tp::to_string(m_aggregate_queue.gso_attempts) +
                           " gso_successes=" + tp::to_string(m_aggregate_queue.gso_successes) +
                           " gso_datagrams=" + tp::to_string(m_aggregate_queue.gso_datagrams) +
                           " gso_bytes=" + tp::to_string(m_aggregate_queue.gso_bytes) +
                           " eagain_retries=" + tp::to_string(m_aggregate_queue.eagain_retries) +
                           " fallback_datagrams=" + tp::to_string(m_aggregate_queue.fallback_datagrams) +
                           " fallback_activations=" + tp::to_string(m_aggregate_queue.fallback_activations) +
                           " buffer_allocations=" + tp::to_string(m_aggregate_pool.buffer_allocations) +
                           " enobufs_drops=" + tp::to_string(m_aggregate_queue.enobufs_drops) +
                           " zero_port_drops=" + tp::to_string(m_zero_port_drops);
        _log_with_date_time("QUIC UDP_SEGMENT " + counters, Log::INFO);
        // Separate from connection CSV; append preserves other endpoints and prior stops.
        const auto sidecar_path = tp::string(stats_path) + ".udp_gso";
        std::ofstream sidecar(sidecar_path.c_str(), std::ios::app);
        if (sidecar) {
            sidecar << counters << '\n';
            sidecar.close();
        }
        if (!sidecar) {
            _log_with_date_time("QUIC UDP_SEGMENT stats write failed: " + tp::string(stats_path) + ".udp_gso", Log::ERROR);
        }
    }
#endif
    auto waiters = std::move(m_aggregate_waiters);
    m_aggregate_waiters.clear();
    m_aggregate_queue.clear();
    m_send_retry.cancel();
    boost::system::error_code ec;
    if (m_socket.is_open()) {
        m_socket.cancel(ec);
        m_socket.close(ec);
    }
    for (auto& conn : waiters) {
        conn->m_waiting_for_capacity = false;
        if (conn->m_close_waiting) {
            boost::asio::post(m_io_context, tp::bind_mem_alloc(
                [conn, self = shared_from_this()] { conn->on_socket_writable(); }));
        }
    }
}

bool QuicEndpoint::send_packet(const boost::asio::ip::udp::endpoint& dest,
                               const uint8_t* data, std::size_t len) {
    if (!send_available() || len == 0) {
        return false;
    }
    if (udp_gso_enabled()) {
        // Stateless/control packets may fail at capacity. A connection reserves
        // capacity before generating its own CONNECTION_CLOSE; never overtake ciphertext.
        if (m_aggregate_queue.full() || len > quic_udp_gso::buffer_size) return false;
        auto bytes = acquire_aggregate_buffer();
        if (!bytes) return false;
        std::memcpy(bytes.data(), data, len);
        bytes.resize(len);
        send_aggregate(dest, std::move(bytes), len);
        return true;
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

void QuicEndpoint::send_shutdown_packet(const boost::asio::ip::udp::endpoint& dest,
                                        const uint8_t* data, std::size_t len) {
    boost::system::error_code ec;
    m_socket.send_to(boost::asio::buffer(data, len), dest, 0, ec);
}

bool QuicEndpoint::aggregate_capacity(QuicConnection& connection) {
    if (!send_available()) return false;
    if (!m_aggregate_queue.full()) return true;
    if (connection.m_waiting_for_capacity) return false;
    connection.m_waiting_for_capacity = true;
    m_aggregate_waiters.push_back(connection.shared_from_this());
    return false;
}

QuicEndpoint::AggregateBuffer QuicEndpoint::acquire_aggregate_buffer() {
    return m_aggregate_pool.acquire([] { return TP_MAKE_UNIQUE(uint8_t[], quic_udp_gso::buffer_size); });
}

void QuicEndpoint::send_aggregate(const boost::asio::ip::udp::endpoint& dest,
                                  AggregateBuffer&& bytes, std::size_t segment) {
    assert(!m_aggregate_queue.full());
    assert(!bytes.empty() && bytes.size() <= quic_udp_gso::buffer_size && segment > 0);
    const bool queued = m_aggregate_queue.push(PendingAggregate{dest, std::move(bytes), segment});
    assert(queued);
    (void)queued;
    drain_aggregates();
}

void QuicEndpoint::drain_aggregates() {
    if (m_send_wait || !m_socket.is_open()) return;
    const int error = m_aggregate_queue.drain(m_socket.native_handle(), [this](int send_error) {
        auto found = std::find_if(m_send_errors.begin(), m_send_errors.end(),
                                  [send_error](const SendError& entry) { return entry.error == send_error; });
        if (found == m_send_errors.end()) {
            m_send_errors.push_back(SendError{send_error});
            found = m_send_errors.end() - 1;
        }
        const auto now = std::chrono::steady_clock::now();
        if (found->last != std::chrono::steady_clock::time_point{} &&
            now - found->last < std::chrono::seconds(10)) {
            ++found->suppressed;
            return;
        }
        const auto family = m_aggregate_queue.pending.front().dest.protocol().family();
        _log_with_date_time("QUIC UDP send failed: errno=" + tp::to_string(send_error) +
                           " suppressed=" + tp::to_string(found->suppressed) +
                           " family=" + tp::to_string(family), Log::WARN);
        found->suppressed = 0;
        found->last = now;
    });
    if (quic_udp_gso::no_buffers(error)) {
        // A writable socket can still have exhausted kernel buffers. Bound retry rate.
        m_send_wait = true;
        m_send_retry.expires_after(std::chrono::milliseconds(m_aggregate_queue.retry_delay_ms()));
        m_send_retry.async_wait(tp::bind_mem_alloc(
            [this, self = shared_from_this()](boost::system::error_code ec) {
                m_send_wait = false;
                if (!ec && m_running) drain_aggregates();
            }));
        return;
    }
    if (quic_udp_gso::would_block(error)) {
        m_send_wait = true;
        m_socket.async_wait(boost::asio::ip::udp::socket::wait_write,
            tp::bind_mem_alloc([this, self = shared_from_this()](boost::system::error_code wait_ec) {
                m_send_wait = false;
                if (!wait_ec) drain_aggregates();
            }));
        return;
    }
    auto waiters = std::move(m_aggregate_waiters);
    m_aggregate_waiters.clear();
    for (auto& conn : waiters) {
        conn->m_waiting_for_capacity = false;
        boost::asio::post(m_io_context, tp::bind_mem_alloc([conn, self = shared_from_this()] { conn->on_socket_writable(); }));
    }
}

boost::asio::ip::udp::endpoint QuicEndpoint::local_endpoint() const {
    boost::system::error_code ec;
    return m_socket.local_endpoint(ec);
}
