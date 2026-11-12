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

#include <algorithm>
#include <chrono>

#include <boost/asio/ip/address.hpp>
#include <cstddef>

#include "core/config.h"
#include "core/log.h"
#include "quic_tls_ctx.h"

QuicClientEndpoint::QuicClientEndpoint(
  boost::asio::io_context& io_ctx, const Config& config, std::shared_ptr<QuicTlsCtx> tls_ctx)
    : QuicEndpoint(io_ctx, config, std::move(tls_ctx)), m_retry_timer(io_ctx), m_handshake_timer(io_ctx),
      m_probe_timer(io_ctx) {}

void QuicClientEndpoint::start() {
    if (m_running) {
        return;
    }

    // Bind to an ephemeral local UDP port.
    boost::asio::ip::udp::endpoint bind_ep(boost::asio::ip::udp::v4(), 0);
    open_socket(bind_ep, false);
    if (!m_socket.is_open()) {
        return;
    }

    m_running = true;
    async_recv();
    _log_with_date_time("QuicClientEndpoint: ready (server " + m_config.get_remote_addr() + ":" +
                          tp::to_string(m_config.get_remote_port()) + ")",
      Log::INFO);

    connect_to_server();
}

void QuicClientEndpoint::stop() {
    m_running = false;
    m_recovering = false;
    m_probing = false;
    m_probe_timer.cancel();
    m_retry_timer.cancel();
    m_handshake_timer.cancel();
    QuicEndpoint::stop();
    fail_all_pending_streams();
    auto conn = std::move(m_conn);
    if (conn) {
        boost::asio::post(m_io_context, tp::bind_mem_alloc([conn, self = shared_from_this()] {
            conn->close();
            conn->shutdown();
        }));
    }
    mark_unreachable();
}

void QuicClientEndpoint::connect_to_server() {
    if (m_conn && m_conn->is_closed()) {
        m_conn.reset();
    }
    if (m_connecting || m_conn) {
        return;
    }
    m_connecting = true;

    // Resolve the server address.
    auto self     = shared_from_this();
    auto resolver = TP_MAKE_SHARED(boost::asio::ip::udp::resolver, m_io_context);
    resolver->async_resolve(tp::string(m_config.get_remote_addr().c_str()),
      tp::to_string(m_config.get_remote_port()).c_str(),
      [this, self, resolver](
        const boost::system::error_code& ec, boost::asio::ip::udp::resolver::results_type results) {
          m_connecting = false;
          if (ec || !m_running) {
              _log_with_date_time(
                "QuicClientEndpoint: server resolve failed: " + tp::string(ec.message().c_str()), Log::WARN);
              mark_unreachable();
              return;
          }
          m_server_ep = results.begin()->endpoint();

          m_conn = TP_MAKE_SHARED(QuicConnection, *this, m_tls_ctx, m_server_ep);

          // Old connections may finish callbacks after reconnect and stream ID reuse.
          std::weak_ptr<QuicConnection> weak_conn = m_conn;
          m_conn->on_stream_data_cb = [this, self, weak_conn](int64_t stream_id, const uint8_t* data, std::size_t len, bool fin) {
              auto conn = weak_conn.lock();
              if (!conn || conn != m_conn) {
                  return;
              }
              auto it = m_stream_data_cb.find(stream_id);
              if (it != m_stream_data_cb.end()) {
                  auto callback = it->second;
                  callback(data, len, fin);
               }
          };

          // On handshake completion, fulfil deferred stream-open requests.
           m_conn->on_handshake_completed_cb = [this, self, weak_conn]() {
              if (weak_conn.lock() != m_conn || !m_running) {
                  return;
              }
               m_handshake_timer.cancel();
               m_known_unreachable = false;
               drain_pending_stream_opens();
           };

          m_conn->on_extend_max_streams_cb = [this, self, weak_conn]() {
              if (weak_conn.lock() != m_conn || !m_running) {
                  return;
              }
              drain_pending_stream_opens();
          };

          m_conn->on_stream_close_cb = [this, self, weak_conn](int64_t stream_id) {
              if (weak_conn.lock() != m_conn) {
                  return;
              }
              m_stream_data_cb.erase(stream_id);
              drain_pending_stream_opens();
          };

          m_conn->on_close_cb = [this, self, weak_conn](QuicConnection* conn) {
              // Keep close's caller alive through reentrant user notifications.
              auto keep_alive = weak_conn.lock();
              if (!keep_alive || m_conn.get() != conn) {
                  return;
              }
              m_conn.reset();
              mark_unreachable();
          };

           if (!m_conn->init_client(local_endpoint(), m_server_ep)) {
               _log_with_date_time("QuicClientEndpoint: init_client failed", Log::ERROR);
               m_conn = nullptr;
               mark_unreachable();
               return;
           }

           auto timeout_seconds = std::max(1, m_config.get_tcp().connect_time_out);
           m_handshake_timer.expires_after(std::chrono::seconds(timeout_seconds));
           m_handshake_timer.async_wait([this, self, weak_conn](const boost::system::error_code& timer_ec) {
               if (timer_ec || !m_running || !m_conn || weak_conn.lock() != m_conn || m_conn->is_handshake_done()) {
                   return;
               }
               _log_with_date_time("QuicClientEndpoint: handshake timeout", Log::WARN);
               auto conn = m_conn;
               conn->close();
           });

      });
}

void QuicClientEndpoint::on_packet(const uint8_t* data, std::size_t len, const boost::asio::ip::udp::endpoint& src) {
    auto conn = m_conn;
    if (conn && !conn->is_closed()) {
        // ngtcp2 callbacks run inside read_pkt; only open streams after it returns.
        m_reading_packet = true;
        conn->on_packet(data, len, local_endpoint(), src);
        m_reading_packet = false;
        if (conn == m_conn) {
            finish_probe();
            drain_pending_stream_opens();
        }
    }
}

void QuicClientEndpoint::on_pump_write(const char* debug_path) {
    auto conn = m_conn;
    if (conn && !conn->is_closed()) {
        conn->on_pump_write(debug_path);
    }
}

bool QuicClientEndpoint::is_connected() const { return m_conn && !m_conn->is_closed() && m_conn->is_handshake_done(); }

void QuicClientEndpoint::stream_extend_window(int64_t stream_id, std::size_t n) {
    if (m_conn) {
        m_conn->stream_extend_window(stream_id, n);
    }
}

void QuicClientEndpoint::stop_reading_stream(int64_t stream_id, uint64_t app_error_code) {
    if (m_conn) {
        m_conn->stop_reading_stream(stream_id, app_error_code);
    }
}

void QuicClientEndpoint::drain_pending_stream_opens() {
    if (m_draining_opens || m_reading_packet || !m_running) {
        return;
    }
    m_draining_opens = true;
    while (!m_pending_stream_opens.empty() && m_running && m_conn && !m_conn->is_closed() &&
           m_conn->is_handshake_done() && !gate_stale_connection()) {
        int64_t sid = -1;
        auto rv = m_conn->open_bidi_stream(sid);
        if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
            break;
        }
        auto pending = std::move(m_pending_stream_opens.front());
        m_pending_stream_opens.pop_front();
        if (pending.callback) {
            pending.callback(rv == 0 ? sid : -1);
        }
    }
    m_draining_opens = false;
}

bool QuicClientEndpoint::gate_stale_connection() {
    if (m_probing) {
        return true;
    }
    const auto& config = m_config.get_quic();
    uint64_t idle_ms = config.max_idle_timeout_ms;
    const auto* peer = ngtcp2_conn_get_remote_transport_params(m_conn->native_handle());
    if (peer && peer->max_idle_timeout) {
        const auto peer_ms = peer->max_idle_timeout / 1'000'000ULL;
        idle_ms = idle_ms ? std::min<uint64_t>(idle_ms, peer_ms) : peer_ms;
    }
    // Disabled keepalive still needs a finite freshness gate. Bound long intervals
    // so an idle, silently lost server cannot consume new application requests.
    uint64_t interval_ms = config.ping_interval_ms ? config.ping_interval_ms : 15'000;
    if (idle_ms) {
        interval_ms = std::min(interval_ms, std::max<uint64_t>(1, idle_ms / 2));
    }
    const auto stale_after = std::chrono::milliseconds(std::clamp<uint64_t>(2 * interval_ms, 1'000, 60'000));
    ngtcp2_conn_info info{};
    ngtcp2_conn_get_conn_info2(m_conn->native_handle(), &info);
    // A download can be in flight only on the server: the client's request may
    // already be ACKed, so local bytes_in_flight cannot detect that PTO backoff.
    // Three RTTs (at least one second) tolerate normal delayed ACKs; arriving
    // packets reset the gate, so healthy busy connections do not reconnect.
    const auto recovery_after = std::chrono::nanoseconds(std::max<uint64_t>(
      1'000'000'000ULL, 3 * info.smoothed_rtt));
    const auto silence = QuicClock::now() - m_conn->last_packet_received();
    if (silence < std::min<std::chrono::nanoseconds>(stale_after, recovery_after)) {
        return false;
    }
    m_probing = true;
    if (!m_recovering) {
        m_recovery_started = QuicClock::now();
    }
    m_probe_last_received = m_conn->last_packet_received();
    auto self = shared_from_this();
    std::weak_ptr<QuicConnection> weak_conn = m_conn;
    m_probe_timer.expires_after(std::chrono::seconds(1));
    m_probe_timer.async_wait([this, self, weak_conn](const boost::system::error_code& ec) {
        auto conn = weak_conn.lock();
        if (ec || !m_running || !m_probing || !conn || conn != m_conn) {
            return;
        }
        if (conn->last_packet_received() > m_probe_last_received) {
            finish_probe();
            drain_pending_stream_opens();
            return;
        }
        m_probing = false;
        m_recovering = m_config.get_quic().retry_connect_timeout_ms != 0;
        _log_with_date_time("QuicClientEndpoint: connection recovery: " +
                              tp::string("stale peer packets and PING probe timeout; ") +
                             tp::string(m_recovering ? "reconnecting with pending opens preserved" : "automatic reconnect disabled"),
                           Log::INFO);
        // Detach before close: close callbacks must not fail preserved opens or
        // erase handlers belonging to a replacement connection.
        m_conn.reset();
        mark_unreachable();
        conn->close();
    });
    auto conn = m_conn;
    conn->probe();
    return true;
}

void QuicClientEndpoint::finish_probe() {
    if (!m_conn || m_conn->is_closed()) {
        return;
    }
    if (m_probing && m_conn->last_packet_received() > m_probe_last_received) {
        m_probing = false;
        m_probe_timer.cancel();
    }
    if (m_recovering && m_conn->is_handshake_done()) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
          QuicClock::now() - m_recovery_started).count();
        m_recovering = false;
        _log_with_date_time("QuicClientEndpoint: dead connection recovered in " + tp::to_string(elapsed) + " ms",
                           Log::INFO);
    }
}

void QuicClientEndpoint::fail_all_pending_streams() {
    auto pending = std::move(m_pending_stream_opens);
    m_pending_stream_opens.clear();
    for (auto& item : pending) {
        if (item.callback) {
            item.callback(-1);
        }
    }
}

void QuicClientEndpoint::mark_unreachable() {
    if (m_probing && m_running) {
        m_recovering = m_config.get_quic().retry_connect_timeout_ms != 0;
        _log_with_date_time("QuicClientEndpoint: dead connection: closed during PING probe", Log::INFO);
    }
    m_probing = false;
    m_probe_timer.cancel();
    m_handshake_timer.cancel();
    m_known_unreachable = !m_recovering;
    if (!m_recovering) {
        fail_all_pending_streams();
    }
    auto stream_data_cb = std::move(m_stream_data_cb);
    m_stream_data_cb.clear();
    for (auto& [stream_id, callback] : stream_data_cb) {
        if (callback) {
            callback(nullptr, 0, true);
        }
    }
    uint32_t retry_ms   = m_config.get_quic().retry_connect_timeout_ms;
    if (retry_ms == 0 || !m_running) {
        return;
    }
    auto self = shared_from_this();
    m_retry_timer.expires_after(std::chrono::milliseconds(retry_ms));
    m_retry_timer.async_wait([this, self](const boost::system::error_code& ec) {
        if (ec || !m_running) {
            return;
        }
        _log_with_date_time("QuicClientEndpoint: retrying QUIC connection to " + m_config.get_remote_addr(), Log::INFO);
        m_known_unreachable = false;
        connect_to_server();
    });
}

QuicClientEndpoint::PendingStreamOpenId QuicClientEndpoint::open_bidi_stream(
  std::function<void(int64_t)> on_stream_ready) {
    if (!on_stream_ready) {
        return 0;
    }
    // close() first fails outstanding writes, which can reenter before on_close.
    // Preserve requests from those callbacks until on_close schedules the retry.
    if (m_running && m_conn && m_conn->is_closed() && !m_recovering &&
        m_config.get_quic().retry_connect_timeout_ms != 0) {
        m_recovering = true;
        if (!m_probing) {
            m_recovery_started = QuicClock::now();
        }
    }
    if (!m_running || (!m_recovering && !m_connecting && (!m_conn || m_conn->is_closed()))) {
        on_stream_ready(-1);
        return 0;
    }
    auto id = m_next_pending_stream_open_id++;
    m_pending_stream_opens.push_back({id, std::move(on_stream_ready)});
    drain_pending_stream_opens();
    const auto pending = std::find_if(m_pending_stream_opens.begin(), m_pending_stream_opens.end(),
                                     [id](const PendingStreamOpen& item) { return item.id == id; });
    return pending == m_pending_stream_opens.end() ? 0 : id;
}

void QuicClientEndpoint::cancel_pending_stream_open(PendingStreamOpenId id) {
    if (id == 0) {
        return;
    }
    for (auto it = m_pending_stream_opens.begin(); it != m_pending_stream_opens.end(); ++it) {
        if (it->id == id) {
            m_pending_stream_opens.erase(it);
            return;
        }
    }
}

void QuicClientEndpoint::send_stream_data(int64_t stream_id, std::shared_ptr<ReadBufWithGuard> buf, bool fin, IoHandler sent_cb){
    if (!m_conn || m_conn->is_closed()) {
        if(sent_cb){
            sent_cb(boost::asio::error::broken_pipe, 0);
        }
        return;
    }
    m_conn->send_stream_data(stream_id, buf, fin, std::move(sent_cb));
}

void QuicClientEndpoint::set_stream_data_handler(
  int64_t stream_id, std::function<void(const uint8_t*, std::size_t, bool)> handler) {
    m_stream_data_cb[stream_id] = std::move(handler);
}

void QuicClientEndpoint::remove_stream_data_handler(int64_t stream_id) { 
    m_stream_data_cb.erase(stream_id);
}
