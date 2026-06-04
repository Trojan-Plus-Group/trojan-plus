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

#include <chrono>

#include <boost/asio/ip/address.hpp>
#include <cstddef>

#include "core/config.h"
#include "core/log.h"
#include "quic_tls_ctx.h"

QuicClientEndpoint::QuicClientEndpoint(
  boost::asio::io_context& io_ctx, const Config& config, std::shared_ptr<QuicTlsCtx> tls_ctx)
    : QuicEndpoint(io_ctx, config, std::move(tls_ctx)), m_retry_timer(io_ctx) {}

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

void QuicClientEndpoint::connect_to_server() {
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

          // Route incoming stream data to registered handlers.
          m_conn->on_stream_data_cb = [this, self](int64_t stream_id, const uint8_t* data, std::size_t len, bool fin) {
              auto it = m_stream_data_cb.find(stream_id);
              if (it != m_stream_data_cb.end()) {
                  it->second(data, len, fin);
               }
          };

          // On handshake completion, fulfil deferred stream-open requests.
          m_conn->on_handshake_completed_cb = [this, self]() {
              auto pending = std::move(m_pending_stream_opens);
              m_pending_stream_opens.clear();
              for (auto& cb : pending) {
                  auto sid = m_conn->open_bidi_stream();
                  if (sid >= 0) {
                      cb(sid);
                  }
              }
          };

          m_conn->on_stream_close_cb = [this, self](int64_t stream_id) { 
            m_stream_data_cb.erase(stream_id); 
          };

          if (!m_conn->init_client(local_endpoint(), m_server_ep)) {
              _log_with_date_time("QuicClientEndpoint: init_client failed", Log::ERROR);
              m_conn = nullptr;
              mark_unreachable();
          }
      });
}

void QuicClientEndpoint::on_packet(const uint8_t* data, std::size_t len, const boost::asio::ip::udp::endpoint& src) {
    if (m_conn && !m_conn->is_closed()) {
        m_conn->on_packet(data, len, local_endpoint(), src);
    }
}

void QuicClientEndpoint::on_pump_write(const char* debug_path) {
    if (m_conn && !m_conn->is_closed()) {
        m_conn->on_pump_write(debug_path);
    }
}

bool QuicClientEndpoint::is_connected() const { return m_conn && !m_conn->is_closed() && m_conn->is_handshake_done(); }

void QuicClientEndpoint::stream_extend_window(int64_t stream_id, std::size_t n) {
    if (m_conn) {
        m_conn->stream_extend_window(stream_id, n);
    }
}

void QuicClientEndpoint::mark_unreachable() {
    m_known_unreachable = true;
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

int64_t QuicClientEndpoint::open_bidi_stream(std::function<void(int64_t)> on_stream_ready) {
    if (!m_conn || m_conn->is_closed()) {
        if (on_stream_ready) {
            on_stream_ready(-1);
        }
        return -1;
    }
    if (m_conn->is_handshake_done()) {
        auto sid = m_conn->open_bidi_stream();
        if (on_stream_ready) {
            on_stream_ready(sid);
        }
        return sid;
    }
    // Handshake not yet done – defer.
    if (on_stream_ready) {
        m_pending_stream_opens.push_back(std::move(on_stream_ready));
    }
    return -1;
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
