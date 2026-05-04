/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_session.h"

#include <boost/asio/connect.hpp>
#include <boost/asio/write.hpp>

#include "core/config.h"
#include "core/log.h"
#include "proto/trojanrequest.h"
#include "quic_connection.h"

QuicProxySession::QuicProxySession(std::shared_ptr<QuicConnection> conn, int64_t stream_id,
                                   const Config& config, boost::asio::io_context& io_ctx)
    : m_conn(std::move(conn)),
      m_stream_id(stream_id),
      m_config(config),
      m_io_ctx(io_ctx),
      m_tcp_socket(io_ctx),
      m_resolver(io_ctx) {
    m_tcp_buf.resize(kTcpBufSize, '\0');
}

QuicProxySession::~QuicProxySession() = default;

void QuicProxySession::start() {
    _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) + " opened",
                        Log::INFO);
}

void QuicProxySession::on_stream_data(const uint8_t* data, std::size_t len, bool fin) {
    if (m_destroyed) {
        return;
    }
    m_recv_buf.append(reinterpret_cast<const char*>(data), len);

    if (m_upstream_forwarding) {
        if (m_tcp_socket.is_open() && !m_recv_buf.empty()) {
            auto self = shared_from_this();
            auto buf  = TP_MAKE_SHARED(tp::string, m_recv_buf);
            m_recv_buf.clear();
            boost::asio::async_write(
                m_tcp_socket, boost::asio::buffer(*buf),
                [this, self, buf](const boost::system::error_code& ec, std::size_t) {
                    if (ec) {
                        destroy();
                    }
                });
        }
        // m_recv_buf will be flushed when the TCP connect completes if socket not open yet.
    } else if (!m_request_parsed) {
        try_parse_request();
    } else if (m_tcp_socket.is_open() && !m_recv_buf.empty()) {
        auto self = shared_from_this();
        auto buf  = TP_MAKE_SHARED(tp::string, m_recv_buf);
        m_recv_buf.clear();
        boost::asio::async_write(
            m_tcp_socket, boost::asio::buffer(*buf),
            [this, self, buf](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    destroy();
                }
            });
    }

    if (fin && m_tcp_socket.is_open()) {
        boost::system::error_code ec;
        m_tcp_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    }
}

void QuicProxySession::on_stream_close() {
    destroy();
}

void QuicProxySession::try_parse_request() {
    TrojanRequest req;
    int parsed = req.parse(m_recv_buf);
    if (parsed == -1) {
        _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                " not a trojan request, forwarding to h3_upstream",
                            Log::WARN);
        forward_to_h3_upstream();
        return;
    }
    if (parsed == 0) {
        // Need more bytes.
        return;
    }

    auto it = m_config.get_password().find(req.password);
    if (it == m_config.get_password().end()) {
        _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                " invalid password, forwarding to h3_upstream",
                            Log::WARN);
        // m_recv_buf still holds the original raw bytes (not yet consumed), forward verbatim.
        forward_to_h3_upstream();
        return;
    }

    _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                            " authenticated as " + it->second + " → " + req.address.address +
                            ":" + tp::to_string(req.address.port),
                        Log::INFO);

    m_request_parsed = true;
    m_payload        = req.payload;
    // Clear consumed bytes from buffer.
    m_recv_buf.clear();

    connect_target(tp::string(req.address.address), req.address.port);
}

void QuicProxySession::forward_to_h3_upstream() {
    const auto& h3 = m_config.get_quic().h3_upstream;
    if (h3.empty()) {
        _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                " h3_upstream not configured, dropping",
                            Log::WARN);
        destroy();
        return;
    }

    // Parse host:port from h3_upstream.
    auto colon_pos = h3.rfind(':');
    tp::string host((colon_pos == tp::string::npos) ? h3 : h3.substr(0, colon_pos));
    tp::string port_str((colon_pos == tp::string::npos) ? "443"
                                                         : h3.substr(colon_pos + 1));

    m_upstream_forwarding = true;

    auto self = shared_from_this();
    m_resolver.async_resolve(
        host, port_str,
        [this, self](const boost::system::error_code& ec,
                     boost::asio::ip::tcp::resolver::results_type results) {
            if (ec || m_destroyed) {
                _log_with_date_time("QuicProxySession: h3_upstream resolve failed: " +
                                        tp::string(ec.message().c_str()),
                                    Log::ERROR);
                destroy();
                return;
            }
            boost::asio::async_connect(
                m_tcp_socket, results,
                [this, self](const boost::system::error_code& ec2,
                             const boost::asio::ip::tcp::endpoint& ep) {
                    if (ec2 || m_destroyed) {
                        _log_with_date_time(
                            "QuicProxySession: h3_upstream config failed: " +
                                tp::string(m_config.get_quic().h3_upstream.c_str()) +
                                " unreachable, dropping client",
                            Log::ERROR);
                        destroy();
                        return;
                    }
                    _log_with_date_time(
                        "QuicProxySession: stream " + tp::to_string(m_stream_id) +
                            " forwarding to h3_upstream " +
                            tp::string(ep.address().to_string().c_str()) + ":" +
                            tp::to_string(ep.port()),
                        Log::INFO);

                    // Forward all buffered raw bytes (the original non-trojan request).
                    if (!m_recv_buf.empty()) {
                        auto buf = TP_MAKE_SHARED(tp::string, m_recv_buf);
                        m_recv_buf.clear();
                        boost::asio::async_write(
                            m_tcp_socket, boost::asio::buffer(*buf),
                            [this, self, buf](const boost::system::error_code& ec3, std::size_t) {
                                if (ec3) {
                                    destroy();
                                    return;
                                }
                                tcp_read();
                            });
                    } else {
                        tcp_read();
                    }
                });
        });
}

void QuicProxySession::connect_target(const tp::string& host, uint16_t port) {
    auto self = shared_from_this();
    m_resolver.async_resolve(
        host, tp::to_string(port).c_str(),
        [this, self](const boost::system::error_code& ec,
                     boost::asio::ip::tcp::resolver::results_type results) {
            if (ec || m_destroyed) {
                if (ec) {
                    _log_with_date_time("QuicProxySession: resolve failed: " +
                                            tp::string(ec.message().c_str()),
                                        Log::WARN);
                }
                destroy();
                return;
            }
            boost::asio::async_connect(
                m_tcp_socket, results,
                [this, self](const boost::system::error_code& ec2,
                             const boost::asio::ip::tcp::endpoint& ep) {
                    if (ec2 || m_destroyed) {
                        if (ec2) {
                            _log_with_date_time("QuicProxySession: connect failed: " +
                                                    tp::string(ec2.message().c_str()),
                                                Log::WARN);
                        }
                        destroy();
                        return;
                    }
                    _log_with_date_time(
                        "QuicProxySession: stream " + tp::to_string(m_stream_id) +
                            " connected to " + tp::string(ep.address().to_string().c_str()) +
                            ":" + tp::to_string(ep.port()),
                        Log::INFO);

                    // Forward payload (header remainder) and any data that
                    // arrived while TCP was connecting.
                    m_payload.append(m_recv_buf);
                    m_recv_buf.clear();

                    if (!m_payload.empty()) {
                        auto buf = TP_MAKE_SHARED(tp::string, std::move(m_payload));
                        m_payload.clear();
                        boost::asio::async_write(
                            m_tcp_socket, boost::asio::buffer(*buf),
                            [this, self, buf](const boost::system::error_code& ec3, std::size_t) {
                                if (ec3) {
                                    destroy();
                                    return;
                                }
                                tcp_read();
                            });
                    } else {
                        tcp_read();
                    }
                });
        });
}

void QuicProxySession::tcp_read() {
    if (m_destroyed || !m_tcp_socket.is_open()) {
        return;
    }
    auto self = shared_from_this();
    m_tcp_socket.async_read_some(
        boost::asio::buffer(&m_tcp_buf[0], kTcpBufSize),
        [this, self](const boost::system::error_code& ec, std::size_t bytes) {
            if (m_destroyed) {
                return;
            }
            if (ec) {
                if (ec != boost::asio::error::eof) {
                    _log_with_date_time("QuicProxySession: tcp read: " +
                                            tp::string(ec.message().c_str()),
                                        Log::WARN);
                }
                if (m_conn && !m_conn->is_closed()) {
                    m_conn->send_stream_data(m_stream_id, nullptr, 0, true);
                    m_conn->pump_write();
                }
                destroy();
                return;
            }
            if (m_conn && !m_conn->is_closed()) {
                m_conn->send_stream_data(m_stream_id,
                                         reinterpret_cast<const uint8_t*>(m_tcp_buf.data()),
                                         bytes, false);
                m_conn->pump_write();
            }
            tcp_read();
        });
}

void QuicProxySession::destroy() {
    if (m_destroyed) {
        return;
    }
    m_destroyed = true;
    m_resolver.cancel();
    boost::system::error_code ec;
    if (m_tcp_socket.is_open()) {
        m_tcp_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        m_tcp_socket.close(ec);
    }
    if (m_conn && !m_conn->is_closed()) {
        m_conn->send_stream_data(m_stream_id, nullptr, 0, true);
        m_conn->pump_write();
    }
    _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) + " closed",
                        Log::INFO);
}
