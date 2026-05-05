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
#include <memory>

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
      m_tcp_socket(io_ctx),
      m_resolver(io_ctx),
      m_udp_socket(io_ctx),
      m_udp_resolver(io_ctx),
      m_write_timer(io_ctx) {
    m_tcp_buf.resize(kTcpBufSize, '\0');
    m_udp_buf.resize(kTcpBufSize, '\0');
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

    if (Log::level == Log::ALL) {
        char hex[129];
        for (int i = 0; i < std::min((int)len, 64); ++i) {
            snprintf(hex + i * 2, 3, "%02x", data[i]);
        }
        hex[std::min((int)len, 64) * 2] = '\0';
        _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) + " recv " +
                            tp::to_string(len) + " bytes, parsed=" + tp::to_string(m_request_parsed) +
                            " hex=" + hex, Log::ALL);
    }


    if (m_upstream_forwarding) {
        if (!m_recv_buf.empty() && m_udp_socket.is_open()) {
            // UDP socket is ready: forward accumulated bytes immediately.
            boost::system::error_code ec;
            m_udp_socket.send_to(boost::asio::buffer(m_recv_buf), m_udp_remote_ep, 0, ec);
            m_recv_buf.clear();
        }
        // If socket is not yet open (DNS resolve still pending), leave m_recv_buf intact
        // so the resolve callback in forward_to_h3_upstream() will flush it once ready.
        if (fin) {
            destroy(); // Close stream if FIN received in fallback mode.
        }
    } else if (!m_request_parsed) {
        try_parse_request();
        if (m_request_parsed && fin) {
            write_to_target(tp::string(), true);
        }
    } else if (!m_recv_buf.empty() || fin) {
        write_to_target(std::move(m_recv_buf), fin);
        m_recv_buf.clear();
    }
}

void QuicProxySession::on_stream_close() {
    destroy();
}

void QuicProxySession::try_parse_request() {
    // Wait for at least the first CRLF (end of password) before deciding if it's Trojan.
    // This avoids premature fallback to h3_upstream if the password is split across packets.
    size_t first_crlf = m_recv_buf.find("\r\n");
    if (first_crlf == tp::string::npos) {
        if (m_recv_buf.length() > 512) { // Reasonable limit for a password line
            _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                    " no CRLF in 512 bytes, falling back to h3_upstream",
                                Log::WARN);
            forward_to_h3_upstream();
        }
        return;
    }

    TrojanRequest req;
    int parsed = req.parse(m_recv_buf);
    if (parsed == -1) {
        // If it has a CRLF but still fails to parse as Trojan, it's definitely non-trojan.
        _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                " parse failed, forwarding to h3_upstream",
                            Log::INFO);
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
                            ":" + tp::to_string(req.address.port) + " payload_len=" + 
                            tp::to_string(req.payload.length()),
                        Log::INFO);

    m_request_parsed = true;
    if (!req.payload.empty()) {
        write_to_target(tp::string(req.payload.data(), req.payload.length()));
    }
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
    tp::string port_str((colon_pos == tp::string::npos) ? "443" : h3.substr(colon_pos + 1));

    m_upstream_forwarding = true;

    auto self = this->shared_from_this();
    m_udp_resolver.async_resolve(
        host, port_str,
        [this, self](const boost::system::error_code& ec,
                     boost::asio::ip::udp::resolver::results_type results) {
            if (ec || m_destroyed) {
                _log_with_date_time("QuicProxySession: h3_upstream UDP resolve failed: " +
                                        tp::string(ec.message().c_str()),
                                    Log::ERROR);
                destroy();
                return;
            }

            m_udp_remote_ep = *results.begin();
            boost::system::error_code ec2;
            m_udp_socket.open(m_udp_remote_ep.protocol(), ec2);
            if (ec2) {
                _log_with_date_time("QuicProxySession: h3_upstream UDP socket open failed: " +
                                        tp::string(ec2.message().c_str()),
                                    Log::ERROR);
                destroy();
                return;
            }

            _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                    " forwarding to UDP h3_upstream " +
                                    tp::string(m_udp_remote_ep.address().to_string().c_str()) + ":" +
                                    tp::to_string(m_udp_remote_ep.port()),
                                Log::INFO);

            // Forward all buffered raw bytes.
            if (!m_recv_buf.empty()) {
                boost::system::error_code ec3;
                m_udp_socket.send_to(boost::asio::buffer(m_recv_buf), m_udp_remote_ep, 0, ec3);
                m_recv_buf.clear();
            }
            udp_read();
        });
}

void QuicProxySession::udp_read() {
    if (m_destroyed || !m_udp_socket.is_open()) {
        return;
    }
    auto self = this->shared_from_this();
    m_udp_socket.async_receive_from(
        boost::asio::buffer(&m_udp_buf[0], kTcpBufSize), m_udp_remote_ep,
        [this, self](const boost::system::error_code& ec, std::size_t bytes) {
            if (m_destroyed) {
                return;
            }
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    _log_with_date_time("QuicProxySession: h3_upstream UDP read: " +
                                            tp::string(ec.message().c_str()),
                                        Log::WARN);
                    destroy();
                }
                return;
            }
            if (m_conn && !m_conn->is_closed()) {
                m_conn->send_stream_data(m_stream_id, reinterpret_cast<const uint8_t*>(&m_udp_buf[0]), bytes, false);
                m_conn->pump_write();
            }
            udp_read();
        });
}

void QuicProxySession::connect_target(const tp::string& host, uint16_t port) {
    auto self = this->shared_from_this();
    m_resolver.async_resolve(
        host, tp::to_string(port).c_str(),
        [this, self, host, port](const boost::system::error_code& ec,
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
                [this, self, host, port](const boost::system::error_code& ec2,
                                         [[maybe_unused]] const boost::asio::ip::tcp::endpoint& ep) {
                    if (ec2 || m_destroyed) {
                        _log_with_date_time(
                            "QuicProxySession: target unreachable (" + host + ":" +
                                tp::to_string(port) + "), dropping client: " +
                                tp::string(ec2.message().c_str()),
                            Log::ERROR);
                        destroy();
                        return;
                    }
                    _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                            " connected to " + host + ":" + tp::to_string(port),
                                        Log::INFO);

                    // Forward any data that arrived while TCP was connecting.
                    if (!m_is_writing_to_tcp && m_tcp_socket.is_open()) {
                        do_tcp_write();
                    }
                    tcp_read();
                });
        });
}

void QuicProxySession::write_to_target(tp::string data, bool fin) {
    if (data.empty() && !fin) {
        return;
    }
    m_tcp_write_queue.push_back({std::move(data), fin});
    if (!m_is_writing_to_tcp && m_tcp_socket.is_open()) {
        do_tcp_write();
    }
}

void QuicProxySession::do_tcp_write() {
    if (m_destroyed || !m_tcp_socket.is_open() || m_tcp_write_queue.empty()) {
        m_is_writing_to_tcp = false;
        return;
    }

    m_is_writing_to_tcp = true;
    auto self = this->shared_from_this();
    auto& front = m_tcp_write_queue.front();
    
    // If we only have a FIN (no data), handle it immediately.
    if (front.data.empty() && front.fin) {
        boost::system::error_code ec;
        m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_send, ec);
        m_tcp_write_queue.pop_front();
        do_tcp_write();
        return;
    }

    auto buf = TP_MAKE_SHARED(tp::string, std::move(front.data));
    bool fin = front.fin;
    m_tcp_write_queue.pop_front();

    boost::asio::async_write(
        m_tcp_socket, boost::asio::buffer(*buf),
        [this, self, buf, fin](const boost::system::error_code& ec, std::size_t) {
            if (m_destroyed) {
                return;
            }
            if (ec) {
                destroy();
                return;
            }
            if (fin) {
                boost::system::error_code ec2;
                m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_send, ec2);
            }
            do_tcp_write();
        });
}

void QuicProxySession::tcp_read() {
    if (m_destroyed || !m_tcp_socket.is_open()) {
        return;
    }
    auto self = this->shared_from_this();
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
                flush_tcp_read_buf(0, bytes);
            }
        });
}

void QuicProxySession::flush_tcp_read_buf(std::size_t offset, std::size_t bytes) {
    if (m_destroyed || !m_conn || m_conn->is_closed()) {
        return;
    }

    int64_t written = m_conn->send_stream_data(m_stream_id,
                                               reinterpret_cast<const uint8_t*>(m_tcp_buf.data() + offset),
                                               bytes - offset, false);
    if (written < 0) {
        destroy();
        return;
    }

    m_conn->pump_write();

    offset += written;
    if (offset < bytes) {
        m_write_timer.expires_after(std::chrono::milliseconds(5));
        auto self = this->shared_from_this();
        m_write_timer.async_wait([this, self, offset, bytes](const boost::system::error_code& ec) {
            if (!ec) {
                flush_tcp_read_buf(offset, bytes);
            }
        });
    } else {
        tcp_read();
    }
}

void QuicProxySession::destroy() {
    if (m_destroyed) {
        return;
    }
    m_destroyed = true;
    m_resolver.cancel();
    m_udp_resolver.cancel();
    boost::system::error_code ec;
    if (m_tcp_socket.is_open()) {
        m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
        m_tcp_socket.close(ec);
    }
    if (m_udp_socket.is_open()) {
        m_udp_socket.close(ec);
    }
    if (m_conn && !m_conn->is_closed()) {
        m_conn->send_stream_data(m_stream_id, nullptr, 0, true);
        m_conn->pump_write();
    }
    _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) + " closed",
                        Log::INFO);
}
