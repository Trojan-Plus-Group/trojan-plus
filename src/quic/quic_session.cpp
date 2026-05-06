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

// Reuse the same upper bound as the password hash storage in Config.
static constexpr std::size_t kMaxPasswordLineBytes = Config::MAX_PASSWORD_LENGTH;

QuicProxySession::QuicProxySession(std::shared_ptr<QuicConnection> conn, int64_t stream_id,
                                   const Config& config, boost::asio::io_context& io_ctx)
    : m_conn(std::move(conn)),
      m_stream_id(stream_id),
      m_config(config),
      m_tcp_socket(io_ctx),
      m_resolver(io_ctx),
      m_write_timer(io_ctx) {
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
        if (m_h3_handler && !m_recv_buf.empty()) {
            m_h3_handler->feed_stream_data(
                reinterpret_cast<const uint8_t*>(m_recv_buf.data()),
                m_recv_buf.size(), fin);
            m_recv_buf.clear();
        }
        if (fin) {
            destroy();
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
    if (m_upstream_forwarding && !m_h3_handler) {
        // TCP not yet connected - defer destroy until connection completes or timeout
        m_stream_fin_received = true;
        return;
    }
    destroy();
}

void QuicProxySession::try_parse_request() {
    // Wait for at least the first CRLF (end of password) before deciding if it's Trojan.
    // This avoids premature fallback to h3_upstream if the password is split across packets.
    size_t first_crlf = m_recv_buf.find("\r\n");
    if (first_crlf == tp::string::npos) {
        if (m_recv_buf.length() > kMaxPasswordLineBytes) {
            _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                    " no CRLF in " + tp::to_string(kMaxPasswordLineBytes) +
                                    " bytes, falling back to h3_upstream",
                                Log::WARN);
            forward_to_h3_upstream();
        }
        return;
    }
    if (first_crlf > kMaxPasswordLineBytes) {
        _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                " password line exceeds " + tp::to_string(kMaxPasswordLineBytes) +
                                " bytes, falling back to h3_upstream",
                            Log::WARN);
        forward_to_h3_upstream();
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
    tp::string host;
    tp::string port_str;

    if (!h3.empty()) {
        auto colon_pos = h3.rfind(':');
        host = (colon_pos == tp::string::npos) ? h3 : h3.substr(0, colon_pos);
        port_str = (colon_pos == tp::string::npos) ? "80" : h3.substr(colon_pos + 1);
    } else if (!m_config.get_remote_addr().empty()) {
        host = m_config.get_remote_addr();
        port_str = tp::to_string(m_config.get_remote_port());
    } else {
        _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                " no h3_upstream or remote_addr configured, dropping",
                            Log::WARN);
        destroy();
        return;
    }

    m_upstream_forwarding = true;

    auto self = this->shared_from_this();
    m_resolver.async_resolve(
        host, port_str,
        [this, self, host, port_str](const boost::system::error_code& ec,
                                     boost::asio::ip::tcp::resolver::results_type results) {
            if (ec || m_destroyed) {
                _log_with_date_time("QuicProxySession: h3_upstream TCP resolve failed: " +
                                        tp::string(ec.message().c_str()),
                                    Log::ERROR);
                destroy();
                return;
            }

            boost::asio::async_connect(
                m_tcp_socket, results,
                [this, self, host, port_str](const boost::system::error_code& ec2, const auto&) {
                    if (ec2 || m_destroyed) {
                        _log_with_date_time("QuicProxySession: h3_upstream TCP connect failed: " +
                                                tp::string(ec2.message().c_str()),
                                            Log::ERROR);
                        destroy();
                        return;
                    }

                    _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                        " HTTP upstream connected to " + host + ":" + port_str, Log::INFO);

                    // Create H3 handler and flush any buffered data
                    m_h3_handler = std::make_unique<H3UpstreamHandler>(
                        *this,
                        [this](tp::string data, bool fin) { write_to_target(std::move(data), fin); },
                        [this]() { destroy(); });

                    if (!m_recv_buf.empty()) {
                        m_h3_handler->feed_stream_data(
                            reinterpret_cast<const uint8_t*>(m_recv_buf.data()),
                            m_recv_buf.size(), m_stream_fin_received);
                        // If h3 handler didn't parse headers, fall back to raw byte forwarding
                        if (m_h3_handler && !m_h3_handler->is_request_complete() && m_h3_handler->is_valid()) {
                            _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) +
                                " h3 parse incomplete, falling back to raw bytes", Log::WARN);
                            write_to_target(std::move(m_recv_buf), m_stream_fin_received);
                        }
                        m_recv_buf.clear();
                    }
                    tcp_read_from_upstream();
                });
        });
}

void QuicProxySession::tcp_read_from_upstream() {
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
                destroy();
                return;
            }
            if (m_conn && !m_conn->is_closed()) {
                flush_tcp_read_buf(0, bytes);
            }
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
        ec = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_send, ec);
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
            // Only shutdown send if there's no data (FIN-only case)
            // If we sent data with fin=true, wait for response before closing
            if (fin && buf->empty()) {
                boost::system::error_code ec2;
                ec2 = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_send, ec2);
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
    if (m_h3_handler) {
        m_h3_handler->close();
        m_h3_handler.reset();
    }
    boost::system::error_code ec;
    if (m_tcp_socket.is_open()) {
        ec = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
        ec = m_tcp_socket.close(ec);
    }
    if (m_conn && !m_conn->is_closed()) {
        m_conn->send_stream_data(m_stream_id, nullptr, 0, true);
        m_conn->pump_write();
    }
    _log_with_date_time("QuicProxySession: stream " + tp::to_string(m_stream_id) + " closed",
                        Log::INFO);
}

// ============================================================================
// H3UpstreamHandler - nghttp3 HTTP/3 decoder and h3→h1.1 converter
// ============================================================================

QuicProxySession::H3UpstreamHandler::H3UpstreamHandler(
    QuicProxySession& parent, WriteCallback write_cb, CloseCallback close_cb)
    : m_parent(parent),
      m_write_cb(std::move(write_cb)),
      m_close_cb(std::move(close_cb)),
      m_conn(nullptr, nghttp3_conn_del),
      m_valid(true) {

    nghttp3_callbacks callbacks = {};
    callbacks.begin_headers = &cb_begin_headers;
    callbacks.recv_header = &cb_recv_header;
    callbacks.end_headers = &cb_end_headers;
    callbacks.recv_data = &cb_recv_data;
    callbacks.end_stream = &cb_end_stream;
    callbacks.stream_close = &cb_stream_close;

    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    settings.max_field_section_size = (1ULL << 62) - 1;
    settings.qpack_max_dtable_capacity = 4096;
    settings.qpack_encoder_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams = 100;

    nghttp3_conn* conn = nullptr;
    auto* mem = nghttp3_mem_default();
    int rv = nghttp3_conn_server_new(&conn, &callbacks, &settings, mem, this);
    if (rv != 0) {
        // nghttp3 init failed - fall back to raw byte forwarding
        m_valid = false;
        return;
    }
    m_conn.reset(conn);
}

QuicProxySession::H3UpstreamHandler::~H3UpstreamHandler() = default;

void QuicProxySession::H3UpstreamHandler::feed_stream_data(const uint8_t* data, size_t len, bool fin) {
    if (!m_valid) {
        // Fallback to raw byte forwarding
        if (len > 0) {
            m_write_cb(tp::string(reinterpret_cast<const char*>(data), len), fin);
        }
        return;
    }
    if (!m_conn) return;

    auto consumed = nghttp3_conn_read_stream(
        m_conn.get(), m_parent.m_stream_id,
        data, len, fin ? 1 : 0);
    if (consumed < 0 || (size_t)consumed < len) {
        // nghttp3 decode failed or didn't consume all data - fall back to raw byte forwarding
        m_valid = false;
        if (len > 0) {
            m_write_cb(tp::string(reinterpret_cast<const char*>(data), len), fin);
        }
        return;
    }
}

void QuicProxySession::H3UpstreamHandler::close() {
    if (m_conn) {
        m_conn.reset();
    }
}

void QuicProxySession::H3UpstreamHandler::build_http1_request_line() {
    // Build HTTP/1.1 request line from pseudo-headers
    // e.g., "GET / HTTP/1.1\r\n"
    m_http1_request = m_method + " " + m_path + " HTTP/1.1\r\n";
    m_request_complete = true;
}

int QuicProxySession::H3UpstreamHandler::cb_begin_headers(
    nghttp3_conn*, int64_t, void* user_data, void*) {
    auto* handler = static_cast<H3UpstreamHandler*>(user_data);
    handler->m_http1_request.clear();
    handler->m_method.clear();
    handler->m_scheme.clear();
    handler->m_authority.clear();
    handler->m_path.clear();
    handler->m_regular_headers.clear();
    handler->m_request_complete = false;
    return 0;
}

int QuicProxySession::H3UpstreamHandler::cb_recv_header(
    nghttp3_conn*, int64_t, int32_t, nghttp3_rcbuf* name,
    nghttp3_rcbuf* value, uint8_t, void* user_data, void*) {
    auto* handler = static_cast<H3UpstreamHandler*>(user_data);
    auto name_vec = nghttp3_rcbuf_get_buf(name);
    auto value_vec = nghttp3_rcbuf_get_buf(value);
    tp::string name_str(reinterpret_cast<char*>(name_vec.base), name_vec.len);
    tp::string value_str(reinterpret_cast<char*>(value_vec.base), value_vec.len);

    // Track pseudo-headers for request line reconstruction
    if (name_str == ":method") {
        handler->m_method = value_str;
    } else if (name_str == ":scheme") {
        handler->m_scheme = value_str;
    } else if (name_str == ":authority") {
        handler->m_authority = value_str;
    } else if (name_str == ":path") {
        handler->m_path = value_str;
    } else {
        // Regular headers: accumulate separately
        handler->m_regular_headers += name_str + ": " + value_str + "\r\n";
    }

    nghttp3_rcbuf_decref(name);
    nghttp3_rcbuf_decref(value);
    return 0;
}

int QuicProxySession::H3UpstreamHandler::cb_end_headers(
    nghttp3_conn*, int64_t, int fin, void* user_data, void*) {
    auto* handler = static_cast<H3UpstreamHandler*>(user_data);
    // Build complete HTTP/1.1 request: request line + headers + \r\n
    // 1. Request line
    handler->m_http1_request = handler->m_method + " " + handler->m_path + " HTTP/1.1\r\n";
    // 2. Regular headers
    handler->m_http1_request += handler->m_regular_headers;
    // 3. Host header from authority if present
    if (!handler->m_authority.empty()) {
        handler->m_http1_request += "Host: " + handler->m_authority + "\r\n";
    }
    // 4. End of headers
    handler->m_http1_request += "\r\n";

    handler->m_request_complete = true;

    if (fin) {
        // Request complete, send to backend
        handler->m_write_cb(tp::string(handler->m_http1_request), true);
    }
    return 0;
}

int QuicProxySession::H3UpstreamHandler::cb_recv_data(
    nghttp3_conn*, int64_t, const uint8_t* data,
    size_t datalen, void* user_data, void*) {
    auto* handler = static_cast<H3UpstreamHandler*>(user_data);
    handler->m_http1_request.append(reinterpret_cast<const char*>(data), datalen);
    return 0;
}

int QuicProxySession::H3UpstreamHandler::cb_end_stream(
    nghttp3_conn*, int64_t, void* user_data, void*) {
    auto* handler = static_cast<H3UpstreamHandler*>(user_data);
    if (!handler->m_http1_request.empty()) {
        handler->m_write_cb(tp::string(handler->m_http1_request), true);
    }
    return 0;
}

int QuicProxySession::H3UpstreamHandler::cb_stream_close(
    nghttp3_conn*, int64_t, uint64_t, void*, void*) {
    return 0;
}
