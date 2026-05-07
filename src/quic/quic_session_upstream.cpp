/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_session_upstream.h"

#include <initializer_list>
#include <string_view>

#include <boost/asio/connect.hpp>
#include <boost/asio/write.hpp>
#include <nghttp3/nghttp3.h>

#include "core/log.h"
#include "quic_connection.h"
#include "quic_to_http3_connect.h"

QuicUpstreamHandler::QuicUpstreamHandler(
    std::shared_ptr<QuicConnection> conn, int64_t stream_id,
    const Config& config, boost::asio::io_context& io_ctx,
    const tp::string& host, const tp::string& port_str)
    : m_conn_ptr(conn),
      m_stream_id(stream_id),
      m_config(config),
      m_io_ctx(io_ctx),
      m_valid(true),
      m_host(host),
      m_port_str(port_str),
      m_tcp_socket(io_ctx),
      m_resolver(io_ctx),
      m_write_timer(io_ctx) {
    m_tcp_buf.resize(kTcpBufSize, '\0');
}

QuicUpstreamHandler::~QuicUpstreamHandler() = default;

void QuicUpstreamHandler::start() {
    auto self = shared_from_this();
    m_resolver.async_resolve(
        m_host, m_port_str,
        [this, self](const boost::system::error_code& ec,
                     boost::asio::ip::tcp::resolver::results_type results) {
            if (m_destroyed || ec) {
                if (ec) {
                    _log_with_date_time("QuicUpstreamHandler: h3_upstream TCP resolve failed: " +
                                            tp::string(ec.message().c_str()),
                                        Log::ERROR);
                }
                destroy();
                return;
            }

            boost::asio::async_connect(
                m_tcp_socket, results,
                [this, self](const boost::system::error_code& ec2, const auto&) {
                    if (m_destroyed || ec2) {
                        if (ec2) {
                            _log_with_date_time("QuicUpstreamHandler: h3_upstream TCP connect failed: " +
                                                    tp::string(ec2.message().c_str()),
                                                Log::ERROR);
                        }
                        destroy();
                        return;
                    }

                    _log_with_date_time("QuicUpstreamHandler: stream " + tp::to_string(m_stream_id) +
                        " HTTP upstream connected to " + m_host + ":" + m_port_str, Log::INFO);

                    if (!m_is_writing_to_tcp && !m_tcp_write_queue.empty()) {
                        do_tcp_write();
                    }
                    tcp_read_from_upstream();
                });
        });
}

void QuicUpstreamHandler::on_stream_data(const uint8_t* data, size_t len, bool fin) {
    auto locked_conn = m_conn_ptr.lock();
    if (!locked_conn || locked_conn->is_closed()) return;

    if (!m_valid) {
        if (len > 0) {
            write_to_upstream(tp::string(reinterpret_cast<const char*>(data), len), false);
        }
        if (fin) {
            write_to_upstream(tp::string(), true);
        }
        return;
    }

    auto& h3 = locked_conn->get_or_create_h3();
    auto consumed = h3.feed_stream_data(m_stream_id, data, len, fin);
    if (consumed < 0 || (size_t)consumed < len) {
        m_valid = false;
        if (len > 0) {
            write_to_upstream(tp::string(reinterpret_cast<const char*>(data), len), false);
        }
        if (fin) {
            write_to_upstream(tp::string(), true);
        }
    }
}

void QuicUpstreamHandler::on_stream_close() {
    destroy();
}

void QuicUpstreamHandler::destroy() {
    if (m_destroyed) {
        return;
    }
    m_destroyed = true;

    auto locked_conn = m_conn_ptr.lock();
    if (locked_conn) {
        // Unregister from h3 BEFORE remove_stream_handler drops the shared_ptr,
        // so no pending nghttp3 callback can dereference a dangling raw pointer.
        if (auto* h3 = locked_conn->h3_if_exists()) {
            h3->unregister_stream(m_stream_id);
        }
    }

    m_resolver.cancel();
    boost::system::error_code ec;
    if (m_tcp_socket.is_open()) {
        ec = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
        ec = m_tcp_socket.close(ec);
    }
    if (locked_conn) {
        locked_conn->remove_stream_handler(m_stream_id);
    }
}

void QuicUpstreamHandler::write_to_upstream(tp::string data, bool fin) {
    if (data.empty() && !fin) {
        return;
    }
    m_tcp_write_queue.push_back({std::move(data), fin});
    if (!m_is_writing_to_tcp && m_tcp_socket.is_open()) {
        do_tcp_write();
    }
}

void QuicUpstreamHandler::do_tcp_write() {
    if (m_destroyed || !m_tcp_socket.is_open() || m_tcp_write_queue.empty()) {
        m_is_writing_to_tcp = false;
        return;
    }

    m_is_writing_to_tcp = true;
    auto self = shared_from_this();
    auto& front = m_tcp_write_queue.front();

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
            if (fin && buf->empty()) {
                boost::system::error_code ec2;
                ec2 = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_send, ec2);
            }
            do_tcp_write();
        });
}

void QuicUpstreamHandler::tcp_read_from_upstream() {
    if (!m_tcp_socket.is_open()) {
        return;
    }
    auto self = shared_from_this();
    m_tcp_socket.async_read_some(
        boost::asio::buffer(&m_tcp_buf[0], kTcpBufSize),
        [this, self](const boost::system::error_code& ec, std::size_t bytes) {
            if (m_destroyed) {
                return;
            }
            auto locked_conn = m_conn_ptr.lock();
            if (ec) {
                if (locked_conn && !locked_conn->is_closed()) {
                    locked_conn->send_stream_data(m_stream_id, nullptr, 0, true);
                    locked_conn->pump_write();
                }
                destroy();
                return;
            }
            if (locked_conn && !locked_conn->is_closed()) {
                flush_tcp_read_buf(0, bytes);
            }
        });
}

void QuicUpstreamHandler::flush_tcp_read_buf(std::size_t offset, std::size_t bytes) {
    auto locked_conn = m_conn_ptr.lock();
    if (m_destroyed || !locked_conn || locked_conn->is_closed()) {
        return;
    }

    int64_t written = locked_conn->send_stream_data(
        m_stream_id,
        reinterpret_cast<const uint8_t*>(m_tcp_buf.data() + offset),
        bytes - offset, false);

    if (written < 0) {
        destroy();
        return;
    }

    locked_conn->pump_write();

    offset += written;
    if (offset < bytes) {
        m_write_timer.expires_after(std::chrono::milliseconds(5));
        auto self = shared_from_this();
        m_write_timer.async_wait([this, self, offset, bytes](const boost::system::error_code& ec) {
            if (!ec && !m_destroyed) {
                flush_tcp_read_buf(offset, bytes);
            }
        });
    } else {
        tcp_read_from_upstream();
    }
}

// ---- on_h3_* instance methods (migrated from old static cb_* callbacks) ----

int QuicUpstreamHandler::on_h3_begin_headers() {
    m_http1_request.clear();
    m_method.clear();
    m_scheme.clear();
    m_authority.clear();
    m_path.clear();
    m_regular_headers.clear();
    m_request_complete = false;
    m_chunked_body     = false;
    m_has_content_length = false;
    m_fin_sent         = false;
    return 0;
}

int QuicUpstreamHandler::on_h3_header(const tp::string& name, const tp::string& value) {
    using namespace std::literals;
    if (value.find_first_of("\r\n\0"sv) != tp::string::npos) {
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    if (name == ":method") {
        if (!m_method.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
        m_method = value;
    } else if (name == ":scheme") {
        if (!m_scheme.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
        m_scheme = value;
    } else if (name == ":authority") {
        if (!m_authority.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
        m_authority = value;
    } else if (name == ":path") {
        if (!m_path.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
        m_path = value;
    } else {
        if (name == "content-length") {
            m_has_content_length = true;
        }
        static const std::initializer_list<std::string_view> kForbiddenH3Headers = {
            "connection", "keep-alive", "proxy-connection",
            "transfer-encoding", "upgrade", "host"
        };
        for (auto& h : kForbiddenH3Headers) {
            if (name == h) return 0;
        }
        m_regular_headers += name + ": " + value + "\r\n";
    }

    return 0;
}

int QuicUpstreamHandler::on_h3_end_headers(bool fin) {
    if (m_method.empty()) {
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    if (m_method == "CONNECT") {
        if (m_authority.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
    } else {
        if (m_path.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    if (m_method == "CONNECT") {
        m_http1_request = "CONNECT " + m_authority + " HTTP/1.1\r\n";
    } else {
        m_http1_request = m_method + " " + m_path + " HTTP/1.1\r\n";
    }
    m_http1_request += m_regular_headers;

    if (!m_has_content_length &&
        (m_method == "POST" || m_method == "PUT" || m_method == "PATCH")) {
        m_http1_request += "Transfer-Encoding: chunked\r\n";
        m_chunked_body = true;
    }

    if (!m_authority.empty()) {
        m_http1_request += "Host: " + m_authority + "\r\n";
    }
    m_http1_request += "Connection: close\r\n\r\n";

    m_request_complete = true;

    write_to_upstream(std::move(m_http1_request), false);
    m_http1_request.clear();
    if (fin) {
        if (m_chunked_body) {
            write_to_upstream(tp::string("0\r\n\r\n"), false);
        }
        write_to_upstream(tp::string(), true);
        m_fin_sent = true;
    }
    return 0;
}

int QuicUpstreamHandler::on_h3_data(const uint8_t* data, std::size_t datalen) {
    if (datalen > 0) {
        if (m_chunked_body) {
            char hex[16];
            int n = snprintf(hex, sizeof(hex), "%zx\r\n", datalen);
            write_to_upstream(tp::string(hex, n), false);
            write_to_upstream(tp::string(reinterpret_cast<const char*>(data), datalen), false);
            write_to_upstream(tp::string("\r\n"), false);
        } else {
            write_to_upstream(tp::string(reinterpret_cast<const char*>(data), datalen), false);
        }
    }
    return 0;
}

int QuicUpstreamHandler::on_h3_end_stream() {
    if (m_fin_sent) return 0;
    if (m_chunked_body) {
        write_to_upstream(tp::string("0\r\n\r\n"), false);
    }
    write_to_upstream(tp::string(), true);
    m_fin_sent = true;
    return 0;
}

int QuicUpstreamHandler::on_h3_stream_close(uint64_t /*app_error_code*/) {
    if (m_fin_sent) return 0;
    if (m_chunked_body) {
        write_to_upstream(tp::string("0\r\n\r\n"), false);
    }
    write_to_upstream(tp::string(), true);
    m_fin_sent = true;
    return 0;
}
