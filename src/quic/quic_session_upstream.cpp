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
#include "quic_connection.h"
#include "core/log.h"
#include <string_view>
#include <initializer_list>
#include <boost/asio/connect.hpp>
#include <boost/asio/write.hpp>

QuicUpstreamHandler::QuicUpstreamHandler(
    std::shared_ptr<QuicConnection> conn, int64_t stream_id,
    const Config& config, boost::asio::io_context& io_ctx,
    const tp::string& host, const tp::string& port_str)
    : m_conn_ptr(conn),
      m_stream_id(stream_id),
      m_config(config),
      m_io_ctx(io_ctx),
      m_conn(nullptr, nghttp3_conn_del),
      m_valid(true),
      m_host(host),
      m_port_str(port_str),
      m_tcp_socket(io_ctx),
      m_resolver(io_ctx),
      m_write_timer(io_ctx) {
    m_tcp_buf.resize(kTcpBufSize, '\0');

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

    nghttp3_conn* h3_conn = nullptr;
    auto* mem = nghttp3_mem_default();
    int rv = nghttp3_conn_server_new(&h3_conn, &callbacks, &settings, mem, this);
    if (rv != 0) {
        m_valid = false;
        return;
    }
    m_conn.reset(h3_conn);
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
    if (!m_valid) {
        if (len > 0) {
            write_to_upstream(tp::string(reinterpret_cast<const char*>(data), len), false);
        }
        if (fin) {
            write_to_upstream(tp::string(), true);
        }
        return;
    }
    if (!m_conn) return;

    auto consumed = nghttp3_conn_read_stream(
        m_conn.get(), m_stream_id,
        data, len, fin ? 1 : 0);
    if (consumed < 0 || (size_t)consumed < len) {
        m_valid = false;
        if (len > 0) {
            write_to_upstream(tp::string(reinterpret_cast<const char*>(data), len), false);
        }
        if (fin) {
            write_to_upstream(tp::string(), true);
        }
        return;
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
    if (m_conn) {
        m_conn.reset();
    }
    m_resolver.cancel();
    boost::system::error_code ec;
    if (m_tcp_socket.is_open()) {
        ec = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
        ec = m_tcp_socket.close(ec);
    }
    auto locked_conn = m_conn_ptr.lock();
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

int QuicUpstreamHandler::cb_begin_headers(
    nghttp3_conn*, int64_t, void* user_data, void*) {
    auto* handler = static_cast<QuicUpstreamHandler*>(user_data);
    handler->m_http1_request.clear();
    handler->m_method.clear();
    handler->m_scheme.clear();
    handler->m_authority.clear();
    handler->m_path.clear();
    handler->m_regular_headers.clear();
    handler->m_request_complete = false;
    handler->m_chunked_body = false;
    handler->m_has_content_length = false;
    handler->m_fin_sent = false;
    return 0;
}

int QuicUpstreamHandler::cb_recv_header(
    nghttp3_conn*, int64_t, int32_t, nghttp3_rcbuf* name,
    nghttp3_rcbuf* value, uint8_t, void* user_data, void*) {
    auto* handler = static_cast<QuicUpstreamHandler*>(user_data);
    auto name_vec = nghttp3_rcbuf_get_buf(name);
    auto value_vec = nghttp3_rcbuf_get_buf(value);
    tp::string name_str(reinterpret_cast<char*>(name_vec.base), name_vec.len);
    tp::string value_str(reinterpret_cast<char*>(value_vec.base), value_vec.len);

    using namespace std::literals;
    if (value_str.find_first_of("\r\n\0"sv) != tp::string::npos) {
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    if (name_str == ":method") {
        if (!handler->m_method.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
        handler->m_method = value_str;
    } else if (name_str == ":scheme") {
        if (!handler->m_scheme.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
        handler->m_scheme = value_str;
    } else if (name_str == ":authority") {
        if (!handler->m_authority.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
        handler->m_authority = value_str;
    } else if (name_str == ":path") {
        if (!handler->m_path.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
        handler->m_path = value_str;
    } else {
        if (name_str == "content-length") {
            handler->m_has_content_length = true;
        }
        static const std::initializer_list<std::string_view> kForbiddenH3Headers = {
            "connection", "keep-alive", "proxy-connection",
            "transfer-encoding", "upgrade", "host"
        };
        for (auto& h : kForbiddenH3Headers) {
            if (name_str == h) return 0;
        }
        handler->m_regular_headers += name_str + ": " + value_str + "\r\n";
    }

    return 0;
}

int QuicUpstreamHandler::cb_end_headers(
    nghttp3_conn*, int64_t, int fin, void* user_data, void*) {
    auto* handler = static_cast<QuicUpstreamHandler*>(user_data);

    if (handler->m_method.empty()) {
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    if (handler->m_method == "CONNECT") {
        if (handler->m_authority.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
    } else {
        if (handler->m_path.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    if (handler->m_method == "CONNECT") {
        handler->m_http1_request = "CONNECT " + handler->m_authority + " HTTP/1.1\r\n";
    } else {
        handler->m_http1_request = handler->m_method + " " + handler->m_path + " HTTP/1.1\r\n";
    }
    handler->m_http1_request += handler->m_regular_headers;

    if (!handler->m_has_content_length &&
        (handler->m_method == "POST" || handler->m_method == "PUT" || handler->m_method == "PATCH")) {
        handler->m_http1_request += "Transfer-Encoding: chunked\r\n";
        handler->m_chunked_body = true;
    }

    if (!handler->m_authority.empty()) {
        handler->m_http1_request += "Host: " + handler->m_authority + "\r\n";
    }
    handler->m_http1_request += "Connection: close\r\n\r\n";

    handler->m_request_complete = true;

    handler->write_to_upstream(std::move(handler->m_http1_request), false);
    handler->m_http1_request.clear();
    if (fin) {
        if (handler->m_chunked_body) {
            handler->write_to_upstream(tp::string("0\r\n\r\n"), false);
        }
        handler->write_to_upstream(tp::string(), true);
        handler->m_fin_sent = true;
    }
    return 0;
}

int QuicUpstreamHandler::cb_recv_data(
    nghttp3_conn*, int64_t, const uint8_t* data,
    size_t datalen, void* user_data, void*) {
    auto* handler = static_cast<QuicUpstreamHandler*>(user_data);
    if (datalen > 0) {
        if (handler->m_chunked_body) {
            char hex[16];
            int n = snprintf(hex, sizeof(hex), "%zx\r\n", datalen);
            handler->write_to_upstream(tp::string(hex, n), false);
            handler->write_to_upstream(tp::string(reinterpret_cast<const char*>(data), datalen), false);
            handler->write_to_upstream(tp::string("\r\n"), false);
        } else {
            handler->write_to_upstream(tp::string(reinterpret_cast<const char*>(data), datalen), false);
        }
    }
    return 0;
}

int QuicUpstreamHandler::cb_end_stream(
    nghttp3_conn*, int64_t, void* user_data, void*) {
    auto* handler = static_cast<QuicUpstreamHandler*>(user_data);
    if (handler->m_fin_sent) return 0;
    if (handler->m_chunked_body) {
        handler->write_to_upstream(tp::string("0\r\n\r\n"), false);
    }
    handler->write_to_upstream(tp::string(), true);
    handler->m_fin_sent = true;
    return 0;
}

int QuicUpstreamHandler::cb_stream_close(
    nghttp3_conn*, int64_t, uint64_t, void* user_data, void*) {
    auto* handler = static_cast<QuicUpstreamHandler*>(user_data);
    if (handler->m_fin_sent) return 0;
    if (handler->m_chunked_body) {
        handler->write_to_upstream(tp::string("0\r\n\r\n"), false);
    }
    handler->write_to_upstream(tp::string(), true);
    handler->m_fin_sent = true;
    return 0;
}
