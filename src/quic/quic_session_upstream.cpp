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
    boost::asio::io_context& io_ctx,
    const tp::string& host, const tp::string& port_str)
    : m_conn_ptr(conn),
      m_stream_id(stream_id),
      m_destroyed(false),
      m_host(host),
      m_port_str(port_str),
      m_tcp_socket(io_ctx),
      m_resolver(io_ctx),
      m_write_timer(io_ctx) {
    m_tcp_buf.resize(kTcpBufSize, '\0');
    m_body_out_buf.resize(kTcpBufSize, '\0');
    m_resp_parser = std::make_unique<H1RespParser>();
    m_resp_parser->eager(true);
    m_resp_parser->body_limit((std::numeric_limits<uint64_t>::max)());
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

    auto& h3 = locked_conn->get_or_create_h3();
    auto consumed = h3.feed_stream_data(m_stream_id, data, len, fin);
    if (consumed < 0) {
        _log_with_date_time("QuicUpstreamHandler: H3 protocol error on stream " +
                                tp::to_string(m_stream_id),
                            Log::WARN);
        locked_conn->close(NGHTTP3_H3_FRAME_ERROR);
        return;
    }

    if ((size_t)consumed < len && !fin) {
        _log_with_date_time("QuicUpstreamHandler: H3 consumption error on stream " +
                                tp::to_string(m_stream_id) + ", closing",
                            Log::WARN);
        destroy();
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
                if (locked_conn && !locked_conn->is_closed() &&
                    m_resp_state == RespState::kStreamingBody) {
                    m_body_eof = true;
                    auto* h3 = locked_conn->h3_if_exists();
                    if (h3) {
                        if (m_reader_blocked) {
                            m_reader_blocked = false;
                            h3->resume_stream(m_stream_id);
                        } else if (m_body_len == 0) {
                            h3->pump_h3_response();
                            locked_conn->pump_write();
                        }
                    }
                    close_tcp_only();
                    return;
                }
                if (locked_conn && !locked_conn->is_closed()) {
                    locked_conn->send_stream_data(m_stream_id, nullptr, 0, true);
                    locked_conn->pump_write();
                }
                destroy();
                return;
            }
            if (locked_conn && !locked_conn->is_closed()) {
                flush_tcp_read_buf(bytes);
            }
        });
}

void QuicUpstreamHandler::flush_tcp_read_buf(std::size_t bytes) {
    auto locked_conn = m_conn_ptr.lock();
    if (m_destroyed || !locked_conn || locked_conn->is_closed()) return;

    // H3 path: encode HTTP/1.1 response as HTTP/3 HEADERS + DATA frames.
    // Taken when the client sent valid H3 traffic (e.g. a real browser).
    // Point Beast's body output at m_body_out_buf for this call.
    auto& body = m_resp_parser->get().body();
    body.data = static_cast<void*>(const_cast<char*>(m_body_out_buf.data()));
    body.size = kTcpBufSize;
    body.more = true;

    boost::system::error_code ec;
    m_resp_parser->put(boost::asio::buffer(m_tcp_buf.data(), bytes), ec);

    if (ec && ec != boost::beast::http::error::need_more) {
        _log_with_date_time("QuicUpstreamHandler: Beast parse error stream " +
            tp::to_string(m_stream_id) + ": " + tp::string(ec.message().c_str()), Log::ERROR);
        handle_parse_error();
        return;
    }

    const std::size_t body_bytes = kTcpBufSize - body.size;
    const bool resp_done = m_resp_parser->is_done();

    if (m_resp_state == RespState::kParsingHeaders) {
        if (!m_resp_parser->is_header_done()) {
            _log_with_date_time("QuicUpstreamHandler: flush_tcp_read_buf stream " + tp::to_string(m_stream_id) + " headers not done", Log::INFO);
            tcp_read_from_upstream();
            return;
        }

        if (submit_h3_response_headers() != 0) {
            handle_parse_error();
            return;
        }
        // submit_h3_response_headers sets m_resp_state to kStreamingBody or kDone.
        if (m_resp_state == RespState::kDone) return;

        if (body_bytes > 0 || resp_done) {
            process_body_chunk(body_bytes, resp_done);
        } else {
            tcp_read_from_upstream();
        }
        return;
    }

    if (m_resp_state == RespState::kStreamingBody) {
        process_body_chunk(body_bytes, resp_done);
    }
}

// ---- HTTP/1.1 → HTTP/3 response conversion helpers --------------------------

int QuicUpstreamHandler::submit_h3_response_headers() {
    auto locked_conn = m_conn_ptr.lock();
    if (!locked_conn) return -1;
    auto* h3 = locked_conn->h3_if_exists();
    if (!h3) return -1;

    auto& msg = m_resp_parser->get();

    tp::vector<std::pair<tp::string, tp::string>> hdrs;
    hdrs.reserve(8);
    hdrs.push_back({":status", tp::to_string(static_cast<unsigned>(msg.result_int()))});

    static const std::initializer_list<std::string_view> kSkip = {
        "connection", "keep-alive", "transfer-encoding",
        "proxy-connection", "upgrade", "te", "trailers"
    };
    for (auto const& f : msg) {
        tp::string name(f.name_string().data(), f.name_string().size());
        for (auto& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        bool skip = false;
        for (auto sv : kSkip) { if (name == sv) { skip = true; break; } }
        if (skip) continue;
        hdrs.push_back({std::move(name), tp::string(f.value().data(), f.value().size())});
    }

    unsigned status = msg.result_int();
    bool has_body = (m_method != "HEAD") &&
                    (status != 204) && (status != 304);

    int rv = h3->submit_response(m_stream_id, hdrs, has_body);
    if (rv != 0) return rv;

    // Pump to push the HEADERS frame (and FIN if no body) into ngtcp2.
    // For has_body: pump triggers the first data_reader call; it returns
    // WOULDBLOCK (m_body_len==0) setting m_reader_blocked=true.
    locked_conn->pump_h3_response();
    m_resp_state = has_body ? RespState::kStreamingBody : RespState::kDone;
    return 0;
}

void QuicUpstreamHandler::process_body_chunk(std::size_t body_bytes, bool eof) {
    auto locked_conn = m_conn_ptr.lock();
    if (m_destroyed || !locked_conn || locked_conn->is_closed()) return;

    m_body_eof = eof;

    if (body_bytes > 0) {
        m_body_ptr = reinterpret_cast<const uint8_t*>(m_body_out_buf.data());
        m_body_len = body_bytes;
    }

    if (m_reader_blocked) {
        // nghttp3 has this stream marked as blocked; must call resume_stream
        // before it will invoke the data_reader again.
        m_reader_blocked = false;
        auto* h3 = locked_conn->h3_if_exists();
        if (h3) h3->resume_stream(m_stream_id);
        // resume_stream calls pump_h3_response internally; after returning,
        // m_body_len reflects how much body data ngtcp2 accepted.
        if (m_body_len == 0 && !m_body_eof) {
            tcp_read_from_upstream();
        } else if (m_body_len > 0) {
            pump_h3_and_read();  // still pending, handle flow control
        }
        // if m_body_len==0 && m_body_eof: EOF was already signaled by on_read_data
    } else if (body_bytes > 0 || eof) {
        pump_h3_and_read();
    } else {
        // No decoded body bytes yet (pure chunked framing consumed); read more.
        tcp_read_from_upstream();
    }
}

void QuicUpstreamHandler::pump_h3_and_read() {
    auto locked_conn = m_conn_ptr.lock();
    if (!locked_conn || locked_conn->is_closed() || m_destroyed) return;

    locked_conn->pump_h3_response();  // drives writev_stream → ngtcp2 → network

    if (m_body_len > 0) {
        // QUIC flow-control blocked; retry after a short delay.
        m_write_timer.expires_after(std::chrono::milliseconds(5));
        auto self = shared_from_this();
        m_write_timer.async_wait([this, self](const boost::system::error_code& ec) {
            if (!ec && !m_destroyed) pump_h3_and_read();
        });
        return;
    }

    m_body_ptr = nullptr;

    if (!m_body_eof && m_resp_state == RespState::kStreamingBody && !m_destroyed) {
        tcp_read_from_upstream();
    } else if (m_body_eof) {
        m_resp_state = RespState::kDone;
    }
}

nghttp3_ssize QuicUpstreamHandler::on_read_data(nghttp3_vec* vec, std::size_t veccnt, uint32_t* pflags) {
    if (m_body_len == 0) {
        if (m_body_eof) {
            *pflags |= NGHTTP3_DATA_FLAG_EOF;
            return 0;
        }
        m_reader_blocked = true;
        return NGHTTP3_ERR_WOULDBLOCK;
    }

    std::size_t n = std::min(veccnt, std::size_t(1));
    vec[0].base = const_cast<uint8_t*>(m_body_ptr);
    vec[0].len  = m_body_len;

    if (m_body_eof) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
    }
    return 1;
}

void QuicUpstreamHandler::notify_body_consumed(std::size_t n) {
    if (n >= m_body_len) {
        m_body_ptr = nullptr;
        m_body_len = 0;
    } else {
        m_body_ptr += n;
        m_body_len -= n;
    }
}

void QuicUpstreamHandler::handle_parse_error() {
    auto locked_conn = m_conn_ptr.lock();
    if (locked_conn && !locked_conn->is_closed()) {
        locked_conn->send_stream_data(m_stream_id, nullptr, 0, true);
        locked_conn->pump_write();
    }
    destroy();
}

void QuicUpstreamHandler::close_tcp_only() {
    m_resolver.cancel();
    boost::system::error_code ec;
    if (m_tcp_socket.is_open()) {
        ec = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
        ec = m_tcp_socket.close(ec);
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
    _log_with_date_time("QuicUpstreamHandler: stream " + tp::to_string(m_stream_id) + " on_h3_end_headers called with fin=" + tp::to_string(fin), Log::INFO);
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
