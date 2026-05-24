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

#include <cstdio>
#include <initializer_list>
#include <string_view>

#include <nghttp3/nghttp3.h>

#include "core/log.h"
#include "quic_connection.h"
#include "quic_to_http3_connect.h"

QuicUpstreamHandler::QuicUpstreamHandler(
    std::shared_ptr<QuicConnection> conn, int64_t stream_id,
    boost::asio::io_context& io_ctx,
    const tp::string& host, const tp::string& port_str)
    : m_conn_ptr(conn),
      m_stream_id(stream_id) {
    m_h1_conn = TP_MAKE_SHARED(Http1UpstreamConn, io_ctx, host, port_str, this);
}

QuicUpstreamHandler::~QuicUpstreamHandler() {
    if (m_h1_conn) {
        m_h1_conn->detach_observer();
    }
}

void QuicUpstreamHandler::start() {
    if (m_destroyed) return;
    m_h1_conn->start();
}

void QuicUpstreamHandler::on_stream_data(const uint8_t* data, size_t len, bool fin) {
    if (m_destroyed) return;
    if (len > 0) {
        m_h3_in_buf.append(reinterpret_cast<const char*>(data), len);
    }
    if (fin) {
        m_h3_in_fin = true;
    }
    retry_feed_h3();
}

void QuicUpstreamHandler::on_connection_pump() { retry_feed_h3(); }

void QuicUpstreamHandler::retry_feed_h3() {
    if (m_destroyed) return;
    if (m_h3_in_buf.empty() && !m_h3_in_fin) return;

    auto locked_conn = m_conn_ptr.lock();
    if (!locked_conn || locked_conn->is_closed()) return;

    auto& h3 = locked_conn->get_or_create_h3();
    auto consumed = h3.feed_stream_data(m_stream_id,
                                        reinterpret_cast<const uint8_t*>(m_h3_in_buf.data()),
                                        m_h3_in_buf.size(),
                                        m_h3_in_fin);
    if (consumed < 0) {
        _log_with_date_time("QuicUpstreamHandler: H3 protocol error on stream " +
                                tp::to_string(m_stream_id) + ": " +
                                tp::string(nghttp3_strerror(static_cast<int>(consumed))),
                            Log::WARN);
        locked_conn->close(NGHTTP3_H3_FRAME_ERROR);
        return;
    }

    if (consumed > 0 || (m_h3_in_buf.empty() && m_h3_in_fin)) {
        std::size_t n = static_cast<std::size_t>(consumed);
        m_unacked_stream_bytes += n;
        if (n > 0) {
            m_h3_in_buf.erase(0, n);
        }

        if (m_h3_in_buf.empty() && m_h3_in_fin) {
            m_h3_in_fin = false;
        }

        // Extend window immediately for all stream types. For uni streams
        // (Control/QPACK) there is no TCP write to defer credit to. For bidi
        // streams, the H3 framing overhead consumed inside this same call is
        // not associated with any send_request_chunk batch and would otherwise
        // leak. Matching pre-refactor semantics — see plan §4.4 future work.
        if (m_unacked_stream_bytes > 0) {
            locked_conn->stream_extend_window(m_stream_id, m_unacked_stream_bytes);
            m_unacked_stream_bytes = 0;
        }
    }
}

void QuicUpstreamHandler::on_stream_close() { destroy(); }

void QuicUpstreamHandler::destroy() {
    if (m_destroyed) return;
    m_destroyed = true;

    // Keep 'this' alive for the full duration of destroy(): remove_stream_handler
    // erases the map entry that may hold the last external shared_ptr to this
    // object, which would trigger ~QuicUpstreamHandler() mid-function if we don't
    // hold a local reference here.
    auto self = shared_from_this();

    if (m_h1_conn) {
        m_h1_conn->detach_observer();
        m_h1_conn->destroy();
    }

    auto locked_conn = m_conn_ptr.lock();
    if (locked_conn) {
        if (auto* h3 = locked_conn->h3_if_exists()) {
            h3->unregister_stream(m_stream_id);
        }
        locked_conn->remove_stream_handler(m_stream_id);
    }

    m_h1_conn.reset();
}

// ---- H3 response submission helpers -------------------------------------

int QuicUpstreamHandler::submit_h3_response_headers(Http1UpstreamConn::H1RespParser& parser) {
    auto locked_conn = m_conn_ptr.lock();
    if (!locked_conn) return -1;
    auto* h3 = locked_conn->h3_if_exists();
    if (!h3) return -1;

    auto& msg = parser.get();
    _log_with_date_time("QuicUpstreamHandler: stream " + tp::to_string(m_stream_id) +
                            " submitting H3 response status=" +
                            tp::to_string(static_cast<unsigned>(msg.result_int())),
                        Log::INFO);

    tp::vector<std::pair<tp::string, tp::string>> hdrs;
    hdrs.reserve(8);
    hdrs.push_back({":status", tp::to_string(static_cast<unsigned>(msg.result_int()))});

    static const std::initializer_list<std::string_view> kSkip = {
        "connection", "keep-alive", "transfer-encoding",
        "proxy-connection", "upgrade", "te", "trailers"};
    for (auto const& f : msg) {
        tp::string name(f.name_string().data(), f.name_string().size());
        for (auto& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        bool skip = false;
        for (auto sv : kSkip) {
            if (name == sv) { skip = true; break; }
        }
        if (skip) continue;
        hdrs.push_back({std::move(name), tp::string(f.value().data(), f.value().size())});
    }

    unsigned status   = msg.result_int();
    bool     has_body = (m_method != "HEAD") &&
                    (status != 204 && status != 304 && (status < 100 || status > 199));

    int rv = h3->submit_response(m_stream_id, hdrs, has_body);
    if (rv != 0) return rv;

    pump_h3_response();
    return 0;
}

void QuicUpstreamHandler::pump_h3_response() {
    if (m_destroyed) return;
    auto locked_conn = m_conn_ptr.lock();
    if (!locked_conn || locked_conn->is_closed()) return;
    locked_conn->on_pump_write();
}

// ---- nghttp3 data_reader / consume notification -------------------------

nghttp3_ssize QuicUpstreamHandler::on_read_data(nghttp3_vec* vec, std::size_t veccnt,
                                                uint32_t* pflags) {
    if (m_destroyed || !m_h1_conn) {
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    bool eof_flag = false;
    auto rv       = m_h1_conn->pull_body_chunks(vec, veccnt, eof_flag);
    if (rv == NGHTTP3_ERR_WOULDBLOCK) {
        m_h3_out_state = H3OutState::BlockedByNghttp3;
        return rv;
    }
    if (eof_flag && rv == 0) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
    }
    return rv;
}

void QuicUpstreamHandler::notify_body_consumed(std::size_t n) {
    if (m_destroyed || !m_h1_conn) return;
    m_h1_conn->notify_body_consumed(n);
}

// ---- Http1UpstreamConn::Observer ----------------------------------------

void QuicUpstreamHandler::on_h1_connect_done(bool ok) {
    if (m_destroyed) return;
    if (!ok) {
        destroy();
        return;
    }
    _log_with_date_time("QuicUpstreamHandler: stream " + tp::to_string(m_stream_id) +
                            " HTTP upstream connected",
                        Log::INFO);
}

void QuicUpstreamHandler::on_h1_resp_headers(Http1UpstreamConn::H1RespParser& parser) {
    if (m_destroyed) return;
    submit_h3_response_headers(parser);
}

void QuicUpstreamHandler::on_h1_body_data_available() {
    if (m_destroyed) return;
    if (m_h3_out_state == H3OutState::BlockedByNghttp3) {
        m_h3_out_state   = H3OutState::Active;
        auto locked_conn = m_conn_ptr.lock();
        if (locked_conn) {
            if (auto* h3 = locked_conn->h3_if_exists()) {
                h3->resume_stream(m_stream_id);
                return; // resume_stream itself pumps
            }
        }
    }
    pump_h3_response();
}

void QuicUpstreamHandler::on_h1_eof() {
    if (m_destroyed) return;
    _log_with_date_time(
        "QuicUpstreamHandler: stream " + tp::to_string(m_stream_id) + " upstream EOF",
        Log::INFO);
    if (m_h3_out_state == H3OutState::BlockedByNghttp3) {
        m_h3_out_state   = H3OutState::Active;
        auto locked_conn = m_conn_ptr.lock();
        if (locked_conn) {
            if (auto* h3 = locked_conn->h3_if_exists()) {
                h3->resume_stream(m_stream_id);
                return;
            }
        }
    }
    pump_h3_response();
}

void QuicUpstreamHandler::on_h1_error(const boost::system::error_code& /*ec*/) {
    // Send FIN on this H3 stream so the client sees the response is over,
    // then tear down. Mirrors the old handle_parse_error path.
    auto locked_conn = m_conn_ptr.lock();
    if (locked_conn && !locked_conn->is_closed()) {
        locked_conn->send_stream_data(m_stream_id, nullptr, 0, true);
        locked_conn->on_pump_write();
    }
    destroy();
}

void QuicUpstreamHandler::on_h1_stream_credit(std::size_t bytes) {
    // Currently always 0 — retry_feed_h3 extends the window immediately. Hook
    // is wired up so the deferred-credit semantic in plan §4.4 can be added
    // later without further interface changes.
    if (bytes == 0 || m_destroyed) return;
    if (auto locked_conn = m_conn_ptr.lock()) {
        locked_conn->stream_extend_window(m_stream_id, bytes);
    }
}

// ---- on_h3_* (H3 request → HTTP/1.1 conversion) -------------------------

int QuicUpstreamHandler::on_h3_begin_headers() {
    m_http1_request.clear();
    m_method.clear();
    m_scheme.clear();
    m_authority.clear();
    m_path.clear();
    m_regular_headers.clear();
    m_request_complete   = false;
    m_chunked_body       = false;
    m_has_content_length = false;
    m_fin_sent           = false;
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
            "transfer-encoding", "upgrade", "host"};
        for (auto& h : kForbiddenH3Headers) {
            if (name == h) return 0;
        }
        m_regular_headers += name + ": " + value + "\r\n";
    }
    return 0;
}

int QuicUpstreamHandler::on_h3_end_headers(bool fin) {
    _log_with_date_time(
        "QuicUpstreamHandler: stream " + tp::to_string(m_stream_id) +
            " on_h3_end_headers fin=" + tp::to_string(fin),
        Log::INFO);
    if (m_method.empty()) return NGHTTP3_ERR_CALLBACK_FAILURE;
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

    m_h1_conn->send_request_chunk(std::move(m_http1_request), 0, false);
    m_http1_request.clear();
    if (fin) {
        if (m_chunked_body) {
            m_h1_conn->send_request_chunk(tp::string("0\r\n\r\n"), 0, false);
        }
        m_h1_conn->send_request_chunk(tp::string(), 0, true);
        m_fin_sent = true;
    }
    return 0;
}

int QuicUpstreamHandler::on_h3_data(const uint8_t* data, std::size_t datalen) {
    if (datalen == 0) return 0;
    if (m_chunked_body) {
        char hex[16];
        int  n = snprintf(hex, sizeof(hex), "%zx\r\n", datalen);
        m_h1_conn->send_request_chunk(tp::string(hex, n), 0, false);
        m_h1_conn->send_request_chunk(
            tp::string(reinterpret_cast<const char*>(data), datalen), 0, false);
        m_h1_conn->send_request_chunk(tp::string("\r\n"), 0, false);
    } else {
        m_h1_conn->send_request_chunk(
            tp::string(reinterpret_cast<const char*>(data), datalen), 0, false);
    }
    return 0;
}

int QuicUpstreamHandler::on_h3_end_stream() {
    if (m_fin_sent) return 0;
    if (m_chunked_body) {
        m_h1_conn->send_request_chunk(tp::string("0\r\n\r\n"), 0, false);
    }
    m_h1_conn->send_request_chunk(tp::string(), 0, true);
    m_fin_sent = true;
    return 0;
}

int QuicUpstreamHandler::on_h3_stream_close(uint64_t /*app_error_code*/) {
    if (m_fin_sent) return 0;
    if (m_chunked_body) {
        m_h1_conn->send_request_chunk(tp::string("0\r\n\r\n"), 0, false);
    }
    m_h1_conn->send_request_chunk(tp::string(), 0, true);
    m_fin_sent = true;
    return 0;
}
