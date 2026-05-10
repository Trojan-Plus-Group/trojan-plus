/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_http1_upstream_conn.h"

#include <limits>
#include <utility>

#include <boost/asio/connect.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/write.hpp>

#include "core/log.h"

Http1UpstreamConn::Http1UpstreamConn(boost::asio::io_context& io_ctx,
                                     const tp::string&        host,
                                     const tp::string&        port_str,
                                     Observer*                observer)
    : m_tcp_socket(io_ctx),
      m_resolver(io_ctx),
      m_host(host),
      m_port_str(port_str),
      m_observer(observer) {
    m_tcp_read_buf.resize(kTcpBufSize, '\0');
    m_resp_parser = std::make_unique<H1RespParser>();
    m_resp_parser->eager(true);
    m_resp_parser->body_limit((std::numeric_limits<uint64_t>::max)());
}

Http1UpstreamConn::~Http1UpstreamConn() = default;

void Http1UpstreamConn::start() {
    if (m_destroyed) return;

    auto self = shared_from_this();
    m_resolver.async_resolve(
        m_host, m_port_str,
        [this, self](const boost::system::error_code&                ec,
                     boost::asio::ip::tcp::resolver::results_type    results) {
            if (m_destroyed) return;
            if (ec) {
                _log_with_date_time("h3_upstream TCP resolve failed " + m_host + ":" + m_port_str +
                                        " failed: " + tp::string(ec.message().c_str()),
                                    Log::ERROR);
                if (m_observer) m_observer->on_h1_connect_done(false);
                return;
            }
            boost::asio::async_connect(
                m_tcp_socket, results,
                [this, self](const boost::system::error_code& ec2, const auto&) {
                    if (m_destroyed) return;
                    if (ec2) {
                        _log_with_date_time("Http1UpstreamConn: connect " + m_host + ":" + m_port_str +
                                                " failed: " + tp::string(ec2.message().c_str()),
                                            Log::ERROR);
                        if (m_observer) m_observer->on_h1_connect_done(false);
                        return;
                    }
                    m_connected = true;
                    _log_with_date_time(
                        "HTTP upstream connected to " + m_host + ":" + m_port_str,
                        Log::INFO);
                    if (m_observer) m_observer->on_h1_connect_done(true);
                    if (m_destroyed) return;

                    if (!m_write_queue.empty() && !m_write_in_progress) {
                        do_tcp_write();
                    }
                    start_async_read();
                });
        });
}

void Http1UpstreamConn::detach_observer() { m_observer = nullptr; }

void Http1UpstreamConn::destroy() {
    if (m_destroyed) return;
    m_destroyed = true;
    m_resolver.cancel();
    close_socket();
}

void Http1UpstreamConn::close_socket() {
    if (m_tcp_socket.is_open()) {
        boost::system::error_code ec;
        ec = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_both, ec);
        ec = m_tcp_socket.close(ec);
    }
}

void Http1UpstreamConn::set_read_state(ReadState s) {
    if (m_read_state == s) return;
    m_read_state = s;
}

void Http1UpstreamConn::buffer_chunk_append(tp::string chunk) {
    if (chunk.empty()) return;
    m_buffered_bytes += chunk.size();
    m_body_out_chunks.push_back(std::move(chunk));
}

void Http1UpstreamConn::buffer_chunk_drop_front(std::size_t n) {
    while (n > 0 && !m_body_out_chunks.empty()) {
        auto& chunk = m_body_out_chunks.front();
        if (chunk.size() <= n) {
            n -= chunk.size();
            m_buffered_bytes -= chunk.size();
            m_body_out_chunks.pop_front();
        } else {
            chunk.erase(0, n);
            m_buffered_bytes -= n;
            n = 0;
        }
    }
    // Trailing n>0 (caller reported more consumed than buffered, e.g. nghttp3
    // framing overhead) is silently absorbed — matches pre-refactor semantics.
}

// ---- write side ---------------------------------------------------------

void Http1UpstreamConn::send_request_chunk(tp::string data, std::size_t stream_bytes, bool fin) {
    if (m_destroyed) return;
    if (data.empty() && !fin && stream_bytes == 0) return;
    m_write_queue.push_back({std::move(data), stream_bytes, fin});
    if (m_connected && !m_write_in_progress && m_tcp_socket.is_open()) {
        do_tcp_write();
    }
}

void Http1UpstreamConn::do_tcp_write() {
    if (m_destroyed || !m_tcp_socket.is_open() || m_write_queue.empty()) {
        m_write_in_progress = false;
        return;
    }
    m_write_in_progress = true;
    auto& front         = m_write_queue.front();

    // Pure-FIN entry: shutdown send half, no async_write.
    if (front.data.empty() && front.fin) {
        boost::system::error_code ec;
        ec                       = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_send, ec);
        std::size_t credit       = front.stream_bytes;
        m_write_queue.pop_front();
        if (credit > 0 && m_observer) m_observer->on_h1_stream_credit(credit);
        do_tcp_write();
        return;
    }

    auto        buf          = TP_MAKE_SHARED(tp::string, std::move(front.data));
    std::size_t stream_bytes = front.stream_bytes;
    bool        fin          = front.fin;
    m_write_queue.pop_front();

    auto self = shared_from_this();
    boost::asio::async_write(
        m_tcp_socket, boost::asio::buffer(*buf),
        [this, self, buf, fin, stream_bytes](const boost::system::error_code& ec, std::size_t) {
            if (m_destroyed) return;
            if (ec) {
                _log_with_date_time(
                    "Http1UpstreamConn: TCP write failed: " + tp::string(ec.message().c_str()),
                    Log::ERROR);
                if (m_observer) m_observer->on_h1_error(ec);
                return;
            }
            if (stream_bytes > 0 && m_observer) {
                m_observer->on_h1_stream_credit(stream_bytes);
            }
            if (m_destroyed) return;
            if (fin) {
                boost::system::error_code ec2;
                ec2 = m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_send, ec2);
            }
            do_tcp_write();
        });
}

// ---- read side ----------------------------------------------------------

void Http1UpstreamConn::start_async_read() {
    if (m_destroyed || !m_connected || !m_tcp_socket.is_open()) return;
    if (m_read_in_progress) return;
    if (m_read_state != ReadState::Reading) return;

    m_read_in_progress = true;
    auto self          = shared_from_this();
    m_tcp_socket.async_read_some(
        boost::asio::buffer(&m_tcp_read_buf[0], kTcpBufSize),
        [this, self](const boost::system::error_code& ec, std::size_t bytes) {
            m_read_in_progress = false;
            on_tcp_read_done(ec, bytes);
        });
}

void Http1UpstreamConn::on_tcp_read_done(const boost::system::error_code& ec, std::size_t bytes) {
    if (m_destroyed) return;

    if (ec) {
        // Treat EOF / peer-reset as graceful EOF — flush any tail bytes first.
        if (ec == boost::asio::error::eof || ec == boost::asio::error::connection_reset) {
            if (bytes > 0) parse_tcp_data(bytes);
            if (m_destroyed) return;
            set_read_state(ReadState::Eof);
            if (m_observer) m_observer->on_h1_eof();
            return;
        }
        _log_with_date_time(
            "Http1UpstreamConn: TCP read error: " + tp::string(ec.message().c_str()), Log::ERROR);
        set_read_state(ReadState::Error);
        if (m_observer) m_observer->on_h1_error(ec);
        return;
    }

    parse_tcp_data(bytes);
    if (m_destroyed) return;
    if (m_read_state == ReadState::Eof || m_read_state == ReadState::Error) return;

    // Hysteresis: read until high watermark, then pause.
    if (m_buffered_bytes >= kHighWM) {
        set_read_state(ReadState::Paused);
    } else {
        start_async_read();
    }
}

void Http1UpstreamConn::parse_tcp_data(std::size_t bytes) {
    boost::system::error_code ec;
    std::size_t               consumed       = 0;
    bool                      any_body_added = false;

    while (consumed < bytes) {
        if (!m_headers_delivered) {
            // Header phase: tell Beast no body buffer; it will buffer headers internally.
            m_resp_parser->get().body().data = nullptr;
            m_resp_parser->get().body().size = 0;

            std::size_t n = m_resp_parser->put(
                boost::asio::buffer(m_tcp_read_buf.data() + consumed, bytes - consumed), ec);
            consumed += n;

            if (ec && ec != boost::beast::http::error::need_buffer) {
                _log_with_date_time(
                    "Http1UpstreamConn: header parse error: " + tp::string(ec.message().c_str()),
                    Log::ERROR);
                set_read_state(ReadState::Error);
                if (m_observer) m_observer->on_h1_error(ec);
                return;
            }
            if (m_resp_parser->is_header_done()) {
                m_headers_delivered = true;
                if (m_observer) m_observer->on_h1_resp_headers(*m_resp_parser);
                if (m_destroyed) return;
                // continue loop — there may be body bytes already in the same buffer
            } else {
                // headers not yet complete; buffer fully consumed
                break;
            }
        } else {
            // Body phase: route into m_parse_buf.
            m_parse_buf.resize(kParseBufSize);
            m_resp_parser->get().body().data = &m_parse_buf[0];
            m_resp_parser->get().body().size = m_parse_buf.size();

            std::size_t n = m_resp_parser->put(
                boost::asio::buffer(m_tcp_read_buf.data() + consumed, bytes - consumed), ec);
            consumed += n;

            std::size_t body_bytes = m_parse_buf.size() - m_resp_parser->get().body().size;
            if (body_bytes > 0) {
                buffer_chunk_append(m_parse_buf.substr(0, body_bytes));
                any_body_added = true;
            }

            if (ec && ec != boost::beast::http::error::need_buffer) {
                if (ec == boost::beast::http::error::end_of_stream) {
                    set_read_state(ReadState::Eof);
                    if (any_body_added && m_observer) m_observer->on_h1_body_data_available();
                    if (m_destroyed) return;
                    if (m_observer) m_observer->on_h1_eof();
                    return;
                }
                _log_with_date_time("Http1UpstreamConn: body parse error: " +
                                        tp::string(ec.message().c_str()),
                                    Log::ERROR);
                set_read_state(ReadState::Error);
                if (m_observer) m_observer->on_h1_error(ec);
                return;
            }

            if (m_resp_parser->is_done()) {
                set_read_state(ReadState::Eof);
                if (any_body_added && m_observer) m_observer->on_h1_body_data_available();
                if (m_destroyed) return;
                if (m_observer) m_observer->on_h1_eof();
                return;
            }

            if (n == 0) {
                // No further progress this iteration; wait for more input.
                break;
            }
        }
    }

    if (any_body_added && m_observer) m_observer->on_h1_body_data_available();
}

// ---- pull / consume -----------------------------------------------------

nghttp3_ssize Http1UpstreamConn::pull_body_chunks(nghttp3_vec* vec, std::size_t veccnt,
                                                  bool& eof_flag) {
    eof_flag = false;
    if (m_body_out_chunks.empty()) {
        if (m_read_state == ReadState::Eof) {
            eof_flag = true;
            return 0;
        }
        return NGHTTP3_ERR_WOULDBLOCK;
    }

    std::size_t nvec = 0;
    for (auto& chunk : m_body_out_chunks) {
        if (nvec >= veccnt) break;
        vec[nvec].base = reinterpret_cast<uint8_t*>(const_cast<char*>(chunk.data()));
        vec[nvec].len  = chunk.size();
        ++nvec;
    }
    return static_cast<nghttp3_ssize>(nvec);
}

void Http1UpstreamConn::notify_body_consumed(std::size_t n) {
    if (n == 0) return;
    buffer_chunk_drop_front(n);

    if (m_read_state == ReadState::Paused && m_buffered_bytes <= kLowWM) {
        set_read_state(ReadState::Reading);
        start_async_read();
    }
}
