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

#include <algorithm>
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
    m_resp_parser = TP_MAKE_UNIQUE(H1RespParser);
    m_resp_parser->eager(true);
    m_resp_parser->body_limit((std::numeric_limits<uint64_t>::max)());
}

Http1UpstreamConn::~Http1UpstreamConn() = default;

void Http1UpstreamConn::on_connect_done(const boost::system::error_code& ec) {
    if (m_destroyed) return;
    if (ec) {
        _log_with_date_time("Http1UpstreamConn: connect " + m_host + ":" + m_port_str +
                                " failed: " + tp::string(ec.message().c_str()),
                            Log::ERROR);
        if (m_observer) m_observer->h1_on_connect_done(false);
        return;
    }
    m_connected = true;
    _log_with_date_time(
        "HTTP upstream connected to " + m_host + ":" + m_port_str,
        Log::INFO);
    if (m_observer) m_observer->h1_on_connect_done(true);
    if (m_destroyed) return;

    if (!m_write_queue.empty() && !m_write_in_progress) {
        do_tcp_write();
    }
    start_async_read();
}

void Http1UpstreamConn::start() {
    if (m_destroyed) return;

    auto self = shared_from_this();

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(m_host.c_str(), ec);
    if (!ec) {
        boost::asio::ip::tcp::endpoint ep(addr, static_cast<unsigned short>(std::stoi(m_port_str.c_str())));
        m_tcp_socket.async_connect(
            ep,
            [this, self](const boost::system::error_code& ec2) {
                on_connect_done(ec2);
            });
        return;
    }

    m_resolver.async_resolve(
        m_host, m_port_str,
        [this, self](const boost::system::error_code&                ec,
                     boost::asio::ip::tcp::resolver::results_type    results) {
            if (m_destroyed) return;
            if (ec) {
                _log_with_date_time("h1_upstream TCP resolve failed " + m_host + ":" + m_port_str +
                                        " failed: " + tp::string(ec.message().c_str()),
                                    Log::ERROR);
                if (m_observer) m_observer->h1_on_connect_done(false);
                return;
            }
            boost::asio::async_connect(
                m_tcp_socket, results,
                [this, self](const boost::system::error_code& ec2, const auto&) {
                    on_connect_done(ec2);
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
    m_shutdown_pending = false;
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
    _log_with_date_time("buffer_chunk_append: chunk size=" + 
        tp::to_string(chunk.size()) + " data_ptr=" + 
        tp::to_string(reinterpret_cast<uintptr_t>(chunk.data())), Log::ALL);
    m_body_out_chunks.push_back(std::move(chunk));
}

void Http1UpstreamConn::buffer_chunk_drop_front(std::size_t n) {
    _log_with_date_time("buffer_chunk_drop_front: n=" + tp::to_string(n) + 
        " m_front_chunk_offset=" + tp::to_string(m_front_chunk_offset) + 
        " m_body_read_offset=" + tp::to_string(m_body_read_offset) + 
        " m_body_out_chunks.size()=" + tp::to_string(m_body_out_chunks.size()), Log::ALL);
    if (m_buffered_bytes >= n) {
        m_buffered_bytes -= n;
    } else {
        m_buffered_bytes = 0;
    }

    m_front_chunk_offset += n;
    while (!m_body_out_chunks.empty()) {
        auto& chunk = m_body_out_chunks.front();
        if (m_front_chunk_offset >= chunk.size()) {
            _log_with_date_time("buffer_chunk_drop_front: popping chunk size=" + 
                tp::to_string(chunk.size()) + " data_ptr=" + 
                tp::to_string(reinterpret_cast<uintptr_t>(chunk.data())), Log::ALL);
            m_front_chunk_offset -= chunk.size();
            m_body_out_chunks.pop_front();
        } else {
            break;
        }
    }

    if (m_body_read_offset >= n) {
        m_body_read_offset -= n;
    } else {
        m_body_read_offset = 0;
    }

    if (m_body_out_chunks.empty()) {
        m_front_chunk_offset = 0;
        m_body_read_offset = 0;
    }
    _log_with_date_time("buffer_chunk_drop_front: done. new m_front_chunk_offset=" + 
        tp::to_string(m_front_chunk_offset) + " m_body_read_offset=" + 
        tp::to_string(m_body_read_offset) + " m_body_out_chunks.size()=" + 
        tp::to_string(m_body_out_chunks.size()), Log::ALL);
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

    // Pure-FIN entry: shutdown send half if headers already delivered, else pending.
    if (front.data.empty() && front.fin) {
        if (m_headers_delivered) {
            boost::system::error_code ec;
            m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_send, ec);
        } else {
            m_shutdown_pending = true;
        }
        std::size_t credit = front.stream_bytes;
        m_write_queue.pop_front();
        if (credit > 0 && m_observer) m_observer->h1_on_stream_credit(credit);
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
                if (m_observer) m_observer->h1_on_error(ec);
                return;
            }
            if (stream_bytes > 0 && m_observer) {
                m_observer->h1_on_stream_credit(stream_bytes);
            }
            if (m_destroyed) return;
            if (fin) {
                if (m_headers_delivered) {
                    boost::system::error_code ec2;
                    m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_send, ec2);
                } else {
                    m_shutdown_pending = true;
                }
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
    
    std::size_t space_left = kTcpBufSize - m_unconsumed_bytes;
    if (space_left == 0) {
        _log_with_date_time("Http1UpstreamConn: parse buffer full, dropping connection", Log::ERROR);
        m_read_in_progress = false;
        set_read_state(ReadState::Error);
        if (m_observer) m_observer->h1_on_error(boost::asio::error::no_buffer_space);
        return;
    }

    m_tcp_socket.async_read_some(
        boost::asio::buffer(&m_tcp_read_buf[m_unconsumed_bytes], space_left),
        [this, self](const boost::system::error_code& ec, std::size_t bytes) {
            m_read_in_progress = false;
            on_tcp_read_done(ec, bytes);
        });
}

void Http1UpstreamConn::on_tcp_read_done(const boost::system::error_code& ec, std::size_t bytes) {
    if (m_destroyed) return;

    m_unconsumed_bytes += bytes;

    if (ec) {
        // Treat EOF / peer-reset as graceful EOF — flush any tail bytes first.
        if (ec == boost::asio::error::eof || ec == boost::asio::error::connection_reset) {
            if (m_unconsumed_bytes > 0) parse_tcp_data();
            if (m_destroyed) return;
            set_read_state(ReadState::Eof);
            if (m_observer) m_observer->h1_on_eof();
            return;
        }
        _log_with_date_time(
            "Http1UpstreamConn: TCP read error: " + tp::string(ec.message().c_str()), Log::ERROR);
        set_read_state(ReadState::Error);
        if (m_observer) m_observer->h1_on_error(ec);
        return;
    }

    parse_tcp_data();
    if (m_destroyed) return;
    if (m_read_state == ReadState::Eof || m_read_state == ReadState::Error) return;

    // Hysteresis: read until high watermark, then pause.
    if (m_buffered_bytes >= kHighWM) {
        set_read_state(ReadState::Paused);
    } else {
        start_async_read();
    }
}

void Http1UpstreamConn::parse_tcp_data() {
    boost::system::error_code ec;
    std::size_t               consumed       = 0;
    bool                      any_body_added = false;

    while (consumed < m_unconsumed_bytes) {
        if (!m_headers_delivered) {
            // Header phase: tell Beast no body buffer; it will buffer headers internally.
            m_resp_parser->get().body().data = nullptr;
            m_resp_parser->get().body().size = 0;

            std::size_t n = m_resp_parser->put(
                boost::asio::buffer(m_tcp_read_buf.data() + consumed, m_unconsumed_bytes - consumed), ec);
            consumed += n;

            if (ec && ec != boost::beast::http::error::need_buffer && ec != boost::beast::http::error::need_more) {
                _log_with_date_time(
                    "Http1UpstreamConn: header parse error: " + tp::string(ec.message().c_str()),
                    Log::ERROR);
                set_read_state(ReadState::Error);
                if (m_observer) m_observer->h1_on_error(ec);
                break; // break instead of return to ensure buffer is shifted
            }
            if (m_resp_parser->is_header_done()) {
                m_headers_delivered = true;
                if (m_shutdown_pending) {
                    boost::system::error_code ec_shutdown;
                    m_tcp_socket.shutdown(boost::asio::socket_base::shutdown_send, ec_shutdown);
                    m_shutdown_pending = false;
                }
                if (m_observer) m_observer->h1_on_resp_headers(*m_resp_parser);
                if (m_destroyed) break;
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
                boost::asio::buffer(m_tcp_read_buf.data() + consumed, m_unconsumed_bytes - consumed), ec);
            consumed += n;

            std::size_t body_bytes = m_parse_buf.size() - m_resp_parser->get().body().size;
            if (body_bytes > 0) {
                buffer_chunk_append(m_parse_buf.substr(0, body_bytes));
                any_body_added = true;
            }

            if (ec && ec != boost::beast::http::error::need_buffer && ec != boost::beast::http::error::need_more) {
                // Log detailed diagnostics for chunked parse errors.
                if (Log::level <= Log::ERROR && ec != boost::beast::http::error::end_of_stream) {
                    tp::string hex_tail;
                    std::size_t dump_start = (consumed > 32) ? consumed - 32 : 0;
                    std::size_t dump_end   = std::min(consumed + 32, m_unconsumed_bytes);
                    for (std::size_t i = dump_start; i < dump_end; ++i) {
                        char hx[4];
                        snprintf(hx, sizeof(hx), "%02x ", static_cast<unsigned char>(m_tcp_read_buf[i]));
                        hex_tail += hx;
                    }
                    _log_with_date_time("Http1UpstreamConn: body parse error: " +
                                            tp::string(ec.message().c_str()) +
                                            " consumed=" + tp::to_string(consumed) +
                                            " unconsumed_bytes=" + tp::to_string(m_unconsumed_bytes) +
                                            " n=" + tp::to_string(n) +
                                            " body_bytes=" + tp::to_string(body_bytes) +
                                            " buffered=" + tp::to_string(m_buffered_bytes) +
                                            " is_done=" + tp::to_string(m_resp_parser->is_done()) +
                                            " hex_around_consumed=[" + hex_tail + "]",
                                        Log::ERROR);
                }
                
                if (ec != boost::beast::http::error::end_of_stream) {
                    // Set error state, but let buffer shifting logic run below before we invoke callbacks
                    set_read_state(ReadState::Error);
                    break;
                }
                
                // End of stream
                set_read_state(ReadState::Eof);
                break;
            }

            if (m_resp_parser->is_done()) {
                set_read_state(ReadState::Eof);
                break;
            }

            if (n == 0) {
                // No further progress this iteration; wait for more input.
                break;
            }
        }
    }

    if (consumed > 0) {
        std::size_t remaining = m_unconsumed_bytes - consumed;
        if (remaining > 0) {
            std::memmove(&m_tcp_read_buf[0], &m_tcp_read_buf[consumed], remaining);
        }
        m_unconsumed_bytes = remaining;
    }

    if (any_body_added && m_observer) m_observer->h1_on_body_data_available();
    
    if (m_destroyed) return;

    if (m_read_state == ReadState::Eof) {
        if (m_observer) m_observer->h1_on_eof();
    } else if (m_read_state == ReadState::Error) {
        if (m_observer) m_observer->h1_on_error(ec);
    }
}

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

    std::size_t skip = m_body_read_offset;
    std::size_t nvec = 0;
    bool is_first = true;

    for (auto& chunk : m_body_out_chunks) {
        std::size_t chunk_avail = chunk.size();
        const uint8_t* chunk_ptr = reinterpret_cast<const uint8_t*>(chunk.data());

        if (is_first) {
            chunk_avail -= m_front_chunk_offset;
            chunk_ptr += m_front_chunk_offset;
            is_first = false;
        }

        if (skip >= chunk_avail) {
            skip -= chunk_avail;
            continue;
        }

        std::size_t len = chunk_avail - skip;
        const uint8_t* base = chunk_ptr + skip;
        skip = 0;

        if (nvec >= veccnt) break;

        vec[nvec].base = const_cast<uint8_t*>(base);
        vec[nvec].len  = len;

        _log_with_date_time("pull_body_chunks: vec[" + tp::to_string(nvec) + "] base=" + 
                            tp::to_string(reinterpret_cast<uintptr_t>(vec[nvec].base)) + 
                            " len=" + tp::to_string(vec[nvec].len) + " (offset from chunk start: " +
                            tp::to_string(base - reinterpret_cast<const uint8_t*>(chunk.data())) + ")", Log::ALL);
        ++nvec;
    }

    if (nvec == 0) {
        if (m_read_state == ReadState::Eof) {
            eof_flag = true;
            return 0;
        }
        return NGHTTP3_ERR_WOULDBLOCK;
    }

    std::size_t bytes_read = 0;
    for (std::size_t i = 0; i < nvec; ++i) {
        bytes_read += vec[i].len;
    }
    m_body_read_offset += bytes_read;
    _log_with_date_time("pull_body_chunks: pulled " + tp::to_string(bytes_read) + " bytes, new m_body_read_offset=" + tp::to_string(m_body_read_offset), Log::ALL);

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
