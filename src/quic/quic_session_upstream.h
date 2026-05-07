/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef QUIC_SESSION_UPSTREAM_H
#define QUIC_SESSION_UPSTREAM_H

#include <memory>
#include <cstdint>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <nghttp3/nghttp3.h>

#include "mem/memallocator.h"
#include "quic_stream_handler.h"
#include "quic_connection.h"

class Config;

// QuicUpstreamHandler: encapsulates nghttp3 HTTP/3 decoding and h3→h1.1 conversion
class QuicUpstreamHandler : public QuicStreamHandler, public std::enable_shared_from_this<QuicUpstreamHandler> {
  public:
    QuicUpstreamHandler(std::shared_ptr<QuicConnection> conn, int64_t stream_id,
                        const Config& config, boost::asio::io_context& io_ctx,
                        const tp::string& host, const tp::string& port_str);
    ~QuicUpstreamHandler() override;

    void start();
    void on_stream_data(const uint8_t* data, size_t len, bool fin) override;
    void on_stream_close() override;
    void destroy();

    [[nodiscard]] bool is_request_complete() const { return m_request_complete; }
    [[nodiscard]] bool is_valid() const { return m_valid; }

  private:
    static int cb_begin_headers(nghttp3_conn*, int64_t, void*, void*);
    static int cb_recv_header(nghttp3_conn*, int64_t, int32_t, nghttp3_rcbuf*, nghttp3_rcbuf*, uint8_t, void*, void*);
    static int cb_end_headers(nghttp3_conn*, int64_t, int, void*, void*);
    static int cb_recv_data(nghttp3_conn*, int64_t, const uint8_t*, size_t, void*, void*);
    static int cb_end_stream(nghttp3_conn*, int64_t, void*, void*);
    static int cb_stream_close(nghttp3_conn*, int64_t, uint64_t, void*, void*);

    void write_to_upstream(tp::string data, bool fin = false);
    void do_tcp_write();
    void tcp_read_from_upstream();
    void flush_tcp_read_buf(std::size_t offset, std::size_t bytes);

    std::weak_ptr<QuicConnection> m_conn_ptr;
    int64_t m_stream_id;
    const Config& m_config;
    boost::asio::io_context& m_io_ctx;

    std::unique_ptr<nghttp3_conn, decltype(&nghttp3_conn_del)> m_conn;
    tp::string m_http1_request;
    tp::string m_method;
    tp::string m_scheme;
    tp::string m_authority;
    tp::string m_path;
    tp::string m_regular_headers;
    bool m_request_complete{false};
    bool m_valid{true};
    bool m_chunked_body{false};
    bool m_has_content_length{false};
    bool m_fin_sent{false};
    bool m_destroyed{false};

    tp::string m_host;
    tp::string m_port_str;
    boost::asio::ip::tcp::socket m_tcp_socket;
    boost::asio::ip::tcp::resolver m_resolver;
    boost::asio::steady_timer m_write_timer;

    struct TcpWriteBuffer {
        tp::string data;
        bool fin{false};
    };
    tp::deque<TcpWriteBuffer> m_tcp_write_queue;
    bool m_is_writing_to_tcp{false};

    tp::string m_tcp_buf;
    static constexpr std::size_t kTcpBufSize = 16 * 1024;
};

#endif // QUIC_SESSION_UPSTREAM_H
