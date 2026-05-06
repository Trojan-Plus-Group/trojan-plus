/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef QUIC_SESSION_H
#define QUIC_SESSION_H

#include <memory>
#include <cstdint>
#include <functional>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <nghttp3/nghttp3.h>

class QuicConnection;
class Config;

#include "mem/memallocator.h"

// Server-side per-stream proxy session. Buffers incoming stream bytes until a
// complete TrojanRequest header is received, then dials a TCP socket to the
// target and splices data bidirectionally.
class QuicProxySession : public std::enable_shared_from_this<QuicProxySession> {
  public:
    QuicProxySession(std::shared_ptr<QuicConnection> conn, int64_t stream_id,
                     const Config& config, boost::asio::io_context& io_ctx);
    ~QuicProxySession();

    void start();

    // Called by QuicConnection when data arrives on this stream.
    void on_stream_data(const uint8_t* data, std::size_t len, bool fin);
    // Called by QuicConnection when this stream is closed remotely.
    void on_stream_close();

    [[nodiscard]] int64_t stream_id() const { return m_stream_id; }

  private:
    void try_parse_request();
    void forward_to_h3_upstream();
    void connect_target(const tp::string& host, uint16_t port);
    void tcp_read();
    void flush_tcp_read_buf(std::size_t offset, std::size_t bytes);
    void write_to_target(tp::string data, bool fin = false);
    void do_tcp_write();
    void tcp_read_from_upstream();
    void destroy();

    // H3UpstreamHandler: encapsulates nghttp3 HTTP/3 decoding and h3→h1.1 conversion
    class H3UpstreamHandler {
      public:
        using WriteCallback = std::function<void(tp::string data, bool fin)>;
        using CloseCallback = std::function<void()>;

        H3UpstreamHandler(QuicProxySession& parent, WriteCallback write_cb, CloseCallback close_cb);
        ~H3UpstreamHandler();

        void feed_stream_data(const uint8_t* data, size_t len, bool fin);
        void close();

        [[nodiscard]] bool is_request_complete() const { return m_request_complete; }
        [[nodiscard]] bool is_valid() const { return m_valid; }
        [[nodiscard]] const tp::string& get_http1_request() const { return m_http1_request; }
        void clear_request() { m_http1_request.clear(); m_request_complete = false; }

      private:
        static int cb_begin_headers(nghttp3_conn*, int64_t, void*, void*);
        static int cb_recv_header(nghttp3_conn*, int64_t, int32_t, nghttp3_rcbuf*, nghttp3_rcbuf*, uint8_t, void*, void*);
        static int cb_end_headers(nghttp3_conn*, int64_t, int, void*, void*);
        static int cb_recv_data(nghttp3_conn*, int64_t, const uint8_t*, size_t, void*, void*);
        static int cb_end_stream(nghttp3_conn*, int64_t, void*, void*);
        static int cb_stream_close(nghttp3_conn*, int64_t, uint64_t, void*, void*);

        void build_http1_request_line();

        QuicProxySession& m_parent;
        WriteCallback m_write_cb;
        CloseCallback m_close_cb;

        std::unique_ptr<nghttp3_conn, decltype(&nghttp3_conn_del)> m_conn;
        tp::string m_http1_request;
        tp::string m_method;
        tp::string m_scheme;
        tp::string m_authority;
        tp::string m_path;
        tp::string m_regular_headers;
        bool m_request_complete{false};
        bool m_valid{true};
    };

    std::shared_ptr<QuicConnection> m_conn;
    int64_t m_stream_id;
    const Config& m_config;

    boost::asio::ip::tcp::socket m_tcp_socket;
    boost::asio::ip::tcp::resolver m_resolver;

    tp::string m_recv_buf;    // accumulates stream bytes until request parsed
    tp::string m_tcp_buf;     // read buffer for upstream → stream direction
    bool m_request_parsed{false};
    bool m_upstream_forwarding{false}; // forwarding non-trojan traffic to h3_upstream
    bool m_stream_fin_received{false}; // client sent QUIC stream FIN
    bool m_destroyed{false};

    static constexpr std::size_t kTcpBufSize = 16 * 1024;
    boost::asio::steady_timer m_write_timer;

    struct TcpWriteBuffer {
        tp::string data;
        bool fin{false};
    };
    tp::deque<TcpWriteBuffer> m_tcp_write_queue;
    bool m_is_writing_to_tcp{false};

    std::unique_ptr<H3UpstreamHandler> m_h3_handler;
};

#endif // QUIC_SESSION_H
