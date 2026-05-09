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

#include <limits>
#include <memory>
#include <cstdint>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/http.hpp>

#include <nghttp3/nghttp3.h>

#include "mem/memallocator.h"
#include "quic_stream_handler.h"
#include "quic_connection.h"

class Config;

enum class RespState : uint8_t {
    kParsingHeaders,
    kStreamingBody,
    kDone,
    kError
};

// QuicUpstreamHandler: owns the TCP connection to the upstream HTTP/1.1 server
// and performs the H3→H1.1 conversion. Decoded h3 events are delivered by
// QuicToHttp3Connect via the on_h3_* methods below.
class QuicUpstreamHandler : public QuicStreamHandler, public std::enable_shared_from_this<QuicUpstreamHandler> {
  public:
    using H1RespParser = boost::beast::http::response_parser<boost::beast::http::buffer_body>;

    QuicUpstreamHandler(std::shared_ptr<QuicConnection> conn, int64_t stream_id,
                        boost::asio::io_context& io_ctx,
                        const tp::string& host, const tp::string& port_str);
    ~QuicUpstreamHandler() override;

    void start();
    void on_stream_data(const uint8_t* data, size_t len, bool fin) override;
    void on_stream_close() override;
    void on_connection_pump() override;
    void destroy();


    // Called by QuicToHttp3Connect callbacks with already-decoded values.
    int on_h3_begin_headers();
    int on_h3_header(const tp::string& name, const tp::string& value);
    int on_h3_end_headers(bool fin);
    int on_h3_data(const uint8_t* data, std::size_t len);
    int on_h3_end_stream();
    int on_h3_stream_close(uint64_t app_error_code);

    // Called by QuicToHttp3Connect::s_read_data (nghttp3 data_reader callback).
    nghttp3_ssize on_read_data(nghttp3_vec* vec, std::size_t veccnt, uint32_t* pflags);
    void notify_body_consumed(std::size_t n);

  private:
    void write_to_upstream(tp::string data, bool fin = false);
    void do_tcp_write();
    void tcp_read_from_upstream();
    void flush_tcp_read_buf(std::size_t bytes);

    int  submit_h3_response_headers();
    void process_body_chunk(bool eof);
    void pump_h3_and_read();
    void retry_feed_h3();
    void handle_parse_error();
    void close_tcp_only();

    std::weak_ptr<QuicConnection> m_conn_ptr;
    int64_t m_stream_id;

    tp::string m_http1_request;
    tp::string m_method;
    tp::string m_scheme;
    tp::string m_authority;
    tp::string m_path;
    tp::string m_regular_headers;
    bool m_request_complete{false};
    bool m_chunked_body{false};
    bool m_has_content_length{false};
    bool m_fin_sent{false};
    bool m_destroyed{false};
    std::size_t m_unacked_stream_bytes{0};

    tp::string m_h3_in_buf;
    bool m_h3_in_fin{false};

    tp::string m_host;
    tp::string m_port_str;
    boost::asio::ip::tcp::socket m_tcp_socket;
    boost::asio::ip::tcp::resolver m_resolver;
    boost::asio::steady_timer m_write_timer;

    struct TcpWriteBuffer {
        tp::string data;
        std::size_t stream_bytes{0};
        bool fin{false};
    };
    tp::deque<TcpWriteBuffer> m_tcp_write_queue;
    bool m_is_writing_to_tcp{false};

    tp::string m_tcp_buf;       // TCP read input (16 KB)
    static constexpr std::size_t kTcpBufSize = 16 * 1024;
    static constexpr std::size_t kMaxBufferedBytes = 64 * 1024;
    bool m_tcp_read_in_progress{false};

    // HTTP/1.1 → HTTP/3 response conversion state
    std::unique_ptr<H1RespParser> m_resp_parser;
    RespState m_resp_state{RespState::kParsingHeaders};
    tp::string m_parse_buf; // for buffer_body target

    // Body window for nghttp3 data_reader
    tp::list<tp::string> m_body_out_chunks;
    std::size_t    m_chunk_consumed{0}; // offset into front chunk that is ACKed
    std::size_t    m_given_offset{0};   // offset from m_chunk_consumed of next byte to give
    bool           m_body_eof{false};
    bool           m_reader_blocked{false};

    std::size_t body_bytes_available() const;
};

#endif // QUIC_SESSION_UPSTREAM_H
