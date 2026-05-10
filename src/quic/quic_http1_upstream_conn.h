/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _QUIC_HTTP1_UPSTREAM_CONN_H_
#define _QUIC_HTTP1_UPSTREAM_CONN_H_

#include <cstdint>
#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/http.hpp>
#include <boost/system/error_code.hpp>

#include <nghttp3/nghttp3.h>

#include "mem/memallocator.h"

// One TCP+HTTP/1.1 upstream connection (one per QUIC stream when fallback occurs).
//
// Owns the TCP socket, resolver, Beast HTTP/1.1 parser, write queue, and the
// response body chunk buffer with watermark-based read backpressure. Communicates
// with QuicUpstreamHandler via the Observer interface — pure event-driven, no
// polling timers.
class Http1UpstreamConn : public std::enable_shared_from_this<Http1UpstreamConn> {
  public:
    using H1RespParser = boost::beast::http::response_parser<boost::beast::http::buffer_body>;

    // TCP read state machine (response direction).
    enum class ReadState : uint8_t {
        Reading, // a read may be issued or in flight
        Paused,  // backpressure: m_buffered_bytes >= kHighWM, not reading
        Eof,     // upstream closed cleanly or body parser saw end_of_stream
        Error,   // unrecoverable TCP/parse error
    };

    class Observer {
      public:
        virtual ~Observer() = default;
        // TCP connect finished. ok==false if resolve or connect failed.
        virtual void on_h1_connect_done(bool ok) = 0;
        // HTTP/1.1 response headers parsed; the parser ref is valid only inside this call.
        virtual void on_h1_resp_headers(H1RespParser& parser) = 0;
        // One or more body chunks were appended to the buffer; observer should
        // drain via pull_body_chunks (typically by pumping H3).
        virtual void on_h1_body_data_available() = 0;
        // TCP read EOF or parser end_of_stream. No more body data will arrive.
        virtual void on_h1_eof() = 0;
        // TCP/parse error. Observer should call destroy() afterwards.
        virtual void on_h1_error(const boost::system::error_code& ec) = 0;
        // A queued write completed; bytes is the QUIC inbound credit
        // (the caller-provided stream_bytes) that may now be returned.
        virtual void on_h1_stream_credit(std::size_t bytes) = 0;
    };

    Http1UpstreamConn(boost::asio::io_context& io_ctx,
                      const tp::string& host,
                      const tp::string& port_str,
                      Observer* observer);
    ~Http1UpstreamConn();

    Http1UpstreamConn(const Http1UpstreamConn&)            = delete;
    Http1UpstreamConn& operator=(const Http1UpstreamConn&) = delete;

    // Resolve + connect. observer->on_h1_connect_done is called on completion.
    void start();

    // Clear observer pointer. Async callbacks already in flight will see this
    // and skip calling the observer. Safe from inside an observer callback.
    void detach_observer();

    // Cancel resolver, shutdown+close socket. In-flight async ops keep this
    // object alive via shared_from_this(); they observe m_destroyed and return.
    void destroy();

    // Append an HTTP/1.1 byte chunk to the write queue. stream_bytes is the
    // QUIC inbound credit associated with this chunk (returned via
    // on_h1_stream_credit when the write is acknowledged by TCP). fin=true
    // shuts down the send half after the queue drains.
    void send_request_chunk(tp::string data, std::size_t stream_bytes, bool fin);

    // nghttp3 data_reader pull. Returns:
    //   >0 vec entries filled, eof_flag undefined.
    //   0  with eof_flag=true: stream complete, caller sets NGHTTP3_DATA_FLAG_EOF.
    //   NGHTTP3_ERR_WOULDBLOCK: chunks empty but more expected; caller transitions
    //                            to BlockedByNghttp3 and waits for on_h1_body_data_available.
    nghttp3_ssize pull_body_chunks(nghttp3_vec* vec, std::size_t veccnt, bool& eof_flag);

    // After nghttp3 has copied n bytes out, release them and (if buffered_bytes
    // drops below kLowWM) resume async read.
    void notify_body_consumed(std::size_t n);

    [[nodiscard]] bool      is_eof() const { return m_read_state == ReadState::Eof; }
    [[nodiscard]] bool      has_buffered_body() const { return m_buffered_bytes > 0; }
    [[nodiscard]] ReadState read_state() const { return m_read_state; }

  private:
    void start_async_read();
    void on_tcp_read_done(const boost::system::error_code& ec, std::size_t bytes);
    void parse_tcp_data(std::size_t bytes);
    void do_tcp_write();
    void close_socket();

    void set_read_state(ReadState s);
    void buffer_chunk_append(tp::string chunk);
    void buffer_chunk_drop_front(std::size_t n);

    boost::asio::ip::tcp::socket   m_tcp_socket;
    boost::asio::ip::tcp::resolver m_resolver;
    tp::string                     m_host;
    tp::string                     m_port_str;

    Observer* m_observer{nullptr};
    bool      m_destroyed{false};
    bool      m_connected{false};

    static constexpr std::size_t kTcpBufSize   = 16 * 1024;
    static constexpr std::size_t kHighWM       = 64 * 1024;
    static constexpr std::size_t kLowWM        = 32 * 1024;
    static constexpr std::size_t kParseBufSize = 8 * 1024;

    // Read side
    tp::string                    m_tcp_read_buf;
    std::unique_ptr<H1RespParser> m_resp_parser;
    bool                          m_headers_delivered{false};
    tp::string                    m_parse_buf;
    tp::list<tp::string>          m_body_out_chunks;
    std::size_t                   m_buffered_bytes{0};
    ReadState                     m_read_state{ReadState::Reading};
    bool                          m_read_in_progress{false};

    // Write side
    struct WriteBuf {
        tp::string  data;
        std::size_t stream_bytes{0};
        bool        fin{false};
    };
    tp::deque<WriteBuf> m_write_queue;
    bool                m_write_in_progress{false};
};

#endif // _QUIC_HTTP1_UPSTREAM_CONN_H_
