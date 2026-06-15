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

#include <cstdint>
#include <memory>

#include <boost/asio/io_context.hpp>

#include <nghttp3/nghttp3.h>

#include "mem/memallocator.h"
#include "../quic_connection.h"
#include "quic_http1_upstream_conn.h"
#include "../quic_stream_handler.h"

class Config;

// QuicUpstreamHandler: glue layer that converts decoded H3 events (delivered by
// QuicToHttp3Connect) into HTTP/1.1 byte chunks fed to Http1UpstreamConn, and
// re-frames the upstream HTTP/1.1 response back into H3.  All TCP I/O and
// HTTP/1.1 parsing live in Http1UpstreamConn — this class is now a thin
// protocol-conversion shell.
class QuicUpstreamHandler : public QuicStreamHandler,
                            public Http1UpstreamConn::Observer,
                            public std::enable_shared_from_this<QuicUpstreamHandler> {
  public:
    // H3 outbound state — the only meaningful distinction we track explicitly
    // is BlockedByNghttp3 (data_reader returned WOULDBLOCK), since that is the
    // only path that requires nghttp3_conn_resume_stream to wake.  Other
    // sub-states (idle, pumping, blocked-by-quic, done) are implicit; see
    // plan §4.2 for the full design rationale.
    enum class H3OutState : uint8_t {
        Active,
        BlockedByNghttp3,
    };

    QuicUpstreamHandler(std::shared_ptr<QuicConnection> conn, int64_t stream_id,
                        boost::asio::io_context& io_ctx,
                        const tp::string& host, const tp::string& port_str);
    ~QuicUpstreamHandler() override;

    void h1_start();
    void on_stream_data(const uint8_t* data, size_t len, bool fin) override;
    void on_stream_close() override;
    void on_connection_pump() override;
    void destroy();

    // Called by QuicToHttp3Connect callbacks with already-decoded values.
    int h3_on_begin_headers();
    int h3_on_header(const tp::string& name, const tp::string& value);
    int h3_on_end_headers(bool fin);
    int h3_on_data(const uint8_t* data, std::size_t len);
    int h3_on_end_stream();
    int h3_on_stream_close(uint64_t app_error_code);

    // Called by QuicToHttp3Connect::s_read_data (nghttp3 data_reader callback).
    nghttp3_ssize h3_on_read_data(nghttp3_vec* vec, std::size_t veccnt, uint32_t* pflags);
    // Called by QuicToHttp3Connect::pump_h3_response after nghttp3 acks bytes.
    void h3_notify_body_consumed(std::size_t n);

    // Http1UpstreamConn::Observer
    void h1_on_connect_done(bool ok) override;
    void h1_on_resp_headers(Http1UpstreamConn::H1RespParser& parser) override;
    void h1_on_body_data_available() override;
    void h1_on_eof() override;
    void h1_on_error(const boost::system::error_code& ec) override;
    void h1_on_stream_credit(std::size_t bytes) override;

    std::shared_ptr<Http1UpstreamConn> h1_get_conn() const { return m_h1_conn; }

  private:
    void h3_retry_feed();
    int  h3_submit_response_headers(Http1UpstreamConn::H1RespParser& parser);
    void h3_pump_response(const char* debug_path);

    std::weak_ptr<QuicConnection> m_conn_ptr;
    int64_t                       m_stream_id;
    boost::asio::io_context&      m_io_ctx;

    // Request assembly (H3 → HTTP/1.1)
    tp::string m_http1_request;
    tp::string m_method;
    tp::string m_scheme;
    tp::string m_authority;
    tp::string m_path;
    tp::string m_regular_headers;
    bool       m_request_complete{false};
    bool       m_chunked_body{false};
    bool       m_has_content_length{false};
    bool       m_fin_sent{false};
    bool       m_destroyed{false};

    // Pending H3 frame bytes received via on_stream_data, awaiting feed.
    tp::streambuf m_h3_in_buf;
    bool          m_h3_in_fin{false};

    // H3 outbound state (response direction).
    H3OutState m_h3_out_state{H3OutState::Active};

    std::shared_ptr<Http1UpstreamConn> m_h1_conn;

    // Struct to buffer request chunks during a synchronous feed_stream_data call.
    struct PendingChunk {
        tp::string data;
        bool fin{false};
    };
    tp::vector<PendingChunk> m_h3_to_h1_feed_chunks;
};

#endif // QUIC_SESSION_UPSTREAM_H
