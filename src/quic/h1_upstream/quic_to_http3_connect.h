/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#ifndef _QUIC_TO_HTTP3_CONNECT_H_
#define _QUIC_TO_HTTP3_CONNECT_H_

#include <cstdint>

#include <nghttp3/nghttp3.h>

#include "mem/memallocator.h"

class QuicConnection;
class QuicUpstreamHandler;

// One nghttp3_conn per QuicConnection. Owns the connection-level QPACK
// dynamic table and stream-id namespace; routes decoded h3 events to the
// per-stream QuicUpstreamHandler registered for that stream_id.
class QuicToHttp3Connect {
  public:
    explicit QuicToHttp3Connect(QuicConnection& owner);
    ~QuicToHttp3Connect();

    QuicToHttp3Connect(const QuicToHttp3Connect&)            = delete;
    QuicToHttp3Connect& operator=(const QuicToHttp3Connect&) = delete;

    [[nodiscard]] bool init();
    [[nodiscard]] bool is_valid() const { return m_conn != nullptr; }

    // Bind H3 server-initiated unidirectional streams (call once after handshake).
    void bind_control_streams(int64_t ctrl_id, int64_t qenc_id, int64_t qdec_id);

    // Raw pointer — handler MUST call unregister_stream from destroy() before its
    // shared_ptr drops, while QuicConnection::m_stream_handlers still holds it.
    void register_stream(int64_t stream_id, std::shared_ptr<QuicUpstreamHandler> handler);
    void unregister_stream(int64_t stream_id);

    // Feed raw QUIC stream bytes into nghttp3. Returns consumed byte count (== len
    // on success) or a negative nghttp3 error code.
    nghttp3_ssize feed_stream_data(int64_t stream_id, const uint8_t* data,
                                   std::size_t len, bool fin);

    // Submit an HTTP/3 response for stream_id.  headers must contain ":status"
    // first.  Pass has_body=true to attach a streaming data_reader; false sends
    // a header-only response with FIN.
    int submit_response(int64_t stream_id,
                        const tp::vector<std::pair<tp::string, tp::string>>& headers,
                        bool has_body);

    // Drive the nghttp3 write loop: pull encoded H3 frames and hand them to
    // QuicConnection::send_stream_vecs, then call add_write_offset.
    void pump_h3_response(const char* debug_path);

    // Resume a stream that previously returned NGHTTP3_ERR_WOULDBLOCK from
    // its data_reader, then immediately pump.
    void resume_stream(int64_t stream_id, const char* debug_path);

    // Unblock a stream blocked by flow control.
    void unblock_stream(int64_t stream_id);

    // Notify H3 of data acknowledged on stream
    int acked_stream_data(int64_t stream_id, std::size_t datalen);

    // Close stream in nghttp3
    int close_stream(int64_t stream_id, uint64_t app_error_code);

    // data_reader callback for nghttp3 — delegates to handler->on_read_data().
    static nghttp3_ssize s_read_data(nghttp3_conn*, int64_t stream_id,
                                     nghttp3_vec* vec, std::size_t veccnt,
                                     uint32_t* pflags,
                                     void* conn_user_data, void* stream_user_data);

  private:
    std::shared_ptr<QuicUpstreamHandler> find_handler(int64_t stream_id);

    static int cb_begin_headers(nghttp3_conn*, int64_t stream_id,
                                void* conn_user_data, void* stream_user_data);
    static int cb_recv_header(nghttp3_conn*, int64_t stream_id, int32_t token,
                              nghttp3_rcbuf* name, nghttp3_rcbuf* value,
                              uint8_t flags,
                              void* conn_user_data, void* stream_user_data);
    static int cb_end_headers(nghttp3_conn*, int64_t stream_id, int fin,
                              void* conn_user_data, void* stream_user_data);
    static int cb_recv_data(nghttp3_conn*, int64_t stream_id,
                            const uint8_t* data, std::size_t datalen,
                            void* conn_user_data, void* stream_user_data);
    static int cb_end_stream(nghttp3_conn*, int64_t stream_id,
                             void* conn_user_data, void* stream_user_data);
    static int cb_stream_close(nghttp3_conn*, int64_t stream_id,
                               uint64_t app_error_code,
                               void* conn_user_data, void* stream_user_data);
    static int cb_acked_stream_data(nghttp3_conn* conn, int64_t stream_id,
                                    uint64_t datalen, void* conn_user_data,
                                    void* stream_user_data);

    QuicConnection& m_owner;
    nghttp3_conn* m_conn{nullptr};
    tp::unordered_map<int64_t, std::weak_ptr<QuicUpstreamHandler>> m_streams;
};

#endif // _QUIC_TO_HTTP3_CONNECT_H_
