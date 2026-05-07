/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_to_http3_connect.h"

#include "core/log.h"
#include "quic_session_upstream.h"

QuicToHttp3Connect::QuicToHttp3Connect(QuicConnection& owner)
    : m_owner(owner) {}

QuicToHttp3Connect::~QuicToHttp3Connect() {
    if (m_conn) {
        nghttp3_conn_del(m_conn);
        m_conn = nullptr;
    }
}

bool QuicToHttp3Connect::init() {
    nghttp3_callbacks callbacks = {};
    callbacks.begin_headers = &cb_begin_headers;
    callbacks.recv_header   = &cb_recv_header;
    callbacks.end_headers   = &cb_end_headers;
    callbacks.recv_data     = &cb_recv_data;
    callbacks.end_stream    = &cb_end_stream;
    callbacks.stream_close  = &cb_stream_close;

    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    settings.max_field_section_size            = (1ULL << 62) - 1;
    settings.qpack_max_dtable_capacity         = 4096;
    settings.qpack_encoder_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams             = 100;

    nghttp3_conn* conn = nullptr;
    int rv = nghttp3_conn_server_new(&conn, &callbacks, &settings,
                                    nghttp3_mem_default(), this);
    if (rv != 0) {
        _log_with_date_time(
            "QuicToHttp3Connect::init: nghttp3_conn_server_new failed: " +
            tp::string(nghttp3_strerror(rv)),
            Log::ERROR);
        return false;
    }
    m_conn = conn;
    return true;
}

void QuicToHttp3Connect::register_stream(int64_t stream_id, QuicUpstreamHandler* handler) {
    m_streams[stream_id] = handler;
}

void QuicToHttp3Connect::unregister_stream(int64_t stream_id) {
    m_streams.erase(stream_id);
}

nghttp3_ssize QuicToHttp3Connect::feed_stream_data(int64_t stream_id,
                                                    const uint8_t* data,
                                                    std::size_t len, bool fin) {
    if (!m_conn) return NGHTTP3_ERR_INVALID_STATE;
    return nghttp3_conn_read_stream(m_conn, stream_id, data, len, fin ? 1 : 0);
}

QuicUpstreamHandler* QuicToHttp3Connect::find_handler(int64_t stream_id) {
    auto it = m_streams.find(stream_id);
    return it != m_streams.end() ? it->second : nullptr;
}

// ---- static callbacks -------------------------------------------------------

int QuicToHttp3Connect::cb_begin_headers(nghttp3_conn*, int64_t stream_id,
                                          void* conn_user_data, void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto* h    = self->find_handler(stream_id);
    if (!h) return 0;
    return h->on_h3_begin_headers();
}

int QuicToHttp3Connect::cb_recv_header(nghttp3_conn*, int64_t stream_id, int32_t,
                                        nghttp3_rcbuf* name, nghttp3_rcbuf* value,
                                        uint8_t, void* conn_user_data, void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto* h    = self->find_handler(stream_id);
    if (!h) return 0;
    auto nb = nghttp3_rcbuf_get_buf(name);
    auto vb = nghttp3_rcbuf_get_buf(value);
    return h->on_h3_header(
        tp::string(reinterpret_cast<char*>(nb.base), nb.len),
        tp::string(reinterpret_cast<char*>(vb.base), vb.len));
}

int QuicToHttp3Connect::cb_end_headers(nghttp3_conn*, int64_t stream_id, int fin,
                                        void* conn_user_data, void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto* h    = self->find_handler(stream_id);
    if (!h) return 0;
    return h->on_h3_end_headers(fin != 0);
}

int QuicToHttp3Connect::cb_recv_data(nghttp3_conn*, int64_t stream_id,
                                      const uint8_t* data, std::size_t datalen,
                                      void* conn_user_data, void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto* h    = self->find_handler(stream_id);
    if (!h) return 0;
    return h->on_h3_data(data, datalen);
}

int QuicToHttp3Connect::cb_end_stream(nghttp3_conn*, int64_t stream_id,
                                       void* conn_user_data, void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto* h    = self->find_handler(stream_id);
    if (!h) return 0;
    return h->on_h3_end_stream();
}

int QuicToHttp3Connect::cb_stream_close(nghttp3_conn*, int64_t stream_id,
                                         uint64_t app_error_code,
                                         void* conn_user_data, void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto* h    = self->find_handler(stream_id);
    if (!h) return 0;
    return h->on_h3_stream_close(app_error_code);
}
