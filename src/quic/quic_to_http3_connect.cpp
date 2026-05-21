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
#include "mem/memallocator.h"

static void *tj_nghttp3_malloc(size_t size, void *user_data) {
    (void)user_data;
    return tp::get_tj_mem_allocator().malloc(size, "nghttp3", 0);
}

static void tj_nghttp3_free(void *ptr, void *user_data) {
    (void)user_data;
    tp::get_tj_mem_allocator().free(ptr);
}

static void *tj_nghttp3_calloc(size_t nmemb, size_t size, void *user_data) {
    (void)user_data;
    size_t real_size = nmemb * size;
    void *ptr = tp::get_tj_mem_allocator().malloc(real_size, "nghttp3", 0);
    if (ptr) {
        std::memset(ptr, 0, real_size);
    }
    return ptr;
}

static void *tj_nghttp3_realloc(void *ptr, size_t size, void *user_data) {
    (void)user_data;
    return tp::get_tj_mem_allocator().realloc(ptr, size, "nghttp3", 0);
}

static const nghttp3_mem tj_nghttp3_mem = {
    nullptr,
    tj_nghttp3_malloc,
    tj_nghttp3_free,
    tj_nghttp3_calloc,
    tj_nghttp3_realloc
};
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
    callbacks.begin_headers     = &cb_begin_headers;
    callbacks.recv_header       = &cb_recv_header;
    callbacks.end_headers       = &cb_end_headers;
    callbacks.recv_data         = &cb_recv_data;
    callbacks.end_stream        = &cb_end_stream;
    callbacks.stream_close      = &cb_stream_close;
    callbacks.acked_stream_data = &cb_acked_stream_data;

    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    settings.max_field_section_size            = (1ULL << 62) - 1;
    settings.qpack_max_dtable_capacity         = 4096;
    settings.qpack_encoder_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams             = 100;

    nghttp3_conn* conn = nullptr;
    int rv = nghttp3_conn_server_new(&conn, &callbacks, &settings,
                                    &tj_nghttp3_mem, this);
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

void QuicToHttp3Connect::bind_control_streams(int64_t ctrl_id, int64_t qenc_id,
                                               int64_t qdec_id) {
    if (!m_conn) return;
    nghttp3_conn_bind_control_stream(m_conn, ctrl_id);
    nghttp3_conn_bind_qpack_streams(m_conn, qenc_id, qdec_id);
}

int QuicToHttp3Connect::submit_response(
    int64_t stream_id,
    const tp::vector<std::pair<tp::string, tp::string>>& headers,
    bool has_body)
{
    if (!m_conn) return NGHTTP3_ERR_INVALID_STATE;

    tp::vector<nghttp3_nv> nva;
    nva.reserve(headers.size());
    for (auto& [n, v] : headers) {
        nghttp3_nv nv;
        nv.name     = reinterpret_cast<uint8_t*>(const_cast<char*>(n.data()));
        nv.namelen  = n.size();
        nv.value    = reinterpret_cast<uint8_t*>(const_cast<char*>(v.data()));
        nv.valuelen = v.size();
        nv.flags    = NGHTTP3_NV_FLAG_NONE;
        nva.push_back(nv);
    }

    const nghttp3_data_reader* dr_ptr = nullptr;
    nghttp3_data_reader dr{};
    if (has_body) {
        dr.read_data = &s_read_data;
        dr_ptr = &dr;
    }

    int rv = nghttp3_conn_submit_response(
        m_conn, stream_id, nva.data(), nva.size(), dr_ptr);
    if (rv == 0) {
        _log_with_date_time("QuicToHttp3Connect: submitted response for stream " + tp::to_string(stream_id) + " has_body=" + tp::to_string(has_body), Log::ALL);
    } else {
        _log_with_date_time(
            "QuicToHttp3Connect::submit_response stream " + tp::to_string(stream_id) +
            ": " + tp::string(nghttp3_strerror(rv)),
            Log::ERROR);
    }
    return rv;
}

void QuicToHttp3Connect::pump_h3_response() {
    if (!m_conn) return;

    constexpr int kMaxVecs = 16;
    nghttp3_vec h3vecs[kMaxVecs];

    for (;;) {
        int64_t sid = -1;
        int fin = 0;
        nghttp3_ssize n = nghttp3_conn_writev_stream(
            m_conn, &sid, &fin, h3vecs, kMaxVecs);
        
        if (n > 0) {
            _log_with_date_time("QuicToHttp3Connect: pump_h3_response stream " + tp::to_string(sid) + " produced " + tp::to_string(n) + " vecs", Log::ALL);
        }

        if (n < 0) {
            _log_with_date_time(
                "QuicToHttp3Connect::pump_h3_response: writev_stream: " +
                tp::string(nghttp3_strerror(static_cast<int>(n))),
                Log::WARN);
            break;
        }
        if (sid == -1) break;  // nothing to write

        // nghttp3_vec and ngtcp2_vec are layout-compatible ({uint8_t* base, size_t len})
        int64_t consumed = m_owner.send_stream_vecs(
            sid,
            reinterpret_cast<const ngtcp2_vec*>(h3vecs),
            static_cast<std::size_t>(n),
            fin != 0);

        // Always report back to nghttp3 how many bytes ngtcp2 accepted
        nghttp3_conn_add_write_offset(
            m_conn, sid,
            consumed > 0 ? static_cast<std::size_t>(consumed) : 0);

        if (consumed < 0 || (consumed == 0 && n > 0)) {
            // error or QUIC flow-control blocked
            break;
        }
    }
}

int QuicToHttp3Connect::acked_stream_data(int64_t stream_id, std::size_t datalen) {
    if (!m_conn) return NGHTTP3_ERR_INVALID_STATE;
    int rv = nghttp3_conn_add_ack_offset(m_conn, stream_id, datalen);
    if (rv != 0) {
        _log_with_date_time("QuicToHttp3Connect::acked_stream_data stream " + tp::to_string(stream_id) + " failed: " + tp::string(nghttp3_strerror(rv)), Log::WARN);
    }
    return rv;
}

void QuicToHttp3Connect::resume_stream(int64_t stream_id) {
    if (!m_conn) return;
    nghttp3_conn_resume_stream(m_conn, stream_id);
    pump_h3_response();
}

nghttp3_ssize QuicToHttp3Connect::s_read_data(
    nghttp3_conn* /*conn*/, int64_t stream_id,
    nghttp3_vec* vec, std::size_t veccnt, uint32_t* pflags,
    void* conn_user_data, void* /*stream_user_data*/)
{
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto h = self->find_handler(stream_id);
    if (!h) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    return h->on_read_data(vec, veccnt, pflags);
}

void QuicToHttp3Connect::register_stream(int64_t stream_id, std::shared_ptr<QuicUpstreamHandler> handler) {
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

std::shared_ptr<QuicUpstreamHandler> QuicToHttp3Connect::find_handler(int64_t stream_id) {
    auto it = m_streams.find(stream_id);
    return it != m_streams.end() ? it->second.lock() : nullptr;
}

// ---- static callbacks -------------------------------------------------------

int QuicToHttp3Connect::cb_begin_headers(nghttp3_conn*, int64_t stream_id,
                                          void* conn_user_data, void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto h = self->find_handler(stream_id);
    if (!h) return 0;
    return h->on_h3_begin_headers();
}

int QuicToHttp3Connect::cb_recv_header(nghttp3_conn*, int64_t stream_id, int32_t,
                                        nghttp3_rcbuf* name, nghttp3_rcbuf* value,
                                        uint8_t, void* conn_user_data, void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto h = self->find_handler(stream_id);
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
    auto h = self->find_handler(stream_id);
    if (!h) return 0;
    return h->on_h3_end_headers(fin != 0);
}

int QuicToHttp3Connect::cb_recv_data(nghttp3_conn*, int64_t stream_id,
                                      const uint8_t* data, std::size_t datalen,
                                      void* conn_user_data, void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto h = self->find_handler(stream_id);
    if (!h) return 0;
    return h->on_h3_data(data, datalen);
}

int QuicToHttp3Connect::cb_end_stream(nghttp3_conn*, int64_t stream_id,
                                       void* conn_user_data, void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto h = self->find_handler(stream_id);
    if (!h) return 0;
    return h->on_h3_end_stream();
}

int QuicToHttp3Connect::cb_stream_close(nghttp3_conn*, int64_t stream_id,
                                         uint64_t app_error_code,
                                         void* conn_user_data, void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto h = self->find_handler(stream_id);
    if (!h) return 0;
    return h->on_h3_stream_close(app_error_code);
}

int QuicToHttp3Connect::cb_acked_stream_data(nghttp3_conn*, int64_t stream_id,
                                             uint64_t datalen, void* conn_user_data,
                                             void*) {
    auto* self = static_cast<QuicToHttp3Connect*>(conn_user_data);
    auto h = self->find_handler(stream_id);
    if (h) {
        _log_with_date_time("QuicToHttp3Connect: acked " + tp::to_string(datalen) + " body bytes on stream " + tp::to_string(stream_id), Log::ALL);
        h->notify_body_consumed(static_cast<std::size_t>(datalen));
    }
    return 0;
}
