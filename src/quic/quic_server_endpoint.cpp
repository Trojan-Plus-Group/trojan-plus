/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_server_endpoint.h"

#include <cstring>
#include <iomanip>
#include <sstream>

#include <boost/asio/ip/address.hpp>
#include <ngtcp2/ngtcp2.h>

#include "core/config.h"
#include "core/log.h"
#include "quic_session.h"
#include "quic_tls_ctx.h"

QuicServerEndpoint::QuicServerEndpoint(boost::asio::io_context& io_ctx, const Config& config,
                                       std::shared_ptr<QuicTlsCtx> tls_ctx)
    : QuicEndpoint(io_ctx, config, std::move(tls_ctx)) {}

void QuicServerEndpoint::start() {
    if (m_running) {
        return;
    }

    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(
        tp::string(m_config.get_local_addr().c_str()), ec);
    if (ec) {
        _log_with_date_time("QuicServerEndpoint: invalid local_addr '" + m_config.get_local_addr() +
                                "': " + tp::string(ec.message().c_str()),
                            Log::ERROR);
        return;
    }

    boost::asio::ip::udp::endpoint bind_ep(addr, m_config.get_local_port());
    open_socket(bind_ep, m_config.get_tcp().reuse_port);
    if (!m_socket.is_open()) {
        return;
    }

    m_running = true;
    async_recv();
    _log_with_date_time("QuicServerEndpoint: listening on UDP " + m_config.get_local_addr() + ":" +
                            tp::to_string(m_config.get_local_port()),
                        Log::INFO);
}

tp::string QuicServerEndpoint::dcid_key(const uint8_t* dcid, std::size_t dcidlen) {
    tp::ostringstream oss;
    for (std::size_t i = 0; i < dcidlen; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(dcid[i]);
    }
    return oss.str();
}

void QuicServerEndpoint::on_packet(const uint8_t* data, std::size_t len,
                                   const boost::asio::ip::udp::endpoint& src) {
    if (len == 0) {
        return;
    }

    ngtcp2_version_cid vc{};
    // Use NGTCP2_MAX_CIDLEN (20) for the short-header DCID length hint.
    int rv = ngtcp2_pkt_decode_version_cid(&vc, data, len, NGTCP2_MAX_CIDLEN);
    if (rv < 0) {
        return;
    }

    tp::string key = dcid_key(vc.dcid, vc.dcidlen);

    // Lightweight GC of closed connections.
    for (auto it = m_conns.begin(); it != m_conns.end();) {
        if (it->second->is_closed()) {
            it = m_conns.erase(it);
        } else {
            ++it;
        }
    }

    auto conn_it = m_conns.find(key);
    if (conn_it != m_conns.end()) {
        conn_it->second->on_packet(data, len, local_endpoint(), src);
        return;
    }

    // New connection – must be an Initial packet.
    if (rv == NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM) {
        return;
    }

    auto conn = TP_MAKE_SHARED(QuicConnection, *this, m_tls_ctx, src);

    // Per-connection stream → session table.
    typedef tp::unordered_map<int64_t, std::shared_ptr<QuicProxySession>> stream_session_type;
    auto stream_sessions = TP_MAKE_SHARED(stream_session_type);

    // stream_open: create a QuicProxySession for each new bidi stream.
    auto weak_conn = std::weak_ptr<QuicConnection>(conn);
    conn->on_stream_open_cb = [this, weak_conn, stream_sessions](int64_t stream_id) {
        auto locked = weak_conn.lock();
        if (!locked) {
            return;
        }
        auto session = TP_MAKE_SHARED(QuicProxySession, locked, stream_id, m_config, m_io_context);
        (*stream_sessions)[stream_id] = session;
        session->start();
    };

    // stream_data: route to the correct session.
    conn->on_stream_data_cb = [stream_sessions](int64_t stream_id, const uint8_t* data,
                                                 std::size_t len, bool fin) {
        auto it = stream_sessions->find(stream_id);
        if (it != stream_sessions->end()) {
            it->second->on_stream_data(data, len, fin);
        }
    };

    // stream_close: clean up session.
    conn->on_stream_close_cb = [stream_sessions](int64_t stream_id) {
        auto it = stream_sessions->find(stream_id);
        if (it != stream_sessions->end()) {
            it->second->on_stream_close();
            stream_sessions->erase(it);
        }
    };

    ngtcp2_cid dcid_c{};
    std::memcpy(dcid_c.data, vc.dcid, vc.dcidlen);
    dcid_c.datalen = vc.dcidlen;

    ngtcp2_cid scid_c{};
    if (vc.scid && vc.scidlen > 0) {
        std::memcpy(scid_c.data, vc.scid, vc.scidlen);
        scid_c.datalen = vc.scidlen;
    }

    ngtcp2_cid sv_scid{};
    if (!conn->init_server(data, len, local_endpoint(), src, &dcid_c,
                           vc.scidlen > 0 ? &scid_c : nullptr, vc.version, &sv_scid)) {
        return;
    }

    // Index under both the initial DCID (for any retransmitted Initials) and
    // the server's SCID (sv_scid), which the client uses as DCID for all
    // Handshake and 1-RTT packets after receiving the server's Initial.
    m_conns[key]                                              = conn;
    m_conns[dcid_key(sv_scid.data, sv_scid.datalen)] = std::move(conn);
}
