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
#include <ngtcp2/ngtcp2_crypto.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "core/config.h"
#include "core/log.h"
#include "quic_connection.h"
#include "quic_session.h"
#include "quic_tls_ctx.h"
#include "h1_upstream/quic_to_http3_connect.h"
#include "core/utils.h"

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

void QuicServerEndpoint::send_stateless_reset(const uint8_t* dcid, std::size_t dcidlen,
                                              const boost::asio::ip::udp::endpoint& dest) {
    // Derive a deterministic Stateless Reset token using HKDF from the
    // per-process endpoint secret and the received DCID.  This is identical to
    // the derivation used in cb_get_new_connection_id, so a client that was
    // previously issued this token via NEW_CONNECTION_ID will recognise it.
    ngtcp2_cid cid_c{};
    cid_c.datalen = dcidlen;
    std::memcpy(cid_c.data, dcid, dcidlen);

    ngtcp2_stateless_reset_token token{};
    if (ngtcp2_crypto_generate_stateless_reset_token(
            token.data, stateless_reset_secret(), kStatelessResetSecretLen,
            &cid_c) != 0) {
        _log_with_date_time(
            "QuicServerEndpoint: ngtcp2_crypto_generate_stateless_reset_token failed",
            Log::WARN);
        return;
    }

    // Random padding bytes preceding the token (RFC 9000 minimum is 5).
    constexpr std::size_t kRandLen = NGTCP2_MIN_STATELESS_RESET_RANDLEN + 16;
    uint8_t rand_bytes[kRandLen];
    wolfSSL_RAND_bytes(rand_bytes, static_cast<int>(kRandLen));

    uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
    auto nwrite = ngtcp2_pkt_write_stateless_reset2(buf, sizeof(buf), &token,
                                                    rand_bytes, kRandLen);
    if (nwrite < 0) {
        _log_with_date_time(
            "QuicServerEndpoint: ngtcp2_pkt_write_stateless_reset2 failed: " +
                tp::string(ngtcp2_strerror(static_cast<int>(nwrite))),
            Log::WARN);
        return;
    }

    tp::string dcid_hex = dcid_key(dcid, dcidlen);
    _log_with_date_time(
        "QuicServerEndpoint: sending Stateless Reset for unknown CID " + dcid_hex +
            " to " + tp::string(dest.address().to_string().c_str()) + ":" +
            tp::to_string(dest.port()),
        Log::INFO);
    send_packet(dest, buf, static_cast<std::size_t>(nwrite));
}

void QuicServerEndpoint::on_packet(const uint8_t* data, std::size_t len,
                                   const boost::asio::ip::udp::endpoint& src) {
    if (len == 0) {
        return;
    }

    ngtcp2_version_cid vc{};
    // Use the expected server SCID length for the short-header DCID length hint.
    int rv = ngtcp2_pkt_decode_version_cid(&vc, data, len, QuicConnection::kServerScidLen);
    if (rv < 0) {
        return;
    }

    tp::string key = dcid_key(vc.dcid, vc.dcidlen);

    auto it = m_conns.find(key);
    if (it != m_conns.end()) {
        it->second->on_packet(data, len, local_endpoint(), src);
        m_pumping_conn.push_back(key);
        return;
    }

    // vc.version == 0 means Short Header (1-RTT) packet – this is a post-handshake
    // packet for an unknown connection.  Send a Stateless Reset per RFC 9000 §10.3.
    if (vc.version == 0) {
        _log_with_date_time(
            "QuicServerEndpoint: Short Header packet for unknown CID " + key +
                ", sending Stateless Reset",
            Log::INFO);
        send_stateless_reset(vc.dcid, vc.dcidlen, src);
        return;
    }

    _log_with_date_time("QuicServerEndpoint: new connection for DCID " + key, Log::INFO);

    // Lightweight GC of closed connections.
    for (auto iter = m_conns.begin(); iter != m_conns.end();) {
        if (iter->second->is_closed()) {
            iter = m_conns.erase(iter);
        } else {
            ++iter;
        }
    }

    // New connection – must be an Initial packet.
    if (rv == NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM) {
        return;
    }

    auto self = shared_from_this();
    auto conn = TP_MAKE_SHARED(QuicConnection, *this, m_tls_ctx, src);

    conn->on_close_cb = [this](QuicConnection* connection) {
        for (auto iter = m_conns.begin(); iter != m_conns.end();) {
            if (iter->second.get() == connection) {
                iter = m_conns.erase(iter);
            } else {
                ++iter;
            }
        }
    };

    // stream_open: create a QuicProxySession for each new bidi stream.
    auto weak_conn = std::weak_ptr<QuicConnection>(conn);
    conn->on_stream_open_cb = [this, self, weak_conn](int64_t stream_id) {
        auto locked = weak_conn.lock();
        if (!locked) {
            return;
        }

        bool route_to_h1 = is_quic_client_uni_stream(stream_id)
                         || locked->conn_type() == QuicConnection::ConnType::other;
        if (route_to_h1) {
            // Uni streams are H3 control/QPACK; bidi streams on an already-identified
            // non-Trojan connection also go directly to H1 upstream.
            if (!locked->forward_to_h1_upstream(stream_id, nullptr, 0, false)) {
                locked->reset_stream(stream_id, NGHTTP3_H3_INTERNAL_ERROR);
            }
        } else {
            auto session = TP_MAKE_SHARED(QuicProxySession, locked, stream_id, m_config, m_io_context);
            locked->set_stream_handler(stream_id, session);
            session->start();
        }
    };

    // new connection ID generated: add it to the routing table.
    conn->on_new_connection_id_cb = [this, self, weak_conn](const ngtcp2_cid* cid) {
        auto locked = weak_conn.lock();
        if (locked) {
            tp::string ckey = dcid_key(cid->data, cid->datalen);
            _log_with_date_time("QuicServerEndpoint: added NEW CID " + ckey, Log::INFO);
            m_conns[ckey] = locked;
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
    _log_with_date_time("QuicServerEndpoint: added initial DCID " + key, Log::INFO);
    m_conns[key] = conn;
    
    tp::string sv_key = dcid_key(sv_scid.data, sv_scid.datalen);
    _log_with_date_time("QuicServerEndpoint: added server SCID " + sv_key, Log::INFO);
    m_conns[sv_key] = std::move(conn);

    m_pumping_conn.push_back(key);
}

void QuicServerEndpoint::on_pump_write(){
    for(const auto& key : m_pumping_conn){
        auto it = m_conns.find(key);
        if(it != m_conns.end()){
            it->second->on_pump_write();
        }
    }

    m_pumping_conn.clear();
}
