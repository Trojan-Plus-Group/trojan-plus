/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_connection.h"

#include "core/log.h"
#include "quic_endpoint.h"

QuicConnection::QuicConnection(QuicEndpoint& endpoint, std::shared_ptr<QuicTlsCtx> tls_ctx,
                               const boost::asio::ip::udp::endpoint& peer)
    : m_endpoint(endpoint),
      m_tls_ctx(std::move(tls_ctx)),
      m_peer(peer),
      m_loss_timer(endpoint.io_context()) {
    _log_with_date_time("QuicConnection: skeleton constructed for peer " +
                        tp::string(peer.address().to_string().c_str()),
                        Log::INFO);
}

QuicConnection::~QuicConnection() = default;

void QuicConnection::close() {
    m_loss_timer.cancel();
    (void)m_endpoint;
}
