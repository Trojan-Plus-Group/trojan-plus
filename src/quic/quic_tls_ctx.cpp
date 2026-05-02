/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "quic_tls_ctx.h"

#include "core/log.h"

// Phase 1 skeleton: the wolfSSL QUIC context will be wired up in a follow-up
// commit using ngtcp2_crypto_wolfssl_configure_{server,client}_context. This
// stub keeps the build green while the QUIC module is fleshed out.

QuicTlsCtx::QuicTlsCtx(const Config& config, Role role)
    : m_ctx(nullptr), m_role(role), m_alpn_token(config.get_quic().alpn_token) {
    _log_with_date_time("QuicTlsCtx: Phase 1 skeleton constructed (role=" +
                        tp::string(role == Role::Server ? "server" : "client") +
                        ", alpn=" + m_alpn_token + ")",
                        Log::INFO);
}

QuicTlsCtx::~QuicTlsCtx() = default;
