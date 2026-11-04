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

#include <cstring>

#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include "ssl/boringssl_compat.h"

#include "core/log.h"

// Server ALPN select callback. We never reject: prefer the configured token
// (default "h3"), fall back to whatever the client offers first, so trojan
// traffic is indistinguishable from standard HTTP/3 at the TLS layer.
static int alpn_select_cb(SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                          const unsigned char* in, unsigned int inlen, void* arg) {
    const auto* want     = static_cast<const char*>(arg);
    auto        want_len = static_cast<unsigned char>(strlen(want));

    // Walk client-offered list (wire format: <1-byte-len><bytes>...).
    unsigned int i = 0;
    while (i < inlen) {
        unsigned char n = in[i];
        if (n == 0 || n > inlen - i - 1) {
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        if (n == want_len && i + 1 + n <= inlen && memcmp(in + i + 1, want, want_len) == 0) {
            *out    = in + i + 1;
            *outlen = n;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1u + n;
    }
    // Preferred ALPN not offered – accept the first offered one (never reject).
    if (inlen > 0 && in[0] > 0) {
        *out    = in + 1;
        *outlen = in[0];
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

QuicTlsCtx::QuicTlsCtx(const Config& config, Role role)
    : m_ctx(nullptr), m_role(role), m_alpn_token(config.get_quic().alpn_token) {

    m_ctx = SSL_CTX_new(TLS_method());

    if (!m_ctx) {
        _log_with_date_time("QuicTlsCtx: TLS context allocation failed", Log::FATAL);
        return;
    }

    int rc = 0;
    rc = role == Role::Server ? ngtcp2_crypto_boringssl_configure_server_context(m_ctx)
                              : ngtcp2_crypto_boringssl_configure_client_context(m_ctx);
    if (rc != 0) {
        _log_with_date_time("QuicTlsCtx: ngtcp2 TLS context configuration failed", Log::FATAL);
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return;
    }

    // Load certificates and keys.
    if (!reload_cert(config)) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return;
    }

    const auto& ssl_cfg = config.get_ssl();

    // Cipher suites (TLS 1.3 names).
    try {
        configure_boringssl_tls13(m_ctx, ssl_cfg.cipher_tls13);
    } catch (...) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        throw;
    }

    // Elliptic curves.
    if (!ssl_cfg.curves.empty() && SSL_CTX_set1_groups_list(m_ctx, ssl_cfg.curves.c_str()) != 1) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        throw std::invalid_argument("Invalid TLS curve list");
    }

    _log_with_date_time("QuicTlsCtx: initialized (role=" +
                            tp::string(role == Role::Server ? "server" : "client") +
                            ", alpn=" + m_alpn_token + ")",
                        Log::INFO);
}

QuicTlsCtx::~QuicTlsCtx() {
    if (m_ctx) {
        SSL_CTX_free(m_ctx);
    }
}

bool QuicTlsCtx::reload_cert(const Config& config) {
    if (!m_ctx) {
        return false;
    }

    const auto& ssl_cfg = config.get_ssl();
    if (m_alpn_token.empty() || m_alpn_token.size() > 255 ||
        m_alpn_token.find('\0') != tp::string::npos) {
        _log_with_date_time("QuicTlsCtx: ALPN token must contain 1 to 255 bytes", Log::ERROR);
        return false;
    }

    if (m_role == Role::Server) {
        // Load certificate chain and private key.
        if (!ssl_cfg.cert.empty() && !ssl_cfg.key.empty()) {
            if (SSL_CTX_use_certificate_chain_file(m_ctx, ssl_cfg.cert.c_str()) != 1) {
                _log_with_date_time("QuicTlsCtx: failed to load certificate: " + ssl_cfg.cert, Log::ERROR);
                return false;
            }
            if (SSL_CTX_use_PrivateKey_file(m_ctx, ssl_cfg.key.c_str(), SSL_FILETYPE_PEM) != 1) {
                _log_with_date_time("QuicTlsCtx: failed to load private key: " + ssl_cfg.key, Log::ERROR);
                return false;
            }
            _log_with_date_time("QuicTlsCtx: server certificate and key loaded", Log::INFO);
        }
        
        // ALPN select callback – never rejects, prefers our configured token.
        // m_alpn_token is kept alive as long as QuicTlsCtx exists.
        SSL_CTX_set_alpn_select_cb(m_ctx, alpn_select_cb,
                                   const_cast<char*>(m_alpn_token.c_str()));
    
    } else {
        // Client: Certificate verification and CA locations.
        if (!ssl_cfg.verify) {
            SSL_CTX_set_verify(m_ctx, SSL_VERIFY_NONE, nullptr);
        } else {
            SSL_CTX_set_default_verify_paths(m_ctx);
            if (!ssl_cfg.cert.empty()) {
                if (SSL_CTX_load_verify_locations(m_ctx, ssl_cfg.cert.c_str(), nullptr) != 1) {
                    _log_with_date_time("QuicTlsCtx: failed to load verify locations: " + ssl_cfg.cert, Log::ERROR);
                    return false;
                }
            }
            SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);
        }

        // Client: advertise the configured ALPN token as a wire-encoded list.
        if (!m_alpn_token.empty() && m_alpn_token.size() <= 255) {
            auto len = static_cast<uint8_t>(m_alpn_token.size());
            tp::vector<uint8_t> wire(1 + len);
            wire[0] = len;
            memcpy(wire.data() + 1, m_alpn_token.c_str(), len);
            if (SSL_CTX_set_alpn_protos(m_ctx, wire.data(), 1u + len) != 0) {
                _log_with_date_time("QuicTlsCtx: failed to configure ALPN", Log::ERROR);
                return false;
            }
        }
        _log_with_date_time("QuicTlsCtx: client verification and ALPN settings updated", Log::INFO);
    }

    return true;
}

SSL* QuicTlsCtx::create_ssl() const {
    if (!m_ctx) {
        return nullptr;
    }
    SSL* ssl = SSL_new(m_ctx);
    if (!ssl) {
        _log_with_date_time("QuicTlsCtx::create_ssl: TLS handle allocation failed", Log::ERROR);
        return nullptr;
    }
    // QUIC v1 transport parameters use extension 0x39.
    SSL_set_quic_use_legacy_codepoint(ssl, 0);

    if (m_role == Role::Server) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
    }
    return ssl;
}
