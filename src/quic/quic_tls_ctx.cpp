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

#include <ngtcp2/ngtcp2_crypto_wolfssl.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "core/log.h"

// Server ALPN select callback. We never reject: prefer the configured token
// (default "h3"), fall back to whatever the client offers first, so trojan
// traffic is indistinguishable from standard HTTP/3 at the TLS layer.
static int alpn_select_cb(WOLFSSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                          const unsigned char* in, unsigned int inlen, void* arg) {
    const auto* want     = static_cast<const char*>(arg);
    auto        want_len = static_cast<unsigned char>(strlen(want));

    // Walk client-offered list (wire format: <1-byte-len><bytes>...).
    unsigned int i = 0;
    while (i < inlen) {
        unsigned char n = in[i];
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
    // Nothing offered – still succeed (empty negotiation).
    return SSL_TLSEXT_ERR_OK;
}

QuicTlsCtx::QuicTlsCtx(const Config& config, Role role)
    : m_ctx(nullptr), m_role(role), m_alpn_token(config.get_quic().alpn_token) {

    if (role == Role::Server) {
        m_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    } else {
        m_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    }

    if (!m_ctx) {
        _log_with_date_time("QuicTlsCtx: wolfSSL_CTX_new failed", Log::FATAL);
        return;
    }

    int rc = 0;
    if (role == Role::Server) {
        rc = ngtcp2_crypto_wolfssl_configure_server_context(m_ctx);
    } else {
        rc = ngtcp2_crypto_wolfssl_configure_client_context(m_ctx);
    }
    if (rc != 0) {
        _log_with_date_time("QuicTlsCtx: ngtcp2_crypto_wolfssl_configure_*_context failed", Log::FATAL);
        wolfSSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return;
    }

    // Load certificates and keys.
    if (!reload_cert(config)) {
        wolfSSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return;
    }

    const auto& ssl_cfg = config.get_ssl();

    // Cipher suites (TLS 1.3 names).
    if (!ssl_cfg.cipher_tls13.empty()) {
        wolfSSL_CTX_set_cipher_list(m_ctx, ssl_cfg.cipher_tls13.c_str());
    }

    // Elliptic curves.
    if (!ssl_cfg.curves.empty()) {
        wolfSSL_CTX_set1_groups_list(m_ctx, const_cast<char*>(ssl_cfg.curves.c_str()));
    }

    _log_with_date_time("QuicTlsCtx: initialized (role=" +
                            tp::string(role == Role::Server ? "server" : "client") +
                            ", alpn=" + m_alpn_token + ")",
                        Log::INFO);
}

QuicTlsCtx::~QuicTlsCtx() {
    if (m_ctx) {
        wolfSSL_CTX_free(m_ctx);
    }
}

bool QuicTlsCtx::reload_cert(const Config& config) {
    if (!m_ctx) {
        return false;
    }

    const auto& ssl_cfg = config.get_ssl();

    if (m_role == Role::Server) {
        // Load certificate chain and private key.
        if (!ssl_cfg.cert.empty() && !ssl_cfg.key.empty()) {
            if (wolfSSL_CTX_use_certificate_chain_file(m_ctx, ssl_cfg.cert.c_str()) != WOLFSSL_SUCCESS) {
                _log_with_date_time("QuicTlsCtx: failed to load certificate: " + ssl_cfg.cert, Log::ERROR);
                return false;
            }
            if (wolfSSL_CTX_use_PrivateKey_file(m_ctx, ssl_cfg.key.c_str(), SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
                _log_with_date_time("QuicTlsCtx: failed to load private key: " + ssl_cfg.key, Log::ERROR);
                return false;
            }
            _log_with_date_time("QuicTlsCtx: server certificate and key loaded", Log::INFO);
        }
        
        // ALPN select callback – never rejects, prefers our configured token.
        // m_alpn_token is kept alive as long as QuicTlsCtx exists.
        wolfSSL_CTX_set_alpn_select_cb(m_ctx, alpn_select_cb,
                                       const_cast<char*>(m_alpn_token.c_str()));
    
    } else {
        // Client: Certificate verification and CA locations.
        if (!ssl_cfg.verify) {
            wolfSSL_CTX_set_verify(m_ctx, WOLFSSL_VERIFY_NONE, nullptr);
        } else {
            wolfSSL_CTX_set_default_verify_paths(m_ctx);
            if (!ssl_cfg.cert.empty()) {
                if (wolfSSL_CTX_load_verify_locations(m_ctx, ssl_cfg.cert.c_str(), nullptr) != WOLFSSL_SUCCESS) {
                    _log_with_date_time("QuicTlsCtx: failed to load verify locations: " + ssl_cfg.cert, Log::ERROR);
                    return false;
                }
            }
            wolfSSL_CTX_set_verify(m_ctx, WOLFSSL_VERIFY_PEER, nullptr);
        }

        // Client: advertise the configured ALPN token as a wire-encoded list.
        if (!m_alpn_token.empty() && m_alpn_token.size() <= 255) {
            auto len = static_cast<uint8_t>(m_alpn_token.size());
            tp::vector<uint8_t> wire(1 + len);
            wire[0] = len;
            memcpy(wire.data() + 1, m_alpn_token.c_str(), len);
            wolfSSL_CTX_set_alpn_protos(m_ctx, wire.data(), 1u + len);
        }
        _log_with_date_time("QuicTlsCtx: client verification and ALPN settings updated", Log::INFO);
    }

    return true;
}

WOLFSSL* QuicTlsCtx::create_ssl() const {
    if (!m_ctx) {
        return nullptr;
    }
    WOLFSSL* ssl = wolfSSL_new(m_ctx);
    if (!ssl) {
        _log_with_date_time("QuicTlsCtx::create_ssl: wolfSSL_new failed", Log::ERROR);
        return nullptr;
    }
    // QUIC v1 transport version extension (0x39 = 57 = QUIC v1).
    wolfSSL_set_quic_transport_version(ssl, 0x39);

    if (m_role == Role::Server) {
        wolfSSL_set_accept_state(ssl);
    } else {
        wolfSSL_set_connect_state(ssl);
    }
    return ssl;
}
