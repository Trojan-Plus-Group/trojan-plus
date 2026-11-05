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
#include "ssl/chrome_profile.h"

#include "core/log.h"

// RFC 9001 requires a shared ALPN: reject unrelated protocols like nginx.
// Keep the configured token for older/custom clients, plus standard HTTP/3.
static int alpn_select_cb(SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                          const unsigned char* in, unsigned int inlen, void* arg) {
    const auto* want     = static_cast<const char*>(arg);
    auto        want_len = static_cast<unsigned char>(strlen(want));

    // Walk client-offered list (wire format: <1-byte-len><bytes>...).
    const unsigned char* preferred = nullptr;
    const unsigned char* h3 = nullptr;
    unsigned int i = 0;
    while (i < inlen) {
        unsigned char n = in[i];
        if (n == 0 || n > inlen - i - 1) {
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        if (n == want_len && memcmp(in + i + 1, want, want_len) == 0) {
            preferred = in + i + 1;
        }
        if (n == 2 && memcmp(in + i + 1, "h3", 2) == 0) {
            h3 = in + i + 1;
        }
        i += 1u + n;
    }
    if (preferred || h3) {
        *out = preferred ? preferred : h3;
        *outlen = preferred ? want_len : 2;
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

QuicTlsCtx::QuicTlsCtx(const Config& config, Role role)
    : m_ctx(nullptr), m_role(role),
      m_alpn_token(config.get_quic().alpn_token),
      m_chrome(role == Role::Client && config.get_ssl().fingerprint == "chrome"), m_curves(config.get_ssl().curves) {

    m_ctx = SSL_CTX_new(TLS_method());

    if (!m_ctx) {
        _log_with_date_time("QuicTlsCtx: TLS context allocation failed", Log::FATAL);
        return;
    }

    // Constructor exceptions must not leak the raw context.
    bssl::UniquePtr<SSL_CTX> context_guard(m_ctx);
    int rc = 0;
    rc = role == Role::Server ? ngtcp2_crypto_boringssl_configure_server_context(m_ctx)
                              : ngtcp2_crypto_boringssl_configure_client_context(m_ctx);
    if (rc != 0) {
        _log_with_date_time("QuicTlsCtx: ngtcp2 TLS context configuration failed", Log::FATAL);
        m_ctx = nullptr;
        return;
    }

    const auto& ssl_cfg = config.get_ssl();

    if (m_chrome) {
        tp::configure_chrome_context(m_ctx, tp::ChromeTransport::Quic, ssl_cfg.cipher,
                                     ssl_cfg.cipher_tls13, ssl_cfg.curves);
    } else {
        configure_boringssl_tls13(m_ctx, ssl_cfg.cipher_tls13.empty() && role == Role::Server ?
          tp::string("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") : ssl_cfg.cipher_tls13);
        if (!ssl_cfg.cipher.empty() && SSL_CTX_set_cipher_list(m_ctx, ssl_cfg.cipher.c_str()) != 1) {
            throw std::invalid_argument("Invalid TLS cipher list");
        }
        if (!ssl_cfg.curves.empty() && SSL_CTX_set1_groups_list(m_ctx, ssl_cfg.curves.c_str()) != 1) {
            throw std::invalid_argument("Invalid TLS curve list");
        }
    }

    // Apply ALPN after the Chrome profile, which otherwise replaces it with h3.
    if (!reload_cert(config)) {
        m_ctx = nullptr;
        return;
    }

    _log_with_date_time("QuicTlsCtx: initialized (role=" +
                            tp::string(role == Role::Server ? "server" : "client") +
                            ", alpn=" + m_alpn_token + ")",
                        Log::INFO);
    context_guard.release();
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
        
        // Reject unsupported ALPNs; prefer our configured token over h3.
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
    bssl::UniquePtr<SSL> ssl_guard(ssl);
    if (m_chrome && m_role == Role::Client) {
        tp::configure_chrome_ssl(ssl, tp::ChromeTransport::Quic, m_curves);
    }
    // QUIC v1 transport parameters use extension 0x39.
    SSL_set_quic_use_legacy_codepoint(ssl, 0);

    if (m_role == Role::Server) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
    }
    return ssl_guard.release();
}
