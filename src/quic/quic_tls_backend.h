/*
 * This file is part of the Trojan Plus project.
 * Copyright (C) 2026 The Trojan Plus Group Authors.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef _QUIC_TLS_BACKEND_H_
#define _QUIC_TLS_BACKEND_H_

#ifdef TROJAN_USE_BORINGSSL
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
using QuicSsl = SSL;
using QuicSslCtx = SSL_CTX;
#define TP_QUIC_TLS(name) SSL_##name
#else
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
using QuicSsl = WOLFSSL;
using QuicSslCtx = WOLFSSL_CTX;
#define TP_QUIC_TLS(name) wolfSSL_##name
#endif

inline int quic_random_bytes(unsigned char* dest, int len) {
#ifdef TROJAN_USE_BORINGSSL
    return RAND_bytes(dest, len);
#else
    return wolfSSL_RAND_bytes(dest, len);
#endif
}

#endif // _QUIC_TLS_BACKEND_H_
