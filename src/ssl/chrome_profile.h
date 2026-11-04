#pragma once

#include <openssl/ssl.h>
#include "mem/memallocator.h"

namespace tp {
enum class ChromeTransport { Tcp, Quic };

// Apply only to fresh client contexts/handles when ssl.fingerprint == "chrome".
// Explicit policy overrides take precedence; verification is never changed.
void configure_chrome_context(SSL_CTX* ctx, ChromeTransport transport, const tp::string& cipher = {},
                              const tp::string& cipher_tls13 = {}, const tp::string& curves = {});
void configure_chrome_ssl(SSL* ssl, ChromeTransport transport, const tp::string& curves = {});

// RFC 8879 Brotli decoder. Failure never transfers ownership to the caller.
int decompress_chrome_certificate(SSL* ssl, CRYPTO_BUFFER** out, size_t uncompressed_len,
                                  const uint8_t* in, size_t in_len) noexcept;
} // namespace tp
