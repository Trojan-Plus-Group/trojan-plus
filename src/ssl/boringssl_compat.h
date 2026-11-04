#pragma once

#include <openssl/ssl.h>
#include <stdexcept>
#include "mem/memallocator.h"

// BoringSSL uses protocol IDs instead of OpenSSL's TLS 1.3 cipher string API.
inline void configure_boringssl_tls13(SSL_CTX* ctx, const tp::string& names) {
    if (names.empty()) {
        return;
    }
    tp::vector<uint16_t> ids;
    size_t start = 0;
    do {
        const auto end = names.find(':', start);
        const auto name = names.substr(start, end == tp::string::npos ? end : end - start);
        uint16_t id;
        if (name == "TLS_AES_128_GCM_SHA256") {
            id = 0x1301;
        } else if (name == "TLS_AES_256_GCM_SHA384") {
            id = 0x1302;
        } else if (name == "TLS_CHACHA20_POLY1305_SHA256") {
            id = 0x1303;
        } else {
            throw std::invalid_argument("Unsupported BoringSSL TLS 1.3 cipher: " + std::string(name.c_str()));
        }
        ids.push_back(id);
        if (end == tp::string::npos) {
            break;
        }
        start = end + 1;
    } while (true);
    if (SSL_CTX_set1_tls13_ciphers(ctx, ids.data(), nullptr, ids.size()) != 1) {
        throw std::invalid_argument("Invalid BoringSSL TLS 1.3 cipher list");
    }
}
