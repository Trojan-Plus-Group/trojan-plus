#include "chrome_profile.h"

#include <brotli/decode.h>
#include <openssl/pool.h>
#include <cstddef>
#include <stdexcept>

#include "boringssl_compat.h"

namespace {
constexpr size_t certificate_limit = 16 * 1024 * 1024;
constexpr size_t decoder_limit = 32 * 1024 * 1024;
struct DecoderBudget { size_t used = 0; };
struct alignas(std::max_align_t) Allocation { size_t size; };

void* decoder_alloc(void* opaque, size_t size) noexcept {
    auto& budget = *static_cast<DecoderBudget*>(opaque);
    if (size > decoder_limit - budget.used || size > SIZE_MAX - sizeof(Allocation)) {
        return nullptr;
    }
    try {
        auto* block = static_cast<Allocation*>(TP_MALLOC(sizeof(Allocation) + size));
        if (!block) {
            return nullptr;
        }
        block->size = size;
        budget.used += size;
        return block + 1;
    } catch (...) {
        return nullptr;
    }
}
void decoder_free(void* opaque, void* ptr) noexcept {
    if (ptr) {
        auto* block = static_cast<Allocation*>(ptr) - 1;
        static_cast<DecoderBudget*>(opaque)->used -= block->size;
        TP_FREE(block);
    }
}
void require(bool ok) {
    if (!ok) {
        throw std::runtime_error("Failed to configure Chrome TLS profile");
    }
}

// Public Chrome 156 advertisements from chrome_tcp_1.pcap. Not a trust store.
constexpr uint8_t anchors[] = {
    0x05,0x82,0xdf,0x13,0x02,0x01,0x05,0x82,0xdf,0x13,0x02,0x06,
    0x05,0x82,0xdf,0x13,0x02,0x0d,0x05,0x82,0xdf,0x13,0x02,0x0e,
    0x05,0x82,0xdf,0x13,0x02,0x0f,0x05,0x82,0xdf,0x13,0x02,0x12,
    0x05,0x82,0xdf,0x13,0x02,0x13,0x05,0x82,0xdf,0x13,0x02,0x14,
    0x08,0x83,0x9a,0x64,0x8c,0x9b,0x2d,0x01,0x07,
    0x08,0x83,0x9a,0x64,0x8c,0x9b,0x2d,0x01,0x08,
    0x08,0x83,0x9a,0x64,0x8c,0x9b,0x2d,0x01,0x09,
    0x08,0x83,0x9a,0x64,0x8c,0x9b,0x2d,0x01,0x0a,
    0x08,0x83,0x9a,0x64,0x8c,0x9b,0x2d,0x01,0x0b,
    0x08,0x83,0x9a,0x64,0x8c,0x9b,0x2d,0x01,0x0c,
    0x08,0x83,0x9a,0x64,0x8c,0x9b,0x2d,0x01,0x0d,
    0x08,0x83,0x9a,0x64,0x8c,0x9b,0x2d,0x01,0x12,
    0x08,0x83,0x9a,0x64,0x8c,0x9b,0x2d,0x01,0x13,
    0x04,0xd6,0x79,0x09,0x01,0x04,0xd6,0x79,0x09,0x04,
    0x04,0xd6,0x79,0x09,0x05,0x04,0xd6,0x79,0x09,0x06,
    0x04,0xd6,0x79,0x09,0x07,0x04,0xd6,0x79,0x09,0x08,
    0x04,0xd6,0x79,0x09,0x0a,0x04,0xd6,0x79,0x09,0x0b,
    0x04,0xd6,0x79,0x09,0x0c,0x04,0xd6,0x79,0x09,0x0d,
    0x04,0xd6,0x79,0x09,0x0f
};
static_assert(sizeof(anchors) == 184);
} // namespace

int tp::decompress_chrome_certificate(SSL*, CRYPTO_BUFFER** out, size_t n,
                                       const uint8_t* in, size_t len) noexcept {
    if (!out || !in || n == 0 || n > certificate_limit || len == 0 || len > certificate_limit) {
        return 0;
    }
    try {
        tp::vector<uint8_t> bytes(n);
        DecoderBudget budget;
        auto* decoder = BrotliDecoderCreateInstance(decoder_alloc, decoder_free, &budget);
        if (!decoder) {
            return 0;
        }
        size_t available_in = len, available_out = n;
        const uint8_t* next_in = in;
        uint8_t* next_out = bytes.data();
        const auto result = BrotliDecoderDecompressStream(decoder, &available_in, &next_in,
                                                          &available_out, &next_out, nullptr);
        BrotliDecoderDestroyInstance(decoder);
        if (result != BROTLI_DECODER_RESULT_SUCCESS || available_in != 0 || available_out != 0) {
            return 0;
        }
        auto* buffer = CRYPTO_BUFFER_new(bytes.data(), bytes.size(), nullptr);
        if (!buffer) {
            return 0;
        }
        *out = buffer;
        return 1;
    } catch (...) {
        return 0;
    }
}

void tp::configure_chrome_context(SSL_CTX* ctx, ChromeTransport transport, const tp::string& cipher,
                                  const tp::string& cipher_tls13, const tp::string& curves) {
    const bool tcp = transport == ChromeTransport::Tcp;
    SSL_CTX_set_grease_enabled(ctx, tcp);
    SSL_CTX_set_permute_extensions(ctx, 1);
    if (tcp) {
        SSL_CTX_enable_signed_cert_timestamps(ctx);
        SSL_CTX_enable_ocsp_stapling(ctx);
    }
    require(SSL_CTX_set_strict_cipher_list(ctx, cipher.empty() ?
      "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:AES128-SHA:AES256-SHA" : cipher.c_str()) == 1);
    configure_boringssl_tls13(ctx, cipher_tls13.empty() ?
      tp::string("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") : cipher_tls13);
    require(SSL_CTX_set1_groups_list(ctx, curves.empty() ? "X25519MLKEM768:X25519:P-256:P-384" : curves.c_str()) == 1);
    const uint16_t tcp_sigs[] = {0x0904,0x0905,0x0906,0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601};
    const uint16_t quic_sigs[] = {0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0806,0x0601,0x0201};
    require(SSL_CTX_set_verify_algorithm_prefs(ctx, tcp ? tcp_sigs : quic_sigs,
                                               tcp ? sizeof(tcp_sigs)/sizeof(uint16_t) : sizeof(quic_sigs)/sizeof(uint16_t)) == 1);
    require(SSL_CTX_add_cert_compression_alg(ctx, 2, nullptr, decompress_chrome_certificate) == 1);
    require(SSL_CTX_set1_requested_trust_anchors(ctx, anchors, sizeof(anchors)) == 1);
    const uint8_t tcp_alpn[] = {2,'h','2',8,'h','t','t','p','/','1','.','1'};
    const uint8_t quic_alpn[] = {2,'h','3'};
    require(SSL_CTX_set_alpn_protos(ctx, tcp ? tcp_alpn : quic_alpn,
                                   tcp ? sizeof(tcp_alpn) : sizeof(quic_alpn)) == 0);
    // Advertising tickets does not cache or restore sessions.
    SSL_CTX_clear_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
}

void tp::configure_chrome_ssl(SSL* ssl, ChromeTransport transport, const tp::string& curves) {
    const bool tcp = transport == ChromeTransport::Tcp;
    require(SSL_add_application_settings(ssl, reinterpret_cast<const uint8_t*>(tcp ? "h2" : "h3"),
                                          2, nullptr, 0) == 1);
    SSL_set_alps_use_new_codepoint(ssl, 1);
    SSL_set_enable_ech_grease(ssl, 1);
    if (curves.empty()) {
        const uint16_t shares[] = {0x11ec, 29};
        require(SSL_set1_client_key_shares(ssl, shares, 2) == 1);
    }
}
