// Run through tests/check_chrome_profile.py; no public network or credentials.
#include "ssl/chrome_profile.h"

#include <brotli/encode.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

namespace {
void require(bool ok, const char *message) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        ERR_print_errors_fp(stderr);
        std::exit(1);
    }
}

enum class Encoding { Valid, Invalid, ShortOutput };
Encoding encoding;
unsigned compressions;
unsigned compressed_messages;

int compress_certificate(SSL *, CBB *out, const uint8_t *input, size_t size) {
    ++compressions;
    if (encoding == Encoding::Invalid) {
        const uint8_t invalid[] = {0xff, 0xff, 0xff};
        return CBB_add_bytes(out, invalid, sizeof(invalid));
    }
    // Keep TLS's declared uncompressed size unchanged; decoder must reject mismatch.
    if (encoding == Encoding::ShortOutput) {
        require(size > 0, "empty certificate message");
        --size;
    }
    std::vector<uint8_t> output(BrotliEncoderMaxCompressedSize(size));
    size_t length = output.size();
    if (!BrotliEncoderCompress(5, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC,
                              size, input, &length, output.data())) {
        return 0;
    }
    return CBB_add_bytes(out, output.data(), length);
}

void message(int write, int, int content_type, const void *buffer, size_t length,
             SSL *, void *) {
    if (write && content_type == SSL3_RT_HANDSHAKE && length > 0 &&
        static_cast<const uint8_t *>(buffer)[0] == 25) {
        ++compressed_messages; // RFC 8879 compressed_certificate handshake message.
    }
}

int password(char *buffer, int size, int, void *) {
    constexpr char fixture_password[] = "123456";
    if (size < static_cast<int>(sizeof(fixture_password))) {
        return 0;
    }
    std::memcpy(buffer, fixture_password, sizeof(fixture_password));
    return sizeof(fixture_password) - 1;
}

// Memory BIO pairs exercise real TLS records, encryption, and production decoder.
void handshake(const char *certificate, const char *key, Encoding mode) {
    encoding = mode;
    compressions = compressed_messages = 0;
    bssl::UniquePtr<SSL_CTX> server(SSL_CTX_new(TLS_method()));
    bssl::UniquePtr<SSL_CTX> client(SSL_CTX_new(TLS_method()));
    require(server && client, "create contexts");
    require(SSL_CTX_set_min_proto_version(server.get(), TLS1_3_VERSION) &&
            SSL_CTX_set_max_proto_version(server.get(), TLS1_3_VERSION), "server TLS 1.3");
    SSL_CTX_set_default_passwd_cb(server.get(), password);
    require(SSL_CTX_use_certificate_chain_file(server.get(), certificate) == 1 &&
            SSL_CTX_use_PrivateKey_file(server.get(), key, SSL_FILETYPE_PEM) == 1 &&
            SSL_CTX_check_private_key(server.get()) == 1, "load fixture certificate/key");
    require(SSL_CTX_add_cert_compression_alg(server.get(), 2, compress_certificate, nullptr) == 1,
            "register server Brotli compressor");
    SSL_CTX_set_msg_callback(server.get(), message);

    tp::configure_chrome_context(client.get(), tp::ChromeTransport::Tcp);
    SSL_CTX_set_verify(client.get(), SSL_VERIFY_PEER, nullptr);
    require(SSL_CTX_load_verify_locations(client.get(), certificate, nullptr) == 1,
            "trust fixture certificate");
    bssl::UniquePtr<SSL> peer(SSL_new(server.get()));
    bssl::UniquePtr<SSL> local(SSL_new(client.get()));
    require(peer && local, "create TLS peers");
    tp::configure_chrome_ssl(local.get(), tp::ChromeTransport::Tcp);
    require(SSL_set_tlsext_host_name(local.get(), "yuchting") == 1 &&
            SSL_set1_host(local.get(), "yuchting") == 1, "fixture hostname");
    BIO *server_bio = nullptr;
    BIO *client_bio = nullptr;
    require(BIO_new_bio_pair(&server_bio, 0, &client_bio, 0) == 1, "memory BIO pair");
    SSL_set_bio(peer.get(), server_bio, server_bio);
    SSL_set_bio(local.get(), client_bio, client_bio);
    SSL_set_accept_state(peer.get());
    SSL_set_connect_state(local.get());

    bool server_done = false;
    bool client_done = false;
    bool client_failed = false;
    for (unsigned step = 0; step < 100 && !client_failed && !(server_done && client_done); ++step) {
        for (SSL *ssl : {local.get(), peer.get()}) {
            bool &done = ssl == local.get() ? client_done : server_done;
            if (done) {
                continue;
            }
            const int result = SSL_do_handshake(ssl);
            if (result == 1) {
                done = true;
                continue;
            }
            const int error = SSL_get_error(ssl, result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
                if (ssl == local.get()) {
                    client_failed = true;
                    break;
                }
                require(false, "unexpected server handshake failure");
            }
        }
    }
    require(compressions == 1, "client advertised Brotli; server compressed exactly once");
    require(compressed_messages == 1, "server emitted real compressed_certificate message");
    if (mode == Encoding::Valid) {
        require(client_done && server_done && !client_failed, "compressed certificate handshake completes");
        require(SSL_get_verify_result(local.get()) == X509_V_OK, "fixture certificate verified");
        const char payload[] = "compressed-certificate-ok";
        require(SSL_write(local.get(), payload, sizeof(payload)) == sizeof(payload), "TLS application write");
        char received[sizeof(payload)];
        require(SSL_read(peer.get(), received, sizeof(received)) == sizeof(received) &&
                std::memcmp(received, payload, sizeof(payload)) == 0, "TLS application round trip");
    } else {
        require(client_failed && !client_done, "malformed compressed certificate rejected by client");
    }
    ERR_clear_error();
}
} // namespace

int main(int argc, char **argv) {
    if (argc == 5 && std::strcmp(argv[1], "--host") == 0 &&
        std::strcmp(argv[3], "--ca") == 0) {
        bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_method()));
        require(context != nullptr, "external TLS context");
        tp::configure_chrome_context(context.get(), tp::ChromeTransport::Tcp);
        SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
        require(SSL_CTX_load_verify_locations(context.get(), argv[4], nullptr) == 1,
                "load supplied CA bundle");
        bssl::UniquePtr<SSL> ssl(SSL_new(context.get()));
        require(ssl != nullptr, "external TLS handle");
        tp::configure_chrome_ssl(ssl.get(), tp::ChromeTransport::Tcp);
        require(SSL_set_tlsext_host_name(ssl.get(), argv[2]) == 1 &&
                SSL_set1_host(ssl.get(), argv[2]) == 1, "external verified hostname");
        bssl::UniquePtr<BIO> connection(BIO_new_connect(argv[2]));
        require(connection && BIO_set_conn_port(connection.get(), "443") == 1 &&
                BIO_do_connect(connection.get()) == 1, "external TCP connect");
        SSL_set_bio(ssl.get(), connection.get(), connection.get());
        connection.release();
        require(SSL_connect(ssl.get()) == 1 && SSL_get_verify_result(ssl.get()) == X509_V_OK,
                "external TLS handshake and certificate/hostname verification");
        std::printf("PASS verified TLS-only handshake %s:443 %s %s; no application data sent\n",
                    argv[2], SSL_get_version(ssl.get()), SSL_CIPHER_get_name(SSL_get_current_cipher(ssl.get())));
        return 0;
    }
    require(argc == 3, "usage: check_chrome_profile CERTIFICATE PRIVATE_KEY | --host HOST --ca CA_FILE");
    handshake(argv[1], argv[2], Encoding::Valid);
    std::puts("PASS real TLS 1.3 Brotli compressed certificate; verified certificate and payload");
    handshake(argv[1], argv[2], Encoding::Invalid);
    std::puts("PASS invalid Brotli compressed certificate rejected");
    handshake(argv[1], argv[2], Encoding::ShortOutput);
    std::puts("PASS wrong uncompressed certificate length rejected");
}
