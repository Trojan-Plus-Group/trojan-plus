// Production lwip_tcp_client close callback vs TUNLocalSession::destroy.
// Owner drops the client while the session still lives, then destroy() runs.
// Unfixed: session close callback calls close_client on zeroed storage (field fault).
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <openssl/ssl.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#include "core/log.h"
#include "core/service.h"
#include "tun/lwip_tcp_client.h"
#include "tun/tunlocalsession.h"
#include "tun/tunproxysession.h"
#include "tun/udplocalforwarder.h"

void tcp_arg(struct tcp_pcb*, void*) {}
void tcp_err(struct tcp_pcb*, tcp_err_fn) {}
void tcp_recv(struct tcp_pcb*, tcp_recv_fn) {}
void tcp_sent(struct tcp_pcb*, tcp_sent_fn) {}
err_t tcp_close(struct tcp_pcb*) { return ERR_OK; }
void tcp_abort(struct tcp_pcb*) {}
void tcp_recved(struct tcp_pcb*, u16_t) {}
err_t tcp_write(struct tcp_pcb*, const void*, u16_t, u8_t) { return ERR_OK; }
err_t tcp_output(struct tcp_pcb*) { return ERR_OK; }
u16_t pbuf_copy_partial(const struct pbuf*, void*, u16_t, u16_t) { return 0; }
u8_t pbuf_free(struct pbuf*) { return 0; }

// BoringSSL headers vs the container's system libssl.
extern "C" int SSL_CTX_set_min_proto_version(SSL_CTX*, uint16_t) { return 1; }
extern "C" int SSL_CTX_set_max_proto_version(SSL_CTX*, uint16_t) { return 1; }
extern "C" const SSL_METHOD* SSLv23_method(void) { return TLS_method(); }
extern "C" const SSL_METHOD* SSLv23_client_method(void) { return TLS_method(); }
extern "C" const SSL_METHOD* SSLv23_server_method(void) { return TLS_method(); }
extern "C" uint32_t SSL_set_mode(SSL*, uint32_t mode) { return mode; }
extern "C" size_t BIO_wpending(const BIO*) { return 0; }

void android_protect_socket(int) {}

// TCP lifetime path never constructs one. Symbol kept because TUNLocalSession::start is virtual.
UDPLocalForwarder::UDPLocalForwarder(Service* service, boost::asio::ip::udp::endpoint local_recv,
  boost::asio::ip::udp::endpoint remote_dst, UDPForwardSession::UDPWriter&& writer, bool is_dns)
    : Session(service, service->get_config()), m_service(service), m_writer(std::move(writer)),
      m_local_src(std::move(local_recv)), m_remote_dst(std::move(remote_dst)),
      m_udp_socket(service->get_io_context()), m_is_dns(is_dns) {}
void UDPLocalForwarder::start() {}
void UDPLocalForwarder::destroy(bool) {}
bool UDPLocalForwarder::process(const boost::asio::ip::udp::endpoint&, const std::string_view&) { return false; }

Service::Service(Config& cfg, bool) : socket_acceptor(io_context), ssl_context(boost::asio::ssl::context::sslv23),
                                       udp_socket(io_context), pipeline_select_idx(0), config(cfg) {}

Service::~Service() = default;

namespace {

tcp_pcb make_pcb() {
    tcp_pcb pcb{};
    IP_ADDR4(&pcb.local_ip, 1, 2, 3, 4);
    pcb.local_port = 80;
    IP_ADDR4(&pcb.remote_ip, 10, 0, 0, 1);
    pcb.remote_port = 40000;
    return pcb;
}

void normal_path(Service& service) {
    auto session = std::make_shared<TUNLocalSession>(&service, false);
    tcp_pcb pcb = make_pcb();
    std::shared_ptr<lwip_tcp_client> client;
    bool owner_called = false;
    client = std::shared_ptr<lwip_tcp_client>(new lwip_tcp_client(&pcb, session, [&](lwip_tcp_client*) {
        owner_called = true;
        client.reset();
    }));
    session->destroy();
    if (!owner_called || !session->is_destroyed()) {
        std::cerr << "normal path did not run production close callback\n";
        std::exit(2);
    }
    std::cerr << "normal-path-ok\n";
}

void stale_path(Service& service) {
    auto session = std::make_shared<TUNLocalSession>(&service, false);
    tcp_pcb pcb = make_pcb();
    alignas(lwip_tcp_client) unsigned char storage[sizeof(lwip_tcp_client)];
    auto* raw = new (storage) lwip_tcp_client(&pcb, session, [](lwip_tcp_client*) {});
    std::shared_ptr<lwip_tcp_client> client(raw, [](lwip_tcp_client* p) {
        p->~lwip_tcp_client();
        std::memset(p, 0, sizeof(lwip_tcp_client));
    });
    client.reset();
    std::cerr << "stale-destroy-begin\n";
    session->destroy();
    std::cerr << "stale-destroy-ok\n";
    if (!session->is_destroyed()) {
        std::cerr << "session destroy skipped\n";
        std::exit(3);
    }
}

void stale_proxy_path(Service& service) {
    auto session = std::make_shared<TUNProxySession>(&service, false);
    tcp_pcb pcb = make_pcb();
    alignas(lwip_tcp_client) unsigned char storage[sizeof(lwip_tcp_client)];
    auto* raw = new (storage) lwip_tcp_client(&pcb, session, [](lwip_tcp_client*) {});
    std::shared_ptr<lwip_tcp_client> client(raw, [](lwip_tcp_client* p) {
        p->~lwip_tcp_client();
        std::memset(p, 0, sizeof(lwip_tcp_client));
    });
    client.reset();
    std::cerr << "proxy-stale-destroy-begin\n";
    session->destroy();
    std::cerr << "proxy-stale-destroy-ok\n";
    if (!session->is_destroyed()) {
        std::cerr << "proxy session destroy skipped\n";
        std::exit(4);
    }
}

} // namespace

int main(int argc, char** argv) {
    Log::level = Log::OFF;
    Config config;
    Service service(config, true);
    const std::string which = argc > 1 ? argv[1] : "all";
    if (which == "all" || which == "local") {
        normal_path(service);
        stale_path(service);
    }
    if (which == "all" || which == "proxy") {
        stale_proxy_path(service);
    }
    std::cerr << "tun client lifetime: PASS\n";
    return 0;
}
