// Production lwip_tcp_client close callback vs TUNLocalSession::destroy.
// Owner drops the client while the session still lives, then destroy() runs.
// Unfixed: session close callback calls close_client on zeroed storage (field fault).
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <openssl/ssl.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <unistd.h>

#include "core/log.h"
#include "core/config.h"
#include "core/service.h"
#include "session/clientpadding.h"
#include "quic/outbound_transport.h"
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

// Padded write fails, legacy reconnect succeeds. Transports are fakes; the session is production code.
std::deque<std::function<void()>> g_tasks;
bool g_fail_first_write = true; // first transport fails its first write, or (false) only after fail_next is set

struct FakeTransport : OutboundTransport {
    bool fail_next;
    int reads = 0, closes = 0;
    IoHandler pending_read;
    std::string written;
    explicit FakeTransport(bool fail) : fail_next(fail) {}
    void async_connect(const tp::string&, uint16_t, std::function<void()> ok, std::function<void()>) override {
        g_tasks.push_back(std::move(ok));
    }
    void async_read_some(boost::asio::mutable_buffer, IoHandler handler) override {
        ++reads;
        pending_read = std::move(handler); // completes only through cancel()
    }
    void async_write(std::shared_ptr<ReadBufWithGuard> buf, IoHandler handler) override {
        written.append(buf->to_string_view());
        const auto ec = fail_next ? boost::asio::error::connection_reset : boost::system::error_code();
        g_tasks.push_back([handler, ec, n = buf->size()] { handler(ec, n); });
    }
    // Same semantics as the fixed QuicStreamTransport and as TLS (asio): a pending read is posted with
    // operation_aborted. Fake limit: this is test code, not the production QUIC transport.
    void cancel() override {
        if (pending_read) g_tasks.push_back([h = std::move(pending_read)] { h(boost::asio::error::operation_aborted, 0); });
        pending_read = nullptr;
    }
    void close() override { ++closes; }
    bool is_via_quic() const override { return false; }
};

std::vector<std::shared_ptr<FakeTransport>> g_transports;

[[noreturn]] void fail(const char* msg);
void drain_tasks() {
    size_t steps = 0;
    while (!g_tasks.empty()) {
        if (++steps > 100) fail("task loop did not settle");
        auto task = std::move(g_tasks.front());
        g_tasks.pop_front();
        task();
    }
}

} // namespace

std::shared_ptr<OutboundTransport> create_outbound_transport(boost::asio::io_context&, boost::asio::ssl::context&,
  const Config&, boost::asio::ip::tcp::endpoint, std::shared_ptr<QuicClientEndpoint>) {
    auto t = std::make_shared<FakeTransport>(g_transports.empty() && g_fail_first_write); // only the first (padded) attempt fails
    g_transports.push_back(t);
    return t;
}

namespace {

// Config::password is private and config.cpp is not linked; write it through an explicit instantiation.
tp::map<tp::string, tp::string>& rob_password(Config&);
template <auto Member> struct RobPassword {
    friend tp::map<tp::string, tp::string>& rob_password(Config& c) { return c.*Member; }
};
template struct RobPassword<&Config::password>;

// ClientPadding memoizes the server capability process-wide; a legacy fallback in one scenario would
// disable padding in the next, so reset it per scenario.
tp::map<tp::string, bool>& (*rob_capabilities())();
template <auto Fn> struct RobCapabilities {
    friend tp::map<tp::string, bool>& (*rob_capabilities())() { return Fn; }
};
template struct RobCapabilities<&ClientPadding::capabilities>;

[[noreturn]] void fail(const char* msg) {
    std::cerr << "FAIL: " << msg << "\n";
    _exit(10);
}

void padding_retry_path() {
    rob_capabilities()().clear();
    Config config{};
    rob_password(config)["hash"] = "pw";
    Service service(config, true);
    auto session = std::make_shared<TUNProxySession>(&service, false);
    int u1 = 0, u2 = 0;
    auto count = [](int& n) {
        return [&n](boost::system::error_code ec) {
            // Unfixed code replays the start handler over the shared waiter list: unbounded re-entry.
            if (ec || ++n > 3) fail("user write handler error or re-entered");
        };
    };
    const char d1[] = "U1DATA", d2[] = "U2DATA";
    session->out_async_send((const uint8_t*)d1, 6, count(u1)); // queued before connect
    session->start();
    g_tasks.front()(); // transport 1 connects; padded start write is now in flight
    g_tasks.pop_front();
    session->out_async_send((const uint8_t*)d2, 6, count(u2)); // queued behind the start write
    size_t steps = 0;
    while (!g_tasks.empty()) {
        if (++steps > 100) fail("task loop did not settle");
        auto task = std::move(g_tasks.front());
        g_tasks.pop_front();
        task();
    }
    if (g_transports.size() != 2) fail("expected exactly one legacy reconnect");
    if (g_transports[0]->reads != 0 || g_transports[1]->reads != 1) fail("out_async_read not started exactly once");
    if (g_transports[0]->closes == 0) fail("padded transport not closed");
    if (u1 != 1 || u2 != 1) fail("pending write handlers must complete exactly once");
    const auto& legacy = g_transports[1]->written;
    if (legacy.find("U1DATA") == std::string::npos || legacy.find("U2DATA") == std::string::npos) fail("replay lost data");
    if (session->is_destroyed()) fail("session destroyed");
    session->destroy();
    drain_tasks(); // destroy() cancels the transport; run the aborted read completion before Service goes away
    g_transports.clear();
    std::cerr << "padding-retry-ok\n";
}

// First padded write succeeds and a read is in flight, then a later user write fails. retry_legacy() cancels the
// transport; the in-flight read must complete (operation_aborted) so reconnect_legacy() can continue.
void padding_retry_read_path() {
    g_fail_first_write = false;
    rob_capabilities()().clear();
    g_transports.clear();
    g_tasks.clear();
    Config config{};
    rob_password(config)["hash"] = "pw";
    Service service(config, true);
    auto session = std::make_shared<TUNProxySession>(&service, false);
    int u1 = 0, u2 = 0;
    auto count = [](int& n) { return [&n](boost::system::error_code ec) { if (ec || ++n > 3) { fail("user write handler error or re-entered"); } }; };
    auto drain = [] { drain_tasks(); };
    const char d1[] = "U1DATA", d2[] = "U2DATA";
    session->out_async_send((const uint8_t*)d1, 6, count(u1)); // queued before connect
    session->start();
    drain(); // connect, first padded write succeeds, read in flight
    if (g_transports.size() != 1 || g_transports[0]->reads != 1 || !g_transports[0]->pending_read) fail("read not in flight");
    if (u1 != 1) fail("first write handler must complete once");
    g_transports[0]->fail_next = true;
    session->out_async_send((const uint8_t*)d2, 6, count(u2)); // this write fails
    drain();
    if (g_transports.size() != 2) fail("expected exactly one legacy reconnect (stalled behind the read?)");
    if (g_transports[0]->closes == 0) fail("padded transport not closed");
    if (g_transports[1]->reads != 1) fail("out_async_read not restarted exactly once");
    if (u1 != 1 || u2 != 1) fail("user write handlers must complete exactly once");
    if (g_transports[1]->written.find("U2DATA") == std::string::npos) fail("replay lost data");
    if (session->is_destroyed()) fail("session destroyed");
    session->destroy(); // cancel() posts the in-flight read's operation_aborted completion
    drain_tasks();      // it must not reconnect or destroy twice
    if (g_transports.size() != 2) fail("read aborted by destroy() triggered a reconnect");
    g_transports.clear();
    std::cerr << "padding-retry-read-ok\n";
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
    if (which == "all" || which == "padding_retry") {
        padding_retry_path();
    }
    if (which == "all" || which == "padding_retry_read") {
        padding_retry_read_path();
    }
    std::cerr << "tun client lifetime: PASS\n";
    return 0;
}
