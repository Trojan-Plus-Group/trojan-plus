// Real UDP sockets, TLS/ngtcp2, endpoint queues and connection lifetimes.
// Access changes are confined to this test translation unit.
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include "core/config.h"
#include "core/utils.h"
#include "mem/memallocator.h"
#include "quic/quic_tls_ctx.h"
#include "quic/quic_stream_handler.h"
#include "quic/quic_clock.h"
#include <quic_stats_config.h>
#include "quic/quic_stats.h"
#include "quic/quic_udp_gso.h"
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/sha.h>
#define private public
#define protected public
#include "quic/quic_client_endpoint.h"
#undef protected
#undef private

using Udp = boost::asio::ip::udp;
using Connection = std::shared_ptr<QuicConnection>;
static void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
static void until(boost::asio::io_context& io, const std::function<bool()>& ready) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!ready()) {
        require(std::chrono::steady_clock::now() < deadline, "runtime test deadline");
        io.restart();
        io.run_for(std::chrono::milliseconds(2));
    }
}
static void poll(boost::asio::io_context& io) { io.restart(); io.poll(); }

class Endpoint : public QuicEndpoint {
  public:
    using QuicEndpoint::QuicEndpoint;
    std::vector<Connection> connections;
    std::weak_ptr<QuicConnection> failed_connection;
    unsigned crypto_failures{0};
    void start() override {
        open_socket(Udp::endpoint(boost::asio::ip::address_v4::loopback(), 0), false);
        m_running = true;
        async_recv();
    }
    Connection client(const Udp::endpoint& peer) {
        auto conn = std::make_shared<QuicConnection>(*this, m_tls_ctx, peer);
        connections.push_back(conn);
        require(conn->init_client(local_endpoint(), peer), "init_client");
        return conn;
    }
    void on_packet(const uint8_t* data, std::size_t len, const Udp::endpoint& src) override {
        for (const auto& conn : connections) {
            if (conn->peer() == src) {
                conn->on_packet(data, len, local_endpoint(), src);
                return;
            }
        }
        ngtcp2_version_cid vc{};
        require(ngtcp2_pkt_decode_version_cid(&vc, data, len, 18) == 0, "decode Initial");
        ngtcp2_cid dcid{}, scid{};
        dcid.datalen = vc.dcidlen;
        scid.datalen = vc.scidlen;
        std::copy_n(vc.dcid, vc.dcidlen, dcid.data);
        std::copy_n(vc.scid, vc.scidlen, scid.data);
        auto conn = std::make_shared<QuicConnection>(*this, m_tls_ctx, src);
        if (conn->init_server(data, len, local_endpoint(), src, &dcid, &scid, vc.version)) {
            connections.push_back(conn);
        } else {
            // A valid encrypted Initial carrying an unacceptable ClientHello
            // must not retain a five-second close timer or TLS state.
            failed_connection = conn;
            ++crypto_failures;
        }
    }
    void on_pump_write(const char* path) override {
        for (const auto& conn : connections) conn->on_pump_write(path);
    }
    void full_queue() {
        while (!m_aggregate_queue.full()) {
            auto bytes = acquire_aggregate_buffer();
            require(bool(bytes), "queue buffer");
            bytes.data()[0] = 0;
            bytes.resize(1);
            require(m_aggregate_queue.push(PendingAggregate{local_endpoint(), std::move(bytes), 1}), "fill queue");
        }
    }
};

static Config config(const char* path) {
    Config result;
    result.load(path);
    return result;
}

static void close_tests(Config& cfg, std::shared_ptr<QuicTlsCtx> tls) {
    boost::asio::io_context io;
    for (bool stop_first : {false, true}) {
        auto endpoint = std::make_shared<Endpoint>(io, cfg, tls);
        endpoint->start();
        auto conn = endpoint->client(endpoint->local_endpoint());
        endpoint->connections.clear();
        endpoint->full_queue();
        unsigned closed = 0;
        conn->on_close_cb = [&](QuicConnection*) { ++closed; };
        std::weak_ptr<QuicConnection> weak = conn;
        if (stop_first) endpoint->stop();
        conn->close();
        if (!stop_first) {
            require(closed == 0 && conn->m_close_waiting, "close must wait for full queue");
            endpoint->stop();
            require(closed == 0, "stop must post waiter, not call it inline");
        }
        conn.reset();
        until(io, [&] { return weak.expired(); });
        require(closed == 1, "close callback exactly once after stop");
        poll(io);
        require(closed == 1, "close callback duplicated");
    }
    // Exercise the actual derived-client stop ordering, not a facsimile.
    auto endpoint = std::make_shared<QuicClientEndpoint>(io, cfg, tls);
    endpoint->open_socket(Udp::endpoint(boost::asio::ip::address_v4::loopback(), 0), false);
    endpoint->m_running = true;
    auto conn = std::make_shared<QuicConnection>(*endpoint, tls, endpoint->local_endpoint());
    require(conn->init_client(endpoint->local_endpoint(), endpoint->local_endpoint()), "client stop init");
    endpoint->m_conn = conn;
    while (!endpoint->m_aggregate_queue.full()) {
        auto bytes = endpoint->acquire_aggregate_buffer();
        bytes.resize(1);
        require(endpoint->m_aggregate_queue.push(QuicEndpoint::PendingAggregate{endpoint->local_endpoint(), std::move(bytes), 1}), "client queue fill");
    }
    unsigned closed = 0;
    unsigned failed_opens = 0;
    endpoint->open_bidi_stream([&](int64_t sid) {
        require(sid == -1, "client stop pending open failed");
        ++failed_opens;
    });
    conn->on_close_cb = [&](QuicConnection*) { ++closed; endpoint->m_conn.reset(); };
    std::weak_ptr<QuicConnection> weak = conn;
    endpoint->stop();
    require(failed_opens == 0, "client stop pending open deferred");
    conn.reset();
    until(io, [&] { return weak.expired(); });
    require(closed == 1, "client stop full queue callback");
    require(failed_opens == 1, "client stop pending open callback");
    std::cout << "PASS close after stop, deferred waiter, client stop, weak_ptr release\n";
}

static std::array<std::chrono::steady_clock::time_point, 9> enobufs_attempts;
static unsigned enobufs_calls;
static int bounded_enobufs(bool) {
    require(enobufs_calls < enobufs_attempts.size(), "unexpected ENOBUFS send attempt");
    enobufs_attempts[enobufs_calls] = std::chrono::steady_clock::now();
    return ++enobufs_calls <= 8 ? ENOBUFS : 0;
}

static void enobufs_test(Config& cfg, const std::shared_ptr<QuicTlsCtx>& tls) {
    boost::asio::io_context io;
    auto endpoint = std::make_shared<Endpoint>(io, cfg, tls);
    endpoint->start();
    require(endpoint->udp_gso_enabled(), "GSO enabled for ENOBUFS runtime test");
    Udp::socket receiver(io, Udp::endpoint(boost::asio::ip::address_v4::loopback(), 0));
    std::array<uint8_t, 16> received{};
    Udp::endpoint source;
    bool delivered = false;
    receiver.async_receive_from(boost::asio::buffer(received), source,
        [&](boost::system::error_code ec, std::size_t size) {
            require(!ec && size == 1 && received[0] == 2, "ENOBUFS must drop head and deliver later item");
            delivered = true;
        });
    // Keep the transfer test's two-WARN contract: this test checks suppression
    // directly instead of emitting another first-occurrence warning.
    endpoint->m_send_errors.push_back(QuicEndpoint::SendError{ENOBUFS});
    endpoint->m_send_errors.back().last = std::chrono::steady_clock::now();
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
    const auto drops = endpoint->m_aggregate_queue.enobufs_drops;
#endif
    enobufs_calls = 0;
    endpoint->m_aggregate_queue.send_fault = bounded_enobufs;
    const uint8_t head = 1, later = 2;
    require(endpoint->send_packet(receiver.local_endpoint(), &head, 1), "enqueue ENOBUFS head");
    require(enobufs_calls == 1 && endpoint->m_send_wait, "ENOBUFS must arm retry timer");
    require(endpoint->send_packet(receiver.local_endpoint(), &later, 1), "enqueue later item");
    require(enobufs_calls == 1 && endpoint->m_aggregate_queue.pending.size() == 2,
        "later enqueue must not bypass ENOBUFS timer");
    until(io, [&] { return delivered; });
    require(enobufs_calls == 9 && endpoint->m_aggregate_queue.pending.empty() && !endpoint->m_send_wait,
        "eight ENOBUFS attempts must drop head and drain later item");
    for (std::size_t i = 1; i < 8; ++i) {
        const auto delay = enobufs_attempts[i] - enobufs_attempts[i - 1];
        const auto expected_ms = 2u << std::min(static_cast<unsigned>(i - 1), 4u);
        // Allow scheduler/clock noise, but reject writable-socket busy retries.
        require(delay >= std::chrono::milliseconds(expected_ms / 2) && delay < std::chrono::seconds(2),
            "ENOBUFS retry timer delay outside tolerance");
    }
    require(enobufs_attempts[8] - enobufs_attempts[0] < std::chrono::seconds(5),
        "ENOBUFS retries must finish within bounded time");
    require(endpoint->m_send_errors.back().suppressed == 1, "ENOBUFS drop must report exactly once");
#if defined(TROJAN_QUIC_STATS_LAYOUT) || TROJAN_QUIC_STATS
    require(endpoint->m_aggregate_queue.enobufs_drops == drops + 1, "ENOBUFS drop counter");
#endif
    require(endpoint->is_running() && !endpoint->m_aggregate_queue.disabled,
        "ENOBUFS must preserve endpoint and GSO");
    endpoint->m_aggregate_queue.send_fault = nullptr;
    endpoint->stop();
    poll(io);
    std::cout << "PASS eight ENOBUFS attempts: bounded timer backoff, one drop, later UDP delivery\n";
}

static int unreachable(bool) { return ENETUNREACH; }
static void transfer_tests(Config& server_cfg, Config& client_cfg) {
    boost::asio::io_context io;
    auto server_tls = std::make_shared<QuicTlsCtx>(server_cfg, QuicTlsCtx::Role::Server);
    auto client_tls = std::make_shared<QuicTlsCtx>(client_cfg, QuicTlsCtx::Role::Client);
    auto server = std::make_shared<Endpoint>(io, server_cfg, server_tls);
    auto first = std::make_shared<Endpoint>(io, client_cfg, client_tls);
    auto second = std::make_shared<Endpoint>(io, client_cfg, client_tls);
    server->start(); first->start(); second->start();
    auto a = first->client(server->local_endpoint());
    auto b = second->client(server->local_endpoint());
    until(io, [&] { return a->is_handshake_done() && b->is_handshake_done() && server->connections.size() == 2; });
    until(io, [&] { return server->connections[0]->is_handshake_done() && server->connections[1]->is_handshake_done(); });
    require(server->udp_gso_enabled(), "GSO enabled for runtime tests");
    // Fault only the third destination. Both healthy peers share this endpoint.
    const auto bad = Udp::endpoint(boost::asio::ip::make_address("192.0.2.1"), 9);
    const uint8_t packet[]{1, 2, 3};
    server->m_aggregate_queue.send_fault = unreachable;
    server->send_packet(bad, packet, sizeof(packet));
    server->send_packet(bad, packet, sizeof(packet));
    server->m_aggregate_queue.send_fault = nullptr;
    require(server->is_running() && !server->m_aggregate_queue.disabled, "unreachable peer stopped endpoint or disabled GSO");
    require(server->m_send_errors.size() == 1 && server->m_send_errors[0].error == ENETUNREACH &&
            server->m_send_errors[0].suppressed == 1, "WARN must count suppressed errors per errno");
    server->m_send_errors[0].last -= std::chrono::seconds(10);
    server->m_aggregate_queue.send_fault = unreachable;
    server->send_packet(bad, packet, sizeof(packet));
    server->m_aggregate_queue.send_fault = nullptr;
    require(server->m_send_errors[0].suppressed == 0, "WARN must reset suppressed count after interval");
    std::vector<uint8_t> payload(1024 * 1024);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<uint8_t>(i);
    std::array<std::vector<uint8_t>, 2> received;
    a->on_stream_data_cb = [&](int64_t id, const uint8_t* data, std::size_t n, bool) {
        received[0].insert(received[0].end(), data, data + n); a->stream_extend_window(id, n); a->conn_extend_window(n);
    };
    b->on_stream_data_cb = [&](int64_t id, const uint8_t* data, std::size_t n, bool) {
        received[1].insert(received[1].end(), data, data + n); b->stream_extend_window(id, n); b->conn_extend_window(n);
    };
    // Clients open streams; server returns independent SHA256-checked payloads.
    int64_t ids[2];
    require(a->open_bidi_stream(ids[0]) == 0 && b->open_bidi_stream(ids[1]) == 0, "open transfer streams");
    uint8_t request = 1;
    ngtcp2_vec request_vec{&request, 1};
    bool accepted;
    a->send_stream_vecs(ids[0], &request_vec, 1, false, accepted, "runtime");
    b->send_stream_vecs(ids[1], &request_vec, 1, false, accepted, "runtime");
    std::array<bool, 2> opened{};
    for (std::size_t i = 0; i != 2; ++i) server->connections[i]->on_stream_data_cb = [&, i](int64_t, const uint8_t*, std::size_t, bool) { opened[i] = true; };
    until(io, [&] { return opened[0] && opened[1]; });
    std::array<std::size_t, 2> sent{};
    until(io, [&] {
        for (std::size_t i = 0; i != 2; ++i) {
            if (sent[i] == payload.size()) continue;
            ngtcp2_vec vec{payload.data() + sent[i], payload.size() - sent[i]};
            auto n = server->connections[i]->send_stream_vecs(0, &vec, 1, true, accepted, "runtime");
            require(n >= 0, "healthy stream write");
            sent[i] += static_cast<std::size_t>(n);
        }
        return received[0].size() == payload.size() && received[1].size() == payload.size();
    });
    std::array<uint8_t, SHA256_DIGEST_LENGTH> expected{}, actual{};
    SHA256(payload.data(), payload.size(), expected.data());
    for (const auto& data : received) {
        SHA256(data.data(), data.size(), actual.data());
        require(actual == expected, "healthy transfer SHA256 mismatch");
    }
    require(!server->m_aggregate_queue.disabled && server->is_running(), "GSO lost after healthy transfers");
    std::cout << "PASS unreachable peer: two healthy 1 MiB SHA256 transfers; GSO remains enabled; one WARN\n";

    // Native ngtcp2 stream errors must propagate through the production GSO callback.
    ngtcp2_vec vec{payload.data(), 1};
    require(a->send_gso(4000000, &vec, 1, false, accepted) == -1, "STREAM_NOT_FOUND must return -1");
    int64_t id;
    require(a->open_bidi_stream(id) == 0, "open shutdown stream");
    require(ngtcp2_conn_shutdown_stream_write(a->native_handle(), 0, id, 1) == 0, "shutdown stream write");
    require(a->send_gso(id, &vec, 1, false, accepted) == -1, "STREAM_SHUT_WR must return -1");
    std::cout << "PASS stream NOT_FOUND and SHUT_WR return -1\n";
    // Enter native closing and draining without QuicConnection::close().
    // A real UnackedBuf::send() must survive the deferred local close.
    std::array<uint8_t, 1500> close_packet{};
    ngtcp2_path_storage close_path;
    ngtcp2_path_storage_zero(&close_path);
    ngtcp2_pkt_info close_pi{};
    ngtcp2_ccerr close_error;
    ngtcp2_ccerr_default(&close_error);
    auto now = static_cast<ngtcp2_tstamp>(std::chrono::duration_cast<std::chrono::nanoseconds>(
        QuicClock::now().time_since_epoch()).count());
    auto nclose = ngtcp2_conn_write_connection_close(a->native_handle(), &close_path.path,
        &close_pi, close_packet.data(), close_packet.size(), &close_error, now);
    require(nclose > 0 && ngtcp2_conn_in_closing_period2(a->native_handle()), "native closing state");
    auto peer = std::find_if(server->connections.begin(), server->connections.end(),
        [&](const Connection& conn) { return conn->peer() == first->local_endpoint(); });
    require(peer != server->connections.end(), "find closing peer");
    auto path = (*peer)->make_path(server->local_endpoint(), first->local_endpoint());
    require(ngtcp2_conn_read_pkt((*peer)->native_handle(), &path, nullptr,
        close_packet.data(), static_cast<std::size_t>(nclose), now) == NGTCP2_ERR_DRAINING,
        "native draining state");
    const std::array<Connection, 2> closing_connections{a, *peer};
    std::array<int64_t, 2> closing_streams{};
    for (std::size_t i = 0; i != closing_connections.size(); ++i)
        require(closing_connections[i]->open_bidi_stream(closing_streams[i]) == 0, "open native close test stream");
    std::array<unsigned, 2> callbacks{};
    for (std::size_t i = 0; i != closing_connections.size(); ++i) {
        const auto& closing = closing_connections[i];
        auto bytes = std::make_shared<ReadBufWithGuard>();
        boost::asio::buffer_copy(bytes->prepare(1), boost::asio::buffer("x", 1));
        bytes->commit(1);
        closing->send_stream_data(closing_streams[i], bytes, false, [&, i](boost::system::error_code ec, std::size_t) {
            require(bool(ec), "closing send must fail"); ++callbacks[i];
        });
        require(!closing->is_closed() && closing->m_close_pending,
            "native CLOSING/DRAINING send must defer close");
    }
    until(io, [&] { return closing_connections[0]->is_closed() && closing_connections[1]->is_closed()
        && callbacks[0] == 1 && callbacks[1] == 1; });
    poll(io);
    require(callbacks[0] == 1 && callbacks[1] == 1, "closing send callback duplicated");
    std::cout << "PASS native CLOSING/DRAINING during UnackedBuf::send\n";
    first->stop(); second->stop(); server->stop();
    first->connections.clear(); second->connections.clear(); server->connections.clear();
    a.reset(); b.reset(); poll(io);
}

static void crypto_failure_test(Config& server_cfg, const char* client_path) {
    boost::asio::io_context io;
    auto bad_config = config(client_path);
    // Initial keys are public: a fresh TLS ClientHello with unsupported ALPN
    // reproduces a forged, correctly encrypted Initial that fails TLS early.
    const uint8_t invalid_alpn[]{20, 'i', 'n', 'v', 'a', 'l', 'i', 'd', '-', 'f', 'i', 'x', 't', 'u', 'r', 'e', '-', 'a', 'l', 'p', 'n'};
    auto server_tls = std::make_shared<QuicTlsCtx>(server_cfg, QuicTlsCtx::Role::Server);
    auto bad_tls = std::make_shared<QuicTlsCtx>(bad_config, QuicTlsCtx::Role::Client);
    require(SSL_CTX_set_alpn_protos(bad_tls->native_handle(), invalid_alpn, sizeof(invalid_alpn)) == 0,
        "configure forged Initial ALPN");
    auto server = std::make_shared<Endpoint>(io, server_cfg, server_tls);
    auto bad = std::make_shared<Endpoint>(io, bad_config, bad_tls);
    server->start(); bad->start();
    const auto baseline = QuicConnection::live_count();
    auto conn = bad->client(server->local_endpoint());
    until(io, [&] { return server->crypto_failures != 0; });
    require(server->failed_connection.expired(), "crypto failure retained connection");
    require(QuicConnection::live_count() == baseline + 1, "crypto failure retained TLS/ngtcp2 owner");
    server->stop(); bad->stop(); bad->connections.clear(); conn.reset(); poll(io);
    std::cout << "PASS forged encrypted Initial: crypto failure releases connection immediately\n";
}

int main_impl(int, const char**) { return 1; } // Unused native-library CLI export.

int main(int argc, char** argv) {
    try {
        require(argc == 3, "usage: runtime SERVER_CONFIG CLIENT_CONFIG");
        auto server = config(argv[1]);
        auto client = config(argv[2]);
        auto tls = std::make_shared<QuicTlsCtx>(client, QuicTlsCtx::Role::Client);
        close_tests(client, tls);
        enobufs_test(client, tls);
        transfer_tests(server, client);
        crypto_failure_test(server, argv[2]);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
