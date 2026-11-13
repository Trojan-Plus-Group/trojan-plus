#!/usr/bin/env python3
"""Run production close/deferred-close methods with a bounded endpoint fixture.

Set QUIC_TEST_SANITIZERS=1 to compile/run with ASan and UBSan.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def method(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


def main():
    source = (ROOT / 'src/quic/quic_connection.cpp').read_text()
    endpoint = (ROOT / 'src/quic/quic_endpoint.cpp').read_text()
    client = (ROOT / 'src/quic/quic_client_endpoint.cpp').read_text()
    close = method(source, 'void QuicConnection::defer_close(') + method(source, 'void QuicConnection::close(')
    writable = method(source, 'void QuicConnection::on_socket_writable(')
    program = r'''
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/udp.hpp>
#include <cassert>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <list>
#include <unordered_map>
#include <cstring>
#define QUIC_STAT(...)
#define QUIC_SEND(...) (++packets)
#define FUNC_NAME __func__
namespace tp {
using string = std::string; using std::to_string;
template<class T> using vector = std::vector<T>;
template<class T> auto bind_mem_alloc(T fn) { return fn; }
}
struct Log { enum { INFO, WARN, ALL }; };
void _log_with_date_time(const std::string&, int) {}
using ngtcp2_ssize = int64_t;
using ngtcp2_tstamp = uint64_t;
struct ngtcp2_conn {};
struct ngtcp2_path { struct { void* addr = nullptr; size_t addrlen = 0; } remote; };
struct ngtcp2_path_storage { ngtcp2_path path; };
struct ngtcp2_vec { uint8_t* base; size_t len; };
constexpr int NGTCP2_ERR_CLOSING = -10, NGTCP2_ERR_DRAINING = -11;
constexpr int NGTCP2_ERR_STREAM_SHUT_WR = -12, NGTCP2_ERR_STREAM_NOT_FOUND = -13;
constexpr int NGTCP2_ERR_STREAM_DATA_BLOCKED = -14;
constexpr int NGTCP2_WRITE_STREAM_FLAG_PADDING = 1, NGTCP2_WRITE_STREAM_FLAG_FIN = 2;
int injected = NGTCP2_ERR_CLOSING;
const char* ngtcp2_strerror(int) { return "injected"; }
size_t ngtcp2_conn_get_path_max_tx_udp_payload_size2(void*) { return 1200; }
namespace quic_udp_gso { constexpr size_t aggregate_limit(size_t) { return 65507; } }
struct ngtcp2_pkt_info;
ngtcp2_ssize ngtcp2_conn_writev_stream(ngtcp2_conn*, ngtcp2_path*, ngtcp2_pkt_info*, uint8_t*,
    size_t, ngtcp2_ssize* consumed, int, int64_t, ngtcp2_vec* vecs, size_t count, uint64_t) {
    if (injected > 0) {
        *consumed = 0;
        for (size_t i = 0; i < count; ++i) *consumed += vecs[i].len;
    }
    return injected;
}
ngtcp2_ssize ngtcp2_conn_write_pkt(ngtcp2_conn*, ngtcp2_path*, ngtcp2_pkt_info*, uint8_t*, size_t, uint64_t) { return 0; }
template<class Callback>
ngtcp2_ssize ngtcp2_conn_write_aggregate_pkt(ngtcp2_conn* conn, ngtcp2_path* path,
    ngtcp2_pkt_info* pi, uint8_t* data, size_t size, size_t*, Callback callback, uint64_t ts);
struct ngtcp2_pkt_info {};
struct ngtcp2_ccerr { int type; uint64_t error_code; size_t reasonlen; const char* reason; };
constexpr int NGTCP2_CCERR_TYPE_APPLICATION = 1;
void ngtcp2_path_storage_zero(ngtcp2_path_storage*) {}
int ngtcp2_conn_get_tls_alert(void*) { return 0; }
void ngtcp2_ccerr_set_tls_alert(ngtcp2_ccerr*, int, const void*, int) {}
void ngtcp2_ccerr_default(ngtcp2_ccerr* error) { error->error_code = 0; }
uint64_t close_error_code = 0;
int ngtcp2_conn_write_connection_close(void*, ngtcp2_path*, ngtcp2_pkt_info*, uint8_t*, size_t,
                                      ngtcp2_ccerr* error, uint64_t) {
    close_error_code = error->error_code;
    return 10;
}
uint64_t now_nanos() { return 1; }
struct QuicConnection;
struct QuicEndpoint : std::enable_shared_from_this<QuicEndpoint> {
    boost::asio::io_context io;
    boost::asio::io_context& m_io_context = io;
    bool m_running = true;
    struct Socket {
        bool open = true;
        bool is_open() const { return open; }
        void cancel(boost::system::error_code&) {}
        void close(boost::system::error_code&) { open = false; }
    } m_socket;
    struct Queue {
        std::vector<int> pending{1};
        bool full() const { return !pending.empty(); }
        void clear() { pending.clear(); }
    } m_aggregate_queue;
    std::vector<std::shared_ptr<QuicConnection>> m_aggregate_waiters;
    boost::asio::steady_timer m_send_retry{io};
    bool send_available() const { return m_running && m_socket.is_open(); }
    bool shutdown_send_available() const { return send_available(); }
    void send_shutdown_packet(const boost::asio::ip::udp::endpoint&, const uint8_t*, size_t) {}
    bool udp_gso_enabled() const { return true; }
    bool aggregate_capacity(QuicConnection&);
    void stop();
    auto& io_context() { return io; }
    struct Buffer {
        std::vector<uint8_t> bytes = std::vector<uint8_t>(65536);
        explicit operator bool() const { return true; }
        uint8_t* data() { return bytes.data(); }
        size_t size() const { return bytes.size(); }
        void resize(size_t n) { bytes.resize(n); }
    };
    Buffer acquire_aggregate_buffer() { return {}; }
    void send_aggregate(const boost::asio::ip::udp::endpoint&, Buffer&&, size_t) {}
};
using Endpoint = QuicEndpoint;
struct ReadBufWithGuard {
    std::string bytes = "payload";
    auto to_string_view() const { return std::string_view(bytes); }
    size_t size() const { return bytes.size(); }
};
struct QuicConnection : std::enable_shared_from_this<QuicConnection> {
    Endpoint& m_endpoint;
    std::weak_ptr<Endpoint> m_endpoint_lifetime;
    boost::asio::steady_timer m_loss_timer;
    bool m_closed = false, m_close_pending = false, m_close_waiting = false;
    bool m_waiting_for_capacity = false, m_resuming_sends = false;
    uint64_t m_partial_write_retries = 0;
    tp::vector<ngtcp2_vec> m_gso_vecs;
    void* m_gso_context = nullptr;
    ngtcp2_conn native;
    bool is_closed() const { return m_closed; }
    void reschedule_loss_timer() {}
    bool m_in_read_pkt = false, m_in_pump_write = false, m_shutdown_pending = false, m_is_server = true;
    bool m_shutdown_close_sent = false;
    unsigned m_callback_depth = 0;
    uint64_t m_close_waiting_error = 0, m_close_pending_error = 0;
    ngtcp2_conn* m_conn = &native;
    boost::asio::ip::udp::endpoint m_peer;
    std::vector<uint8_t> m_write_buf = std::vector<uint8_t>(1200);
    std::function<void(QuicConnection*)> on_close_cb;
    std::function<void()> on_handshake_completed_cb, on_stream_data_cb, on_stream_open_cb,
        on_stream_close_cb, on_new_connection_id_cb, on_extend_max_streams_cb;
    struct StreamHandler { void on_stream_close() {} };
    std::unordered_map<int64_t, std::shared_ptr<StreamHandler>> m_stream_handlers;
    std::function<void()> sent_cb;
    int packets = 0, pumps = 0;
    explicit QuicConnection(Endpoint& e)
        : m_endpoint(e), m_endpoint_lifetime(e.weak_from_this()), m_loss_timer(e.io) {}
    using IoHandler = std::function<void(boost::system::error_code, size_t)>;
    struct UnackedBuf : std::enable_shared_from_this<UnackedBuf> {
        int64_t m_stream_id = 1;
        std::shared_ptr<ReadBufWithGuard> m_buf = std::make_shared<ReadBufWithGuard>();
        bool m_fin = false;
        IoHandler m_sent_cb;
        boost::asio::steady_timer m_write_timer;
        std::weak_ptr<QuicConnection> m_conn;
        bool m_timer_running = false;
        uint64_t m_timer_generation = 0;
        size_t m_retry_delay_ms = 50, m_sending_offset = 0;
        explicit UnackedBuf(boost::asio::io_context& io) : m_write_timer(io) {}
        void send();
        void cancel_timer();
        void complete(const boost::system::error_code&, size_t);
    };
    struct UnackedBuffers {
        std::list<std::shared_ptr<UnackedBuf>> buffers;
        bool m_sending = true;
    };
    std::unordered_map<int64_t, std::shared_ptr<UnackedBuffers>> m_conn_unacked_bufs;
    void fail_unacked_buffers(int64_t, const boost::system::error_code&);
    void fail_all_unacked_buffers(const boost::system::error_code&);
    void send_next_unacked_buff(int64_t, UnackedBuf*);
    int64_t send_stream_data_impl(int64_t, const uint8_t*, size_t, bool);
    int64_t send_gso(int64_t, const ngtcp2_vec*, size_t, bool, bool&);
    void resume_blocked_sends() { ++pumps; }
    void on_pump_write(const char*) { ++pumps; }
    void defer_close(uint64_t = 0);
    void shutdown();
    void send_shutdown_close();
    void close(uint64_t = 0);
    void on_socket_writable();
};
'''
    program += r'''
struct QuicClientEndpoint : QuicEndpoint {
    bool m_recovering = false, m_probing = false;
    boost::asio::steady_timer m_probe_timer{io}, m_retry_timer{io}, m_handshake_timer{io};
    std::shared_ptr<QuicConnection> m_conn;
    void fail_all_pending_streams() {}
    void mark_unreachable() {}
    void stop();
};
// The transport stub injects ngtcp2's terminal states, keeping production send path.
QuicConnection* active_connection;
template<class Callback>
ngtcp2_ssize ngtcp2_conn_write_aggregate_pkt(ngtcp2_conn* conn, ngtcp2_path* path,
    ngtcp2_pkt_info* pi, uint8_t* data, size_t size, size_t*, Callback callback, uint64_t ts) {
    return callback(conn, path, pi, data, size, ts, active_connection);
}
'''
    program += close + method(source, 'void QuicConnection::shutdown(') + writable
    program += method(source, 'void QuicConnection::send_shutdown_close(')
    for signature in ('void QuicConnection::UnackedBuf::cancel_timer(',
                      'void QuicConnection::UnackedBuf::complete(',
                      'void QuicConnection::UnackedBuf::send(',
                      'void QuicConnection::send_next_unacked_buff(',
                      'void QuicConnection::fail_unacked_buffers(',
                      'void QuicConnection::fail_all_unacked_buffers(',
                      'int64_t QuicConnection::send_gso('):
        program += method(source, signature)
    # Compile production GSO dispatch; legacy packet writer is outside this fixture.
    dispatch = source[source.index('int64_t QuicConnection::send_stream_data_impl('):]
    dispatch = dispatch[:dispatch.index('    _log_with_date_time("send_stream_data_impl enter:')]
    program += dispatch + '    return -1;\n}\n'
    program += method(endpoint, 'void QuicEndpoint::stop(')
    program += method(endpoint, 'bool QuicEndpoint::aggregate_capacity(')
    program += method(client, 'void QuicClientEndpoint::stop(')
    program += r'''
int main() {
    for (bool server : {false, true}) {
        for (bool closed_socket : {false, true}) {
            auto endpoint_owner = std::make_shared<Endpoint>();
            auto& endpoint = *endpoint_owner;
            auto conn = std::make_shared<QuicConnection>(endpoint);
            std::weak_ptr<QuicConnection> weak = conn;
            conn->m_is_server = server;
            int closed = 0, sent = 0;
            conn->on_close_cb = [&](auto*) { ++closed; };
            auto queue = std::make_shared<QuicConnection::UnackedBuffers>();
            auto buf = std::make_shared<QuicConnection::UnackedBuf>(endpoint.io);
            buf->m_sent_cb = [&](auto, auto) { ++sent; };
            queue->buffers.push_back(buf);
            conn->m_conn_unacked_bufs.emplace(1, queue);
            conn->close(42); // Full FIFO: no ciphertext or callbacks yet.
            assert(conn->m_close_waiting && !conn->m_closed);
            assert(closed == 0 && sent == 0 && conn->packets == 0);
            conn->close(42); // O(1) waiter deduplication.
            assert(endpoint.m_aggregate_waiters.size() == 1);
            if (closed_socket) endpoint.m_socket.open = false;
            endpoint.stop();
            assert(endpoint.m_aggregate_waiters.empty() && !conn->m_waiting_for_capacity);
            assert(closed == 0 && sent == 0); // stop only releases waiters.
            conn->close(42);
            assert(closed == 1 && sent == 1 && conn->packets == 0);
            conn.reset();
            buf.reset();
            queue.reset();
            endpoint.io.run();
            assert(weak.expired());
        }
    }
    auto endpoint_owner = std::make_shared<Endpoint>();
    auto& endpoint = *endpoint_owner;
    endpoint.m_aggregate_queue.pending.clear();
    auto conn = std::make_shared<QuicConnection>(endpoint);
    conn->m_is_server = false;
    int closed = 0, sent = 0;
    conn->on_close_cb = [&](auto*) { ++closed; };
    auto queue = std::make_shared<QuicConnection::UnackedBuffers>();
    auto buf = std::make_shared<QuicConnection::UnackedBuf>(endpoint.io);
    buf->m_sent_cb = [&](auto, auto) { ++sent; };
    queue->buffers.push_back(buf);
    conn->m_conn_unacked_bufs.emplace(1, queue);
    // CLOSING/DRAINING send path must not run callbacks on its caller's stack.
    conn->defer_close();
    conn->defer_close();
    assert(!conn->m_closed && closed == 0 && sent == 0);
    assert(endpoint.io.poll_one() == 1);
    assert(conn->m_closed && closed == 1 && sent == 1 && conn->packets == 1);
    assert(endpoint.io.poll_one() == 0); // Guard posts exactly once.
    conn->close();
    assert(closed == 1 && sent == 1);

    for (uint64_t first : {0, 5}) {
        auto owner = std::make_shared<Endpoint>();
        owner->m_aggregate_queue.pending.clear();
        auto c = std::make_shared<QuicConnection>(*owner);
        c->m_is_server = false;
        c->m_in_read_pkt = true;
        c->close(first);
        c->close(7);
        assert(!c->m_closed && c->m_close_pending);
        c->m_in_read_pkt = false;
        assert(owner->io.poll_one() == 1);
        assert(c->m_closed && c->packets == 1);
        assert(close_error_code == (first == 0 ? 7 : 5));
        assert(owner->io.poll_one() == 0);
    }

    for (int terminal : {NGTCP2_ERR_CLOSING, NGTCP2_ERR_DRAINING}) {
      for (bool via_next : {false, true}) {
        auto owner = std::make_shared<Endpoint>();
        auto& e = *owner;
        e.m_aggregate_queue.pending.clear();
        auto c = std::make_shared<QuicConnection>(e);
        c->m_is_server = false;
        active_connection = c.get();
        injected = terminal;
        int completed = 0, close_count = 0;
        auto q = std::make_shared<QuicConnection::UnackedBuffers>();
        auto b = std::make_shared<QuicConnection::UnackedBuf>(e.io);
        std::weak_ptr<QuicConnection::UnackedBuf> weak_buf = b;
        b->m_conn = c;
        b->m_sent_cb = [&](auto ec, auto) { assert(ec); ++completed; };
        q->buffers.push_back(b);
        c->m_conn_unacked_bufs.emplace(1, q);
        c->on_close_cb = [&](auto*) { ++close_count; };
        auto* raw = b.get();
        b.reset();
        q.reset();
        // Production next-buffer loop invokes production send(), dispatch and GSO.
        // Negative send removes the sole owning queue while send() is on stack.
        if (via_next) c->send_next_unacked_buff(1, nullptr);
        else raw->send();
        assert(completed == 1 && close_count == 0 && !c->m_closed);
        assert(weak_buf.expired() && c->m_conn_unacked_bufs.empty());
        e.io.run();
        assert(c->m_closed && close_count == 1 && completed == 1);
      }
    }
    {
        auto owner = std::make_shared<Endpoint>();
        auto& e = *owner;
        e.m_aggregate_queue.pending.clear();
        auto c = std::make_shared<QuicConnection>(e);
        active_connection = c.get();
        injected = 20;
        auto q = std::make_shared<QuicConnection::UnackedBuffers>();
        auto b = std::make_shared<QuicConnection::UnackedBuf>(e.io);
        std::weak_ptr<QuicConnection::UnackedBuf> weak = b;
        b->m_conn = c;
        int completed = 0;
        b->m_sent_cb = [&](auto ec, auto n) {
            assert(!ec && n == 7);
            ++completed;
            c->m_conn_unacked_bufs.clear(); // Last queue removed inside send callback.
            assert(!weak.expired()); // send() must retain itself through cancel_timer().
        };
        q->buffers.push_back(b);
        c->m_conn_unacked_bufs.emplace(1, q);
        auto* raw = b.get();
        b.reset();
        q.reset();
        raw->send();
        assert(completed == 1 && weak.expired());
    }
    {
        auto owner = std::make_shared<Endpoint>();
        auto& e = *owner;
        auto c = std::make_shared<QuicConnection>(e);
        c->m_is_server = false;
        active_connection = c.get();
        auto q = std::make_shared<QuicConnection::UnackedBuffers>();
        auto b = std::make_shared<QuicConnection::UnackedBuf>(e.io);
        b->m_conn = c;
        int completed = 0, closed = 0;
        b->m_sent_cb = [&](auto ec, auto) { assert(ec); ++completed; };
        q->buffers.push_back(b);
        c->m_conn_unacked_bufs.emplace(1, q);
        c->on_close_cb = [&](auto*) { ++closed; };
        b->send(); // Ordinary full-queue send registers waiter and retry timer.
        assert(!c->m_close_waiting && c->m_waiting_for_capacity && b->m_timer_running);
        std::weak_ptr<QuicConnection> weak = c;
        std::weak_ptr<QuicConnection::UnackedBuf> weak_buf = b;
        b.reset();
        q.reset();
        e.stop();
        c->close();
        c.reset();
        e.io.run();
        assert(closed == 1 && completed == 1 && weak.expired() && weak_buf.expired());
    }
    {
        struct DyingEndpoint : Endpoint {
            std::shared_ptr<QuicConnection> conn;
            ~DyingEndpoint() {
                conn->close(); // weak_from_this() cannot lock during destruction.
                assert(conn->m_closed && conn->packets == 0);
            }
        };
        int closed = 0;
        auto owner = std::make_shared<DyingEndpoint>();
        owner->conn = std::make_shared<QuicConnection>(*owner);
        owner->conn->on_close_cb = [&](auto*) { ++closed; };
        owner.reset();
        assert(closed == 1);
    }
    {
        auto owner = std::make_shared<QuicClientEndpoint>();
        auto& e = *owner;
        e.m_conn = std::make_shared<QuicConnection>(e);
        e.m_conn->m_is_server = false;
        std::weak_ptr<QuicConnection> weak = e.m_conn;
        int closed = 0;
        e.m_conn->on_close_cb = [&](auto*) { ++closed; };
        e.m_conn->close(); // Queue full before client stop.
        assert(e.m_aggregate_waiters.size() == 1);
        e.stop(); // Pending close completes outside stop.
        assert(closed == 0 && !e.m_conn);
        e.io.run();
        assert(closed == 1 && weak.expired());
    }
}
'''
    with tempfile.TemporaryDirectory(prefix='quic-gso-close-') as directory:
        cpp = Path(directory) / 'check.cpp'
        binary = Path(directory) / 'check'
        cpp.write_text(program)
        flags = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if os.environ.get('QUIC_TEST_SANITIZERS') else []
        subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-pthread',
                        *flags, str(cpp), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
    print('QUIC GSO stopped-endpoint close and deferred-close checks passed')


if __name__ == '__main__':
    main()
