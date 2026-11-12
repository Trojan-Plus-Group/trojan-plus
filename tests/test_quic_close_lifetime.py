#!/usr/bin/env python3
"""Exercise production close() when callbacks release the last endpoint reference.

Set QUIC_TEST_SANITIZERS=1 for ASan and UBSan.
"""
import os
from pathlib import Path
import subprocess
import tempfile

from test_quic_udp_gso_close import method

ROOT = Path(__file__).resolve().parents[1]


def main():
    source = (ROOT / 'src/quic/quic_connection.cpp').read_text()
    program = r'''
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/udp.hpp>
#include <cassert>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#define QUIC_STAT(...)
#define QUIC_SEND(...) do { assert(!endpoint_weak.expired()); ++packets; } while (false)
namespace tp { using string = std::string; using std::to_string; }
struct Log { enum { INFO }; };
void _log_with_date_time(const std::string&, int) {}
struct ngtcp2_path_storage { int path; };
struct ngtcp2_pkt_info {};
struct ngtcp2_ccerr { int type; uint64_t error_code; size_t reasonlen; const char* reason; };
constexpr int NGTCP2_CCERR_TYPE_APPLICATION = 1;
void ngtcp2_path_storage_zero(ngtcp2_path_storage*) {}
int ngtcp2_conn_get_tls_alert(void*) { return 0; }
void ngtcp2_ccerr_set_tls_alert(ngtcp2_ccerr*, int, const void*, int) {}
void ngtcp2_ccerr_default(ngtcp2_ccerr*) {}
int ngtcp2_conn_write_connection_close(void*, int*, ngtcp2_pkt_info*, unsigned char*, size_t,
                                       ngtcp2_ccerr*, uint64_t) { return 1; }
uint64_t now_nanos() { return 0; }
struct QuicConnection;
struct Endpoint;
std::weak_ptr<Endpoint> endpoint_weak;
struct Endpoint : std::enable_shared_from_this<Endpoint> {
    boost::asio::io_context& io;
    explicit Endpoint(boost::asio::io_context& context) : io(context) {}
    bool send_available() const { return true; }
    bool udp_gso_enabled() const { return false; }
    bool aggregate_capacity(QuicConnection&) { return true; }
};
struct QuicConnection : std::enable_shared_from_this<QuicConnection> {
    Endpoint& m_endpoint;
    std::weak_ptr<Endpoint> m_endpoint_lifetime;
    boost::asio::steady_timer m_loss_timer;
    bool m_closed = false, m_in_read_pkt = false, m_in_pump_write = false, m_close_waiting = false, m_is_server = false;
    uint64_t m_close_waiting_error = 0;
    void* m_conn = this;
    boost::asio::ip::udp::endpoint m_peer;
    std::vector<unsigned char> m_write_buf = std::vector<unsigned char>(1200);
    std::function<void(QuicConnection*)> on_close_cb;
    std::function<void()> fail_cb;
    int packets = 0;
    explicit QuicConnection(Endpoint& endpoint)
        : m_endpoint(endpoint), m_endpoint_lifetime(endpoint.weak_from_this()), m_loss_timer(endpoint.io) {}
    void defer_close(uint64_t) { assert(false); }
    void fail_all_unacked_buffers(const boost::system::error_code&) { if (fail_cb) fail_cb(); }
    void close(uint64_t);
};
'''
    program += method(source, 'void QuicConnection::close(')
    program += r'''
int main() {
    for (bool release_in_fail : {false, true}) {
        boost::asio::io_context io;
        auto endpoint = std::make_shared<Endpoint>(io);
        endpoint_weak = endpoint;
        auto conn = std::make_shared<QuicConnection>(*endpoint);
        auto* raw = conn.get();
        int closed = 0;
        auto release = [&] {
            endpoint.reset();
            assert(!endpoint_weak.expired()); // close() must retain endpoint through callbacks and send.
        };
        if (release_in_fail) raw->fail_cb = release;
        raw->on_close_cb = [&](QuicConnection* current) {
            assert(current == raw);
            ++closed;
            if (!release_in_fail) release();
        };
        raw->close(42);
        assert(closed == 1 && endpoint_weak.expired());
        assert(conn->packets == 1);
    }
}
'''
    with tempfile.TemporaryDirectory(prefix='quic-close-lifetime-') as directory:
        cpp = Path(directory) / 'check.cpp'
        binary = Path(directory) / 'check'
        cpp.write_text(program)
        flags = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if os.environ.get('QUIC_TEST_SANITIZERS') else []
        subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-pthread',
                        *flags, str(cpp), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
    print('QUIC close callback lifetime checks passed')


if __name__ == '__main__':
    main()
