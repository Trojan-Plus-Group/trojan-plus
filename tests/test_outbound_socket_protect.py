#!/usr/bin/env python3
"""Compile production TLS connect path; exercise protection on real TCP sockets."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/quic/outbound_transport.cpp").read_text()
connect = source[source.index("    void async_connect("):source.index("    void async_read_some(")]
private = source.split("  private:", 1)[1].split("    SSLSocket", 1)[0]
program = r'''
#include <boost/asio.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <cassert>
#include <functional>
#include <memory>
#include <string>
#include <sys/socket.h>
namespace tp {
using namespace std;
template<class Handler> Handler bind_mem_alloc(Handler handler) { return handler; }
}
using boost::asio::ip::tcp;
using Error = boost::system::error_code;
namespace Log { constexpr int WARN = 1; }
void _log_with_endpoint(tcp::endpoint, const std::string&, int = 0) {}
int protections = 0;
void android_protect_socket(int fd) {
    sockaddr_storage peer{};
    socklen_t size = sizeof(peer);
    assert(getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &size) == -1);
    assert(errno == ENOTCONN); // Protection must precede connect, not follow it.
    sockaddr_in local{};
    size = sizeof(local);
    assert(getsockname(fd, reinterpret_cast<sockaddr*>(&local), &size) == 0);
    assert(local.sin_port == 0); // Fresh, unconnected descriptor on every retry.
    ++protections;
}
struct FakeSSL {
    tcp::socket socket;
    explicit FakeSSL(boost::asio::io_context& io) : socket(io) {}
    tcp::socket& next_layer() { return socket; }
    template<class Mode, class Handler>
    void async_handshake(Mode, Handler handler) {
        assert(socket.remote_endpoint().port() != 0);
        boost::asio::post(socket.get_executor(), [handler]() mutable { handler(Error{}); });
    }
};
struct Config { void prepare_ssl_reuse(FakeSSL&) const {} };
struct Resolver {
    boost::asio::io_context& io;
    tcp::resolver::results_type results;
    Error error;
    template<class Handler>
    void async_resolve(std::string, std::string, Handler handler) {
        boost::asio::post(io, [this, handler]() mutable { handler(error, results); });
    }
};
struct Transport : std::enable_shared_from_this<Transport> {
    FakeSSL m_socket;
    Resolver m_resolver;
    Config m_config;
    tcp::endpoint m_in_ep;
    explicit Transport(boost::asio::io_context& io) : m_socket(io), m_resolver{io, {}, {}} {}
    CONNECT
    PRIVATE
};
int main() {
    for (int mode = 0; mode < 6; ++mode) {
        boost::asio::io_context io;
        tcp::acceptor listener(io, {boost::asio::ip::address_v4::loopback(), 0});
        // Bound but not listening: reliably refuses connections without port races.
        tcp::acceptor refused(io);
        refused.open(tcp::v4());
        refused.bind({boost::asio::ip::address_v4::loopback(), 0});
        auto transport = std::make_shared<Transport>(io);
        std::vector<tcp::endpoint> endpoints;
        if (mode == 1 || mode == 2) endpoints.push_back(refused.local_endpoint());
        if (mode == 2) endpoints.push_back(refused.local_endpoint());
        else if (mode != 3) endpoints.push_back(listener.local_endpoint());
        transport->m_resolver.results = tcp::resolver::results_type::create(
            endpoints.begin(), endpoints.end(), "loopback", "0");
        if (mode == 4) transport->m_resolver.error = boost::asio::error::host_not_found;
        protections = 0;
        int success = 0, failure = 0;
        transport->async_connect("loopback", 0, [&] { ++success; }, [&] { ++failure; });
        assert(success == 0 && failure == 0);
        if (mode == 5) {
            assert(io.poll_one() == 1); // Resolve completes and starts TCP connect.
            transport->m_socket.next_layer().cancel();
        }
        io.run_for(std::chrono::seconds(3));
        assert(io.stopped());
        assert(success == (mode < 2 ? 1 : 0));
        assert(failure == (mode < 2 ? 0 : 1));
        assert(protections == (mode == 0 || mode == 5 ? 1 : mode < 3 ? 2 : 0));
    }
}
'''.replace("CONNECT", connect.replace(" override", "")).replace("PRIVATE", private)
with tempfile.TemporaryDirectory(prefix="outbound-protect-") as directory:
    cpp = Path(directory) / "test.cpp"
    binary = Path(directory) / "test"
    cpp.write_text(program)
    subprocess.run(["c++", "-std=c++17", "-DBOOST_ASIO_NO_DEPRECATED", "-pthread",
                    str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("Outbound socket protection checks passed")
