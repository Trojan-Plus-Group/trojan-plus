#!/usr/bin/env python3
"""Exercise server pump when a connection synchronously stops its endpoint."""
import os
from pathlib import Path
import subprocess
import tempfile

from test_quic_udp_gso_close import method

ROOT = Path(__file__).resolve().parents[1]


def main():
    source = (ROOT / 'src/quic/quic_server_endpoint.cpp').read_text()
    program = r'''
#include <cassert>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>
struct Connection {
    std::function<void()> callback;
    void on_pump_write(const char*) { callback(); }
};
struct QuicServerEndpoint {
    bool m_running = true;
    std::map<std::string, std::shared_ptr<Connection>> m_conns;
    std::vector<std::string> m_pumping_conn;
    void on_pump_write(const char*);
};
'''
    program += method(source, 'void QuicServerEndpoint::on_pump_write(')
    program += r'''
int main() {
    QuicServerEndpoint endpoint;
    int calls = 0;
    auto first = std::make_shared<Connection>();
    auto second = std::make_shared<Connection>();
    std::weak_ptr<Connection> weak = first;
    first->callback = [&] {
        ++calls;
        endpoint.m_running = false;
        endpoint.m_conns.clear();
        endpoint.m_pumping_conn.clear();
        assert(!weak.expired());
    };
    second->callback = [&] { ++calls; };
    endpoint.m_conns["a"] = first;
    endpoint.m_conns["b"] = second;
    first.reset();
    endpoint.m_pumping_conn = {"a", "b"};
    endpoint.on_pump_write("test");
    assert(calls == 1 && weak.expired());
    assert(endpoint.m_pumping_conn.empty());
}
'''
    with tempfile.TemporaryDirectory(prefix='quic-reentrant-stop-') as directory:
        cpp = Path(directory) / 'check.cpp'
        binary = Path(directory) / 'check'
        cpp.write_text(program)
        flags = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if os.environ.get('QUIC_TEST_SANITIZERS') else []
        subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', *flags, str(cpp), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)
    print('PASS: QUIC reentrant stop')


if __name__ == '__main__':
    main()
