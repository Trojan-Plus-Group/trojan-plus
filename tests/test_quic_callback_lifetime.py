#!/usr/bin/env python3
"""Exercise production callback guard and shutdown under reentrant callbacks."""
import os
from pathlib import Path
import subprocess
import tempfile

from test_quic_udp_gso_close import method

ROOT = Path(__file__).resolve().parents[1]


def main():
    header = (ROOT / 'src/quic/quic_connection.h').read_text()
    source = (ROOT / 'src/quic/quic_connection.cpp').read_text()
    guard = header[header.index('    struct CallbackScope {'):header.index('    // ngtcp2 static callbacks')]
    program = r'''
#include <cassert>
#include <functional>
#include <memory>
#include <unordered_map>
struct Handler { void on_stream_close() {} };
struct QuicConnection : std::enable_shared_from_this<QuicConnection> {
    struct Timer { void cancel() {} } m_loss_timer;
    bool m_in_read_pkt = false, m_in_pump_write = false, m_shutdown_pending = false, m_closed = false;
    unsigned m_callback_depth = 0;
    std::function<void()> on_close_cb, on_handshake_completed_cb, on_stream_data_cb,
        on_stream_open_cb, on_stream_close_cb, on_new_connection_id_cb, on_extend_max_streams_cb;
    std::unordered_map<int, std::shared_ptr<Handler>> m_stream_handlers;
    void close() { m_closed = true; }
    void shutdown();
'''
    program += guard + '};\n' + method(source, 'void QuicConnection::shutdown(')
    program += r'''
struct Capture {
    bool* destroyed;
    ~Capture() { *destroyed = true; }
};
int main() {
    for (bool reading : {false, true}) {
        auto conn = std::make_shared<QuicConnection>();
        std::weak_ptr<QuicConnection> weak = conn;
        auto* raw = conn.get();
        bool destroyed = false;
        auto capture = std::make_shared<Capture>();
        capture->destroyed = &destroyed;
        raw->on_stream_data_cb = [raw, capture, &conn, &destroyed] {
            QuicConnection::CallbackScope nested(*raw);
            raw->shutdown();
            conn.reset();
            assert(!destroyed && raw->m_shutdown_pending);
        };
        capture.reset();
        raw->m_in_read_pkt = reading;
        auto read_owner = reading ? conn : nullptr;
        {
            QuicConnection::CallbackScope scope(*raw);
            raw->on_stream_data_cb();
            assert(!destroyed);
        }
        if (reading) {
            assert(!destroyed && !weak.expired());
            raw->m_in_read_pkt = false;
            raw->shutdown();
            assert(destroyed);
            read_owner.reset();
            assert(weak.expired());
        } else {
            assert(destroyed && weak.expired());
        }
    }
}
'''
    with tempfile.TemporaryDirectory(prefix='quic-callback-lifetime-') as directory:
        cpp = Path(directory) / 'check.cpp'
        binary = Path(directory) / 'check'
        cpp.write_text(program)
        flags = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if os.environ.get('QUIC_TEST_SANITIZERS') else []
        subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', *flags, str(cpp), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
    print('QUIC callback lifetime checks passed')


if __name__ == '__main__':
    main()
