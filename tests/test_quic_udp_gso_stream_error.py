#!/usr/bin/env python3
"""Execute production GSO callback for terminal stream errors and ciphertext prefix."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    source = (ROOT / 'src/quic/quic_connection.cpp').read_text()
    send = source[source.index('int64_t QuicConnection::send_gso('):
                  source.index('// ---- open_bidi_stream')]
    callback = send[send.index('    auto callback = '):send.index('    auto buffer = ')]
    result = send[send.index('    if (error == NGTCP2_ERR_STREAM_SHUT_WR || error == NGTCP2_ERR_STREAM_NOT_FOUND) return -1;'):
                  send.index('\n}')]
    program = r'''
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>
using ngtcp2_ssize = int64_t;
using ngtcp2_tstamp = uint64_t;
struct ngtcp2_conn {};
struct ngtcp2_path {};
struct ngtcp2_pkt_info {};
struct ngtcp2_vec { uint8_t* base; size_t len; };
constexpr int NGTCP2_WRITE_STREAM_FLAG_PADDING = 1, NGTCP2_WRITE_STREAM_FLAG_FIN = 2;
constexpr int NGTCP2_ERR_STREAM_DATA_BLOCKED = -1;
constexpr int NGTCP2_ERR_STREAM_SHUT_WR = -2, NGTCP2_ERR_STREAM_NOT_FOUND = -3;
int injected, control_writes;
ngtcp2_ssize ngtcp2_conn_writev_stream(ngtcp2_conn*, ngtcp2_path*, ngtcp2_pkt_info*,
    uint8_t*, size_t, ngtcp2_ssize*, int, int64_t, ngtcp2_vec*, size_t, uint64_t) {
    return injected;
}
ngtcp2_ssize ngtcp2_conn_write_pkt(ngtcp2_conn*, ngtcp2_path*, ngtcp2_pkt_info*,
                                 uint8_t*, size_t, uint64_t) { ++control_writes; return 20; }
struct Context {
    int64_t id = 0;
    std::vector<ngtcp2_vec> vecs;
    size_t written = 0;
    bool fin = false, accepted = false;
    size_t encrypted = 0;
    int error = 0;
};
struct QuicConnection { void* m_gso_context; };
int64_t result(int error, int64_t n, const Context& context) {
'''
    program += result + '\n}\nint main() {\n' + callback
    program += r'''
    for (int error : {NGTCP2_ERR_STREAM_SHUT_WR, NGTCP2_ERR_STREAM_NOT_FOUND}) {
        for (size_t prefix : {size_t(0), size_t(1200)}) {
            Context context;
            context.encrypted = prefix;
            context.written = prefix ? 100 : 0;
            QuicConnection conn{&context};
            injected = error;
            control_writes = 0;
            auto n = callback(nullptr, nullptr, nullptr, nullptr, 1200, 0, &conn);
            assert(context.error == error && control_writes == 0);
            assert(n == (prefix ? 0 : error)); // Zero preserves aggregate's prefix.
            assert(result(context.error, prefix ? 1200 : n, context) == -1);
        }
    }
    Context context;
    QuicConnection conn{&context};
    injected = NGTCP2_ERR_STREAM_DATA_BLOCKED;
    control_writes = 0;
    assert(callback(nullptr, nullptr, nullptr, nullptr, 1200, 0, &conn) == 20);
    assert(control_writes == 1 && context.error == 0 && context.encrypted == 20);
}
'''
    with tempfile.TemporaryDirectory(prefix='quic-gso-stream-') as directory:
        cpp = Path(directory) / 'check.cpp'
        binary = Path(directory) / 'check'
        cpp.write_text(program)
        flags = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if os.environ.get('QUIC_TEST_SANITIZERS') else []
        subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', *flags,
                        str(cpp), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=15)
    print('QUIC GSO terminal stream errors and ciphertext-prefix flush checks passed')


if __name__ == '__main__':
    main()
