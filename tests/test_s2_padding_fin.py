#!/usr/bin/env python3
"""Run production encoder and QUIC receive method against short-session FIN."""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    source = (ROOT / 'src/quic/quic_session.cpp').read_text()
    receive = source[source.index('void QuicProxySession::receive_tcp_data('):
                     source.index('void QuicProxySession::write_to_target(')]
    program = r'''
#include "proto/padding.h"
#include <cassert>
#include <iostream>
extern "C" int RAND_bytes(uint8_t* out, size_t size) {
    for (size_t i = 0; i < size; ++i) out[i] = 123;
    return 1;
}
struct Log { enum { WARN }; };
void _log_with_date_time(const tp::string&, int) {}
constexpr int NGHTTP3_H3_INTERNAL_ERROR = 1;
struct QuicProxySession {
    bool m_padded = true, reset = false, finished = false;
    s2::Decoder m_padding_decoder;
    tp::string plain;
    void destroy(bool, int) { reset = true; }
    void write_to_target(tp::string data, bool fin, size_t) {
        plain += data;
        finished = fin;
    }
    void receive_tcp_data(std::string_view, bool);
};
'''
    program += receive
    program += r'''
int main() {
    // ClientPadding uses this production encoder with the request as a prefix.
    const tp::string request = tp::string(56, 'a') + tp::string("\r\n\x05\x01\x7f\0\0\x01\x01\xbb\r\n", 12);
    s2::Encoder encoder;
    auto encoded = encoder.encode("short", {request.data(), request.size()});
    assert(encoded.success && !encoder.ended() && encoded.flushes.size() == 1);
    const auto wire = encoded.flushes.front().substr(request.size());
    for (size_t split = 0; split <= wire.size(); ++split) {
        QuicProxySession server;
        server.receive_tcp_data({wire.data(), split}, false);
        server.receive_tcp_data({wire.data() + split, wire.size() - split}, true);
        if (server.reset) {
            std::cerr << "FAIL: complete short DATA/PAD followed by FIN resets without END\n";
            return 1;
        }
        assert(server.finished && server.plain == "short");
    }
    // Every non-boundary cut inside DATA/PAD must still reset.
    size_t boundary = 0;
    for (size_t pos = 0; pos < wire.size();) {
        const size_t length = (static_cast<unsigned char>(wire[pos + 1]) << 8) |
                              static_cast<unsigned char>(wire[pos + 2]);
        boundary = pos + 3 + length;
        for (size_t cut = pos + 1; cut < boundary; ++cut) {
            QuicProxySession server;
            server.receive_tcp_data({wire.data(), cut}, true);
            assert(server.reset && !server.finished);
        }
        pos = boundary;
    }
    QuicProxySession empty;
    empty.receive_tcp_data({}, true); // Request already decoded; no frames needed.
    assert(!empty.reset && empty.finished);
    QuicProxySession malformed;
    malformed.receive_tcp_data(std::string_view("\x02\0\x01x", 4), true);
    assert(malformed.reset);
    QuicProxySession ended;
    ended.receive_tcp_data(std::string_view("\x02\0\0raw", 6), true);
    assert(!ended.reset && ended.finished && ended.plain == "raw");
    std::cout << "S2 short-session FIN checks passed; mid-frame truncation rejected\n";
}
'''
    with tempfile.TemporaryDirectory(prefix='padding-fin-') as directory:
        cpp = Path(directory) / 'check.cpp'
        binary = Path(directory) / 'check'
        cpp.write_text(program)
        subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-pthread',
                        '-I', str(ROOT / 'src'), '-I', str(ROOT / 'boringssl/include'),
                        str(cpp), str(ROOT / 'src/mem/memallocator.cpp'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=10)


if __name__ == '__main__':
    main()
