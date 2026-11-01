"""Check real H3 pump with deterministic QUIC backpressure.

Run: python3 tests/LinuxFullTest/check_h3_fin_retry.py
Requires C++17 compiler; no network or build dependencies.
"""
import os
from pathlib import Path
import subprocess
import tempfile


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "src/quic/h1_upstream/quic_to_http3_connect.cpp").read_text()
    pump = source[source.index("void QuicToHttp3Connect::pump_h3_response("):
                  source.index("int QuicToHttp3Connect::acked_stream_data(")]
    harness = r'''
#include <cassert>
#include <cstdint>
#include <string>
namespace tp { using std::string; using std::to_string; }
struct Log { enum { ALL, WARN, ERROR }; };
void _log_with_date_time(const std::string&, int) {}
using nghttp3_ssize = int64_t;
struct nghttp3_vec {};
struct ngtcp2_vec {};
constexpr int NGHTTP3_H3_FRAME_ERROR = 1, NGHTTP3_H3_INTERNAL_ERROR = 2;
struct State { bool committed = false; int offsets = 0; };
const char* nghttp3_strerror(int) { return "error"; }
int nghttp3_conn_writev_stream(State* s, int64_t* id, int* fin, nghttp3_vec*, int) {
    *id = s->committed ? -1 : 0;
    *fin = 1;
    return 0;
}
int nghttp3_conn_add_write_offset(State* s, int64_t, size_t n) {
    assert(n == 0);
    s->committed = true;
    ++s->offsets;
    return 0;
}
int nghttp3_conn_close_stream(State*, int64_t, int) { assert(false); return 0; }
void nghttp3_conn_block_stream(State*, int64_t) { assert(false); }
struct Owner {
    bool accept = false;
    int calls = 0;
    bool is_closed() { return false; }
    void close(int) { assert(false); }
    bool is_stream_flow_control_blocked(int64_t) { return false; }
    int64_t send_stream_vecs(int64_t, const ngtcp2_vec*, size_t, bool fin,
                             bool& accepted, const char*) {
        assert(fin);
        assert(++calls <= 3); // Reject busy loops on unaccepted empty FIN.
        accepted = accept;
        return 0;
    }
};
struct QuicToHttp3Connect {
    State* m_conn;
    Owner m_owner;
    void pump_h3_response(const char*);
};
'''
    harness += pump
    harness += r'''
int main() {
    State state;
    QuicToHttp3Connect h3{&state, {}};
    h3.pump_h3_response("blocked");
    assert(h3.m_owner.calls == 1);
    assert(state.offsets == 0 && !state.committed);
    h3.m_owner.accept = true;
    h3.pump_h3_response("retry");
    assert(h3.m_owner.calls == 2);
    assert(state.offsets == 1 && state.committed);
}
'''
    with tempfile.TemporaryDirectory() as directory:
        cpp = Path(directory) / "check.cpp"
        binary = Path(directory) / "check"
        cpp.write_text(harness)
        subprocess.run([os.environ.get("CXX", "c++"), "-std=c++17", str(cpp),
                        "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=5)
    print("H3 empty FIN backpressure/retry check passed")


if __name__ == "__main__":
    main()
