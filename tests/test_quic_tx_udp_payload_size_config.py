#!/usr/bin/env python3
"""Compile production quic.tx_udp_payload_size parsing; check default, range and WARN."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/core/config.cpp").read_text()
block = source.split('    quic.tx_udp_payload_size    = 0;', 1)[1].split(
    '    quic.recv_buffer_size', 1
)[0]
block = '    quic.tx_udp_payload_size    = 0;' + block
program = r'''
#include <boost/property_tree/json_parser.hpp>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <string>
namespace Log { constexpr int WARN = 1; }
unsigned warnings = 0;
std::string last;
void _log_with_date_time(const std::string& text, int level) {
    assert(level == Log::WARN);
    last = text;
    ++warnings;
}
struct QUIC { uint32_t tx_udp_payload_size; };
QUIC parse(const std::string& json) {
    boost::property_tree::ptree tree;
    std::istringstream input(json);
    boost::property_tree::read_json(input, tree);
    QUIC quic;
    BLOCK
    return quic;
}
uint32_t value(const std::string& v) { return parse(R"({"quic":{"tx_udp_payload_size":)" + v + "}}").tx_udp_payload_size; }
int main() {
    assert(parse("{}").tx_udp_payload_size == 0 && warnings == 0);
    for (const char* v : {"0", "1200", "1452", "1400", "\"1300\""}) {
        warnings = 0;
        assert(value(v) == (std::string(v) == "\"1300\"" ? 1300U : (uint32_t)std::stoul(v)));
        assert(warnings == 0);
    }
    for (const char* v : {"1", "1199", "1453", "65536", "4294967296", "99999999999999999999999",
                          "-1", "1200.5", "\"abc\"", "\"\"", "\"1300x\""}) {
        warnings = 0;
        assert(value(v) == 0);
        assert(warnings == 1);
        assert(last.find("quic.tx_udp_payload_size") != std::string::npos);
        assert(last.find("1200..1452") != std::string::npos);
    }
}
'''.replace("BLOCK", block)
with tempfile.TemporaryDirectory(prefix="tp-tx-udp-config-") as directory:
    cpp = Path(directory) / "test.cpp"
    binary = Path(directory) / "test"
    cpp.write_text(program)
    subprocess.run(["c++", "-std=c++17", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("PASS quic.tx_udp_payload_size config checks")
