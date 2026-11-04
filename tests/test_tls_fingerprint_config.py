#!/usr/bin/env python3
"""Compile production fingerprint parsing; check defaults, validation and warnings."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "src/core/config.cpp").read_text()
profile = source.split('    ssl.fingerprint = tree.get(', 1)[1].split(
    '    ssl.prefer_server_cipher', 1
)[0]
profile = '    ssl.fingerprint = tree.get(' + profile
curves = source.split('    ssl.curves                 = tree.get(', 1)[1].split(
    '    if (!tree.get("ssl.dhparam"', 1
)[0]
curves = '    ssl.curves                 = tree.get(' + curves
program = r'''
#include <boost/property_tree/json_parser.hpp>
#include <cassert>
#include <sstream>
#include <stdexcept>
#include <string>
namespace tp = std;
namespace Log { constexpr int WARN = 1; }
unsigned warnings = 0;
void _log_with_date_time(const std::string& text, int level) {
    assert(level == Log::WARN);
    assert(text.find("fingerprint differs") != std::string::npos);
    ++warnings;
}
struct SSLConfig { std::string fingerprint, cipher, cipher_tls13, curves; };
SSLConfig parse(const std::string& json, bool is_server = false) {
    boost::property_tree::ptree tree;
    std::istringstream input(json);
    boost::property_tree::read_json(input, tree);
    SSLConfig ssl;
    PROFILE
    CURVES
    return ssl;
}
int main() {
    auto ssl = parse("{}");
    assert(ssl.fingerprint == "chrome");
    assert(ssl.cipher.empty() && ssl.cipher_tls13.empty() && ssl.curves.empty());
    assert(warnings == 0);
    assert(parse(R"({"ssl":{"fingerprint":"none"}})").fingerprint == "none");
    for (const auto* value : {"", "Chrome", "firefox"}) {
        bool rejected = false;
        try { parse(std::string(R"({"ssl":{"fingerprint":")") + value + R"("}})"); }
        catch (const std::runtime_error&) { rejected = true; }
        assert(rejected);
    }
    for (const auto* field : {"cipher", "cipher_tls13", "curves"}) {
        warnings = 0;
        parse(std::string(R"({"ssl":{")") + field + R"(":"override"}})");
        assert(warnings == 1);
    }
    const auto* overrides = R"({"ssl":{"cipher":"a","cipher_tls13":"b","curves":"c"}})";
    warnings = 0;
    parse(overrides);
    assert(warnings == 1);
    warnings = 0;
    parse(overrides, true);
    assert(warnings == 0);
    parse(R"({"ssl":{"fingerprint":"none","curves":"c"}})");
    assert(warnings == 1);
}
'''.replace("PROFILE", profile).replace("CURVES", curves)
with tempfile.TemporaryDirectory(prefix="tp-fingerprint-config-") as directory:
    cpp = Path(directory) / "test.cpp"
    binary = Path(directory) / "test"
    cpp.write_text(program)
    subprocess.run(["c++", "-std=c++17", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("TLS fingerprint config checks passed")
