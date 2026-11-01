#!/usr/bin/env python3
"""Benchmark for DNS proxy address index maintenance: incremental vs full rebuild."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def function(source: str, signature: str) -> str:
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


proto_header = (ROOT / "src/proto/dns_header.h").read_text()
proto_header = proto_header[proto_header.index("namespace trojan {"):]
proto_header = proto_header.rsplit("#endif", 1)[0]
proto_source = (ROOT / "src/proto/dns_header.cpp").read_text()
dns_header = (ROOT / "src/tun/dnsserver.h").read_text()
dns_source = (ROOT / "src/tun/dnsserver.cpp").read_text()
cache = dns_header.split("    class DNSCache {", 1)[1].split("\n    class SocketQueryer", 1)[0]

program = r'''
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/io_context.hpp>
#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace tp = std;
#define _guard
#define _unguard
#define _define_getter_const(type, name) type get_##name() const { return name; }
#define _define_getter(type, name) type get_##name() { return name; }
#define _define_is_const(name) bool is_##name() const { return name; }
#define _define_simple_getter_setter(type, name) type get_##name() const { return name; } void set_##name(type v) { name = v; }
#define _log_with_endpoint_ALL(...)
#define _log_with_date_time_ALL(...)
constexpr int one_byte_shift_8_bits = 8, one_byte_mask_0xFF = 255;
constexpr int two_bytes_shift_16_bits = 16, half_byte_mask_0xF = 15, half_byte_shift_4_bits = 4;
uint32_t parse_uint32(size_t offset, const std::string& data) {
    uint32_t result = 0;
    for (size_t i = 0; i < 4; ++i) result = (result << 8) | uint8_t(data.at(offset + i));
    return result;
}

PROTO_HEADER
namespace trojan {
PROTO_FUNCTIONS
}

using namespace trojan;
using namespace boost::asio::ip;

struct Service {
    struct Config {
        struct DNS { bool enable_cached = true; } dns;
        const DNS& get_dns() const { return dns; }
    } config;
    const Config& get_config() const { return config; }
};

namespace Log { constexpr int WARN = 1; }
#define _log_with_date_time(...)

class DNSServer {
public:
    class DNSCache { public: CACHE
    Service* m_service;
    tp::map<std::pair<tp::string, uint16_t>, DNSCache> m_dns_cache;
    mutable tp::map<address, time_t> m_proxy_address_expiry;
    static address normalize_address(const address&);
    void index_addresses(const DNSCache&);
    bool is_ip_in_gfwlist(const address&) const;
    bool is_ip_in_gfwlist(uint32_t ip) const {
        return is_ip_in_gfwlist(address_v4(ip));
    }
    explicit DNSServer(Service* s) : m_service(s) {}
    static bool is_interest_dns_msg(const dns_question&);
    void store_in_dns_cache(const std::string_view&, bool);
};

CACHE_FUNCTIONS

// Old full-rebuild implementation reconstructed from /home/hermes/work/logs/4b-pre-r7.diff
class DNSServerOld {
public:
    using DNSCache = DNSServer::DNSCache;
    Service* m_service;
    tp::vector<DNSCache> m_dns_cache;
    tp::map<address, time_t> m_proxy_address_expiry;
    explicit DNSServerOld(Service* s) : m_service(s) {}

    void rebuild_address_index() {
        m_proxy_address_expiry.clear();
        for (const auto& dns : m_dns_cache) {
            if (dns.is_proxyed()) {
                const auto expiry = dns.get_cached_time() + dns.get_ttl();
                for (const auto& ip : dns.get_ips()) {
                    auto& indexed = m_proxy_address_expiry[ip];
                    indexed = std::max(indexed, expiry);
                }
            }
        }
    }

    void store_in_dns_cache(const std::string_view& data, bool proxyed) {
        if (m_service->get_config().get_dns().enable_cached) {
            tp::string read_data(data);
            tp::istringstream is(read_data);

            dns_answer answer;
            if (is >> answer) {
                if (answer.get_header().QR() == dns_header::QR_RESPONE && answer.get_header().Opcode() == 0 &&
                    (answer.get_header().RCODE() == 0 || answer.get_header().RCODE() == dns_header::RCODE_NAME_ERROR) &&
                    !answer.get_header().TC() && answer.get_questions().size() == 1 &&
                    DNSServer::is_interest_dns_msg(answer.get_questions()[0])) {

                    const auto& domain = answer.get_questions()[0].get_QNAME();
                    const auto qtype = answer.get_questions()[0].get_QTYPE();
                    uint32_t ttl = std::numeric_limits<uint32_t>::max();
                    tp::vector<std::pair<size_t, uint32_t>> ttl_fields;
                    tp::vector<address> A_list;
                    bool has_address = false;
                    const auto collect = [&](const auto& records) {
                        for (const auto& an : records) {
                            if (an.TYPE != 41) {
                                ttl = std::min(ttl, an.TTL);
                                ttl_fields.emplace_back(an.ttl_offset, an.TTL);
                            }
                        }
                    };
                    collect(answer.get_answers());
                    collect(answer.get_authorities());
                    collect(answer.get_additionals());
                    for (const auto& an : answer.get_answers()) {
                        if (an.CLASS == dns_header::QCLASS_INTERNET && an.TYPE == qtype) {
                            has_address = true;
                            if (qtype == dns_header::QTYPE_A_RECORD) {
                                A_list.emplace_back(address_v4(an.A));
                            } else {
                                A_list.emplace_back(DNSServer::normalize_address(address_v6(an.AAAA)));
                            }
                        }
                    }

                    const bool negative = answer.get_header().RCODE() == dns_header::RCODE_NAME_ERROR || !has_address;
                    bool has_soa = false;
                    if (negative) {
                        A_list.clear();
                        uint32_t negative_ttl = 300;
                        for (const auto& an : answer.get_authorities()) {
                            if (an.TYPE == dns_header::QTYPE_SOA && an.CLASS == dns_header::QCLASS_INTERNET) {
                                has_soa = true;
                                negative_ttl = std::min(negative_ttl, std::min(an.TTL, an.soa_minimum));
                            }
                        }
                        ttl = std::min(ttl, negative_ttl);
                        for (auto& field : ttl_fields) field.second = std::min(field.second, ttl);
                    }
                    const auto now = time(nullptr);
                    m_dns_cache.erase(std::remove_if(m_dns_cache.begin(), m_dns_cache.end(), [&](const auto& c) {
                        return c.expired(now) || (c.get_domain() == domain && c.get_qtype() == qtype);
                    }), m_dns_cache.end());
                    if ((!negative || has_soa) && ttl > 0 && ttl != std::numeric_limits<uint32_t>::max()) {
                        std::sort(A_list.begin(), A_list.end());
                        m_dns_cache.emplace_back(domain, qtype, ttl, std::move(ttl_fields), A_list, proxyed, data);
                    }
                    rebuild_address_index();
                }
            }
        }
    }
};

std::string make_response_2ips(const std::string& domain, uint32_t ip1, uint32_t ip2, uint32_t ttl = 300) {
    dns_header h;
    h.QR(1); h.QDCOUNT(1); h.ANCOUNT(2);
    dns_question q;
    q.set_QNAME(domain); q.set_QTYPE(1); q.set_QCLASS(1);
    std::ostringstream os;
    os << h << q;
    auto record = [&](uint32_t life, uint32_t ip_u) {
        os << char(0xc0) << char(0x0c);
        dns_question::encode(os, 1); dns_question::encode(os, 1);
        dns_question::encode(os, life >> 16); dns_question::encode(os, life & 65535);
        dns_question::encode(os, 4);
        uint8_t bytes[4] = {
            static_cast<uint8_t>((ip_u >> 24) & 0xff),
            static_cast<uint8_t>((ip_u >> 16) & 0xff),
            static_cast<uint8_t>((ip_u >> 8) & 0xff),
            static_cast<uint8_t>(ip_u & 0xff)
        };
        os.write(reinterpret_cast<const char*>(bytes), 4);
    };
    record(ttl, ip1);
    record(ttl, ip2);
    return os.str();
}

int main() {
    Service service;
    const std::vector<size_t> test_sizes = {100, 1000, 5000, 20000};

    std::cout << "|     N | old us/op | new us/op | lookup ns/op |" << std::endl;
    std::cout << "|-------|-----------|-----------|--------------|" << std::endl;

    for (size_t n : test_sizes) {
        DNSServer new_server(&service);
        DNSServerOld old_server(&service);

        // Populate new_server with N entries, each containing 2 addresses.
        for (size_t i = 0; i < n; ++i) {
            std::string domain = "domain" + std::to_string(i) + ".example";
            uint32_t ip1 = (10u << 24) | static_cast<uint32_t>(i * 2 + 1);
            uint32_t ip2 = (10u << 24) | static_cast<uint32_t>(i * 2 + 2);
            std::string resp = make_response_2ips(domain, ip1, ip2, 3600);
            new_server.store_in_dns_cache(resp, true);
        }

        // Initialize old_server with the identical N entries and rebuild index once for setup.
        old_server.m_dns_cache.reserve(n);
        for (const auto& kv : new_server.m_dns_cache) {
            old_server.m_dns_cache.push_back(kv.second);
        }
        old_server.rebuild_address_index();

        assert(new_server.m_dns_cache.size() == n);
        assert(old_server.m_dns_cache.size() == n);
        assert(new_server.m_proxy_address_expiry.size() == 2 * n);
        assert(old_server.m_proxy_address_expiry.size() == 2 * n);

        // Response with 2 addresses to benchmark storing into populated cache
        std::string bench_resp = make_response_2ips("bench_target.example", 0xc0000201, 0xc0000202, 300);

        // 1. Measure old full-rebuild store cost
        size_t iters_old = (n <= 100) ? 1000 : (n <= 1000 ? 200 : (n <= 5000 ? 50 : 20));
        auto t0 = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < iters_old; ++i) {
            old_server.store_in_dns_cache(bench_resp, true);
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        double old_us = std::chrono::duration<double, std::micro>(t1 - t0).count() / iters_old;

        // 2. Measure new incremental store cost
        size_t iters_new = 5000;
        auto t2 = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < iters_new; ++i) {
            new_server.store_in_dns_cache(bench_resp, true);
        }
        auto t3 = std::chrono::high_resolution_clock::now();
        double new_us = std::chrono::duration<double, std::micro>(t3 - t2).count() / iters_new;

        // 3. Measure lookup cost of is_ip_in_gfwlist at same N (50% hit, 50% miss)
        size_t lookup_iters = 100000;
        volatile int hits = 0;
        auto t4 = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < lookup_iters; ++i) {
            uint32_t ip_u = (i & 1) ? ((10u << 24) | static_cast<uint32_t>((i % n) * 2 + 1))
                                    : (198u << 24 | static_cast<uint32_t>(i));
            if (new_server.is_ip_in_gfwlist(ip_u)) {
                hits = hits + 1;
            }
        }
        auto t5 = std::chrono::high_resolution_clock::now();
        double lookup_ns = std::chrono::duration<double, std::nano>(t5 - t4).count() / lookup_iters;

        std::cout << "| " << std::setw(5) << n
                  << " | " << std::setw(9) << std::fixed << std::setprecision(2) << old_us
                  << " | " << std::setw(9) << std::fixed << std::setprecision(2) << new_us
                  << " | " << std::setw(12) << std::fixed << std::setprecision(1) << lookup_ns
                  << " |" << std::endl;
    }
    return 0;
}
'''

proto_functions = "\n".join(function(proto_source, signature) for signature in [
    "std::istream& dns_header::read_label", "std::ostream& dns_header::write_label",
    "std::istream& dns_answer::read_answer", "std::istream& operator>>(std::istream& is, dns_answer& answer)",
])
cache_functions = "\n".join(function(dns_source, signature) for signature in [
    "bool DNSServer::is_interest_dns_msg(const trojan::dns_question&",
    "void DNSServer::store_in_dns_cache(",
    "address DNSServer::normalize_address(", "void DNSServer::index_addresses(",
    "bool DNSServer::is_ip_in_gfwlist(",
])

program = program.replace("PROTO_HEADER", proto_header).replace("PROTO_FUNCTIONS", proto_functions)
program = program.replace("CACHE_FUNCTIONS", cache_functions).replace("CACHE", cache)

with tempfile.TemporaryDirectory(prefix=".dns-bench-", dir=ROOT) as directory:
    cpp = Path(directory) / "bench.cpp"
    binary = Path(directory) / "bench"
    cpp.write_text(program)
    subprocess.run(["c++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
