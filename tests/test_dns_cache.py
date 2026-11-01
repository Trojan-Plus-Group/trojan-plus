#!/usr/bin/env python3
"""Compile production DNS parsing and cache code without TLS dependencies."""
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
#include <cstdint>
#include <ctime>
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
void output_debug_info_ec(const boost::system::error_code&) { assert(false); }
class SocketHarness {
public:
    using DataQueryHandler = std::function<void()>;
    boost::asio::io_context io;
    udp::socket socket{io};
    DataQueryHandler data_handler;
    void async_read_udp() {}
    bool open(DataQueryHandler&&, int);
    bool send(const udp::endpoint&, const std::string_view&);
};
SOCKET_FUNCTIONS
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
    tp::string sent;
    explicit DNSServer(Service* s) : m_service(s) {}
    static bool is_interest_dns_msg(const dns_question&);
    bool find_in_dns_cache(const udp::endpoint&, const dns_header&, const dns_question&);
    void store_in_dns_cache(const std::string_view&, bool);
    void send_to_local(const udp::endpoint&, const std::string_view& data) { sent = data; }
};
CACHE_FUNCTIONS
std::string response(uint16_t type, uint32_t ttl, bool cname = false) {
    dns_header h;
    h.QR(1); h.QDCOUNT(1); h.ANCOUNT(cname ? 2 : 1);
    dns_question q;
    q.set_QNAME("example.com"); q.set_QTYPE(type); q.set_QCLASS(1);
    std::ostringstream os;
    os << h << q;
    auto record = [&](uint16_t t, uint32_t life, const std::string& bytes) {
        os << char(0xc0) << char(0x0c);
        dns_question::encode(os, t); dns_question::encode(os, 1);
        dns_question::encode(os, life >> 16); dns_question::encode(os, life & 65535);
        dns_question::encode(os, bytes.size()); os << bytes;
    };
    if (cname) record(5, 10, std::string("\xc0\x0c", 2));
    record(type, ttl, std::string(type == 1 ? 4 : 16, '\x01'));
    return os.str();
}
std::string custom_response(const std::string& domain, uint16_t type, uint32_t ttl,
                            const std::vector<address>& addrs, bool cname = false) {
    dns_header h;
    h.QR(1); h.QDCOUNT(1); h.ANCOUNT((cname ? 1 : 0) + static_cast<uint16_t>(addrs.size()));
    dns_question q;
    q.set_QNAME(domain); q.set_QTYPE(type); q.set_QCLASS(1);
    std::ostringstream os;
    os << h << q;
    auto record = [&](uint16_t t, uint32_t life, const std::string& bytes) {
        os << char(0xc0) << char(0x0c);
        dns_question::encode(os, t); dns_question::encode(os, 1);
        dns_question::encode(os, life >> 16); dns_question::encode(os, life & 65535);
        dns_question::encode(os, bytes.size()); os << bytes;
    };
    if (cname) record(5, 10, std::string("\xc0\x0c", 2));
    for (const auto& addr : addrs) {
        if (addr.is_v4()) {
            const auto bytes = addr.to_v4().to_bytes();
            record(1, ttl, std::string(reinterpret_cast<const char*>(bytes.data()), 4));
        } else {
            const auto bytes = addr.to_v6().to_bytes();
            record(28, ttl, std::string(reinterpret_cast<const char*>(bytes.data()), 16));
        }
    }
    return os.str();
}
std::string negative_response(uint16_t type, uint8_t rcode, uint32_t ttl, uint32_t minimum,
                              bool soa = true, int malformed = 0) {
    dns_header h; h.QR(1); h.QDCOUNT(1); h.RCODE(rcode); h.NSCOUNT(soa ? 1 : 0);
    dns_question q; q.set_QNAME("negative.example"); q.set_QTYPE(type); q.set_QCLASS(1);
    std::ostringstream os; os << h << q;
    if (soa) {
        os << char(0xc0) << char(0x0c);
        dns_question::encode(os, 6); dns_question::encode(os, 1);
        dns_question::encode(os, ttl >> 16); dns_question::encode(os, ttl & 65535);
        dns_question::encode(os, malformed == 1 ? 23 : 24);
        if (malformed == 2) {
            const auto self = static_cast<uint16_t>(os.tellp());
            os << char(0xc0 | (self >> 8)) << char(self & 255);
        } else os << char(0xc0) << char(0x0c);
        os << char(0xc0) << char(0x0c);
        for (int i = 0; i < 4; ++i) { dns_question::encode(os, 0); dns_question::encode(os, 1); }
        dns_question::encode(os, minimum >> 16); dns_question::encode(os, minimum & 65535);
    }
    return os.str();
}
int main() {
    SocketHarness socket;
    assert(socket.open([] {}, 0));
    if (socket.socket.local_endpoint().protocol() == udp::v6()) {
        assert(socket.send(udp::endpoint(address_v6::loopback(), socket.socket.local_endpoint().port()), "v6"));
    }
    assert(socket.send(udp::endpoint(address_v4::loopback(), socket.socket.local_endpoint().port()), "v4"));
    Service service;
    DNSServer dns(&service);
    dns_header h; h.ID(1234); h.QDCOUNT(1);
    dns_question q; q.set_QNAME("example.com"); q.set_QCLASS(1); q.set_QTYPE(1);
    udp::endpoint local;
    dns.store_in_dns_cache(response(1, 60), false);
    assert(dns.find_in_dns_cache(local, h, q));
    q.set_QTYPE(28);
    assert(!dns.find_in_dns_cache(local, h, q));
    dns.store_in_dns_cache(response(28, 30, true), true);
    assert(dns.m_dns_cache.size() == 2);
    assert(dns.m_dns_cache.at({"example.com", 28}).get_ttl() == 10);
    assert(dns.m_dns_cache.at({"example.com", 28}).get_ips().size() == 1);
    const auto v6 = make_address("101:101:101:101:101:101:101:101");
    const auto v4 = make_address("1.1.1.1");
    assert(dns.is_ip_in_gfwlist(v6));
    assert(!dns.is_ip_in_gfwlist(v4));
    DNSServer routing(&service);
    routing.store_in_dns_cache(response(28, 60), false);
    assert(!routing.is_ip_in_gfwlist(v6));
    routing.store_in_dns_cache(response(28, 60), true);
    assert(routing.is_ip_in_gfwlist(v6));
    routing.store_in_dns_cache(response(28, 60), false);
    assert(routing.is_ip_in_gfwlist(v6)); // direct replacement retains prior proxied address
    routing.store_in_dns_cache(response(1, 60), true);
    assert(routing.is_ip_in_gfwlist(v4));
    assert(routing.is_ip_in_gfwlist(make_address("::ffff:1.1.1.1")));
    routing.store_in_dns_cache(response(1, 60), false);
    assert(routing.is_ip_in_gfwlist(v4));
    auto mapped = response(28, 60);
    const auto mapped_bytes = make_address_v6("::ffff:1.1.1.1").to_bytes();
    mapped.replace(mapped.size() - 16, 16, reinterpret_cast<const char*>(mapped_bytes.data()), 16);
    routing.store_in_dns_cache(mapped, true);
    assert(routing.is_ip_in_gfwlist(v4));
    assert(routing.is_ip_in_gfwlist(make_address("::ffff:1.1.1.1")));
    routing.store_in_dns_cache(response(1, 60), true);
    routing.store_in_dns_cache(response(28, 0), false);
    assert(routing.is_ip_in_gfwlist(v4)); // zero-TTL replacement retains prior address
    routing.m_proxy_address_expiry[v4] = time(nullptr) - 1;
    assert(!routing.is_ip_in_gfwlist(v4));
    assert(routing.m_proxy_address_expiry.count(v4) == 0);
    // Expired index entries disappear without a DNS lookup.
    dns.m_proxy_address_expiry[v6] = time(nullptr) - 1;
    assert(!dns.is_ip_in_gfwlist(v6));
    assert(dns.m_proxy_address_expiry.count(v6) == 0);
    // Index updates retain maximum expiry and addresses from replaced answers.
    {
        DNSServer retained(&service);
        retained.store_in_dns_cache(response(1, 600), true);
        const auto expiry = retained.m_proxy_address_expiry.at(v4);
        retained.store_in_dns_cache(response(1, 1), true);
        assert(retained.m_proxy_address_expiry.at(v4) == expiry);
        auto changed = response(1, 60);
        changed.replace(changed.size() - 4, 4, std::string(4, '\x02'));
        retained.store_in_dns_cache(changed, true);
        assert(retained.m_dns_cache.size() == 1);
        assert(retained.is_ip_in_gfwlist(v4));
        assert(retained.is_ip_in_gfwlist(make_address("2.2.2.2")));
        // Response processing does not scan expired cache or index entries.
        retained.m_dns_cache.at({"example.com", 1}).cached_time -= 61;
        retained.m_proxy_address_expiry[v4] = time(nullptr) - 1;
        retained.store_in_dns_cache(response(28, 60), true);
        assert(retained.m_dns_cache.size() == 2);
        assert(retained.m_proxy_address_expiry.count(v4) == 1);
        dns_question lookup = q;
        lookup.set_QTYPE(1);
        assert(!retained.find_in_dns_cache(local, h, lookup));
        assert(retained.m_dns_cache.size() == 1);
        assert(retained.m_proxy_address_expiry.count(v4) == 0);
    }
    // Verify wire TTL matches local expiry.
    const auto now = time(nullptr);
    auto& entry = dns.m_dns_cache.at({"example.com", 28});
    entry.cached_time -= 3;
    assert(dns.find_in_dns_cache(local, h, q));
    std::istringstream input(dns.sent);
    dns_answer answer; input >> answer;
    assert(input && answer.get_header().ID() == 1234);
    assert(answer.get_questions()[0].get_QTYPE() == 28);
    const auto age = static_cast<uint32_t>(time(nullptr) - entry.get_cached_time());
    assert(answer.get_answers()[0].TTL <= 10 && answer.get_answers()[0].TTL >= 10 - age);
    assert(answer.get_answers()[1].TTL <= 30 && answer.get_answers()[1].TTL >= 30 - age);
    assert(entry.expired(now + 11));
    dns.store_in_dns_cache(response(28, 40), true);
    assert(dns.m_dns_cache.size() == 2 && dns.m_dns_cache.at({"example.com", 28}).get_ttl() == 40);
    dns.store_in_dns_cache(response(1, 0), false);
    assert(dns.m_dns_cache.size() == 1);
    q.set_QTYPE(1);
    assert(!dns.find_in_dns_cache(local, h, q));
    auto malformed = response(28, 30);
    malformed.resize(malformed.size() - 1);
    std::istringstream bad(malformed); dns_answer invalid; bad >> invalid;
    assert(!bad);
    // RFC 2308: keyed by name/type, authority SOA required, cap 300.
    DNSServer negative(&service);
    q.set_QNAME("negative.example"); q.set_QTYPE(28);
    negative.store_in_dns_cache(negative_response(28, 0, 60, 12), true);
    assert(negative.m_dns_cache.size() == 1 && negative.m_dns_cache.at({"negative.example", 28}).get_ttl() == 12);
    assert(negative.find_in_dns_cache(local, h, q)); // second query is cache hit
    assert(negative.m_dns_cache.at({"negative.example", 28}).get_ips().empty());
    q.set_QTYPE(1); assert(!negative.find_in_dns_cache(local, h, q)); q.set_QTYPE(28);
    negative.m_dns_cache.at({"negative.example", 28}).cached_time -= 3;
    h.ID(4321); assert(negative.find_in_dns_cache(local, h, q));
    std::istringstream neg_input(negative.sent); dns_answer neg_answer; neg_input >> neg_answer;
    assert(neg_input && neg_answer.get_header().ID() == 4321);
    assert(neg_answer.get_authorities()[0].TTL <= 9);
    negative.m_dns_cache.at({"negative.example", 28}).cached_time -= 12;
    assert(!negative.find_in_dns_cache(local, h, q));
    negative.store_in_dns_cache(negative_response(28, 3, 900, 800), false);
    assert(negative.m_dns_cache.at({"negative.example", 28}).get_ttl() == 300);
    assert(negative.find_in_dns_cache(local, h, q));
    std::istringstream nx_input(negative.sent); dns_answer nx; nx_input >> nx;
    assert(nx_input && nx.get_header().RCODE() == 3 && nx.get_authorities()[0].TTL <= 300);
    negative.store_in_dns_cache(negative_response(28, 3, 900, 800, false), false);
    assert(!negative.find_in_dns_cache(local, h, q));
    negative.store_in_dns_cache(negative_response(28, 0, 60, 12, false), false);
    assert(negative.m_dns_cache.empty());
    negative.store_in_dns_cache(negative_response(28, 0, 0, 12), false);
    assert(negative.m_dns_cache.empty());
    negative.store_in_dns_cache(negative_response(28, 0, 60, 0), false);
    assert(negative.m_dns_cache.empty());
    for (int malformed_soa : {1, 2}) {
        const auto raw = negative_response(28, 0, 60, 12, true, malformed_soa);
        std::istringstream stream(raw); dns_answer parsed; stream >> parsed;
        assert(!stream);
        negative.store_in_dns_cache(raw, false);
        assert(negative.m_dns_cache.empty());
    }
    auto truncated_soa = negative_response(28, 3, 60, 12);
    truncated_soa.pop_back();
    negative.store_in_dns_cache(truncated_soa, false);
    assert(negative.m_dns_cache.empty());

    // Unit tests for dns_header::read_label: pointer loops, forward pointers, overlong names
    {
        // 1. Self pointer at offset 0
        std::string self_ptr = "\xc0\x00";
        std::istringstream s1(self_ptr);
        tp::string name;
        dns_header::read_label(s1, name);
        assert(!s1);

        // 2. Self pointer after a label: offset 4 points to 4
        std::string self_ptr2 = "\x03foo\xc0\x04";
        std::istringstream s2(self_ptr2);
        name.clear();
        dns_header::read_label(s2, name);
        assert(!s2);

        // 3. Forward pointer: offset 0 points to offset 16
        std::string fwd_ptr = std::string("\xc0\x10", 2) + std::string(14, '\0') + std::string("\x03", 1) + "bar" + std::string("\x00", 1);
        std::istringstream s3(fwd_ptr);
        name.clear();
        dns_header::read_label(s3, name);
        assert(!s3);

        // 4. Over-long name: wire length > 255 bytes (5 labels of 60 bytes each = 305 bytes)
        std::string long_name;
        for (int i = 0; i < 5; ++i) {
            long_name += char(60);
            long_name.append(60, 'a' + i);
        }
        long_name += '\0';
        std::istringstream s4(long_name);
        name.clear();
        dns_header::read_label(s4, name);
        assert(!s4);

        // 5. Reserved bits in sign: 0x40 or 0x80
        for (uint8_t bad_sign : {uint8_t(0x40), uint8_t(0x80)}) {
            std::string res_sign(1, char(bad_sign));
            res_sign += std::string("\x03", 1) + "foo" + std::string("\x00", 1);
            std::istringstream s5(res_sign);
            name.clear();
            dns_header::read_label(s5, name);
            assert(!s5);
        }

        // 6. Out-of-bounds pointer
        std::string oob_ptr = "\xc0\x7f";
        std::istringstream s6(oob_ptr);
        name.clear();
        dns_header::read_label(s6, name);
        assert(!s6);
    }

    // Malformed packets in read_answer / store_in_dns_cache
    {
        // Malformed question with forward pointer
        std::string bad_q_resp;
        {
            dns_header bh; bh.QR(1); bh.QDCOUNT(1);
            std::ostringstream os;
            os << bh;
            os << "\xc0\x10\x00\x01\x00\x01"; // forward ptr question
            bad_q_resp = os.str();
        }
        std::istringstream bq_stream(bad_q_resp);
        dns_answer bq_ans;
        bq_stream >> bq_ans;
        assert(!bq_stream);
        dns.store_in_dns_cache(bad_q_resp, false);

        // Malformed answer with self-pointer in CNAME
        std::string bad_cname_resp;
        {
            dns_header bh; bh.QR(1); bh.QDCOUNT(1); bh.ANCOUNT(1);
            dns_question bq; bq.set_QNAME("cname.loop"); bq.set_QTYPE(1); bq.set_QCLASS(1);
            std::ostringstream os;
            os << bh << bq;
            os << char(0xc0) << char(0x0c); // name ptr to question
            dns_question::encode(os, 5); // TYPE CNAME
            dns_question::encode(os, 1); // CLASS IN
            dns_question::encode(os, 0); dns_question::encode(os, 60); // TTL 60
            const auto cname_offset = static_cast<uint16_t>(os.tellp()) + 2;
            dns_question::encode(os, 2); // RDLENGTH 2
            os << char(0xc0 | (cname_offset >> 8)) << char(cname_offset & 0xff); // points to itself
            bad_cname_resp = os.str();
        }
        std::istringstream bc_stream(bad_cname_resp);
        dns_answer bc_ans;
        bc_stream >> bc_ans;
        assert(!bc_stream);
        dns.store_in_dns_cache(bad_cname_resp, false);
    }

    // dns.enable_cached = false: positive/negative caching completely disabled
    {
        service.config.dns.enable_cached = false;
        DNSServer no_cache(&service);
        no_cache.store_in_dns_cache(response(1, 60), false);
        assert(no_cache.m_dns_cache.empty());
        no_cache.store_in_dns_cache(response(28, 60), true);
        assert(no_cache.m_dns_cache.empty());
        assert(no_cache.m_proxy_address_expiry.empty());
        no_cache.store_in_dns_cache(negative_response(28, 0, 60, 12), true);
        assert(no_cache.m_dns_cache.empty());
        no_cache.store_in_dns_cache(negative_response(28, 3, 60, 12), false);
        assert(no_cache.m_dns_cache.empty());
        q.set_QNAME("example.com"); q.set_QTYPE(1);
        assert(!no_cache.find_in_dns_cache(local, h, q));
        q.set_QTYPE(28);
        assert(!no_cache.find_in_dns_cache(local, h, q));
        service.config.dns.enable_cached = true;
    }

    // Query structure: QDCOUNT != 1 and TC == 1 checks
    {
        dns.store_in_dns_cache(response(1, 60), false);
        q.set_QNAME("example.com"); q.set_QTYPE(1);
        h.QDCOUNT(0);
        assert(!dns.find_in_dns_cache(local, h, q));
        h.QDCOUNT(2);
        assert(!dns.find_in_dns_cache(local, h, q));
        h.QDCOUNT(1);
        assert(dns.find_in_dns_cache(local, h, q));

        std::string tc_resp = response(1, 60);
        tc_resp[2] |= 0x02; // TC bit
        DNSServer tc_dns(&service);
        tc_dns.store_in_dns_cache(tc_resp, false);
        assert(tc_dns.m_dns_cache.empty());
    }

    // 1. Shared address between two domains & max expiry retention across domains
    {
        DNSServer shared(&service);
        const auto shared_ip = make_address("198.51.100.1");
        const auto now = time(nullptr);
        shared.store_in_dns_cache(custom_response("domain-a.org", 1, 60, {shared_ip}), true);
        assert(shared.is_ip_in_gfwlist(shared_ip));
        const auto expiry_a = shared.m_proxy_address_expiry.at(shared_ip);
        assert(expiry_a >= now + 60);

        shared.store_in_dns_cache(custom_response("domain-b.org", 1, 300, {shared_ip}), true);
        const auto expiry_b = shared.m_proxy_address_expiry.at(shared_ip);
        assert(expiry_b >= now + 300);
        assert(expiry_b > expiry_a);

        // domain-c resolves to the same IP but is unproxied; proxy expiry must NOT shrink or be removed
        shared.store_in_dns_cache(custom_response("domain-c.org", 1, 10, {shared_ip}), false);
        assert(shared.m_proxy_address_expiry.at(shared_ip) == expiry_b);
        assert(shared.is_ip_in_gfwlist(shared_ip));

        // Replacement of domain-a with a different IP does not affect shared_ip
        shared.store_in_dns_cache(custom_response("domain-a.org", 1, 60, {make_address("198.51.100.2")}), true);
        assert(shared.is_ip_in_gfwlist(shared_ip));
        assert(shared.is_ip_in_gfwlist(make_address("198.51.100.2")));

        // Old address remains valid until domain-b's expiry
        shared.m_proxy_address_expiry[shared_ip] = time(nullptr) - 1;
        assert(!shared.is_ip_in_gfwlist(shared_ip));
        assert(shared.m_proxy_address_expiry.count(shared_ip) == 0);
    }

    // 2. Incremental extend (larger TTL extends expiry, smaller TTL does not shrink)
    {
        DNSServer ext(&service);
        const auto ip = make_address("203.0.113.10");
        const auto start_time = time(nullptr);
        ext.store_in_dns_cache(custom_response("extend.org", 1, 100, {ip}), true);
        const auto exp1 = ext.m_proxy_address_expiry.at(ip);
        assert(exp1 >= start_time + 100);

        ext.store_in_dns_cache(custom_response("extend.org", 1, 20, {ip}), true);
        assert(ext.m_proxy_address_expiry.at(ip) == exp1);

        ext.store_in_dns_cache(custom_response("extend.org", 1, 500, {ip}), true);
        const auto exp2 = ext.m_proxy_address_expiry.at(ip);
        assert(exp2 > exp1);
        assert(exp2 >= start_time + 500);
    }

    // 3. Replacement keeps old addresses until their own expiry
    {
        DNSServer repl(&service);
        const auto old_ip = make_address("192.0.2.1");
        const auto new_ip = make_address("192.0.2.2");
        repl.store_in_dns_cache(custom_response("replace.org", 1, 60, {old_ip}), true);
        assert(repl.is_ip_in_gfwlist(old_ip));

        repl.store_in_dns_cache(custom_response("replace.org", 1, 120, {new_ip}), true);
        assert(repl.is_ip_in_gfwlist(old_ip));
        assert(repl.is_ip_in_gfwlist(new_ip));

        repl.m_proxy_address_expiry[old_ip] = time(nullptr) - 1;
        assert(!repl.is_ip_in_gfwlist(old_ip));
        assert(repl.m_proxy_address_expiry.count(old_ip) == 0);
        assert(repl.is_ip_in_gfwlist(new_ip));
    }

    // 4. Lazy expiry erase on lookup (IPv4, native IPv6, v4-mapped IPv6, uint32_t)
    {
        DNSServer lazy(&service);
        const auto l_v4 = make_address("192.0.2.10");
        const auto l_v6 = make_address("2001:db8::10");
        lazy.store_in_dns_cache(custom_response("lazy4.org", 1, 60, {l_v4}), true);
        lazy.store_in_dns_cache(custom_response("lazy6.org", 28, 60, {l_v6}), true);
        assert(lazy.is_ip_in_gfwlist(l_v4));
        assert(lazy.is_ip_in_gfwlist(l_v6));
        assert(lazy.is_ip_in_gfwlist(l_v4.to_v4().to_uint()));
        assert(lazy.is_ip_in_gfwlist(make_address("::ffff:192.0.2.10")));

        lazy.m_proxy_address_expiry[l_v4] = time(nullptr) - 1;
        assert(!lazy.is_ip_in_gfwlist(make_address("::ffff:192.0.2.10")));
        assert(lazy.m_proxy_address_expiry.count(l_v4) == 0);

        lazy.m_proxy_address_expiry[l_v6] = time(nullptr) - 1;
        assert(!lazy.is_ip_in_gfwlist(l_v6));
        assert(lazy.m_proxy_address_expiry.count(l_v6) == 0);

        assert(!lazy.is_ip_in_gfwlist(make_address("192.0.2.99")));
        assert(!lazy.is_ip_in_gfwlist(l_v4.to_v4().to_uint()));
    }

    // 5. Pruning on find_in_dns_cache (expired entries pruned, active entries retained)
    {
        DNSServer prune(&service);
        const auto act_ip = make_address("192.0.2.20");
        const auto exp_ip = make_address("192.0.2.21");
        prune.store_in_dns_cache(custom_response("active.org", 1, 300, {act_ip}), true);
        prune.store_in_dns_cache(custom_response("stale.org", 1, 10, {exp_ip}), true);
        assert(prune.m_dns_cache.size() == 2);
        assert(prune.m_proxy_address_expiry.size() == 2);

        prune.m_dns_cache.at({"stale.org", 1}).cached_time -= 20;
        prune.m_proxy_address_expiry[exp_ip] = time(nullptr) - 5;

        dns_header qh; qh.ID(5555); qh.QDCOUNT(1);
        dns_question q_act;
        q_act.set_QNAME("active.org"); q_act.set_QCLASS(1); q_act.set_QTYPE(1);
        assert(prune.find_in_dns_cache(local, qh, q_act));

        assert(prune.m_dns_cache.size() == 1);
        assert(prune.m_dns_cache.count({"active.org", 1}) == 1);
        assert(prune.m_proxy_address_expiry.size() == 1);
        assert(prune.m_proxy_address_expiry.count(act_ip) == 1);
        assert(prune.m_proxy_address_expiry.count(exp_ip) == 0);
    }

    // 6. IPv4 and v4-mapped normalization
    {
        assert(DNSServer::normalize_address(make_address("192.0.2.1")) == make_address("192.0.2.1"));
        assert(DNSServer::normalize_address(make_address("::ffff:192.0.2.1")) == make_address("192.0.2.1"));
        assert(DNSServer::normalize_address(make_address("2001:db8::1")) == make_address("2001:db8::1"));

        DNSServer norm(&service);
        const auto mapped_ip = make_address("::ffff:198.51.100.50");
        norm.store_in_dns_cache(custom_response("mapped.org", 28, 60, {mapped_ip}), true);

        assert(norm.m_proxy_address_expiry.count(make_address("198.51.100.50")) == 1);
        assert(norm.m_proxy_address_expiry.count(mapped_ip) == 0);
        assert(norm.is_ip_in_gfwlist(make_address("198.51.100.50")));
        assert(norm.is_ip_in_gfwlist(mapped_ip));
        assert(norm.is_ip_in_gfwlist(make_address_v4("198.51.100.50").to_uint()));
    }

    // 7. Non-proxied answers not indexed
    {
        DNSServer unproxied(&service);
        const auto unp4 = make_address("192.0.2.100");
        const auto unp6 = make_address("2001:db8::100");
        unproxied.store_in_dns_cache(custom_response("clean.org", 1, 60, {unp4}), false);
        unproxied.store_in_dns_cache(custom_response("clean.org", 28, 60, {unp6}), false);

        assert(unproxied.m_proxy_address_expiry.empty());
        assert(!unproxied.is_ip_in_gfwlist(unp4));
        assert(!unproxied.is_ip_in_gfwlist(unp6));
        assert(unproxied.m_dns_cache.size() == 2);
        dns_header qh; qh.ID(6666); qh.QDCOUNT(1);
        dns_question q_unp;
        q_unp.set_QNAME("clean.org"); q_unp.set_QCLASS(1); q_unp.set_QTYPE(1);
        assert(unproxied.find_in_dns_cache(local, qh, q_unp));
    }

    // 8. Negative answers not indexed (even when proxyed=true)
    {
        DNSServer neg_idx(&service);
        neg_idx.store_in_dns_cache(negative_response(1, 0, 60, 30), true);
        neg_idx.store_in_dns_cache(negative_response(28, 3, 60, 30), true);

        assert(neg_idx.m_dns_cache.size() == 2);
        assert(neg_idx.m_proxy_address_expiry.empty());
        assert(!neg_idx.is_ip_in_gfwlist(make_address("192.0.2.1")));
        assert(!neg_idx.is_ip_in_gfwlist(make_address("2001:db8::1")));
    }
}
'''
proto_functions = "\n".join(function(proto_source, signature) for signature in [
    "std::istream& dns_header::read_label", "std::ostream& dns_header::write_label",
    "std::istream& dns_answer::read_answer", "std::istream& operator>>(std::istream& is, dns_answer& answer)",
])
cache_functions = "\n".join(function(dns_source, signature) for signature in [
    "bool DNSServer::is_interest_dns_msg(const trojan::dns_question&",
    "bool DNSServer::find_in_dns_cache(", "void DNSServer::store_in_dns_cache(",
    "address DNSServer::normalize_address(", "void DNSServer::index_addresses(",
    "bool DNSServer::is_ip_in_gfwlist(",
])
socket_functions = "\n".join(function(dns_source, signature) for signature in [
    "bool DNSServer::SocketQueryer::open(", "bool DNSServer::SocketQueryer::send(",
]).replace("DNSServer::SocketQueryer::", "SocketHarness::")
program = program.replace("SOCKET_FUNCTIONS", socket_functions)
program = program.replace("PROTO_HEADER", proto_header).replace("PROTO_FUNCTIONS", proto_functions)
program = program.replace("CACHE_FUNCTIONS", cache_functions).replace("CACHE", cache)
with tempfile.TemporaryDirectory(prefix=".dns-cache-", dir=ROOT) as directory:
    cpp = Path(directory) / "test.cpp"
    binary = Path(directory) / "test"
    cpp.write_text(program)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("DNS cache checks passed")
