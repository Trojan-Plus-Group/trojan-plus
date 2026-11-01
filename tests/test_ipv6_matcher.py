#!/usr/bin/env python3
"""Compile production IPMatcher / IPv4Matcher / IPv6Matcher; check mixed lists and load time."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
header = (ROOT / "src/core/utils.h").read_text()
source = (ROOT / "src/core/utils.cpp").read_text()
declaration = "class IPv4Matcher {" + header.split("class IPv4Matcher {", 1)[1].split(
    "// prefer_ipv4", 1
)[0]
implementation = "static const uint32_t mask_values[] = {" + source.split(
    "static const uint32_t mask_values[] = {", 1
)[1].split("bool set_udp_send_recv_buf", 1)[0]
route_implementation = (ROOT / "src/tun/tundev.cpp").read_text().split(
    "bool TUNDev::should_proxy", 1
)[1].split("err_t TUNDev::listener_accept_func", 1)[0]
program = r'''
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <chrono>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include <cassert>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
namespace tp = std;
namespace Log { constexpr int WARN = 1; constexpr int ERROR = 2; }
#define _guard
#define _unguard
#define _test_case_assert(value, expected) assert((value) == (expected))
namespace gsl {
    template <typename T, size_t N> const T& at(const T (&array)[N], size_t i) { return array[i]; }
}
unsigned warnings = 0;
void _log_with_date_time(const std::string&, int) { ++warnings; }
DECLARATION
IMPLEMENTATION
struct CountingMatcher : IPMatcher {
    mutable unsigned calls = 0;
    bool is_match(const boost::asio::ip::address& address) const {
        ++calls;
        return IPMatcher::is_match(address);
    }
};
struct Config {
    enum { route_all, route_bypass_local, route_bypass_cn_mainland,
           route_bypass_local_and_cn_mainland, route_gfwlist, route_cn_mainland };
    struct Route {
        int proxy_type = route_cn_mainland;
        CountingMatcher _cn_mainland_ips_matcher, _white_ips_matcher, _proxy_ips_matcher;
    } route;
    const Route& get_route() const { return route; }
};
struct Service {
    Config config;
    const Config& get_config() const { return config; }
};
struct DNS {
    mutable unsigned calls = 0;
    bool matched = false;
    bool is_ip_in_gfwlist(const boost::asio::ip::address&) const { ++calls; return matched; }
};
struct TUNDev {
    Service* m_service;
    DNS* m_dns_server = nullptr;
    bool should_proxy(const boost::asio::ip::address& addr) const;
};
using boost::asio::ip::make_address_v4;
using boost::asio::ip::v4_mapped;
bool TUNDev::should_proxy ROUTE_IMPLEMENTATION
int main() {
    IPv6Matcher matcher;
    size_t count = 99;
    auto match = [&](const char* ip) {
        return matcher.is_match(boost::asio::ip::make_address_v6(ip));
    };
    std::istringstream input(
        " # comment\n2001:db8::1/128\n2001:db8::/127\n2001:db8::2/127\n"
        "2001:db8:1::abcd/64 # normalize host bits\r\n"
        "::ffff:192.0.2.1\nffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n"
        "2001:db8::/129\n2001:db8::/-1\n2001:db8::/\n2001:db8::/64x\n"
        "fe80::1%2\nnot-an-ip\n2001:db8::/99999999999999999999999999\n");
    assert(matcher.load_from_stream(input, "test", count));
    assert(count == 6 && warnings == 7);
    assert(match("2001:db8::") && match("2001:db8::3"));
    assert(!match("2001:db8::4"));
    assert(match("2001:db8:1::") && match("2001:db8:1:0:ffff:ffff:ffff:ffff"));
    assert(!match("2001:db8:2::"));
    assert(match("::ffff:192.0.2.1") && !match("::ffff:192.0.2.2"));
    assert(match("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    std::istringstream edges("2001:db8::ff/128\n2001:db8::100/128\n8000::/1\n");
    assert(matcher.load_from_stream(edges, "edges", count) && count == 3);
    assert(match("2001:db8::ff") && match("2001:db8::100"));
    assert(!match("2001:db8::fe") && !match("2001:db8::101"));
    assert(match("8000::") && !match("7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    std::istringstream subnet48("2001:db8:abcd:1234::/48\n");
    assert(matcher.load_from_stream(subnet48, "48", count) && count == 1);
    assert(match("2001:db8:abcd::") && match("2001:db8:abcd:ffff:ffff:ffff:ffff:ffff"));
    assert(!match("2001:db8:abcc:ffff:ffff:ffff:ffff:ffff") && !match("2001:db8:abce::"));
    std::istringstream all("::/0\n2001:db8::/32\n");
    assert(matcher.load_from_stream(all, "all", count) && count == 2);
    assert(match("::") && match("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    std::istringstream empty("");
    assert(matcher.load_from_stream(empty, "empty", count) && count == 0);
    assert(!match("::"));

    IPMatcher mixed;
    size_t v4_count = 99, v6_count = 99;
    auto mixed_match = [&](const char* ip) {
        return mixed.is_match(boost::asio::ip::make_address(ip));
    };
    std::istringstream small(
        "192.0.2.0/24\n2001:db8::/127\n# comment: no address\n"
        "198.51.100.7\n2001:db8:1::1 # comment\n2001:db8::/129\n");
    assert(mixed.load_from_stream(small, "mixed", v4_count, v6_count));
    assert(v4_count == 2 && v6_count == 2 && mixed.has_ipv6());
    assert(mixed_match("192.0.2.0") && mixed_match("192.0.2.255"));
    assert(!mixed_match("192.0.1.255") && !mixed_match("192.0.3.0"));
    assert(mixed_match("::ffff:192.0.2.1") && !mixed_match("::ffff:192.0.3.0"));
    assert(mixed_match("2001:db8::") && mixed_match("2001:db8::1"));
    assert(!mixed_match("2001:db8::2") && mixed_match("2001:db8:1::1"));

    // Preserve legacy IPv4 filtering, atoi, and error logs without stricter validation.
    const auto before = warnings;
    std::istringstream legacy("text192.0.2.7\n198.51.100.0/24junk\n0.0.0.0/0\n192.0.2.1/33\n");
    assert(mixed.load_from_stream(legacy, "legacy", v4_count, v6_count));
    assert(v4_count == 2 && v6_count == 0 && !mixed.has_ipv6());
    assert(warnings == before + 2 && mixed_match("192.0.2.7"));
    assert(!mixed_match("2001:db8::1"));
    std::istringstream invalid("2001:db8::/129\n");
    assert(mixed.load_from_stream(invalid, "invalid", v4_count, v6_count));
    assert(v4_count == 0 && v6_count == 0 && !mixed.has_ipv6());
    assert(!mixed_match("192.0.2.7"));
    assert(!mixed.load_from_file("/nonexistent/ip-matcher-list", v4_count, v6_count));
    assert(v4_count == 0 && v6_count == 0 && !mixed.has_ipv6());

    // Each unrelated list alone must leave mainland-only fallback intact.
    for (bool proxy_list : {false, true}) {
        Service isolated;
        TUNDev isolated_tun{&isolated};
        std::istringstream unrelated("2001:db8::/64\n");
        auto& list = proxy_list ? isolated.config.route._proxy_ips_matcher : isolated.config.route._white_ips_matcher;
        assert(list.load_from_stream(unrelated, "unrelated", v4_count, v6_count));
        assert(isolated_tun.should_proxy(boost::asio::ip::make_address("2001:db9::1")));
    }
    Service no_lists;
    no_lists.config.route.proxy_type = Config::route_gfwlist;
    DNS unmatched_dns;
    TUNDev no_lists_tun{&no_lists, &unmatched_dns};
    assert(!no_lists_tun.should_proxy(boost::asio::ip::make_address("2001:db9::1")));
    assert(unmatched_dns.calls == 1); // No IPv6 lists must not bypass DNS lookup.

    Service service;
    TUNDev tun{&service};
    auto proxy = [&](const char* ip) { return tun.should_proxy(boost::asio::ip::make_address(ip)); };
    assert(proxy("2001:db8::1")); // Zero valid IPv6 entries overrides route_cn_mainland.
    std::istringstream bad_route("2001:db8::/129\n");
    service.config.route._white_ips_matcher.load_from_stream(bad_route, "bad", v4_count, v6_count);
    assert(proxy("2001:db8::1"));
    std::istringstream white("2001:db8::/64\n192.0.2.0/24\n");
    service.config.route._white_ips_matcher.load_from_stream(white, "white", v4_count, v6_count);
    assert(!proxy("2001:db8::1") && proxy("2001:db9::1")); // White-only IPv6 data must not disable mainland fallback.
    assert(!proxy("::ffff:192.0.2.1"));
    std::istringstream forced("2001:db8::1\n192.0.2.1\n");
    service.config.route._proxy_ips_matcher.load_from_stream(forced, "proxy", v4_count, v6_count);
    assert(proxy("2001:db8::1") && proxy("::ffff:192.0.2.1"));
    assert(proxy("2001:db9::1")); // Proxy-only IPv6 data must not disable mainland fallback.
    auto& route = service.config.route;
    DNS dns;
    tun.m_dns_server = &dns;
    auto reset_calls = [&] {
        route._proxy_ips_matcher.calls = route._white_ips_matcher.calls = route._cn_mainland_ips_matcher.calls = dns.calls = 0;
    };
    reset_calls();
    assert(proxy("2001:db8::1")); // Proxy beats white and stops before white/mainland/DNS.
    assert(route._proxy_ips_matcher.calls == 1 && route._white_ips_matcher.calls == 0);
    assert(route._cn_mainland_ips_matcher.calls == 0 && dns.calls == 0);
    reset_calls();
    assert(!proxy("2001:db8::2"));
    assert(route._proxy_ips_matcher.calls == 1 && route._white_ips_matcher.calls == 1);
    assert(route._cn_mainland_ips_matcher.calls == 0 && dns.calls == 0);
    service.config.route.proxy_type = Config::route_gfwlist;
    reset_calls();
    assert(!proxy("2001:db9::1") && !proxy("198.51.100.1")); // Unmatched native IPv6 DNS mapping stays direct.
    assert(route._cn_mainland_ips_matcher.calls == 0 && dns.calls == 2);
    dns.matched = true;
    assert(proxy("2001:db9::1"));
    tun.m_dns_server = nullptr;
    assert(!proxy("2001:db9::1"));
    tun.m_dns_server = &dns;
    for (int mode : {Config::route_all, Config::route_bypass_local}) {
        route.proxy_type = mode;
        reset_calls();
        assert(proxy("2001:db9::1"));
        assert(route._cn_mainland_ips_matcher.calls == 0 && dns.calls == 0);
    }
    service.config.route.proxy_type = Config::route_bypass_cn_mainland;
    std::istringstream mainland("2001:db9::/32\n");
    service.config.route._cn_mainland_ips_matcher.load_from_stream(mainland, "cn", v4_count, v6_count);
    reset_calls();
    assert(!proxy("2001:db9::1") && proxy("2001:dba::1"));
    assert(route._cn_mainland_ips_matcher.calls == 2 && dns.calls == 0);
    route.proxy_type = Config::route_cn_mainland;
    assert(proxy("2001:db9::1") && !proxy("2001:dba::1"));
    assert(!proxy("::ffff:198.51.100.1")); // Native-v6 fallback must not apply to mapped IPv4.

    // Gap 2: Malformed IPv6 lines in a mixed route file
    {
        IPMatcher malformed_mixed;
        size_t m_v4 = 99, m_v6 = 99;
        const auto prev_warn = warnings;
        std::istringstream bad_mixed_stream(
            "192.0.2.0/24\n"
            "2001:db8:1::/48\n"
            "2001:db8:2::/129\n"
            "2001:db8:2::/-1\n"
            "2001:db8:2::/\n"
            "2001:db8:2::/64x\n"
            "fe80::1%eth0\n"
            "fe80::2%2\n"
            "not:a:valid:ipv6:address\n"
            "random_plain_text\n"
            "2001:db8:2::/99999999999999999999999999\n"
            "   \t  \r\n"
            "# comment line only\n"
            "198.51.100.1\n"
            "2001:db8:4::/64\n"
        );
        assert(malformed_mixed.load_from_stream(bad_mixed_stream, "bad_mixed", m_v4, m_v6));
        assert(m_v4 == 2 && m_v6 == 2 && malformed_mixed.has_ipv6());
        assert(warnings > prev_warn);
        assert(malformed_mixed.is_match(boost::asio::ip::make_address("192.0.2.1")));
        assert(malformed_mixed.is_match(boost::asio::ip::make_address("198.51.100.1")));
        assert(malformed_mixed.is_match(boost::asio::ip::make_address("2001:db8:1::1")));
        assert(malformed_mixed.is_match(boost::asio::ip::make_address("2001:db8:4::1")));
        assert(!malformed_mixed.is_match(boost::asio::ip::make_address("2001:db8:2::1")));
        assert(!malformed_mixed.is_match(boost::asio::ip::make_address("fe80::1")));
    }

    // Gap 1: Old IPv4-only route files and configs
    {
        IPMatcher v4_only;
        size_t old_v4 = 99, old_v6 = 99;
        std::istringstream old_stream(
            "10.0.0.0/8\n"
            "172.16.0.0/12\n"
            "192.168.1.1/32\n"
            "192.168.100.5\n"
            "# just a comment\n"
            "1.0.0.0/8\n"
        );
        assert(v4_only.load_from_stream(old_stream, "old_v4", old_v4, old_v6));
        assert(old_v4 == 5 && old_v6 == 0 && !v4_only.has_ipv6());
        std::string log_msg = "[route] load " + std::to_string(old_v4) + " IPv4 + " +
                              std::to_string(old_v6) + " IPv6 cn_mainland_ips from file old_v4.txt";
        assert(log_msg == "[route] load 5 IPv4 + 0 IPv6 cn_mainland_ips from file old_v4.txt");

        Service v4_service;
        TUNDev v4_tun{&v4_service};
        auto v4_proxy = [&](const char* ip) {
            return v4_tun.should_proxy(boost::asio::ip::make_address(ip));
        };

        size_t c_v4 = 0, c_v6 = 0;
        std::istringstream cn_v4("10.0.0.0/8\n");
        v4_service.config.route._cn_mainland_ips_matcher.load_from_stream(cn_v4, "cn", c_v4, c_v6);

        v4_service.config.route.proxy_type = Config::route_all;
        assert(v4_proxy("10.1.2.3") && v4_proxy("1.2.3.4"));

        v4_service.config.route.proxy_type = Config::route_bypass_local;
        assert(v4_proxy("10.1.2.3") && v4_proxy("1.2.3.4"));

        v4_service.config.route.proxy_type = Config::route_bypass_cn_mainland;
        assert(!v4_proxy("10.1.2.3") && v4_proxy("1.2.3.4"));

        v4_service.config.route.proxy_type = Config::route_bypass_local_and_cn_mainland;
        assert(!v4_proxy("10.1.2.3") && v4_proxy("1.2.3.4"));

        DNS gfw_dns;
        v4_tun.m_dns_server = &gfw_dns;
        v4_service.config.route.proxy_type = Config::route_gfwlist;
        assert(!v4_proxy("1.2.3.4"));
        gfw_dns.matched = true;
        assert(v4_proxy("1.2.3.4"));

        v4_service.config.route.proxy_type = Config::route_cn_mainland;
        assert(v4_proxy("10.1.2.3") && !v4_proxy("1.2.3.4"));

        std::istringstream p_v4("1.2.3.4\n");
        v4_service.config.route._proxy_ips_matcher.load_from_stream(p_v4, "proxy", c_v4, c_v6);
        assert(v4_proxy("1.2.3.4"));

        std::istringstream w_v4("10.1.2.3\n");
        v4_service.config.route._white_ips_matcher.load_from_stream(w_v4, "white", c_v4, c_v6);
        assert(!v4_proxy("10.1.2.3"));
    }

    // Gap 5: route_bypass_local_and_cn_mainland with native IPv6
    {
        Service s_mode3;
        TUNDev tun_mode3{&s_mode3};
        s_mode3.config.route.proxy_type = Config::route_bypass_local_and_cn_mainland;
        auto m3_proxy = [&](const char* ip) {
            return tun_mode3.should_proxy(boost::asio::ip::make_address(ip));
        };

        // (a) WITHOUT mainland IPv6 entries:
        size_t v4_c = 0, v6_c = 0;
        std::istringstream cn_v4_only("10.0.0.0/8\n");
        s_mode3.config.route._cn_mainland_ips_matcher.load_from_stream(cn_v4_only, "cn_v4", v4_c, v6_c);
        assert(!s_mode3.config.route._cn_mainland_ips_matcher.has_ipv6());

        assert(m3_proxy("2001:db8::1"));
        assert(m3_proxy("2001:db9::1"));

        std::istringstream white_v6("2001:db8::1\n");
        s_mode3.config.route._white_ips_matcher.load_from_stream(white_v6, "w_v6", v4_c, v6_c);
        assert(!m3_proxy("2001:db8::1"));
        assert(m3_proxy("2001:db9::1"));

        std::istringstream proxy_v6("2001:db8::1\n");
        s_mode3.config.route._proxy_ips_matcher.load_from_stream(proxy_v6, "p_v6", v4_c, v6_c);
        assert(m3_proxy("2001:db8::1"));

        // (b) WITH mainland IPv6 entries:
        std::istringstream empty_str("");
        s_mode3.config.route._white_ips_matcher.load_from_stream(empty_str, "empty", v4_c, v6_c);
        s_mode3.config.route._proxy_ips_matcher.load_from_stream(empty_str, "empty", v4_c, v6_c);

        std::istringstream cn_mixed("10.0.0.0/8\n2001:db9::/32\n");
        s_mode3.config.route._cn_mainland_ips_matcher.load_from_stream(cn_mixed, "cn_mixed", v4_c, v6_c);
        assert(s_mode3.config.route._cn_mainland_ips_matcher.has_ipv6());

        assert(!m3_proxy("2001:db9::1"));
        assert(!m3_proxy("2001:db9:ffff::1"));
        assert(m3_proxy("2001:db8::1"));
        assert(m3_proxy("2001:dba::1"));

        std::istringstream p_override("2001:db9::1\n");
        s_mode3.config.route._proxy_ips_matcher.load_from_stream(p_override, "p_ov", v4_c, v6_c);
        assert(m3_proxy("2001:db9::1"));

        std::istringstream w_override("2001:dba::1\n");
        s_mode3.config.route._white_ips_matcher.load_from_stream(w_override, "w_ov", v4_c, v6_c);
        assert(!m3_proxy("2001:dba::1"));

        assert(!m3_proxy("::ffff:10.1.2.3"));
        assert(m3_proxy("::ffff:1.2.3.4"));
    }

    std::ostringstream large;
    for (unsigned i = 0; i < 8800; ++i) {
        large << "10." << i / 256 << '.' << i % 256 << ".17/24\n";
        if (i < 1500) {
            large << "2001:db8:" << std::hex << i << std::dec << ":abcd::1/48\n";
        }
    }
    std::istringstream scale(large.str());
    const auto started = std::chrono::steady_clock::now();
    assert(mixed.load_from_stream(scale, "scale", v4_count, v6_count));
    const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    assert(v4_count == 8800 && v6_count == 1500 && mixed.has_ipv6());
    assert(mixed_match("10.0.0.0") && mixed_match("10.34.95.255"));
    assert(!mixed_match("9.255.255.255") && !mixed_match("10.34.96.0"));
    assert(mixed_match("2001:db8::") && mixed_match("2001:db8:5db:ffff:ffff:ffff:ffff:ffff"));
    assert(!mixed_match("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff") && !mixed_match("2001:db8:5dc::"));
    assert(elapsed < 5.0);
    std::cout << "8800 IPv4 + 1500 IPv6 load: " << elapsed << " s\n";
}
'''.replace("DECLARATION", declaration).replace("ROUTE_IMPLEMENTATION", route_implementation).replace("IMPLEMENTATION", implementation)
# Keep temporary build artifacts inside the worktree.
with tempfile.TemporaryDirectory(prefix=".ipv6-matcher-", dir=ROOT) as directory:
    cpp = Path(directory) / "test.cpp"
    binary = Path(directory) / "test"
    cpp.write_text(program)
    subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(cpp), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
print("IPMatcher / IPv6Matcher / should_proxy checks passed")
