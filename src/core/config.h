/*
 * This file is part of the Trojan Plus project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Trojan Plus is derived from original trojan project and writing
 * for more experimental features.
 * Copyright (C) 2017-2020  The Trojan Authors.
 * Copyright (C) 2020 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "log.h"
#include "utils.h"
#include <boost/asio/ssl.hpp>
#include <boost/property_tree/ptree.hpp>
#include <cstdint>
#include <map>
#include <vector>
#include "mem/memallocator.h"

class Config {

  public:
    enum { MAX_PASSWORD_LENGTH = (EVP_MAX_MD_SIZE << 1) };
    enum RunType {
        SERVER,
        CLIENT,
        FORWARD,
        NAT,

        CLIENT_TUN,
        SERVERT_TUN
    };

    enum RouteType {
        route_all                          = 0, // controlled by route table
        route_bypass_local                 = 1, // controlled by route table
        route_bypass_cn_mainland           = 2,
        route_bypass_local_and_cn_mainland = 3,
        route_gfwlist                      = 4,
        route_cn_mainland                  = 5,
    };

    using SSLConfig = struct {
        bool verify;
        bool verify_hostname;
        tp::string cert;
        tp::string key;
        tp::string key_password;
        tp::string cipher;
        tp::string cipher_tls13;
        bool prefer_server_cipher;
        tp::string sni;
        tp::string alpn;
        tp::map<tp::string, uint16_t> alpn_port_override;
        bool reuse_session;
        bool session_ticket;
        long session_timeout;
        int ssl_shutdown_wait_time;
        tp::string plain_http_response;
        tp::string curves;
        tp::string dhparam;
    };
    using TCPConfig = struct {
        bool prefer_ipv4;
        bool no_delay;
        bool keep_alive;
        bool reuse_port;
        bool fast_open;
        bool use_tproxy;
        int fast_open_qlen;
        int connect_time_out;
    };

    using Experimental = struct {
        uint32_t pipeline_num;
        uint32_t pipeline_timeout;
        uint32_t pipeline_ack_window;
        tp::vector<tp::string> pipeline_loadbalance_configs;
        tp::vector<std::shared_ptr<Config>> _pipeline_loadbalance_configs;
        tp::vector<std::shared_ptr<boost::asio::ssl::context>> _pipeline_loadbalance_context;
        bool pipeline_proxy_icmp;
    };

    using TUN = struct {
        tp::string tun_name;
        tp::string net_ip;
        tp::string net_mask;
        uint16_t mtu;
        int tun_fd;
        bool redirect_local; // redirect all ip to localhost for test
    };

    using DNS = struct {
        bool enabled;
        uint16_t port;
        int udp_timeout;
        int udp_recv_buf;
        int udp_socket_buf;
        tp::string gfwlist;
        bool enable_cached;
        bool enable_ping_test;
        DomainMatcher _gfwlist_matcher;
        tp::vector<tp::string> up_dns_server;
        tp::vector<tp::string> up_gfw_dns_server;
    };

    using ROUTE = struct {
        bool enabled;
        RouteType proxy_type;

        tp::string cn_mainland_ips_file;
        IPv4Matcher _cn_mainland_ips_matcher;

        tp::string white_ips;
        IPv4Matcher _white_ips_matcher;

        tp::string proxy_ips;
        IPv4Matcher _proxy_ips_matcher;
    };

  private:
    RunType run_type;
    tp::string local_addr;
    uint16_t local_port;
    tp::string remote_addr;
    uint16_t remote_port;
    tp::string target_addr;
    uint16_t target_port;
    tp::map<tp::string, tp::string> password;
    int udp_timeout;
    int udp_socket_buf;
    int udp_forward_socket_buf;
    int udp_recv_buf;
    Log::Level log_level;
    SSLConfig ssl;
    TCPConfig tcp;
    Experimental experimental;
    TUN tun;
    DNS dns;
    ROUTE route;

    int compare_hash = 0;

    void populate(const boost::property_tree::ptree& tree);
    void populate(const tp::string& JSON);

    void load_dns(const boost::property_tree::ptree& tree);

    static tp::string SHA224(const tp::string& message);

  public:
    [[nodiscard]] bool sip003();
    void load(const tp::string& filename);
    void prepare_ssl_context(boost::asio::ssl::context& ssl_context, tp::string& plain_http_response);
    void prepare_ssl_reuse(SSLSocket& socket) const;
    [[nodiscard]] bool operator==(const Config& other) const { return compare_hash == other.compare_hash; }
    [[nodiscard]] bool try_prepare_pipeline_proxy_icmp(bool is_ipv4);

    _define_getter_const(RunType, run_type);
    _define_getter_const(const tp::string&, local_addr);
    _define_getter_const(uint16_t, local_port);
    _define_getter_const(const tp::string&, remote_addr);
    _define_getter_const(uint16_t, remote_port);
    _define_getter_const(const tp::string&, target_addr);
    _define_getter_const(uint16_t, target_port);
    [[nodiscard]] const tp::map<tp::string, tp::string>& get_password() const { return password; }
    _define_getter_const(int, udp_timeout);
    _define_getter_const(int, udp_socket_buf);
    _define_getter_const(int, udp_forward_socket_buf);
    _define_getter_const(int, udp_recv_buf);
    _define_getter_const(Log::Level, log_level);
    _define_getter_const(const SSLConfig&, ssl);
    _define_getter_const(const TCPConfig&, tcp);
    _define_getter_const(const Experimental&, experimental);
    _define_getter_const(const TUN&, tun);
    _define_getter_const(const DNS&, dns);
    _define_getter_const(const ROUTE&, route);
};

#endif // _CONFIG_H_
