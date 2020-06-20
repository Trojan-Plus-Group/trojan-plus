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

#include <cstdint>
#include <map>
#include <boost/property_tree/ptree.hpp>
#include <boost/asio/ssl.hpp>
#include "log.h"
#include "utils.h"

class Config {
   
public:
    enum RunType {
        SERVER,
        CLIENT,
        FORWARD,
        NAT,

        CLIENT_TUN,
        SERVERT_TUN
    };

    using SSLConfig = struct {
        bool verify;
        bool verify_hostname;
        std::string cert;
        std::string key;
        std::string key_password;
        std::string cipher;
        std::string cipher_tls13;
        bool prefer_server_cipher;
        std::string sni;
        std::string alpn;
        std::map<std::string, uint16_t> alpn_port_override;
        bool reuse_session;
        bool session_ticket;
        long session_timeout;
        int ssl_shutdown_wait_time;
        std::string plain_http_response;
        std::string curves;
        std::string dhparam;
    };
    using TCPConfig = struct {
        bool prefer_ipv4;
        bool no_delay;
        bool keep_alive;
        bool reuse_port;
        bool fast_open;
        int fast_open_qlen;
        int connect_time_out;
    };

    using MySQLConfig = struct  {
        bool enabled;
        std::string server_addr;
        uint16_t server_port;
        std::string database;
        std::string username;
        std::string password;
        std::string cafile;
    };

    using Experimental = struct{
        uint32_t pipeline_num;
        uint32_t pipeline_ack_window;
        std::vector<std::string> pipeline_loadbalance_configs;
        std::vector<std::shared_ptr<Config>> _pipeline_loadbalance_configs;
        std::vector<std::shared_ptr<boost::asio::ssl::context>> _pipeline_loadbalance_context;
        bool pipeline_proxy_icmp;
    };

    using TUN = struct{
        std::string tun_name;
        std::string net_ip;
        std::string net_mask;
        uint16_t mtu;
        int tun_fd;
    };

private:

    RunType run_type;
    std::string local_addr;
    uint16_t local_port;
    std::string remote_addr;
    uint16_t remote_port;
    std::string target_addr;
    uint16_t target_port;
    std::map<std::string, std::string> password;
    int udp_timeout;
    int udp_socket_buf;
    int udp_forward_socket_buf;
    int udp_recv_buf;
    Log::Level log_level;
    SSLConfig ssl;
    TCPConfig tcp;
    MySQLConfig mysql;
    Experimental experimental;
    TUN tun;

    int compare_hash = 0;

    void populate(const boost::property_tree::ptree &tree);
    void populate(const std::string &JSON);
    
    static std::string SHA224(const std::string &message);

public:
    [[nodiscard]] bool sip003();
    void load(const std::string &filename);
    void prepare_ssl_context(boost::asio::ssl::context& ssl_context, std::string& plain_http_response);
    void prepare_ssl_reuse(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& socket) const;
    [[nodiscard]] bool operator==(const Config& other) const{ return compare_hash == other.compare_hash; }
    [[nodiscard]] bool try_prepare_pipeline_proxy_icmp(bool is_ipv4);

    _define_getter_const(RunType, run_type)
    _define_getter_const(const std::string&, local_addr)
    _define_getter_const(uint16_t, local_port)
    _define_getter_const(const std::string&, remote_addr)
    _define_getter_const(uint16_t, remote_port)
    _define_getter_const(const std::string&, target_addr)
    _define_getter_const(uint16_t, target_port)
    [[nodiscard]] const std::map<std::string, std::string>& get_password() const {return password;}
    _define_getter_const(int, udp_timeout)
    _define_getter_const(int, udp_socket_buf)
    _define_getter_const(int, udp_forward_socket_buf)
    _define_getter_const(int, udp_recv_buf)
    _define_getter_const(Log::Level, log_level)
    _define_getter_const(const SSLConfig&, ssl)
    _define_getter_const(const TCPConfig&, tcp)
    _define_getter_const(const MySQLConfig&, mysql)
    _define_getter_const(const Experimental&, experimental)
    _define_getter_const(const TUN&, tun)
};

#endif // _CONFIG_H_
