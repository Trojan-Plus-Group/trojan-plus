/*
 * This file is part of the Trojan Plus project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Trojan Plus is derived from original trojan project and writing
 * for more experimental features.
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

#ifndef _TROJAN_DNS_SERVER_HPP
#define _TROJAN_DNS_SERVER_HPP

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/streambuf.hpp>
#include <ctime>
#include <istream>
#include <memory>
#include <string>
#include <vector>

#include "core/utils.h"
#include "proto/dns_header.h"

class UDPForwardSession;
class UDPLocalForwarder;
class Service;
class DNSServer : public std::enable_shared_from_this<DNSServer> {

    enum { DEFAULT_UP_STREAM_NS_SVR_PORT = 53 };

    class DNSCache {
        std::string domain;
        int ttl;
        time_t cached_time{time(nullptr)};
        std::string answer_data;

      public:
        DNSCache(std::string _domain, int _ttl, const std::string_view& data)
            : domain(std::move(_domain)), ttl(_ttl), answer_data(data) {}

        [[nodiscard]] inline bool expired(time_t curr) const { return int(curr - cached_time) >= ttl; }

        _define_getter_const(const std::string&, domain) _define_getter_const(int, ttl);
        _define_getter_const(time_t, cached_time);

        _define_getter(std::string&, answer_data);
    };

    Service* m_service;

    std::vector<DNSCache> m_dns_cache;
    boost::asio::ip::udp::socket m_serv_udp_socket;
    ReadBufWithGuard m_udp_read_buf;
    boost::asio::ip::udp::endpoint m_udp_recv_endpoint;

    std::list<std::weak_ptr<UDPForwardSession>> m_proxy_forwarders;
    std::list<std::weak_ptr<UDPLocalForwarder>> m_forwarders;

    void in_recved(std::istream& is, const trojan::dns_header& header, const std::string_view& former_data);
    void async_read_udp();
    void recv_up_stream_data(const boost::asio::ip::udp::endpoint& local_src, const std::string_view& data);
    void send_to_local(const boost::asio::ip::udp::endpoint& local_src, const std::string_view& data);
    bool find_in_dns_cache(const boost::asio::ip::udp::endpoint& local_src, const trojan::dns_header& header,
      const trojan::dns_question& question);
    void store_in_dns_cache(const std::string_view& data);

    [[nodiscard]] bool is_in_gfwlist(const std::string& domain) const;

    [[nodiscard]] bool try_to_find_existed(
      const boost::asio::ip::udp::endpoint& local_src, const std::string_view& data);

    [[nodiscard]] static bool is_proxy_dns_msg(const trojan::dns_header& hdr);

    [[nodiscard]] static bool is_proxy_dns_msg(const trojan::dns_question& question);

    static int s_dns_file_lock;

  public:
    DNSServer(Service* _service);
    ~DNSServer();

    bool start();
    static bool get_dns_lock();
};

#endif //_TROJAN_DNS_SERVER_HPP
