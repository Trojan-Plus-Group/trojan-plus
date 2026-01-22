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
#include "mem/memallocator.h"
#include "core/utils.h"
#include "proto/dns_header.h"

class UDPForwardSession;
class UDPLocalForwarder;
class Service;
class DNSServer : public std::enable_shared_from_this<DNSServer> {
  public:
    using DataQueryHandler =
      std::function<void(const boost::asio::ip::udp::endpoint& src, tp::streambuf& data)>;
    class IDataQueryer : public std::enable_shared_from_this<IDataQueryer> {
      public:
        virtual ~IDataQueryer(){};

        virtual bool open(DataQueryHandler&& handler, int port)                                   = 0;
        virtual bool send(const boost::asio::ip::udp::endpoint& to, const std::string_view& data) = 0;
    };

  private:
    enum { DEFAULT_UP_STREAM_NS_SVR_PORT = 53 };

    class DNSCache {
        tp::string domain;
        int ttl;
        tp::vector<uint32_t> ips;
        bool proxyed;
        time_t cached_time{time(nullptr)};
        tp::string answer_data;

      public:
        DNSCache(
          tp::string _domain, int _ttl, tp::vector<uint32_t>& _ips, bool _proxyed, const std::string_view& data)
            : domain(std::move(_domain)), ttl(_ttl), ips(std::move(_ips)), proxyed(_proxyed), answer_data(data) {}

        [[nodiscard]] inline bool expired(time_t curr) const { return int(curr - cached_time) >= ttl; }

        _define_getter_const(const tp::string&, domain);
        _define_getter_const(int, ttl);
        _define_getter_const(const tp::vector<uint32_t>&, ips);
        _define_getter_const(time_t, cached_time);
        _define_is_const(proxyed);

        _define_getter(tp::string&, answer_data);
    };

    class SocketQueryer : public IDataQueryer {
        Service* service;
        boost::asio::ip::udp::socket socket;
        ReadBufWithGuard buf;
        boost::asio::ip::udp::endpoint recv_endpoint;
        DataQueryHandler data_handler;

        void async_read_udp();

      public:
        SocketQueryer(Service* serv);
        ~SocketQueryer();

        bool open(DataQueryHandler&& handler, int port) override;
        bool send(const boost::asio::ip::udp::endpoint& to, const std::string_view& data) override;
    };

    Service* m_service;
    tp::vector<DNSCache> m_dns_cache;

    std::shared_ptr<IDataQueryer> m_data_queryer;
    boost::asio::ip::udp::endpoint m_udp_recv_endpoint;

    tp::list<std::weak_ptr<UDPForwardSession>> m_proxy_forwarders;
    tp::list<std::weak_ptr<UDPLocalForwarder>> m_forwarders;

    void in_recved(std::istream& is, const trojan::dns_header& header, const std::string_view& former_data);
    void async_read_udp();
    void recv_up_stream_data(
      const boost::asio::ip::udp::endpoint& local_src, const std::string_view& data, bool proxyed);
    void send_to_local(const boost::asio::ip::udp::endpoint& local_src, const std::string_view& data);
    bool find_in_dns_cache(const boost::asio::ip::udp::endpoint& local_src, const trojan::dns_header& header,
      const trojan::dns_question& question);
    void store_in_dns_cache(const std::string_view& data, bool proxyed);

    [[nodiscard]] bool try_to_find_existed(
      const boost::asio::ip::udp::endpoint& local_src, const std::string_view& data);

    [[nodiscard]] bool is_remote_domain(const tp::string& domain) const;

    [[nodiscard]] static bool is_interest_dns_msg(const trojan::dns_header& hdr);

    [[nodiscard]] static bool is_interest_dns_msg(const trojan::dns_question& question);

    static FILE_LOCK_HANDLE s_dns_file_lock;

  public:
    DNSServer(Service* _service);
    DNSServer(Service* _service, std::shared_ptr<IDataQueryer> queryer);
    ~DNSServer();

    void destroy();
    [[nodiscard]] bool start();
    [[nodiscard]] bool is_ip_in_gfwlist(uint32_t ip) const;

    [[nodiscard]] static bool get_dns_lock();
};

#endif //_TROJAN_DNS_SERVER_HPP
