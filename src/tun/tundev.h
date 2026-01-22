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

#ifndef _TROJAN_TUNDEV_HPP
#define _TROJAN_TUNDEV_HPP

#include <list>
#include <memory>
#include <string>

#include <lwip/init.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>
#include <lwip/ip_addr.h>
#include <lwip/nd6.h>
#include <lwip/netif.h>
#include <lwip/priv/tcp_priv.h>
#include <lwip/tcp.h>

#ifdef __linux__
#include <linux/if_tun.h>
#include <linux/input.h>
#endif

#include <boost/asio/io_context.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/streambuf.hpp>

#include "mem/memallocator.h"
#include "core/config.h"

#ifndef _WIN32
using BoostStreamDescriptor = boost::asio::posix::stream_descriptor;
#else
class BoostStreamDescriptor {
  public:
    BoostStreamDescriptor(boost::asio::io_context&) {}
    void assign(int) {}

    template <typename ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers, boost::system::error_code& ec) {
        return 0;
    }

    template <typename ConstBufferSequence, typename Handler>
    void async_read_some(const ConstBufferSequence&, Handler&&) {}

    void close() {}
    void release() {}
};
#endif

class Service;
class lwip_tcp_client;
class TUNSession;
class DNSServer;
class TUNDNSQueryer;
// this class canot support ipv6
class TUNDev {

    enum IPVersion { IPV4 = 4, IPV6 = 6 };
    enum DefaultVar { Default_UDP_TTL = 60 };

    static TUNDev* sm_tundev;
    static err_t static_netif_init_func(struct netif* netif) { return sm_tundev->netif_init_func(netif); }

    static err_t static_netif_input_func(struct pbuf* p, struct netif* inp) {
        return sm_tundev->netif_input_func(p, inp);
    }

    static err_t static_netif_output_func(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr) {
        return sm_tundev->netif_output_func(netif, p, ipaddr);
    }

    static err_t static_listener_accept_func(void* arg, struct tcp_pcb* newpcb, err_t err) {
        return ((TUNDev*)arg)->listener_accept_func(newpcb, err);
    }

    // lwip TUN netif device handler
    struct netif m_netif {};
    bool m_netif_configured;

    // lwip TCP listener
    struct tcp_pcb* m_tcp_listener;

    err_t netif_init_func(struct netif* netif) const;
    err_t netif_input_func(struct pbuf* p, struct netif* inp);
    err_t netif_output_func(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr);

    err_t listener_accept_func(struct tcp_pcb* newpcb, err_t err);

  private:
    tp::list<std::shared_ptr<lwip_tcp_client>> m_tcp_clients;
    tp::list<std::shared_ptr<TUNSession>> m_udp_clients;

    Service* m_service;
    std::shared_ptr<DNSServer> m_dns_server;
    std::shared_ptr<TUNDNSQueryer> m_dns_queryer;
    boost::asio::ip::udp::endpoint m_dns_server_endpoint;
    int m_tun_fd;
    const bool m_is_outside_tun_fd;
    uint16_t m_mtu;

    bool m_quitting;
    tp::streambuf m_write_fill_buf;
    tp::streambuf m_writing_buf;

    tp::streambuf m_sd_read_buffer;
    BoostStreamDescriptor m_boost_sd;

    tp::string m_packet_parse_buff;

    void async_read();
    void write_to_tun();

    int try_to_process_udp_packet(uint8_t* data, int data_len);
    void parse_packet();
    void input_netif_packet(const uint8_t* data, uint16_t packet_len);
    int handle_write_upd_data(const TUNSession* _session, std::string_view& data_str);
    int handle_write_upd_data(const boost::asio::ip::udp::endpoint& local_endpoint,
      const boost::asio::ip::udp::endpoint& remote_endpoint, std::string_view& data_str);

    [[nodiscard]] bool proxy_by_route(uint32_t ip) const;

  public:
    TUNDev(Service* _service, const tp::string& _tun_name, const tp::string& _ipaddr, const tp::string& _netmask,
      uint16_t _mtu, int _outside_tun_fd = -1);
    ~TUNDev();

    void destroy();
    [[nodiscard]] int get_tun_fd() const { return m_tun_fd; }
};
#endif //_TROJAN_TUNDEV_HPP
