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

#include "tundev.h"

#include <cstring>
#include <stdexcept>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <functional>

#include <lwip/ip6.h>
#include <lwip/ip6_addr.h>
#include <misc/ipv4_proto.h>
#include <misc/udp_proto.h>

#include "tun/lwip_addr.h"

#include "proto/ipv4_header.h"
#include "proto/ipv6_header.h"

#include "core/log.h"
#include "core/service.h"
#include "tun/dnsserver.h"
#include "tun/lwip_tcp_client.h"
#include "tun/tunlocalsession.h"
#include "tun/tunproxysession.h"
#include "tun/tunsession.h"
#include "mem/memallocator.h"

using namespace boost::asio::ip;

static void tcp_remove(struct tcp_pcb* pcb_list) {
    struct tcp_pcb* pcb  = pcb_list;
    struct tcp_pcb* pcb2 = nullptr;

    while (pcb != nullptr) {
        pcb2 = pcb;
        pcb  = pcb->next;
        tcp_abort(pcb2);
    }
}

using DNSSendHanlder = std::function<bool(const boost::asio::ip::udp::endpoint& to, const std::string_view& data)>;
class TUNDNSQueryer : public DNSServer::IDataQueryer {
    DNSServer::DataQueryHandler data_handler;
    DNSSendHanlder send_handler;
    tp::streambuf buf;

  public:
    TUNDNSQueryer(DNSSendHanlder&& sender) : send_handler(std::move(sender)) {}

    void recved(const boost::asio::ip::udp::endpoint& from, const std::string_view& data) {
        buf.consume(buf.size());
        streambuf_append(buf, data);

        data_handler(from, buf);
    }

    bool open(DNSServer::DataQueryHandler&& handler, int) override {
        data_handler = std::move(handler);
        return true;
    }
    bool send(const boost::asio::ip::udp::endpoint& to, const std::string_view& data) override {
        return send_handler(to, data);
    }
};

namespace {

using boost::asio::ip::address_v4;
using boost::asio::ip::address_v6;
using boost::asio::ip::make_address;
using boost::asio::ip::make_address_v4;
using boost::asio::ip::make_address_v6;

struct TunAddresses {
    bool have_v4{false};
    bool have_v6{false};
    address_v4 v4;
    address_v6 v6;
    uint8_t prefix{64};
};

address_v6 parse_tun_ipv6(const tp::string& text) {
    if (text.find('%') != tp::string::npos) {
        throw std::runtime_error("[tun] IPv6 address must not include a zone id");
    }

    boost::system::error_code ec;
    const auto addr = make_address(text.c_str(), ec);
    if (ec || !addr.is_v6()) {
        throw std::runtime_error((tp::string("[tun] invalid IPv6 address ") + text).c_str());
    }

    const auto v6 = addr.to_v6();
    if (v6.is_unspecified() || v6.is_multicast() || v6.is_v4_mapped() || v6.scope_id() != 0) {
        throw std::runtime_error((tp::string("[tun] unsupported IPv6 tun address ") + text).c_str());
    }
    return v6;
}

uint8_t prefix_from_ipv6_mask(const tp::string& mask, uint8_t fallback) {
    if (mask.empty() || mask.find(':') == tp::string::npos) {
        return fallback;
    }

    boost::system::error_code ec;
    const auto addr = make_address(mask.c_str(), ec);
    if (ec || !addr.is_v6()) {
        return fallback;
    }

    uint8_t prefix = 0;
    bool seen_zero = false;
    for (const auto byte : addr.to_v6().to_bytes()) {
        for (int bit = 7; bit >= 0; --bit) {
            if ((byte & static_cast<uint8_t>(1u << bit)) != 0) {
                if (seen_zero) {
                    return fallback;
                }
                ++prefix;
            } else {
                seen_zero = true;
            }
        }
    }
    return prefix;
}

TunAddresses resolve_tun_addresses(const tp::string& net_ip, const tp::string& net_mask, const tp::string& net_ipv6,
  uint8_t prefix) {
    TunAddresses out;
    out.prefix = prefix;

    if (!net_ipv6.empty()) {
        out.v6      = parse_tun_ipv6(net_ipv6);
        out.have_v6 = true;
    }

    if (!net_ip.empty()) {
        if (net_ip.find(':') != tp::string::npos) {
            if (out.have_v6) {
                throw std::runtime_error("[tun] net_ip is IPv6 but tun.net_ipv6 is also set");
            }
            out.v6      = parse_tun_ipv6(net_ip);
            out.have_v6 = true;
            out.prefix  = prefix_from_ipv6_mask(net_mask, prefix);
        } else {
            // Same exception as the historical IPv4-only parser for a bad net_ip.
            out.v4      = make_address_v4(net_ip.c_str());
            out.have_v4 = true;
        }
    }

    if (!out.have_v4 && !out.have_v6) {
        throw std::runtime_error("[tun] tun.net_ip or tun.net_ipv6 is required");
    }

    if (out.have_v4) {
        // Reject a bad IPv4 mask before the device is opened.
        (void)make_address_v4(net_mask.c_str());
    }
    return out;
}

bool ipv6_bytes_is_v4_mapped(const uint8_t* addr) {
    static const uint8_t kMappedPrefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    return std::memcmp(addr, kMappedPrefix, sizeof(kMappedPrefix)) == 0;
}

// Walk hop-by-hop, routing, and destination options. Fragment, AH, and ESP are
// not reassembled on the UDP path (return 0 so the packet is left for lwIP).
// -1 means the chain is truncated and the packet should be dropped.
int ipv6_locate_udp(uint8_t* payload, int payload_len, uint8_t next, uint8_t** out_udp, int* out_len) {
    constexpr uint8_t kHopByHop = 0;
    constexpr uint8_t kRouting  = 43;
    constexpr uint8_t kFragment = 44;
    constexpr uint8_t kDestOpts = 60;

    while (next == kHopByHop || next == kRouting || next == kDestOpts || next == kFragment) {
        if (next == kFragment) {
            return 0;
        }
        if (payload_len < 2) {
            return -1;
        }
        const uint8_t ext_next = payload[0];
        const int hdr_len      = (static_cast<int>(payload[1]) + 1) * 8;
        if (hdr_len < 8 || hdr_len > payload_len) {
            return -1;
        }
        next         = ext_next;
        payload     += hdr_len;
        payload_len -= hdr_len;
    }
    if (next != IPV6_NEXT_UDP) {
        return 0;
    }
    *out_udp = payload;
    *out_len = payload_len;
    return 1;
}

} // namespace

TUNDev* TUNDev::sm_tundev = nullptr;

TUNDev::TUNDev(Service* _service, const tp::string& _tun_name, const tp::string& _ipaddr, const tp::string& _netmask,
  uint16_t _mtu, int _outside_tun_fd)
    : m_netif_configured(false),
      m_ipv6_enabled(false),
      m_tcp_listener(nullptr),
      m_tcp_listener_v6(nullptr),
      m_service(_service),
      m_tun_fd(_outside_tun_fd),
      m_is_outside_tun_fd(_outside_tun_fd != -1),
      m_mtu(_mtu),
      m_quitting(false),
      m_boost_sd(_service->get_io_context()) {

    _guard;

    _assert(sm_tundev == nullptr);
    sm_tundev = this;

    const auto& tun_config = m_service->get_config().get_tun();
    const TunAddresses addresses =
      resolve_tun_addresses(_ipaddr, _netmask, tun_config.net_ipv6, tun_config.net_ipv6_prefix);
    m_ipv6_enabled = addresses.have_v6;

    if (m_tun_fd == -1) {
#ifdef __linux__
        // open TUN device, check detail information:
        // https://www.kernel.org/doc/Documentation/networking/tuntap.txt
        if ((m_tun_fd = open("/dev/net/tun", O_RDWR)) < 0) {
            throw std::runtime_error(tp::string("[tun] error opening device").c_str());
        }

        struct ifreq ifr {};
        ifr.ifr_flags = IFF_NO_PI | IFF_TUN;
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", _tun_name.c_str());

        if (ioctl(m_tun_fd, TUNSETIFF, (void*)&ifr) < 0) {
            throw std::runtime_error(tp::string("[tun] error configuring device").c_str());
        }

        _log_with_date_time("[tun] /dev/net/tun ifr.ifr_mtu: " + tp::to_string(ifr.ifr_mtu), Log::WARN);
#else
        throw std::logic_error(tp::string("[tun] cannot enable tun run type in NON-linux system ! " + _tun_name).c_str());
#endif //__linux__
    }

    m_boost_sd.assign(m_tun_fd);

    // init lwip
    lwip_init();

    // make addresses for netif. IPv4-only configs keep the historical host-order
    // assignment. An IPv6-only config uses 0.0.0.0 so netif_add still succeeds.
    ip4_addr_t addr;
    ip4_addr_t netmask;
    ip4_addr_t gw;
    ip4_addr_set_any(&gw);
    if (addresses.have_v4) {
        addr.addr    = addresses.v4.to_uint();
        netmask.addr = make_address_v4(_netmask.c_str()).to_uint();
    } else {
        ip4_addr_set_any(&addr);
        ip4_addr_set_any(&netmask);
    }

    // init netif
    if (netif_add(&m_netif, &addr, &netmask, &gw, nullptr, (netif_init_fn)static_netif_init_func,
          (netif_input_fn)static_netif_input_func) == nullptr) {
        throw std::runtime_error(tp::string("[tun] netif_add failed").c_str());
    }

    // tp::set netif up
    netif_set_up(&m_netif);

    // tp::set netif link up, otherwise ip route will refuse to route
    netif_set_link_up(&m_netif);

    // tp::set netif pretend TCP
    netif_set_pretend_tcp(&m_netif, 1);

    // tp::set netif default
    netif_set_default(&m_netif);

    if (m_ipv6_enabled) {
        ip6_addr_t ip6addr;
        std::memset(&ip6addr, 0, sizeof(ip6addr));
        const auto bytes = addresses.v6.to_bytes();
        std::memcpy(ip6addr.addr, bytes.data(), bytes.size());
        netif_ip6_addr_set(&m_netif, 0, &ip6addr);
        netif_ip6_addr_set_state(&m_netif, 0, IP6_ADDR_PREFERRED);
        _log_with_date_time("[tun] IPv6 netif " + addresses.v6.to_string() + "/" +
                              tp::to_string(static_cast<unsigned>(addresses.prefix)),
          Log::INFO);
    }

    m_netif_configured = true;

    m_tcp_listener = listen_on_netif(IPADDR_TYPE_V4);
    if (m_ipv6_enabled) {
        m_tcp_listener_v6 = listen_on_netif(IPADDR_TYPE_V6);
    }

    async_read();

    // The built-in DNS interceptor matches an IPv4 endpoint. IPv6 DNS (AAAA
    // and DNS over IPv6) is a later step, so an IPv6-only TUN does not claim
    // a DNS address. Non-DNS IPv6 UDP is forwarded below.
    if (addresses.have_v4) {
        m_dns_server_endpoint.address(addresses.v4);
    } else {
        m_dns_server_endpoint.address(make_address_v4("0.0.0.0"));
    }
    m_dns_server_endpoint.port(m_service->get_config().get_dns().port);

    m_dns_queryer =
      TP_MAKE_SHARED(TUNDNSQueryer, [this](const boost::asio::ip::udp::endpoint& local, const std::string_view& data) {
          std::string_view data_str(data);
          return handle_write_upd_data(local, m_dns_server_endpoint, data_str) == 0;
      });

    m_dns_server = TP_MAKE_SHARED(DNSServer, m_service, m_dns_queryer);
    if (!m_dns_server->start()) {
        throw std::runtime_error(tp::string("[tun] dns server start failed").c_str());
    }

    _unguard;
}

TUNDev::~TUNDev() {
    _log_with_date_time("~TUNDev called");
    if (m_tun_fd != -1 && !m_is_outside_tun_fd) {
        m_boost_sd.close();
    } else {
        m_boost_sd.release();
    }
}

void TUNDev::destroy() {
    _guard;

    if (m_quitting) {
        return;
    }

    m_quitting = true;

    _log_with_date_time("[tun] destoryed, clear all tcp_clients: " + tp::to_string(m_tcp_clients.size()) +
                          " udp_clients: " + tp::to_string(m_udp_clients.size()),
      Log::INFO);

    for (auto& it : m_tcp_clients) {
        it->close_client(true, true);
    }
    m_tcp_clients.clear();

    for (auto& it : m_udp_clients) {
        it->set_close_from_tundev_flag();
        it->destroy();
    }
    m_udp_clients.clear();

    // free listeners
    if (m_tcp_listener != nullptr) {
        tcp_close(m_tcp_listener);
        m_tcp_listener = nullptr;
    }
    if (m_tcp_listener_v6 != nullptr) {
        tcp_close(m_tcp_listener_v6);
        m_tcp_listener_v6 = nullptr;
    }

    // free netif
    if (m_netif_configured) {
        netif_remove(&m_netif);
        m_netif_configured = false;
    }

    tcp_remove(tcp_bound_pcbs);
    tcp_remove(tcp_active_pcbs);
    tcp_remove(tcp_tw_pcbs);

    sm_tundev = nullptr;

    _unguard;
}

err_t TUNDev::netif_init_func(struct netif* netif) const {
    _guard;

    netif->name[0] = 'h';
    netif->name[1] = 'o';
    netif->mtu     = m_mtu;
    netif->output  = static_netif_output_func;
    if (m_ipv6_enabled) {
        netif->output_ip6 = static_netif_output_ip6_func;
    }
    return ERR_OK;

    _unguard;
}

err_t TUNDev::netif_input_func(struct pbuf* p, struct netif* inp) {
    _guard;

    uint8_t ip_version = 0;
    if (p->len > 0) {
        ip_version = (((uint8_t*)p->payload)[0] >> half_byte_shift_4_bits);
    }

    switch (ip_version) {
        case IPV4: {
            return ip_input(p, inp);
        } break;
        case IPV6: {
            if (m_ipv6_enabled) {
                // lwIP's ip6_input rejects IPv4-mapped addresses and multicast
                // sources with ERR_OK and does not free the pbuf (badvpn
                // ip6.c). Drop them here so the buffer is released. Mapped
                // TCP is not proxied; native IPv4 packets are the IPv4 path.
                uint8_t hdr[sizeof(struct ipv6_header)];
                if (pbuf_copy_partial(p, hdr, sizeof(hdr), 0) == sizeof(hdr)) {
                    const uint8_t* src = hdr + 8;
                    const uint8_t* dst = hdr + 24;
                    const bool mapped  = ipv6_bytes_is_v4_mapped(src) || ipv6_bytes_is_v4_mapped(dst);
                    const bool mcast_src = src[0] == 0xff;
                    if (mapped || mcast_src) {
                        const char* why = mapped ? "[tun] drop IPv4-mapped IPv6 packet before lwIP"
                                                 : "[tun] drop IPv6 packet with multicast source";
                        _log_with_date_time(why, Log::INFO);
                        pbuf_free(p);
                        return ERR_OK;
                    }
                }
                return ip6_input(p, inp);
            }
        } break;
    }

    pbuf_free(p);
    return ERR_OK;

    _unguard;
}

err_t TUNDev::netif_output_func(struct netif*, struct pbuf* p, const ip4_addr_t*) {
    return write_pbuf_to_tun(p);
}

err_t TUNDev::netif_output_ip6_func(struct netif*, struct pbuf* p, const ip6_addr_t*) {
    return write_pbuf_to_tun(p);
}

struct tcp_pcb* TUNDev::listen_on_netif(uint8_t ip_type) {
    struct tcp_pcb* l = tcp_new_ip_type(ip_type);
    if (l == nullptr) {
        throw std::runtime_error(tp::string("[tun] tcp_new_ip_type failed").c_str());
    }

    if (tcp_bind_to_netif(l, "ho0") != ERR_OK) {
        tcp_close(l);
        throw std::runtime_error(tp::string("[tun] tcp_bind_to_netif failed").c_str());
    }

    tcp_bind_netif(l, &m_netif);

    struct tcp_pcb* listener = tcp_listen(l);
    if (listener == nullptr) {
        tcp_close(l);
        throw std::runtime_error(tp::string("[tun] tcp_listen failed").c_str());
    }

    tcp_arg(listener, this);
    tcp_accept(listener, static_listener_accept_func);
    return listener;
}

err_t TUNDev::write_pbuf_to_tun(struct pbuf* p) {
    _guard;

    if (m_quitting) {
        return ERR_OK;
    }

    if (p != nullptr) {
        if (p->next == nullptr && p->len <= m_mtu) {
            boost::system::error_code ec;
            m_boost_sd.write_some(boost::asio::buffer(p->payload, p->len), ec);
            if (ec) {
                output_debug_info_ec(ec);
            }
        } else {
            do {
                if (p->len > 0) {
                    auto* write_buff = static_cast<uint8_t*>(boost::asio::buffer_sequence_begin(m_write_fill_buf.prepare(p->len))->data());
                    memcpy(write_buff, (uint8_t*)p->payload, p->len);
                    m_write_fill_buf.commit(p->len);
                }
            } while ((p = p->next) != nullptr);

            write_to_tun();
        }
    }

    return ERR_OK;
    _unguard;
}

bool TUNDev::proxy_by_route(uint32_t ip) const {
    _guard;

    auto route = m_service->get_config().get_route();
    if (route._proxy_ips_matcher.is_match(ip)) {
        return true;
    }

    if (route._white_ips_matcher.is_match(ip)) {
        return false;
    }

    switch (route.proxy_type) {
        case Config::route_all:          // Controlled by route tables
        case Config::route_bypass_local: // Controlled by route tables
            return true;
        case Config::route_bypass_cn_mainland:
        case Config::route_bypass_local_and_cn_mainland: // Local ips Controlled by route tables
            return !route._cn_mainland_ips_matcher.is_match(ip);
        case Config::route_gfwlist:
            return m_dns_server != nullptr && m_dns_server->is_ip_in_gfwlist(ip);
        case Config::route_cn_mainland:
            return route._cn_mainland_ips_matcher.is_match(ip);
        default:
            throw std::logic_error((tp::string("[dns] error proxy type: ") + tp::to_string((int)route.proxy_type)).c_str());
    }

    _unguard;
}

bool TUNDev::should_proxy(const boost::asio::ip::address& addr) const {
    if (addr.is_v4()) {
        return proxy_by_route(addr.to_v4().to_uint());
    }
    // IPv4-mapped destinations still consult the IPv4 route tables. Other
    // IPv6 destinations are proxied; IPv6 route matchers are a later step.
    if (addr.is_v6() && addr.to_v6().is_v4_mapped()) {
        return proxy_by_route(make_address_v4(v4_mapped, addr.to_v6()).to_uint());
    }
    return true;
}

err_t TUNDev::listener_accept_func(struct tcp_pcb* newpcb, err_t err) {
    _guard;
    if (err != ERR_OK) {
        return err;
    }

    const auto dest                = address_from_lwip(newpcb->local_ip);
    auto proxy                     = should_proxy(dest);
    std::shared_ptr<TUNSession> session = nullptr;
    if (proxy) {

        _log_with_date_time_ALL("[tun] [tcp] proxy connect: " + dest.to_string());

        session = TP_MAKE_SHARED(TUNProxySession, m_service, false);
    } else {

        _log_with_date_time_ALL("[tun] [tcp] directly connect: " + dest.to_string());

        session = TP_MAKE_SHARED(TUNLocalSession, m_service, false);
    }
    auto tcp_client = TP_MAKE_SHARED(lwip_tcp_client, newpcb, session, [this](lwip_tcp_client* client) {
        _guard;
        for (auto it = m_tcp_clients.begin(); it != m_tcp_clients.end(); it++) {
            if (it->get() == client) {
                m_tcp_clients.erase(it);
                break;
            }
        }
        _unguard;
    });

    if (!proxy) {
        session->start();
        if (!session->is_destroyed()) {
            m_tcp_clients.emplace_back(tcp_client);
        }
    } else {
        m_service->start_session(session, [this, session, tcp_client](boost::system::error_code ec) {
            _guard;
            if (!ec) {
                session->start();
                if (!session->is_destroyed()) {
                    m_tcp_clients.emplace_back(tcp_client);
                }
            } else {
                session->destroy();
                tcp_client->close_client(true);
            }
            _unguard;
        });
    }

    // start_session callback immediately and destory the session
    return session->is_destroyed() ? ERR_ABRT : ERR_OK;
    _unguard;
}

void TUNDev::input_netif_packet(const uint8_t* data, uint16_t packet_len) {
    _guard;
    struct pbuf* p = pbuf_alloc(PBUF_RAW, packet_len, PBUF_POOL);
    if (p == nullptr) {
        _log_with_date_time("[tun] device read: pbuf_alloc failed", Log::ERROR);
        return;
    }

    // write packet to pbuf
    if (pbuf_take(p, (void*)data, packet_len) != ERR_OK) {
        _log_with_date_time("[tun] device read: pbuf_take failed", Log::ERROR);
        pbuf_free(p);
        return;
    }

    // pass pbuf to input
    if (m_netif.input(p, &m_netif) != ERR_OK) {
        _log_with_date_time("[tun] device read: input failed", Log::ERROR);
        pbuf_free(p);
        return;
    }
    _unguard;
}

void TUNDev::parse_packet() {
    _guard;

    // Lengths are size_t. A uint16_t sum of an IPv6 payload_length and the
    // 40-byte header wraps (65496 + 40 == 0) and substr(0) then re-parses the
    // same bytes forever. An IPv4 total_length of 0 does the same.
    while (!m_packet_parse_buff.empty()) {
        auto* data             = (uint8_t*)m_packet_parse_buff.c_str();
        const size_t data_len  = m_packet_parse_buff.length();
        const auto ip_version  = (data[0] >> half_byte_shift_4_bits) & half_byte_mask_0xF;

        if (ip_version != IPV4 && ip_version != IPV6) {
            m_packet_parse_buff.clear();
            break;
        }

        size_t header_len   = 0;
        size_t total_length = 0;
        if (ip_version == IPV4) {
            header_len = sizeof(struct ipv4_header);
            if (data_len < header_len) {
                return;
            }
            struct ipv4_header ipv4_hdr;
            memcpy(&ipv4_hdr, data, sizeof(ipv4_hdr));
            total_length = ntoh16(ipv4_hdr.total_length);
        } else {
            header_len = sizeof(struct ipv6_header);
            if (data_len < header_len) {
                return;
            }
            struct ipv6_header ipv6_hdr;
            memcpy(&ipv6_hdr, data, sizeof(ipv6_hdr));
            total_length = static_cast<size_t>(ntoh16(ipv6_hdr.payload_length)) + header_len;
        }

        // Shorter than the header, or larger than the TUN MTU: not a frame we
        // can skip safely. Drop everything already buffered so the next read
        // starts clean, including when IPv6 is disabled.
        if (total_length < header_len || total_length > m_mtu) {
            _log_with_date_time(tp::string("[tun] drop malformed IPv") + (ip_version == IPV4 ? "4" : "6") +
                                  " packet, length " + tp::to_string(total_length),
              Log::WARN);
            m_packet_parse_buff.clear();
            break;
        }
        if (total_length > data_len) {
            return;
        }

        const auto result = try_to_process_udp_packet(data, static_cast<int>(total_length));
        if (result == 0) {
            input_netif_packet(data, static_cast<uint16_t>(total_length));
        }

        if (data_len == total_length) {
            m_packet_parse_buff.clear();
            break;
        }
        m_packet_parse_buff = m_packet_parse_buff.substr(total_length);
    }

    _unguard;
}

int TUNDev::handle_write_udp_ipv6(const boost::asio::ip::udp::endpoint& local_endpoint,
  const boost::asio::ip::udp::endpoint& remote_endpoint, std::string_view& data_str) {
    _guard;

    if (!local_endpoint.address().is_v6() || !remote_endpoint.address().is_v6()) {
        _log_with_date_time("[tun] drop UDP reply with mixed address families", Log::ERROR);
        return 1;
    }

    auto data_len = data_str.length();
    if (data_len == 0) {
        return 0;
    }

    const auto* data   = (const uint8_t*)data_str.data();
    auto header_length = (uint16_t)(sizeof(struct ipv6_header) + sizeof(struct udp_header));
    auto max_len       = std::min(std::numeric_limits<uint16_t>::max(), m_mtu);
    if (max_len <= header_length) {
        return 1;
    }
    max_len = max_len - header_length;
    if (data_len > max_len) {
        data_len = max_len;
    }

    const auto source_bytes      = remote_endpoint.address().to_v6().to_bytes();
    const auto destination_bytes = local_endpoint.address().to_v6().to_bytes();

    struct ipv6_header ipv6_hdr;
    std::memset(&ipv6_hdr, 0, sizeof(ipv6_hdr));
    ipv6_hdr.version4_tc4   = hton8(static_cast<uint8_t>(6 << 4));
    ipv6_hdr.payload_length = hton16(uint16_t(sizeof(struct udp_header) + data_len));
    ipv6_hdr.next_header    = hton8(IPV6_NEXT_UDP);
    ipv6_hdr.hop_limit      = hton8(64);
    std::memcpy(ipv6_hdr.source_address, source_bytes.data(), source_bytes.size());
    std::memcpy(ipv6_hdr.destination_address, destination_bytes.data(), destination_bytes.size());

    struct udp_header udp_hdr;
    udp_hdr.source_port = hton16(remote_endpoint.port());
    udp_hdr.dest_port   = hton16(local_endpoint.port());
    udp_hdr.length      = hton16(uint16_t(sizeof(udp_hdr) + data_len));
    udp_hdr.checksum    = hton16(0);
    udp_hdr.checksum    = udp_ip6_checksum(&udp_hdr, data, static_cast<uint16_t>(data_len), ipv6_hdr.source_address,
      ipv6_hdr.destination_address);

    auto packat_length = header_length + data_len;
    auto* write_buf =
      static_cast<uint8_t*>(boost::asio::buffer_sequence_begin(m_write_fill_buf.prepare(packat_length))->data());

    memcpy(write_buf, &ipv6_hdr, sizeof(ipv6_hdr));
    memcpy(write_buf + sizeof(ipv6_hdr), &udp_hdr, sizeof(udp_hdr));
    memcpy(write_buf + sizeof(ipv6_hdr) + sizeof(udp_hdr), data, data_len);
    m_write_fill_buf.commit(packat_length);

    _log_with_endpoint_ALL(local_endpoint, "<- " + remote_endpoint.address().to_string() + ":" +
                                             tp::to_string(remote_endpoint.port()) + " length:" + tp::to_string(data_len));

    write_to_tun();

    data_str = data_str.substr(data_len);
    if (data_str.length() > 0) {
        handle_write_udp_ipv6(local_endpoint, remote_endpoint, data_str);
    }

    return 0;
    _unguard;
}

int TUNDev::handle_write_upd_data(const boost::asio::ip::udp::endpoint& local_endpoint,
  const boost::asio::ip::udp::endpoint& remote_endpoint, std::string_view& data_str) {

    _guard;
    if (local_endpoint.address().is_v6() || remote_endpoint.address().is_v6()) {
        return handle_write_udp_ipv6(local_endpoint, remote_endpoint, data_str);
    }

    auto* local_addr  = (struct sockaddr_in*)local_endpoint.data();
    auto* remote_addr = (struct sockaddr_in*)remote_endpoint.data();

    auto data_len = data_str.length();
    if (data_len == 0) {
        return 0;
    }

    const auto* data   = (const uint8_t*)data_str.data();
    auto header_length = (uint16_t)(sizeof(struct ipv4_header) + sizeof(struct udp_header));
    auto max_len       = std::min(std::numeric_limits<uint16_t>::max(), m_mtu);
    max_len            = max_len - header_length;
    if (data_len > max_len) {
        data_len = max_len;
    }

    // build IP header
    struct ipv4_header ipv4_hdr;
    ipv4_hdr.version4_ihl4           = IPV4_MAKE_VERSION_IHL(sizeof(ipv4_hdr));
    ipv4_hdr.ds                      = hton8(0);
    ipv4_hdr.total_length            = hton16(uint16_t(sizeof(ipv4_hdr) + sizeof(struct udp_header) + data_len));
    ipv4_hdr.identification          = hton16(0);
    ipv4_hdr.flags3_fragmentoffset13 = hton16(0);
    ipv4_hdr.ttl                     = hton8(Default_UDP_TTL);
    ipv4_hdr.protocol                = hton8(IPV4_PROTOCOL_UDP);
    ipv4_hdr.checksum                = hton16(0);
    ipv4_hdr.source_address          = (remote_addr->sin_addr.s_addr);
    ipv4_hdr.destination_address     = (local_addr->sin_addr.s_addr);
    ipv4_hdr.checksum                = ipv4_checksum(&ipv4_hdr, nullptr, 0);

    // build UDP header
    struct udp_header udp_hdr;
    udp_hdr.source_port = hton16(remote_endpoint.port());
    udp_hdr.dest_port   = hton16(local_endpoint.port());
    udp_hdr.length      = hton16(uint16_t(sizeof(udp_hdr) + data_len));
    udp_hdr.checksum    = hton16(0);
    udp_hdr.checksum =
      udp_checksum(&udp_hdr, data, (uint16_t)data_len, ipv4_hdr.source_address, ipv4_hdr.destination_address);

    // compose packet
    auto packat_length = header_length + data_len;
    auto* write_buf    = static_cast<uint8_t*>(boost::asio::buffer_sequence_begin(m_write_fill_buf.prepare(packat_length))->data());

    memcpy(write_buf, &ipv4_hdr, sizeof(ipv4_hdr));
    memcpy(write_buf + sizeof(ipv4_hdr), &udp_hdr, sizeof(udp_hdr));
    memcpy(write_buf + sizeof(ipv4_hdr) + sizeof(udp_hdr), data, data_len);

    m_write_fill_buf.commit(packat_length);

    _log_with_endpoint_ALL(local_endpoint, "<- " + remote_endpoint.address().to_string() + ":" +
                                             tp::to_string(remote_endpoint.port()) + " length:" + tp::to_string(data_len));

    write_to_tun();

    data_str = data_str.substr(data_len);
    if (data_str.length() > 0) {
        handle_write_upd_data(local_endpoint, remote_endpoint, data_str);
    }

    return 0;
    _unguard;
}

int TUNDev::handle_write_upd_data(const TUNSession* _session, std::string_view& data_str) {
    _guard;
    _assert(_session->is_udp_forward_session());
    return handle_write_upd_data(_session->get_udp_local_endpoint(), _session->get_udp_remote_endpoint(), data_str);
    _unguard;
}

void TUNDev::open_udp_session(const udp::endpoint& local_endpoint, const udp::endpoint& remote_endpoint,
  const uint8_t* data, int data_len, bool proxy) {
    std::shared_ptr<TUNSession> session = nullptr;
    if (proxy) {
        _log_with_date_time_ALL("[tun] [udp] proxy connect: " + remote_endpoint.address().to_string());
        session = TP_MAKE_SHARED(TUNProxySession, m_service, true);
    } else {
        _log_with_date_time_ALL("[tun] [udp] directly connect: " + remote_endpoint.address().to_string());
        session = TP_MAKE_SHARED(TUNLocalSession, m_service, true);
    }
    session->set_udp_connect(local_endpoint, remote_endpoint);
    session->set_write_to_lwip([this](const TUNSession* _se, std::string_view* _data) {
        _guard;
        _assert(_data != nullptr);
        return handle_write_upd_data(_se, *_data);
        _unguard;
    });

    session->set_close_callback([this](TUNSession* _session) {
        _guard;
        for (auto it = m_udp_clients.begin(); it != m_udp_clients.end(); it++) {
            if (it->get() == _session) {
                m_udp_clients.erase(it);
                break;
            }
        }
        _unguard;
    });

    session->out_async_send(data, data_len, [](boost::system::error_code) {}); // send as buf
    m_udp_clients.emplace_back(session);

    _log_with_endpoint(local_endpoint,
      "TUNDev start to connected " + remote_endpoint.address().to_string() + ":" +
        tp::to_string(remote_endpoint.port()),
      Log::INFO);

    if (!proxy) {
        session->start();
    } else {
        m_service->start_session(session, [session, local_endpoint, remote_endpoint](boost::system::error_code ec) {
            _guard;

            if (!ec) {
                session->start();
            } else {
                output_debug_info_ec(ec);
                session->destroy();
            }

            _unguard;
        });
    }
}

int TUNDev::try_to_process_udp_packet(uint8_t* data, int data_len) {
    _guard;

    uint8_t ip_version = 0;
    if (data_len > 0) {
        ip_version = (data[0] >> half_byte_shift_4_bits) & half_byte_mask_0xF;
    }

    if (ip_version == IPV4) {
        // ignore non-UDP packets
        if (data_len < (int)sizeof(struct ipv4_header) ||
            data[offsetof(struct ipv4_header, protocol)] != IPV4_PROTOCOL_UDP) {
            return 0;
        }

        // parse IPv4 header
        struct ipv4_header ipv4_hdr;
        if (ipv4_check(data, data_len, &ipv4_hdr, &data, &data_len) == 0) {
            return 1;
        }

        // parse UDP
        struct udp_header udp_hdr;
        if (udp_check(data, data_len, &udp_hdr, &data, &data_len) == 0) {
            return 1;
        }

        // verify UDP checksum
        uint16_t checksum_in_packet = udp_hdr.checksum;
        udp_hdr.checksum            = 0;
        uint16_t checksum_computed =
          udp_checksum(&udp_hdr, data, data_len, ipv4_hdr.source_address, ipv4_hdr.destination_address);

        if (checksum_in_packet != checksum_computed) {
            return 1;
        }

        auto local_endpoint = udp::endpoint(
          make_address_v4((address_v4::uint_type)ntoh32(ipv4_hdr.source_address)), ntoh16(udp_hdr.source_port));

        auto remote_endpoint = udp::endpoint(
          make_address_v4((address_v4::uint_type)ntoh32(ipv4_hdr.destination_address)), ntoh16(udp_hdr.dest_port));

        _log_with_endpoint_ALL(local_endpoint, " -> " + remote_endpoint.address().to_string() + ":" +
                                                 tp::to_string(remote_endpoint.port()) +
                                                 " [tun] length:" + tp::to_string(data_len));

        if (m_dns_server_endpoint == remote_endpoint) {
            m_dns_queryer->recved(local_endpoint, std::string_view((const char*)data, data_len));
            return 1;
        }

        for (auto& it : m_udp_clients) {
            if (it->try_to_process_udp(local_endpoint, remote_endpoint, data, data_len)) {
                return 1;
            }
        }

        open_udp_session(local_endpoint, remote_endpoint, data, data_len,
          proxy_by_route(ntoh32(ipv4_hdr.destination_address)));
        return 1;
    }

    if (ip_version == IPV6) {
        if (!m_ipv6_enabled) {
            return 0;
        }

        // TCP and anything that is not UDP after hop-by-hop, routing, or
        // destination options is given to lwIP. Fragments are not reassembled here.
        if (data_len < (int)sizeof(struct ipv6_header)) {
            return 0;
        }

        struct ipv6_header ipv6_hdr;
        uint8_t* payload = nullptr;
        int payload_len  = 0;
        if (ipv6_check(data, data_len, &ipv6_hdr, &payload, &payload_len) == 0) {
            return 1;
        }

        uint8_t* udp_bytes = nullptr;
        int udp_len        = 0;
        const int located =
          ipv6_locate_udp(payload, payload_len, ipv6_hdr.next_header, &udp_bytes, &udp_len);
        if (located < 0) {
            return 1;
        }
        if (located == 0) {
            return 0;
        }
        data     = udp_bytes;
        data_len = udp_len;

        struct udp_header udp_hdr;
        if (udp_check(data, data_len, &udp_hdr, &data, &data_len) == 0) {
            return 1;
        }

        // IPv6 UDP checksums are mandatory. A zero or mismatched checksum is dropped.
        uint16_t checksum_in_packet = udp_hdr.checksum;
        udp_hdr.checksum            = 0;
        uint16_t checksum_computed  = udp_ip6_checksum(&udp_hdr, data, static_cast<uint16_t>(data_len),
          ipv6_hdr.source_address, ipv6_hdr.destination_address);
        if (checksum_in_packet != checksum_computed) {
            return 1;
        }

        address_v6::bytes_type source_bytes{};
        address_v6::bytes_type destination_bytes{};
        std::memcpy(source_bytes.data(), ipv6_hdr.source_address, source_bytes.size());
        std::memcpy(destination_bytes.data(), ipv6_hdr.destination_address, destination_bytes.size());

        // Keep the packet family so the reply written back to the TUN is IPv6.
        // TrojanRequest encoding turns an IPv4-mapped UDP literal into ATYP 1.
        // Mapped TCP is dropped in netif_input_func; lwIP does not accept it.
        auto local_endpoint =
          udp::endpoint(make_address_v6(source_bytes), ntoh16(udp_hdr.source_port));
        auto remote_endpoint =
          udp::endpoint(make_address_v6(destination_bytes), ntoh16(udp_hdr.dest_port));

        _log_with_endpoint_ALL(local_endpoint, " -> " + remote_endpoint.address().to_string() + ":" +
                                                 tp::to_string(remote_endpoint.port()) +
                                                 " [tun] length:" + tp::to_string(data_len));

        for (auto& it : m_udp_clients) {
            if (it->try_to_process_udp(local_endpoint, remote_endpoint, data, data_len)) {
                return 1;
            }
        }

        open_udp_session(local_endpoint, remote_endpoint, data, data_len, should_proxy(remote_endpoint.address()));
        return 1;
    }

    return 0;

    _unguard;
}

void TUNDev::write_to_tun() {
    _guard;

    if (m_quitting) {
        return;
    }

    while (m_write_fill_buf.size() > 0) {
        boost::system::error_code ec;
        size_t wrote = 0;
        if (m_write_fill_buf.size() > m_mtu) {
            auto copied = boost::asio::buffer_copy(m_writing_buf.prepare(m_mtu), m_write_fill_buf.data(), m_mtu);
            m_writing_buf.commit(copied);

            wrote = m_boost_sd.write_some(m_writing_buf.data(), ec);
            m_writing_buf.consume(m_writing_buf.size());
        } else {
            wrote = m_boost_sd.write_some(m_write_fill_buf.data(), ec);
        }

        if (!ec && wrote > 0) {
            m_write_fill_buf.consume(wrote);
        } else {
            m_write_fill_buf.consume(m_write_fill_buf.size());
        }
    }

    _unguard;
}

void TUNDev::async_read() {
    _guard;

    m_sd_read_buffer.consume(m_sd_read_buffer.size());
    m_boost_sd.async_read_some(m_sd_read_buffer.prepare(m_mtu), tp::bind_mem_alloc([this](boost::system::error_code ec, size_t data_len) {
        if (m_quitting) {
            return;
        }

        if (!ec) {
            m_sd_read_buffer.commit(data_len);

            const auto* data = static_cast<const char*>(boost::asio::buffer_sequence_begin(m_sd_read_buffer.data())->data());
            m_packet_parse_buff.append(data, data_len);

            parse_packet();
        }

        async_read();
    }));

    // sleep for test
    //::sleep(1);

    _unguard;
}