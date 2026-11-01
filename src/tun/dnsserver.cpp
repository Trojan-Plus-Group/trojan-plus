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

#include "dnsserver.h"
#include "core/service.h"
#include "proto/dns_header.h"
#include "tun/udplocalforwarder.h"
#include "mem/memallocator.h"
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <sstream>

using namespace boost::asio::ip;
using namespace trojan;

FILE_LOCK_HANDLE DNSServer::s_dns_file_lock = INVALID_LOCK_HANDLE;
bool DNSServer::get_dns_lock() {
#ifndef __ANDROID__
    s_dns_file_lock = get_file_lock("./trojan_dns_lock.output");
    return s_dns_file_lock != INVALID_LOCK_HANDLE;
#else
    // android don't need the lock file
    return true;
#endif // __ANDROID__
}

DNSServer::SocketQueryer::SocketQueryer(Service* serv) : service(serv), socket(service->get_io_context()) {}
DNSServer::SocketQueryer::~SocketQueryer() {
    if (socket.is_open()) {
        boost::system::error_code ec;
        socket.cancel(ec);
        socket.close(ec);
    }
}

bool DNSServer::SocketQueryer::open(DataQueryHandler&& handler, int port) {
    _guard;

    boost::system::error_code ec;

    socket.open(udp::v6(), ec);
    if (!ec) {
        socket.set_option(v6_only(false), ec);
    }
    if (!ec) {
        socket.bind(udp::endpoint(address_v6::any(), port), ec);
    }
    if (ec) {
        _log_with_date_time("[dns] dual-stack bind failed: " + tp::string(ec.message().c_str()) +
                              "; falling back to IPv4", Log::WARN);
        boost::system::error_code close_ec;
        socket.close(close_ec);
        socket.open(udp::v4(), ec);
        if (!ec) {
            socket.bind(udp::endpoint(address_v4::any(), port), ec);
        }
    }
    if (ec) {
        output_debug_info_ec(ec);
        return false;
    }

    data_handler = std::move(handler);
    async_read_udp();
    return true;

    _unguard;
}

void DNSServer::SocketQueryer::async_read_udp() {
    _guard;

    if (!socket.is_open()) {
        return;
    }

    auto self         = shared_from_this();
    auto prepare_size = service->get_config().get_udp_recv_buf();
    buf.begin_read(__FILE__, __LINE__);
    buf.consume_all();
    socket.async_receive_from(
      buf.prepare(prepare_size), recv_endpoint, tp::bind_mem_alloc([self, this](const boost::system::error_code error, size_t length) {
          buf.end_read();
          if (error) {
              async_read_udp();
              return;
          }

          buf.commit(length);
          data_handler(recv_endpoint, buf);
          async_read_udp();
      }));

    _unguard;
}

bool DNSServer::SocketQueryer::send(const boost::asio::ip::udp::endpoint& to, const std::string_view& data) {
    _guard;

    boost::system::error_code ec;
    auto destination = to;
    if (to.address().is_v4() && socket.local_endpoint(ec).protocol() == udp::v6()) {
        destination.address(make_address_v6(v4_mapped, to.address().to_v4()));
    }
    if (ec) {
        return false;
    }
    socket.send_to(boost::asio::buffer(data), destination, 0, ec);
    return (!ec);

    _unguard;
}

DNSServer::DNSServer(Service* _service) : m_service(_service) { m_data_queryer = TP_MAKE_SHARED(SocketQueryer, _service); }

DNSServer::DNSServer(Service* _service, std::shared_ptr<IDataQueryer> queryer)
    : m_service(_service), m_data_queryer(std::move(queryer)) {}

DNSServer::~DNSServer() {
    _log_with_date_time("~DNSServer called");
    close_file_lock(s_dns_file_lock);
}

void DNSServer::destroy() {
    _guard;

    clear_weak_ptr_list(m_proxy_forwarders);
    clear_weak_ptr_list(m_forwarders);

    for (auto& it : m_proxy_forwarders) {
        it.lock()->destroy();
    }
    m_proxy_forwarders.clear();

    for (auto& it : m_forwarders) {
        it.lock()->destroy();
    }
    m_forwarders.clear();

    _unguard;
}

bool DNSServer::start() {
    _guard;

    return m_data_queryer->open(
      [this](const boost::asio::ip::udp::endpoint& recv_endpoint, tp::streambuf& data) {
          m_udp_recv_endpoint     = recv_endpoint;
          std::string_view former_data = streambuf_to_string_view(data);
          std::istream is(&data);

          dns_header dns_hdr;
          is >> dns_hdr;

          if (is && is_interest_dns_msg(dns_hdr)) {
              in_recved(is, dns_hdr, former_data);
          }
      },
      m_service->get_config().get_dns().port);

    _unguard;
}

bool DNSServer::is_interest_dns_msg(const dns_header& dns_hdr) {
    _guard;

    return dns_hdr.QR() == 0 && dns_hdr.RCODE() == 0 && dns_hdr.ANCOUNT() == 0 && dns_hdr.NSCOUNT() == 0 &&
           dns_hdr.QDCOUNT() > 0;

    _unguard;
}

bool DNSServer::is_interest_dns_msg(const trojan::dns_question& qt) {
    _guard;
    return qt.get_QCLASS() == dns_header::QCLASS_INTERNET &&
           (qt.get_QTYPE() == dns_header::QTYPE_A_RECORD || qt.get_QTYPE() == dns_header::QTYPE_AAAA_RECORD);
    _unguard;
}

bool DNSServer::try_to_find_existed(const boost::asio::ip::udp::endpoint& local_src, const std::string_view& data) {
    _guard;

    clear_weak_ptr_list(m_proxy_forwarders);
    clear_weak_ptr_list(m_forwarders);

    for (const auto& f : m_proxy_forwarders) {
        if (f.lock()->process(local_src, data)) {
            return true;
        }
    }

    for (const auto& f : m_forwarders) {
        if (f.lock()->process(local_src, data)) {
            return true;
        }
    }

    return false;

    _unguard;
}
bool DNSServer::find_in_dns_cache(
  const udp::endpoint& local_src, const dns_header& header, const dns_question& question) {
    _guard;

    if (m_service->get_config().get_dns().enable_cached && header.QDCOUNT() == 1) {
        auto curr_time = time(nullptr);

        auto it = m_dns_cache.begin();
        while (it != m_dns_cache.end()) {
            if (it->second.expired(curr_time)) {
                it = m_dns_cache.erase(it);
            } else {
                it++;
            }
        }

        for (auto it = m_proxy_address_expiry.begin(); it != m_proxy_address_expiry.end();) {
            if (it->second <= curr_time) {
                it = m_proxy_address_expiry.erase(it);
            } else {
                ++it;
            }
        }

        const auto found = m_dns_cache.find(std::make_pair(question.get_QNAME(), question.get_QTYPE()));
        if (found != m_dns_cache.end()) {
            auto& c = found->second;
            _log_with_endpoint_ALL(local_src, "[dns] find " + question.get_QNAME() + " in cache ttl: " +
                                                tp::to_string(c.get_ttl() - (curr_time - c.get_cached_time())));

            tp::string& raw_data = c.get_answer_data();
            raw_data[0]           = header.ID() >> one_byte_shift_8_bits;
            raw_data[1]           = header.ID() & one_byte_mask_0xFF;
            const auto age = static_cast<uint32_t>(std::max<time_t>(0, curr_time - c.get_cached_time()));
            for (const auto& field : c.get_ttl_fields()) {
                const uint32_t remaining = field.second > age ? field.second - age : 0;
                for (size_t i = 0; i < 4; ++i) {
                    raw_data[field.first + i] = static_cast<char>(remaining >> ((3 - i) * 8));
                }
            }

            send_to_local(local_src, raw_data);
            return true;
        }
    }

    return false;

    _unguard;
}

void DNSServer::store_in_dns_cache(const std::string_view& data, bool proxyed) {
    _guard;

    if (m_service->get_config().get_dns().enable_cached) {
        tp::string read_data(data);
        tp::istringstream is(read_data);

        dns_answer answer;
        if (is >> answer) {
            if (answer.get_header().QR() == dns_header::QR_RESPONE && answer.get_header().Opcode() == 0 &&
                (answer.get_header().RCODE() == 0 || answer.get_header().RCODE() == dns_header::RCODE_NAME_ERROR) &&
                !answer.get_header().TC() && answer.get_questions().size() == 1 &&
                is_interest_dns_msg(answer.get_questions()[0])) {

                const auto& domain = answer.get_questions()[0].get_QNAME();
                const auto qtype = answer.get_questions()[0].get_QTYPE();
                uint32_t ttl = std::numeric_limits<uint32_t>::max();
                tp::vector<std::pair<size_t, uint32_t>> ttl_fields;
                tp::vector<address> A_list;
                bool has_address = false;
                const auto collect = [&](const auto& records) {
                    for (const auto& an : records) {
                        // OPT's TTL field contains flags, not a cache lifetime.
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
                            A_list.emplace_back(normalize_address(address_v6(an.AAAA)));
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
                const auto key = std::make_pair(domain, qtype);
                m_dns_cache.erase(key);
                if ((!negative || has_soa) && ttl > 0 && ttl != std::numeric_limits<uint32_t>::max()) {
                    const auto inserted = m_dns_cache.emplace(key,
                      DNSCache(domain, qtype, ttl, std::move(ttl_fields), A_list, proxyed, data));
                    index_addresses(inserted.first->second);

                    _log_with_date_time_ALL("[dns] cache " + domain + " qtype: " + tp::to_string(qtype) +
                                            " in ttl: " + tp::to_string(ttl));
                }
            }
        }
    }

    _unguard;
}

void DNSServer::send_to_local(const udp::endpoint& local_src, const std::string_view& data) {
    _guard;

    _log_with_endpoint_ALL(local_src, "[dns] <-- " + tp::to_string(data.length()));
    m_data_queryer->send(local_src, data);

    _unguard;
}

void DNSServer::recv_up_stream_data(const udp::endpoint& local_src, const std::string_view& data, bool proxyed) {
    _guard;

    send_to_local(local_src, data);
    store_in_dns_cache(data, proxyed);

    _unguard;
}

bool DNSServer::is_remote_domain(const tp::string& domain) const {
    _guard;

    const auto& config = m_service->get_config();
    if (domain == config.get_remote_addr()) {
        return true;
    }

    if (config.get_experimental().pipeline_num > 0) {
        for (const auto& c : config.get_experimental()._pipeline_loadbalance_configs) {
            if (c->get_remote_addr() == domain) {
                return true;
            }
        }
    }

    return false;

    _unguard;
}

void DNSServer::in_recved(std::istream& is, const dns_header& header, const std::string_view& former_data) {
    _guard;

    bool proxy = false;
    dns_question qt;
    is >> qt;
    if (is) {
        if (is_interest_dns_msg(qt)) {
            if (find_in_dns_cache(m_udp_recv_endpoint, header, qt)) {
                return;
            }

            if (!is_remote_domain(qt.get_QNAME())) {
                proxy = m_service->get_config().get_dns()._gfwlist_matcher.is_match(qt.get_QNAME());
            }
        }
    } else {
        _log_with_date_time_ALL("[dns] error dns_question message");
        return;
    }

    if (try_to_find_existed(m_udp_recv_endpoint, former_data)) {
        return;
    }

    if (proxy) {

        _log_with_date_time_ALL("[dns] lookup [" + qt.get_QNAME() + "] by proxy");

        auto up_stream_ns_svr = m_service->get_config().get_dns().up_gfw_dns_server.at(0);
        auto dst              = std::make_pair(up_stream_ns_svr, DEFAULT_UP_STREAM_NS_SVR_PORT);
        auto forwarder        = TP_MAKE_SHARED(UDPForwardSession, 
          m_service, m_service->get_config(), m_service->get_ssl_context(), m_udp_recv_endpoint, dst,
          [this](const udp::endpoint& endpoint, const std::string_view& data) { recv_up_stream_data(endpoint, data, true); },
          false, true);

        auto data = m_service->get_sending_data_allocator().allocate(former_data);
        m_service->start_session(forwarder, [this, forwarder, data](boost::system::error_code ec) {
            _guard;
            if (!ec) {
                m_proxy_forwarders.emplace_back(forwarder);
                forwarder->start_udp(streambuf_to_string_view(*data));
            }
            m_service->get_sending_data_allocator().free(data);
            _unguard;
        });

    } else {

        _log_with_date_time_ALL("[dns] lookup [" + qt.get_QNAME() + "] directly");

        auto up_stream_ns_svr = m_service->get_config().get_dns().up_dns_server.at(0);
        auto dst              = udp::endpoint(make_address(up_stream_ns_svr), DEFAULT_UP_STREAM_NS_SVR_PORT);
        auto forwarder        = TP_MAKE_SHARED(UDPLocalForwarder, 
          m_service, m_udp_recv_endpoint, dst,
          [this](
            const udp::endpoint& endpoint, const std::string_view& data) { recv_up_stream_data(endpoint, data, false); },
          true);

        forwarder->start();

        if (forwarder->process(m_udp_recv_endpoint, former_data)) {
            m_forwarders.emplace_back(forwarder);
        }
    }
    _unguard;
}

address DNSServer::normalize_address(const address& ip) {
    _guard;

    if (ip.is_v6() && ip.to_v6().is_v4_mapped()) {
        const auto bytes = ip.to_v6().to_bytes();
        return address_v4({{bytes[12], bytes[13], bytes[14], bytes[15]}});
    }
    return ip;

    _unguard;
}

void DNSServer::index_addresses(const DNSCache& cache) {
    _guard;

    if (cache.is_proxyed()) {
        const auto expiry = cache.get_cached_time() + cache.get_ttl();
        // Replaced answers may still be in use; retain their addresses until expiry.
        for (const auto& ip : cache.get_ips()) {
            auto& indexed = m_proxy_address_expiry[normalize_address(ip)];
            indexed = std::max(indexed, expiry);
        }
    }

    _unguard;
}

bool DNSServer::is_ip_in_gfwlist(const address& ip) const {
    _guard;

    const auto found = m_proxy_address_expiry.find(normalize_address(ip));
    if (found == m_proxy_address_expiry.end()) {
        return false;
    }
    if (found->second <= time(nullptr)) {
        m_proxy_address_expiry.erase(found);
        return false;
    }
    return true;

    _unguard;
}
