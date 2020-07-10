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
#include <boost/asio/ip/udp.hpp>
#include <sstream>

using namespace std;
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
    boost::system::error_code ec;

    auto udp_bind_endpoint = udp::endpoint(make_address_v4("0.0.0.0"), port);
    auto udp_protocol      = udp_bind_endpoint.protocol();

    socket.open(udp_protocol, ec);
    if (ec) {
        output_debug_info_ec(ec);
        return false;
    }
    socket.bind(udp_bind_endpoint, ec);
    if (ec) {
        output_debug_info_ec(ec);
        return false;
    }

    data_handler = move(handler);
    async_read_udp();
    return true;
}

void DNSServer::SocketQueryer::async_read_udp() {
    if (!socket.is_open()) {
        return;
    }

    auto self         = shared_from_this();
    auto prepare_size = service->get_config().get_udp_recv_buf();
    buf.begin_read(__FILE__, __LINE__);
    buf.consume_all();
    socket.async_receive_from(
      buf.prepare(prepare_size), recv_endpoint, [self, this](const boost::system::error_code error, size_t length) {
          buf.end_read();
          if (error) {
              async_read_udp();
              return;
          }

          buf.commit(length);
          data_handler(recv_endpoint, buf);
          async_read_udp();
      });
}

bool DNSServer::SocketQueryer::send(const boost::asio::ip::udp::endpoint& to, const std::string_view& data) {
    boost::system::error_code ec;
    socket.send_to(boost::asio::buffer(data), to, 0, ec);
    return (!ec);
}

DNSServer::DNSServer(Service* _service) : m_service(_service) { m_data_queryer = make_shared<SocketQueryer>(_service); }

DNSServer::DNSServer(Service* _service, std::shared_ptr<IDataQueryer> queryer)
    : m_service(_service), m_data_queryer(move(queryer)) {}

DNSServer::~DNSServer() { close_file_lock(s_dns_file_lock); }

bool DNSServer::start() {
    return m_data_queryer->open(
      [this](const boost::asio::ip::udp::endpoint& recv_endpoint, boost::asio::streambuf& data) {
          m_udp_recv_endpoint     = recv_endpoint;
          string_view former_data = streambuf_to_string_view(data);
          std::istream is(&data);

          dns_header dns_hdr;
          is >> dns_hdr;

          if (is && is_interest_dns_msg(dns_hdr)) {
              in_recved(is, dns_hdr, former_data);
          }
      },
      m_service->get_config().get_dns().port);
}

bool DNSServer::is_interest_dns_msg(const dns_header& dns_hdr) {
    return dns_hdr.QR() == 0 && dns_hdr.RCODE() == 0 && dns_hdr.ANCOUNT() == 0 && dns_hdr.NSCOUNT() == 0 &&
           dns_hdr.QDCOUNT() > 0;
}

bool DNSServer::is_interest_dns_msg(const trojan::dns_question& qt) {
    return qt.get_QCLASS() == dns_header::QCLASS_INTERNET &&
           (qt.get_QTYPE() == dns_header::QTYPE_A_RECORD || qt.get_QTYPE() == dns_header::QTYPE_AAAA_RECORD);
}

bool DNSServer::try_to_find_existed(const boost::asio::ip::udp::endpoint& local_src, const std::string_view& data) {
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
}
bool DNSServer::find_in_dns_cache(
  const udp::endpoint& local_src, const dns_header& header, const dns_question& question) {
    if (m_service->get_config().get_dns().enable_cached) {
        auto curr_time = time(nullptr);

        auto it = m_dns_cache.begin();
        while (it != m_dns_cache.end()) {
            if (it->expired(curr_time)) {
                it = m_dns_cache.erase(it);
            } else {
                it++;
            }
        }

        for (auto& c : m_dns_cache) {
            if (c.get_domain() == question.get_QNAME()) {
                _log_with_endpoint_ALL(local_src, "[dns] find " + question.get_QNAME() + " in cache ttl: " +
                                                    to_string(c.get_ttl() - (curr_time - c.get_cached_time())));

                std::string& raw_data = c.get_answer_data();
                raw_data[0]           = header.ID() >> one_byte_shift_8_bits;
                raw_data[1]           = header.ID() & one_byte_mask_0xFF;

                send_to_local(local_src, raw_data);
                return true;
            }
        }
    }

    return false;
}

void DNSServer::store_in_dns_cache(const string_view& data, bool proxyed) {
    if (m_service->get_config().get_dns().enable_cached) {
        string read_data(data);
        istringstream is(read_data);

        dns_answer answer;
        if (is >> answer) {
            if (!answer.get_questions().empty() && is_interest_dns_msg(answer.get_questions()[0])) {

                const auto& domain = answer.get_questions()[0].get_QNAME();
                uint32_t ttl       = numeric_limits<uint32_t>::max();
                vector<uint32_t> A_list;
                for (const auto& an : answer.get_answers()) {
                    if (an.A != 0) {
                        if (ttl > an.TTL) { // find min
                            ttl = an.TTL;
                        }

                        A_list.emplace_back(an.A);
                    }
                }

                if (ttl != numeric_limits<uint32_t>::max()) {
                    sort(A_list.begin(), A_list.end());
                    m_dns_cache.emplace_back(DNSCache(domain, ttl, A_list, proxyed, data));
                    _log_with_date_time_ALL("[dns] cache " + domain + " in ttl: " + to_string(ttl));
                }
            }
        }
    }
}

void DNSServer::send_to_local(const udp::endpoint& local_src, const string_view& data) {
    _log_with_endpoint_ALL(local_src, "[dns] <-- " + to_string(data.length()));
    m_data_queryer->send(local_src, data);
}

void DNSServer::recv_up_stream_data(const udp::endpoint& local_src, const string_view& data, bool proxyed) {
    send_to_local(local_src, data);
    store_in_dns_cache(data, proxyed);
}

bool DNSServer::is_remote_domain(const std::string& domain) const {
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
}

void DNSServer::in_recved(istream& is, const dns_header& header, const string_view& former_data) {
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
        auto dst              = make_pair(up_stream_ns_svr, DEFAULT_UP_STREAM_NS_SVR_PORT);
        auto forwarder        = make_shared<UDPForwardSession>(
          m_service, m_service->get_config(), m_service->get_ssl_context(), m_udp_recv_endpoint, dst,
          [this](const udp::endpoint& endpoint, const string_view& data) { recv_up_stream_data(endpoint, data, true); },
          false, true);

        auto data = m_service->get_sending_data_allocator().allocate(former_data);
        m_service->start_session(forwarder, [this, forwarder, data](boost::system::error_code ec) {
            if (!ec) {
                m_proxy_forwarders.emplace_back(forwarder);
                forwarder->start_udp(streambuf_to_string_view(*data));
            }
            m_service->get_sending_data_allocator().free(data);
        });

    } else {

        _log_with_date_time_ALL("[dns] lookup [" + qt.get_QNAME() + "] directly");

        auto up_stream_ns_svr = m_service->get_config().get_dns().up_dns_server.at(0);
        auto dst              = udp::endpoint(make_address(up_stream_ns_svr), DEFAULT_UP_STREAM_NS_SVR_PORT);
        auto forwarder        = make_shared<UDPLocalForwarder>(
          m_service, m_udp_recv_endpoint, dst,
          [this](
            const udp::endpoint& endpoint, const string_view& data) { recv_up_stream_data(endpoint, data, false); },
          true);

        forwarder->start();

        if (forwarder->process(m_udp_recv_endpoint, former_data)) {
            m_forwarders.emplace_back(forwarder);
        }
    }
}

bool DNSServer::is_ip_in_gfwlist(uint32_t ip) const {
    for (const auto& dns : m_dns_cache) {
        if (dns.is_proxyed() && binary_search(dns.get_ips().cbegin(), dns.get_ips().cend(), ip)) {
            return true;
        }
    }

    return false;
}
