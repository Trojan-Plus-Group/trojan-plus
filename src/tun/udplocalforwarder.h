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

#ifndef _TROJAN_UDP_LOCAL_FORWARDER_HPP
#define _TROJAN_UDP_LOCAL_FORWARDER_HPP

#include "session/session.h"
#include "session/udpforwardsession.h"

class Service;
class UDPLocalForwarder : public Session {

    Service* m_service;
    UDPForwardSession::UDPWriter m_writer;
    boost::asio::ip::udp::endpoint m_local_src;
    boost::asio::ip::udp::endpoint m_remote_dst;
    boost::asio::ip::udp::socket m_udp_socket;

    ReadBufWithGuard m_read_buf;
    bytes_stat m_stat;
    bool m_is_dns;

    bool m_destroyed{false};
    std::function<void()> m_destroy_cb;

    bool write_to(const std::string_view& data);
    void async_read();

  public:
    UDPLocalForwarder(Service* service, boost::asio::ip::udp::endpoint local_recv,
      boost::asio::ip::udp::endpoint remote_dst, UDPForwardSession::UDPWriter&& writer, bool is_dns);

    ~UDPLocalForwarder() override;

    void start() override;
    void destroy(bool pipeline_call = false) override;
    bool process(const boost::asio::ip::udp::endpoint& endpoint, const std::string_view& data);

    [[nodiscard]] bool is_destroyed() const { return m_destroyed; }
    void set_destroy_callback(std::function<void()>&& destroy_cb) { m_destroy_cb = std::move(destroy_cb); }
};

#endif //_TROJAN_UDP_LOCAL_FORWARDER_HPP