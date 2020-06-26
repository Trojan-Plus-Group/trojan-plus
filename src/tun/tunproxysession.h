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

#ifndef _TUN_PROXY_SESSION_H_
#define _TUN_PROXY_SESSION_H_

#include "tun/tunsession.h"

class TUNProxySession : public TUNSession {

    int m_read_ack_count{0};

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> m_out_socket;
    boost::asio::ip::tcp::resolver m_out_resolver;

    void out_async_read();
    void try_out_async_read();

    [[nodiscard]] size_t parse_udp_packet_data(const std::string_view& data);

    void out_async_send_impl(const std::string_view& data_to_send, SentHandler&& _handler);

    [[nodiscard]] boost::asio::ip::udp::endpoint get_redirect_local_remote_addr(bool output_log = false) const;

  public:
    TUNProxySession(Service* service, bool udp);
    ~TUNProxySession();

    void start() override;
    void destroy(bool pipeline_call = false) override;
    void out_async_send(const uint8_t* _data, size_t _length, SentHandler&& _handler) override;
    void recv_ack_cmd(int ack_count) override;

    // interfaces for TCP
    void recv_buf_consume(uint16_t _length) override;
    void recv_buf_ack_sent(uint16_t _length) override;

    // interfaces for UDP
    bool try_to_process_udp(const boost::asio::ip::udp::endpoint& _local, const boost::asio::ip::udp::endpoint& _remote,
      const uint8_t* payload, size_t payload_length) override;
};

#endif //_TUN_PROXY_SESSION_H_