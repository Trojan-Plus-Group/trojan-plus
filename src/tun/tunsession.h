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

#ifndef _TUNSESSION_H_
#define _TUNSESSION_H_

#include <string>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include "session/session.h"
#include "core/pipeline.h"
#include "core/utils.h"

class Service;
class TUNSession : public Session{

public:
    using CloseCallback = std::function<void(TUNSession*)>;
    using WriteToLwipCallback = std::function<int(TUNSession*, std::string_view*)>;

private:

    Service* m_service;
    ReadBufWithGuard m_recv_buf;
    size_t m_recv_buf_ack_length;

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> m_out_socket;
    boost::asio::ip::tcp::resolver m_out_resolver;

    bool m_destroyed;
    CloseCallback m_close_cb;
    bool m_close_from_tundev_flag;
    bool m_connected;
    boost::asio::streambuf m_send_buf;
    WriteToLwipCallback m_write_to_lwip;
    std::list<SentHandler> m_wait_ack_handler;

    boost::asio::ip::tcp::endpoint m_local_addr;
    boost::asio::ip::tcp::endpoint m_remote_addr;

    boost::asio::ip::udp::endpoint m_local_addr_udp;
    boost::asio::ip::udp::endpoint m_remote_addr_udp;

    boost::asio::steady_timer m_udp_timout_timer;

    void out_async_read();
    void try_out_async_read();
    void reset_udp_timeout();

    [[nodiscard]]
    size_t parse_udp_packet_data(const std::string_view& data);

    void out_async_send_impl(const std::string_view& data_to_send, SentHandler&& _handler);
public:
    TUNSession(Service* _service, bool _is_udp);
    ~TUNSession() final;

    void set_tcp_connect(const boost::asio::ip::tcp::endpoint& _local, 
      const boost::asio::ip::tcp::endpoint& _remote){
        m_local_addr = _local;
        m_remote_addr = _remote;
    }

    void set_udp_connect(const boost::asio::ip::udp::endpoint& _local, 
      const boost::asio::ip::udp::endpoint& _remote){
        m_local_addr_udp = _local;
        m_remote_addr_udp = _remote;
    }
    
    [[nodiscard]]
    const boost::asio::ip::udp::endpoint& get_udp_local_endpoint()const { 
        return m_local_addr_udp;
    }

    [[nodiscard]]
    const boost::asio::ip::udp::endpoint& get_udp_remote_endpoint()const { 
        return m_remote_addr_udp;
    }

    void set_write_to_lwip(WriteToLwipCallback&& _handler){ m_write_to_lwip = std::move(_handler); }
    void set_close_callback(CloseCallback&& _cb){ m_close_cb = std::move(_cb); }
    void set_close_from_tundev_flag(){ m_close_from_tundev_flag = true;}

    void start() override;
    void destroy(bool pipeline_call = false) override;

    void out_async_send(const uint8_t* _data, size_t _length, SentHandler&& _handler);
    void recv_ack_cmd() override;

    void recv_buf_sent(uint16_t _length);

    [[nodiscard]]
    size_t recv_buf_ack_length() const { return m_recv_buf_ack_length; }

    void recv_buf_consume(uint16_t _length);

    [[nodiscard]]
    size_t recv_buf_size() const { return m_recv_buf.size(); }

    [[nodiscard]]
    const uint8_t* recv_buf() const {
        return boost::asio::buffer_cast<const uint8_t*>(m_recv_buf.data());
    }

    [[nodiscard]]
    bool is_destroyed()const { return m_destroyed; }

    bool try_to_process_udp(const boost::asio::ip::udp::endpoint& _local, 
        const boost::asio::ip::udp::endpoint& _remote, const uint8_t* payload, size_t payload_length);
};
#endif //_TUNSESSION_H_