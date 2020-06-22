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

#ifndef _TROJAN_LWIP_TCP_CLIENT_HPP
#define _TROJAN_LWIP_TCP_CLIENT_HPP

#include <memory>

#include <boost/asio/ip/tcp.hpp>
#include <lwip/opt.h>
#include <lwip/err.h>
#include <lwip/tcp.h>

#include "core/service.h"
#include "tun/tunsession.h"

class lwip_tcp_client : public std::enable_shared_from_this<lwip_tcp_client> {

    static void static_client_err_func(void *arg, err_t err){
        ((lwip_tcp_client*)arg)->client_err_func(err);
    }

    static err_t static_client_recv_func(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err){
        return ((lwip_tcp_client*)arg)->client_recv_func(tpcb, p, err);
    }

    static err_t static_client_sent_func(void *arg, struct tcp_pcb *tpcb, uint16_t len){
        return ((lwip_tcp_client*)arg)->client_sent_func(tpcb, len);
    }

public:
    typedef std::function<void(lwip_tcp_client*)> CloseCallback;
private:
    boost::asio::ip::tcp::endpoint m_local_addr;
    boost::asio::ip::tcp::endpoint m_remote_addr;

    struct tcp_pcb* m_pcb;
    bool m_closed;
    bool m_aborted;

    uint32_t m_recved_len{};
    uint32_t m_output_len{};
    
    uint32_t m_sending_len{};
    uint32_t m_sent_len{};
    
    uint8_t send_buf[TCP_WND]{};
    std::shared_ptr<TUNSession> m_tun_session;
    CloseCallback m_close_cb;

    void close_session();
    void release_client(bool _called_by_tun_dev); 
    void client_log(const char *fmt, ...);
    int client_socks_recv_send_out();

    void client_err_func(err_t err);
    err_t client_recv_func(struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
    err_t client_sent_func(struct tcp_pcb *tpcb, u16_t len);

public:
    lwip_tcp_client(struct tcp_pcb * _pcb, std::shared_ptr<TUNSession> _session, CloseCallback&& _close_cb);
    void close_client(bool _abort, bool _called_by_tun_dev = false);
};
#endif //_TROJAN_LWIP_TCP_CLIENT_HPP