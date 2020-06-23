/*
 * This file is part of the Trojan Plus project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Trojan Plus is derived from original trojan project and writing 
 * for more experimental features.
 * Copyright (C) 2017-2020  The Trojan Authors.
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

#include "lwip_tcp_client.h"

#include <cstdarg>
#include <algorithm>
#include <boost/asio/ip/address.hpp>


#include "core/log.h"

using namespace std;
using namespace boost::asio::ip;

lwip_tcp_client::lwip_tcp_client(struct tcp_pcb *_pcb, shared_ptr<TUNSession> _session, CloseCallback&& _close_cb) : 
    m_pcb(_pcb),
    m_closed(false),
    m_aborted(false),
    m_tun_session(move(_session)),
    m_close_cb(move(_close_cb)){

    // special for reverse local to remote
    m_remote_addr = tcp::endpoint(make_address_v4((address_v4::uint_type)ntoh32(_pcb->local_ip.u_addr.ip4.addr)), _pcb->local_port);
    m_local_addr = tcp::endpoint(make_address_v4((address_v4::uint_type)ntoh32(_pcb->remote_ip.u_addr.ip4.addr)), _pcb->remote_port);

    m_tun_session->set_tcp_connect(m_local_addr, m_remote_addr);
    m_tun_session->set_write_to_lwip([this](TUNSession*, std::string_view*){ return client_socks_recv_send_out(); });
    m_tun_session->set_close_callback([this](TUNSession* session){ 
        if(session->recv_buf_ack_length() == 0){ // need to wait send remain buff
            output_debug_info();
            close_client(false); 
        }        
    });

    tcp_arg(m_pcb, this);

    // setup handlers
    tcp_err(m_pcb, static_client_err_func);
    tcp_recv(m_pcb, static_client_recv_func);
    tcp_sent(m_pcb, static_client_sent_func);

    client_log("accepted");
}

void lwip_tcp_client::client_log(const char *fmt, ...){
    const auto logout_level = Log::INFO;

    if(Log::level <= logout_level){
        const int buf_size = 256;
        char buf[buf_size];
        int n = snprintf((char*)buf, buf_size, "[lwip] [%s:%d->%s:%d] [pcb:0x%llx session_id: %d] ", 
            m_local_addr.address().to_string().c_str(), m_local_addr.port(),
            m_remote_addr.address().to_string().c_str(), m_remote_addr.port(), 
            (unsigned long long)m_pcb, (int)m_tun_session->get_session_id());

        va_list vl;
        va_start(vl, fmt);
        vsnprintf(buf + n, buf_size - n, fmt, vl);
        va_end(vl);

        _log_with_date_time(buf, logout_level);
    }    
}

void lwip_tcp_client::client_err_func(err_t err){
    client_log("client_err_func (%d)", (int)err);

    // do NOT call close_client with tcp_close/tcp_abort, otherwise it will assert to free double
    // this client_err_func will be called by lwip and then lwip system will be free pcb
    close_session();
    release_client(false);
}

err_t lwip_tcp_client::client_recv_func(struct tcp_pcb *, struct pbuf *p, err_t err){
    
    if(m_aborted){
        return ERR_ABRT;
    }

    if (p == nullptr || err != ERR_OK) {
        client_log("client_recv_func closed (%d)", (int)err);
        close_client(false);
    } else {

        if(m_tun_session->is_destroyed()){
            client_log("m_tun_session->is_destroyed closed");
            output_debug_info();
            close_client(true);
            return ERR_ABRT;
        }

        assert(p->tot_len > 0);
        if(p->tot_len > sizeof(send_buf)){
            return ERR_MEM;
        }

        // copy data to buffer
        auto length = pbuf_copy_partial(p, (void*)send_buf, p->tot_len, 0);
        assert(length == p->tot_len);
        pbuf_free(p);
        m_sending_len += length;
        m_tun_session->out_async_send((const uint8_t*)send_buf, length, [this, length](boost::system::error_code ec){
            if(ec){
                output_debug_info_ec(ec);
                close_client(true);
            }else{
                if(!m_closed){
                    tcp_recved(m_pcb, length);
                    m_sent_len += length;
                }                
            }            
        });
    }
    
    return ERR_OK;
}

err_t lwip_tcp_client::client_sent_func(struct tcp_pcb *, u16_t len){

    if(m_aborted){
        return ERR_ABRT;
    }
    
    m_recved_len += len;
    m_tun_session->recv_buf_ack_sent(len);

    if(m_tun_session->is_destroyed()){
        if(m_tun_session->recv_buf_ack_length() > 0){
            if(client_socks_recv_send_out() < 0){
                return ERR_ABRT;
            }

            return ERR_OK;
        }
        output_debug_info();
        close_client(false);
        return ERR_OK;
    }

    if(client_socks_recv_send_out() < 0){
        return ERR_ABRT;
    }

    return ERR_OK;
}

int lwip_tcp_client::client_socks_recv_send_out(){
    if(m_aborted){
        return -1;
    }

    if(m_closed){
        return 0;
    }

    auto recv_size = m_tun_session->recv_buf_size();
    if(recv_size == 0){
        return 0;
    }

    const auto* recv_data = m_tun_session->recv_buf();
    size_t wrote_size = 0;
    do {
        
        auto to_write = min(recv_size, (size_t)tcp_sndbuf(m_pcb));
        if (to_write == 0) {
            break;
        }
            
        err_t err = tcp_write(m_pcb, (const void*)(recv_data + wrote_size), (uint16_t)to_write, TCP_WRITE_FLAG_COPY);
        if (err != ERR_OK) {
            if (err == ERR_MEM) {
                break;
            }
            
            client_log("tcp_write failed (%d)", (int)err);
            close_client(true);
            return -1;
        }
        
        recv_size -= to_write;
        wrote_size += to_write;
    } while (recv_size > 0);

    // start sending now
    err_t err = tcp_output(m_pcb);
    if (err != ERR_OK) {
        client_log("tcp_output failed (%d)", (int)err);
        close_client(true);
        return -1;
    }

    m_output_len += wrote_size;
    m_tun_session->recv_buf_consume((uint16_t)wrote_size);
    return 0;
}

void lwip_tcp_client::close_session(){
    if(m_closed || m_aborted){
        return;
    }

    m_closed = true;

    // remove callbacks
    tcp_err(m_pcb, nullptr);
    tcp_recv(m_pcb, nullptr);
    tcp_sent(m_pcb, nullptr);

    if(!m_tun_session->is_destroyed()){
        output_debug_info();
        m_tun_session->destroy();
    }

    client_log("close_session (output: %u, recved: %u), (sending: %u, sent: %u)", 
        m_output_len, m_recved_len, m_sending_len, m_sent_len);
}

void lwip_tcp_client::close_client(bool _abort, bool _called_by_tun_dev /*= false*/){
    if(m_closed || m_aborted){
        return;
    }

    close_session();

    if(_abort){
        client_log("close_client abort");
        m_aborted = true;
        tcp_abort(m_pcb);
    }else{
        // free m_pcb
        err_t err = tcp_close(m_pcb);
        client_log("close_client");
        if (err != ERR_OK){
            client_log("tcp_close failed (%d)", err);
            m_aborted = true;
            // abort the PCB
            tcp_abort(m_pcb);
        }
    }

    release_client(_called_by_tun_dev);
}

void lwip_tcp_client::release_client(bool _called_by_tun_dev){
    if(m_pcb != nullptr){
        tcp_arg(m_pcb, nullptr);
        m_pcb = nullptr;

        if(!_called_by_tun_dev){
            // this callback will trigger decontructor
            m_close_cb(this); 
        } 
    }
}

