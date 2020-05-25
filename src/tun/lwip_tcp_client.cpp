#include "lwip_tcp_client.h"

#include <stdarg.h>
#include <algorithm>
#include <boost/asio/ip/address.hpp>


#include "core/log.h"

using namespace std;
using namespace boost::asio::ip;

lwip_tcp_client::lwip_tcp_client(struct tcp_pcb *_pcb, shared_ptr<TUNSession> _session, CloseCallback&& _close_cb) : 
    m_pcb(_pcb),
    m_closed(false),
    m_aborted(false),
    m_tun_session(_session),
    m_close_cb(move(_close_cb)){

    // special for reverse local to remote
    m_remote_addr = tcp::endpoint(make_address_v4((address_v4::uint_type)ntoh32(_pcb->local_ip.u_addr.ip4.addr)), _pcb->local_port);
    m_local_addr = tcp::endpoint(make_address_v4((address_v4::uint_type)ntoh32(_pcb->remote_ip.u_addr.ip4.addr)), _pcb->remote_port);

    m_tun_session->set_tcp_connect(m_local_addr, m_remote_addr);
    m_tun_session->set_write_to_lwip([this](){ return client_socks_recv_send_out(); });
    m_tun_session->set_close_callback([this](TUNSession* session){ 
        if(session->recv_buf_ack_length() == 0){ // need to wait send remain buff
            close_client(true); 
        }        
    });

    tcp_arg(m_pcb, this);

    // setup handlers
    tcp_err(m_pcb, (tcp_err_fn)&lwip_tcp_client::client_err_func);
    tcp_recv(m_pcb, (tcp_recv_fn)&lwip_tcp_client::client_recv_func);
    tcp_sent(m_pcb, (tcp_sent_fn)&lwip_tcp_client::client_sent_func);

    client_log("accepted");
}

void lwip_tcp_client::client_log(const char *fmt, ...){
    if(Log::level == Log::ALL){
        char buf[256];
        int n = snprintf(buf, sizeof(buf), "[lwip] [%s:%d->%s:%d] [pcb:0x%lx session_id:%d] ", 
            m_local_addr.address().to_string().c_str(), m_local_addr.port(),
            m_remote_addr.address().to_string().c_str(), m_remote_addr.port(), 
            (uint64_t)m_pcb, (int)m_tun_session->session_id);

        va_list vl;
        va_start(vl, fmt);
        vsnprintf(buf + n, sizeof(buf) - n, fmt, vl);
        va_end(vl);

        _log_with_date_time(buf);
    }    
}

void lwip_tcp_client::client_err_func(err_t err){
    client_log("client_err_func (%d)", (int)err);

    // do NOT call close_client with tcp_close/tcp_abort, otherwise it will assert to free double
    // this client_err_func will be called by lwip and then lwip system will be free pcb
    close_session(false);
}

err_t lwip_tcp_client::client_recv_func(struct tcp_pcb *, struct pbuf *p, err_t err){
    
    if(m_aborted){
        return ERR_ABRT;
    }

    if (!p || err != ERR_OK) {
        client_log("client_recv_func closed");
        close_client(false);
    } else {

        if(m_tun_session->is_destroyed()){
            client_log("m_tun_session->is_destroyed closed");
            close_client(true);
            return ERR_ABRT;
        }

        assert(p->tot_len > 0);
        if(p->tot_len > sizeof(send_buf)){
            return ERR_MEM;
        }

        // copy data to buffer
        auto length = pbuf_copy_partial(p, send_buf, p->tot_len, 0);
        assert(length == p->tot_len);
        pbuf_free(p);

        m_tun_session->out_async_send((const char*)send_buf, length, [this, length](boost::system::error_code ec){
            if(ec){
                close_client(true);
            }else{
                if(!m_closed){
                    tcp_recved(m_pcb, length);
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

    m_tun_session->recv_buf_sent(len);

    if(m_tun_session->is_destroyed()){
        if(m_tun_session->recv_buf_ack_length() > 0){
            if(client_socks_recv_send_out() < 0){
                return ERR_ABRT;
            }else{
                return ERR_OK;
            }
        }
        close_client(true);
        return ERR_ABRT;
    }

    if(client_socks_recv_send_out() < 0){
        return ERR_ABRT;
    }else{
        return ERR_OK;
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
    auto recv_data = m_tun_session->recv_buf();

    size_t wrote_size = 0;
    do {
        
        auto to_write = min(recv_size, (size_t)tcp_sndbuf(m_pcb));
        if (to_write == 0) {
            break;
        }
            
        err_t err = tcp_write(m_pcb, (const void*)recv_data, (uint16_t)to_write, TCP_WRITE_FLAG_COPY);
        if (err != ERR_OK) {
            if (err == ERR_MEM) {
                break;
            }
            
            client_log("tcp_write failed (%d)", (int)err);
            close_client(true);
            return -1;
        }
        
        recv_size -= to_write;
        recv_data += to_write;

        wrote_size += to_write;
    } while (true);
    
    // start sending now
    err_t err = tcp_output(m_pcb);
    if (err != ERR_OK) {
        client_log("tcp_output failed (%d)", (int)err);
        close_client(true);
        return -1;
    }

    m_tun_session->recv_buf_consume(wrote_size);
    return 0;
}

void lwip_tcp_client::close_session(bool _call_by_tun_dev){
    if(m_closed || m_aborted){
        return;
    }

    m_closed = true;

    m_tun_session->destroy();
    if(!_call_by_tun_dev){
        m_close_cb(this);
    } 

    // remove callbacks
    tcp_err(m_pcb, NULL);
    tcp_recv(m_pcb, NULL);
    tcp_sent(m_pcb, NULL);
}

void lwip_tcp_client::close_client(bool _abort, bool _call_by_tun_dev /*= false*/){
    if(m_closed || m_aborted){
        return;
    }

    close_session(_call_by_tun_dev);
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
    
    m_pcb = nullptr;       
}

