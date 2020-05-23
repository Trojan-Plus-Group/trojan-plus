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
public:
    typedef std::function<void(lwip_tcp_client*)> CloseCallback;
private:
    boost::asio::ip::tcp::endpoint m_local_addr;
    boost::asio::ip::tcp::endpoint m_remote_addr;

    struct tcp_pcb* m_pcb;
    bool m_closed;
    bool m_aborted;
    
    uint8_t send_buf[TCP_WND];

    std::shared_ptr<TUNSession> m_tun_session;

    CloseCallback m_close_cb;

private:
    void client_log(const char *fmt, ...);
    int client_socks_recv_send_out();

    void client_err_func(err_t err);
    err_t client_recv_func(struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
    err_t client_sent_func(struct tcp_pcb *tpcb, u16_t len);

public:
    lwip_tcp_client(struct tcp_pcb * _pcb, std::shared_ptr<TUNSession> _session, CloseCallback&& _close_cb);
    void close_client(bool _abort, bool _call_by_tun_dev = false);
};
#endif //_TROJAN_LWIP_TCP_CLIENT_HPP