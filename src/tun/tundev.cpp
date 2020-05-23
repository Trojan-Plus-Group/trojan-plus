
#include "tundev.h"

#include <linux/if_tun.h>
#include <functional>
#include <assert.h>
#include <boost/asio/ip/address_v4.hpp>

#include "proto/ipv4_header.h"
#include "proto/ipv6_header.h"
#include "core/log.h"
#include "core/service.h"
#include "tun/tunsession.h"
#include "tun/lwip_tcp_client.h"


using namespace std;
using namespace boost::asio::ip;

TUNDev* TUNDev::sm_tundev = nullptr;

TUNDev::TUNDev(Service* _service, const std::string& _tun_name, 
        const std::string& _ipaddr, const std::string& _netmask, int _mtu, int _outside_tun_fd) : 
    m_netif_configured(false),
    m_tcp_listener(nullptr),    
    m_service(_service),
    m_tun_fd(_outside_tun_fd), 
    m_is_outsize_tun_fd(_outside_tun_fd != -1),
    m_mtu(_mtu), 
    m_quitting(false), 
    m_boost_sd(_service->service()) {

    assert(sm_tundev == nullptr);
    sm_tundev = this;

    if(m_tun_fd == -1){
        // open TUN device, check detail information:
        // https://www.kernel.org/doc/Documentation/networking/tuntap.txt          
        if ((m_tun_fd = open("/dev/net/tun", O_RDWR)) < 0) {
            throw runtime_error("[tun] error opening device");
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));

        ifr.ifr_flags = IFF_NO_PI | IFF_TUN;
        snprintf(ifr.ifr_name, IFNAMSIZ, "%s", _tun_name.c_str());
            
        if (ioctl(m_tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
            throw runtime_error("[tun] error configuring device");
        }

        if(ifr.ifr_mtu != m_mtu){
            m_mtu = ifr.ifr_mtu;
            _log_with_date_time("[tun] ifr.ifr_mtu:" + to_string(ifr.ifr_mtu), Log::WARN);
        }
    }

    m_boost_sd.assign(m_tun_fd);

    // init lwip
    lwip_init();

    // make addresses for netif
    ip4_addr_t addr;
    addr.addr = make_address_v4(_ipaddr).to_uint();

    ip4_addr_t netmask;
    netmask.addr = make_address_v4(_netmask).to_uint();

    ip4_addr_t gw;
    ip4_addr_set_any(&gw);

    // init netif
    if (!netif_add(&m_netif, &addr, &netmask, &gw, NULL, static_netif_init_func, static_netif_input_func)){
        throw runtime_error("[tun] netif_add failed");
    }

    // set netif up
    netif_set_up(&m_netif);

    // set netif link up, otherwise ip route will refuse to route
    netif_set_link_up(&m_netif);

    // set netif pretend TCP
    netif_set_pretend_tcp(&m_netif, 1);

    // set netif default
    netif_set_default(&m_netif);

    m_netif_configured = true;

    // init listener
    struct tcp_pcb *l = tcp_new_ip_type(IPADDR_TYPE_V4);
    if (!l){
        throw runtime_error("[tun] tcp_new_ip_type failed");
    }

    // bind listener
    if (tcp_bind_to_netif(l, "ho0") != ERR_OK){
        tcp_close(l);
        throw runtime_error("[tun] tcp_bind_to_netif failed");
    }

    tcp_bind_netif(l, &m_netif);
    
    // listen listener
    if (!(m_tcp_listener = tcp_listen(l))){
        tcp_close(l);
        throw runtime_error("[tun] tcp_listen failed");
    }

    tcp_arg(m_tcp_listener, this);

    // setup listener accept handler
    tcp_accept(m_tcp_listener,(tcp_accept_fn)&TUNDev::listener_accept_func);

    m_device_write_buf = new uint8_t[m_mtu];
    async_read();
}

TUNDev::~TUNDev(){
    if(m_quitting){
        return;
    }

    m_quitting = true;

    _log_with_date_time("[tun] destoryed, clear all tcp_client:" + to_string(m_tcp_clients.size()));
    for(auto it = m_tcp_clients.begin();it != m_tcp_clients.end();it++){
        it->get()->close_client(true, true);
    }
    m_tcp_clients.clear();

    // free listener
    if (m_tcp_listener) {
        tcp_close(m_tcp_listener);
    }

    // free netif
    if (m_netif_configured) {
        netif_remove(&m_netif);
        m_netif_configured = false;
    }

    if(m_tun_fd != -1 && !m_is_outsize_tun_fd){
        close(m_tun_fd);
        m_tun_fd = -1;
    }

    sm_tundev = nullptr;
}

err_t TUNDev::netif_init_func(struct netif *netif){
    netif->name[0] = 'h';
    netif->name[1] = 'o';
    netif->output = static_netif_output_func;
    return ERR_OK;
}

err_t TUNDev::netif_input_func(struct pbuf *p, struct netif *inp){
    uint8_t ip_version = 0;
    if (p->len > 0) {
        ip_version = (((uint8_t *)p->payload)[0] >> 4);
    }
    
    switch (ip_version) {
        case 4: {
            return ip_input(p, inp);
        } 
        break;
        case 6: {
            //throw runtime_error("haven't supported ipv6");
        }
        break;
    }
    
    pbuf_free(p);
    return ERR_OK;
}

err_t TUNDev::netif_output_func(struct netif *, struct pbuf *p, const ip4_addr_t *){
    if (m_quitting) {
        return ERR_OK;
    }
    
    // if there is just one chunk, send it directly, else via buffer
    if (!p->next) {
        if (p->len > m_mtu) {
            _log_with_date_time("[tun] netif func output: no space left");
            return ERR_OK;
        }
        auto write_len = write(m_tun_fd, (uint8_t *)p->payload, p->len);
        if(write_len != p->len){
            _log_with_date_time("[tun] netif func output: haven't writen full length! wrote " + to_string(write_len) + " need " + to_string(p->len) );
        }
    } else {
        int len = 0;
        do {
            if (p->len > m_mtu - len) {
                _log_with_date_time("[tun] netif func output: no space left");
                return ERR_OK;
            }
            memcpy(m_device_write_buf + len, p->payload, p->len);
            len += p->len;
        } while ((p = p->next) != NULL);
        
        auto write_len = write(m_tun_fd, m_device_write_buf, len);
        if(write_len != len){
            _log_with_date_time("[tun] netif func output: haven't writen full length2 ! wrote " + to_string(write_len) + " need " + to_string(len) );
        }
    }

    return ERR_OK;
}

err_t TUNDev::listener_accept_func(struct tcp_pcb *newpcb, err_t err){

    if(err != ERR_OK){
        return err;
    }

    auto session = make_shared<TUNSession>(m_service, false);
    auto tcp_client = make_shared<lwip_tcp_client>(newpcb, session,[this](lwip_tcp_client* client){
        for(auto it = m_tcp_clients.begin(); it != m_tcp_clients.end(); it++){
            if(it->get() == client){
                m_tcp_clients.erase(it);
                break;
            }
        }
    });
    
    m_service->start_session(session, false, [this, session, tcp_client](boost::system::error_code ec){
        if(!ec){
            session->start();
            m_tcp_clients.emplace_back(tcp_client);
        }else{
            session->destroy();
            tcp_client->close_client(true);
        }
    });
    
    return  ERR_OK;
}

bool TUNDev::try_to_process_udp_packet(const uint8_t*, size_t){
    // TODO
    return false;
}

void TUNDev::input_netif_packet(const uint8_t* data, size_t packet_len){
    if (try_to_process_udp_packet(data, packet_len)) {
        return;
    }            

    struct pbuf *p = pbuf_alloc(PBUF_RAW, packet_len, PBUF_POOL);
    if (!p) {
        _log_with_date_time("[tun] device read: pbuf_alloc failed");
        return;
    }
    
    // write packet to pbuf            
    if(pbuf_take(p, (void*)data, packet_len) != ERR_OK){
        _log_with_date_time("[tun] device read: pbuf_take failed");
        pbuf_free(p);
        return;
    }
    
    // pass pbuf to input
    if (m_netif.input(p, &m_netif) != ERR_OK) {
        _log_with_date_time("[tun] device read: input failed");
        pbuf_free(p);
        return;
    }
}

void TUNDev::parse_packet(){
    if(m_packet_parse_buff.size() == 0){
        // need more byte for version
        return;
    }

    auto data = (uint8_t*)m_packet_parse_buff.c_str();
    auto data_len = m_packet_parse_buff.length();
    auto ip_version = (data[0] >> 4) & 0xF;

    if(ip_version == 4 || ip_version == 6){

        istringstream is(m_packet_parse_buff);
        uint16_t total_length = 0;

        if(ip_version == 4){
            ipv4_header ipv4_hdr;        
            is >> ipv4_hdr;
            if(is){
                total_length = ipv4_hdr.total_length();
            }
            
        }else{
            ipv6_header ipv6_hdr;
            is >> ipv6_hdr;
            if(is){
                total_length = ipv6_hdr.payload_length() + ipv6_header::HEADER_FIXED_LENGTH;
            }
        }

        if(total_length != 0){
            if(total_length <= data_len){
                input_netif_packet(data, total_length);

                if(data_len == total_length){
                    //_log_with_date_time("full packet process");
                    m_packet_parse_buff.clear();
                }else{
                    //_log_with_date_time("split packet process--------------");
                    m_packet_parse_buff = m_packet_parse_buff.substr(total_length);
                    parse_packet();
                }
            }
        }else{
            if(is.bad()){
                m_packet_parse_buff.clear();
            }
        }

    }else{
        m_packet_parse_buff.clear();
    }
}

void TUNDev::async_read(){

    m_sd_read_buffer.consume(m_sd_read_buffer.size());

    const auto max_buff_size = m_mtu;
    m_boost_sd.async_read_some(m_sd_read_buffer.prepare(max_buff_size),[this, max_buff_size](boost::system::error_code ec, size_t data_len){
        if(m_quitting){
            return;
        }

        if(!ec){
            //_log_with_date_time("TUNDev::async_read length: " + to_string(data_len));
            m_sd_read_buffer.commit(data_len);

            auto data = boost::asio::buffer_cast<const char*>(m_sd_read_buffer.data());
            m_packet_parse_buff.append(data, data_len);

            parse_packet();
            async_read();
        }
    });

    // sleep for test
    //::sleep(1);
}