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
    typedef std::function<void(TUNSession*)> CloseCallback;
    typedef std::function<int(TUNSession*)> WriteToLwipCallback;
private:

    Service* m_service;
    boost::asio::streambuf m_recv_buf;
    boost::asio::streambuf m_recv_udp_buf;
    size_t m_recv_buf_ack_length;

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> m_out_socket;
    boost::asio::ip::tcp::resolver m_out_resolver;

    bool m_destroyed;
    CloseCallback m_close_cb;
    bool m_close_from_tundev_flag;
    bool m_connected;
    std::string m_send_buf;
    WriteToLwipCallback m_write_to_lwip;
    std::list<SentHandler> m_wait_ack_handler;
    ReadDataCache m_pipeline_data_cache;

    boost::asio::ip::tcp::endpoint m_local_addr;
    boost::asio::ip::tcp::endpoint m_remote_addr;

    boost::asio::ip::udp::endpoint m_local_addr_udp;
    boost::asio::ip::udp::endpoint m_remote_addr_udp;

    boost::asio::steady_timer m_udp_timout_timer;

    void out_async_read();
    void reset_udp_timeout();
    void parse_udp_packet_data();

    void out_async_send_impl(std::string data_to_send, SentHandler&& _handler);
public:
    TUNSession(Service* _service, bool _is_udp);
    ~TUNSession();

    void set_tcp_connect(boost::asio::ip::tcp::endpoint _local, boost::asio::ip::tcp::endpoint _remote){
        m_local_addr = _local;
        m_remote_addr = _remote;
    }

    void set_udp_connect(boost::asio::ip::udp::endpoint _local, boost::asio::ip::udp::endpoint _remote){
        m_local_addr_udp = _local;
        m_remote_addr_udp = _remote;
    }
    
    boost::asio::ip::udp::endpoint get_udp_local_endpoint()const { 
        return m_local_addr_udp;
    }

    boost::asio::ip::udp::endpoint get_udp_remote_endpoint()const { 
        return m_remote_addr_udp;
    }

    void set_write_to_lwip(WriteToLwipCallback&& _handler){ m_write_to_lwip = std::move(_handler); }
    void set_close_callback(CloseCallback&& _cb){ m_close_cb = std::move(_cb); }
    void set_close_from_tundev_flag(){ m_close_from_tundev_flag = true;}

    void start() override;
    void destroy(bool pipeline_call = false) override;

    void out_async_send(const char* _data, size_t _length, SentHandler&& _handler);
    void recv_ack_cmd() override;

    void recv_buf_sent(uint16_t _length);

    size_t recv_buf_ack_length() const { 
        return m_recv_buf_ack_length;
    }

    void recv_buf_consume(uint16_t _length){
        m_recv_buf.consume(_length);
    }

    size_t recv_buf_size() const {
        return m_recv_buf.size();
    }

    const uint8_t* recv_buf() const {
        return boost::asio::buffer_cast<const uint8_t*>(m_recv_buf.data());
    }

    bool is_destroyed()const { return m_destroyed; }

    bool try_to_process_udp(const boost::asio::ip::udp::endpoint& _local, 
        const boost::asio::ip::udp::endpoint& _remote, uint8_t* payload, size_t payload_length);
};
#endif //_TUNSESSION_H_