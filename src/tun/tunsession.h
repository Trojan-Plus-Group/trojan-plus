#ifndef _TUNSESSION_H_
#define _TUNSESSION_H_

#include <string>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include "session/session.h"
#include "core/pipeline.h"

class Service;
class TUNSession : public Session{
    Service* m_service;
    boost::asio::streambuf m_recv_buf;
    size_t m_recv_buf_ack_length;

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> m_out_socket;
    boost::asio::ip::tcp::resolver m_out_resolver;

    bool m_destroyed;
    bool m_connected;
    std::string m_send_buf;
    std::function<int()> m_write_to_lwip;
    std::list<Pipeline::SentHandler> m_wait_ack_handler;
    Pipeline::ReadDataCache m_pipeline_data_cache;

    boost::asio::ip::tcp::endpoint m_local_addr;
    boost::asio::ip::tcp::endpoint m_remote_addr;

    boost::asio::ip::udp::endpoint m_local_addr_udp;
    boost::asio::ip::udp::endpoint m_remote_addr_udp;

    void out_async_read();

public:
    TUNSession(Service* _service, bool _is_udp);
    ~TUNSession();

    void set_tcp_connect(boost::asio::ip::tcp::endpoint _local, boost::asio::ip::tcp::endpoint _remote);
    void set_udp_connect(boost::asio::ip::udp::endpoint _local, boost::asio::ip::udp::endpoint _remote);
    void set_write_to_lwip(std::function<int()>&& _handler){ m_write_to_lwip = std::move(_handler); }

    void start() override;
    void destroy(bool pipeline_call = false) override;

    void out_async_send(const char* _data, size_t _length, Pipeline::SentHandler&& _handler);
    void pipeline_out_recv(std::string&& data);
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

};
#endif //_TUNSESSION_H_