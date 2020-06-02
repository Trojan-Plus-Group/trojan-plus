#ifndef _SOCKET_SESSION_HPP_
#define _SOCKET_SESSION_HPP_

#include <ctime>
#include <set>
#include <memory>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <boost/asio/streambuf.hpp>

#include "core/config.h"
#include "session.h"

class Service;
class SocketSession : public Session {
protected:    
    boost::asio::streambuf in_read_buf;
    boost::asio::streambuf out_read_buf;
    boost::asio::streambuf udp_read_buf;
    uint64_t recv_len;
    uint64_t sent_len;
    time_t start_time{};
    boost::asio::streambuf out_write_buf;
    boost::asio::streambuf udp_data_buf;
    boost::asio::ip::tcp::resolver resolver;
    
    boost::asio::ip::udp::socket udp_socket;
    boost::asio::ip::udp::endpoint udp_recv_endpoint;
    
public:
    SocketSession(Service* _service, const Config& config);

    virtual boost::asio::ip::tcp::socket& accept_socket() = 0;

    boost::asio::ip::tcp::endpoint in_endpoint;
};

#endif //_SOCKET_SESSION_HPP_