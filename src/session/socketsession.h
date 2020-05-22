#ifndef _SOCKET_SESSION_HPP_
#define _SOCKET_SESSION_HPP_

#include <ctime>
#include <set>
#include <memory>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include "core/config.h"
#include "session.h"

class SocketSession : public Session {
protected:    
    uint8_t in_read_buf[MAX_BUF_LENGTH]{};
    uint8_t out_read_buf[MAX_BUF_LENGTH]{};
    uint8_t udp_read_buf[MAX_BUF_LENGTH]{};
    uint64_t recv_len;
    uint64_t sent_len;
    time_t start_time{};
    std::string out_write_buf;
    std::string udp_data_buf;
    boost::asio::ip::tcp::resolver resolver;
    
    boost::asio::ip::udp::socket udp_socket;
    boost::asio::ip::udp::endpoint udp_recv_endpoint;
    
public:
    SocketSession(const Config &config, boost::asio::io_context &io_context);

    virtual boost::asio::ip::tcp::socket& accept_socket() = 0;

    boost::asio::ip::tcp::endpoint in_endpoint;
};

#endif //_SOCKET_SESSION_HPP_