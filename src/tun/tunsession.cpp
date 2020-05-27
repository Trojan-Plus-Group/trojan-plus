#include "tunsession.h"

#include <ostream>
#include <string>

#include "core/service.h"
#include "core/utils.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"

using namespace std;

TUNSession::TUNSession(Service* _service, bool _is_udp) : 
    Session(_service->config, _service->service()),
    m_service(_service), 
    m_recv_buf_ack_length(0),
    m_out_socket(_service->service(), _service->get_ssl_context()),
    m_out_resolver(_service->service()),
    m_destroyed(false),
    m_close_from_tundev_flag(false),
    m_connected(false),
    m_udp_timout_timer(_service->service()){

    is_udp_forward_session = _is_udp;
    allocate_session_id()();
}

TUNSession::~TUNSession(){
    free_session_id()();
}

void TUNSession::start(){
    reset_udp_timeout();

    auto self = shared_from_this();
    auto cb = [this, self](){
        m_connected  = true;

        if(is_udp_forward()){
            m_send_buf = TrojanRequest::generate(config.password.cbegin()->first, 
                m_remote_addr_udp.address().to_string(), m_remote_addr_udp.port(), false) + m_send_buf;
        }else{
            m_send_buf = TrojanRequest::generate(config.password.cbegin()->first, 
                m_remote_addr.address().to_string(), m_remote_addr.port(), true) + m_send_buf;
        }        

        out_async_send_impl(m_send_buf, [this](boost::system::error_code ec){
            if(ec){
                output_debug_info_ec(ec);
                destroy();
                return;
            }
            out_async_read();
        });
        m_send_buf.clear();
    };

    if(m_service->is_use_pipeline()){
        cb();
    }else{
        m_service->config.prepare_ssl_reuse(m_out_socket);
        if(is_udp_forward()){
            connect_remote_server_ssl(this, m_service->config.remote_addr, to_string(m_service->config.remote_port), 
                m_out_resolver, m_out_socket, m_local_addr_udp ,  cb);
        }else{
            connect_remote_server_ssl(this, m_service->config.remote_addr, to_string(m_service->config.remote_port), 
                m_out_resolver, m_out_socket, m_local_addr,  cb);
        }
        
    }
}

void TUNSession::reset_udp_timeout(){
    if(is_udp_forward()){
        m_udp_timout_timer.cancel();

        m_udp_timout_timer.expires_after(chrono::seconds(m_service->config.udp_timeout));
        auto self = shared_from_this();
        m_udp_timout_timer.async_wait([this, self](const boost::system::error_code error) {
            if (!error) {
                _log_with_endpoint(m_remote_addr_udp, "session_id: " + to_string(session_id()) + " UDP TUNSession timeout");
                destroy();
            }
        });
    }
}

void TUNSession::destroy(bool pipeline_call){
    if(m_destroyed){
        return;
    }
    m_destroyed = true;

    if(is_udp_forward()){
        _log_with_endpoint(m_local_addr_udp, "TUNSession session_id: " + to_string(session_id()) + " disconnected ", Log::INFO);
    }else{
        _log_with_endpoint(m_local_addr, "TUNSession session_id: " + to_string(session_id()) + " disconnected ", Log::INFO);
    }    

    m_wait_ack_handler.clear();
    m_out_resolver.cancel();   
    m_udp_timout_timer.cancel();
    shutdown_ssl_socket(this, m_out_socket);

    if(!pipeline_call && m_service->is_use_pipeline()){
        pipeline_client_service->session_destroy_in_pipeline(*this);
    }

    if(!m_close_from_tundev_flag){
        m_close_cb(this);
    }    
}

void TUNSession::pipeline_out_recv(string&& data){
    if (!m_service->is_use_pipeline()) {
        throw logic_error("cannot call pipeline_out_recv without pipeline!");
    }

    if (!is_destroyed()) {
        m_pipeline_data_cache.push_data(move(data));
    }    
}

void TUNSession::parse_udp_packet_data(){

    for(;;){
        if(m_recv_udp_buf.size() == 0){
            return;
        }

        auto data = boost::asio::buffer_cast<const char*>(m_recv_udp_buf.data());
        auto data_len = m_recv_udp_buf.size();

        // parse trojan protocol
        UDPPacket packet;
        size_t packet_len;
        if(!packet.parse(string(data, data_len), packet_len)){
            if(data_len > numeric_limits<uint16_t>::max()){
                _log_with_endpoint(get_udp_local_endpoint(), "[tun] error UDPPacket.parse! destroy it.", Log::ERROR);
                destroy();
                return;
            }else{
                _log_with_endpoint(get_udp_local_endpoint(), "[tun] error UDPPacket.parse! Might need to read more...", Log::WARN);
            }
            return;
        }
        m_recv_udp_buf.consume(packet_len);

        ostream os(&m_recv_buf);
        os << packet.payload;
        m_recv_buf_ack_length += packet.payload.length();
    }
}

void TUNSession::out_async_read() {
    if(m_service->is_use_pipeline()){
        m_pipeline_data_cache.async_read([this](const string &data) {
            if(is_udp_forward()){
                ostream os(&m_recv_udp_buf);
                os << data;
                parse_udp_packet_data();
            }else{
                ostream os(&m_recv_buf);
                os << data;

                m_recv_buf_ack_length += data.length();
            }
            
            reset_udp_timeout();

            // don't need to call m_recv_buf.commit(length);
            if(m_write_to_lwip(this) < 0){
                output_debug_info();
                destroy();
            }
        });
    }else{
        auto self = shared_from_this();
        boost::asio::streambuf& recv_buf = is_udp_forward() ? m_recv_udp_buf : m_recv_buf;
        m_out_socket.async_read_some(recv_buf.prepare(Session::MAX_BUF_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
            if (error) {
                output_debug_info_ec(error);
                destroy();
                return;
            }

            if(is_udp_forward()){
                m_recv_udp_buf.commit(length);
                parse_udp_packet_data();
            }else{
                m_recv_buf.commit(length);
                m_recv_buf_ack_length += length;
            }

            reset_udp_timeout();

            if(m_write_to_lwip(this) < 0){
                output_debug_info();
                destroy();
            }
        });
    }
}
void TUNSession::recv_ack_cmd(){
    Session::recv_ack_cmd();
    if(!m_wait_ack_handler.empty()){
        m_wait_ack_handler.front()(boost::system::error_code());
        m_wait_ack_handler.pop_front();
    }
}

void TUNSession::out_async_send_impl(std::string data_to_send, Pipeline::SentHandler&& _handler){
    auto self = shared_from_this();
    if(m_service->is_use_pipeline()){

        m_service->session_async_send_to_pipeline(*this, PipelineRequest::DATA, data_to_send,
         [this, self, _handler](const boost::system::error_code error) {
            reset_udp_timeout();
            if (error) {
                output_debug_info_ec(error);
                destroy();

                _handler(error);
            }else{
                if(!pre_call_ack_func()){
                    m_wait_ack_handler.emplace_back(move(_handler));
                    _log_with_endpoint(m_local_addr, "Cannot TUNSession::out_async_send ! Is waiting for ack");
                    return;
                }
                _log_with_endpoint(m_local_addr, "Permit to TUNSession::out_async_send ! ack:" + to_string(pipeline_ack_counter));

                _handler(error);
            }            
        });
    }else{

        auto data_copy = make_shared<string>(data_to_send);
        boost::asio::async_write(m_out_socket, boost::asio::buffer(*data_copy), [this, self, data_copy, _handler](const boost::system::error_code error, size_t) {
            reset_udp_timeout();

            if (error) {
                output_debug_info_ec(error);
                destroy();
            }

            _handler(error);
        });
    }
}
void TUNSession::out_async_send(const char* _data, size_t _length, Pipeline::SentHandler&& _handler){
    if(!m_connected){
        if(m_send_buf.length() < numeric_limits<uint16_t>::max()){ // 100 is more greater than ip/udp header
            string data_to_send;
            if(is_udp_forward()){
                data_to_send.append(UDPPacket::generate(m_remote_addr_udp, string(_data, _length)));
            }else{
                data_to_send.append(_data, _length);
            }
            m_send_buf.append(data_to_send);
        }
        return;
    }else{        
        m_send_buf.clear();
        if(is_udp_forward()){
            m_send_buf.append(UDPPacket::generate(m_remote_addr_udp, string(_data, _length)));
        }else{
            m_send_buf.append(_data, _length);
        }
        
        out_async_send_impl(m_send_buf, move(_handler));
    }
    
    
}

void TUNSession::recv_buf_sent(uint16_t _length){
    m_recv_buf_ack_length -= _length;

    if(is_destroyed()){
        return;
    }

    if(m_recv_buf_ack_length <= 0){
        if(m_service->is_use_pipeline() && !is_udp_forward()){
            auto self = shared_from_this();
            m_service->session_async_send_to_pipeline(*this, PipelineRequest::ACK, "", [this, self](const boost::system::error_code error) {
                if (error) {
                    output_debug_info_ec(error);
                    destroy();
                    return;
                }

                out_async_read();
            });
        }else{
            out_async_read();
        }
    }
}

bool TUNSession::try_to_process_udp(const boost::asio::ip::udp::endpoint& _local, 
        const boost::asio::ip::udp::endpoint& _remote, uint8_t* payload, size_t payload_length){
            
    if(is_udp_forward()){
        if(_local == m_local_addr_udp && _remote == m_remote_addr_udp){
            out_async_send((const char*)payload, payload_length, [](boost::system::error_code){});
            return true;
        }
    }

    return false;
}

