/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
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

#include "pipelinesession.h"

#include <boost/asio/ssl.hpp>

#include "core/authenticator.h"
#include "core/service.h"
#include "core/utils.h"
#include "proto/trojanrequest.h"
#include "serversession.h"

using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

PipelineSession::PipelineSession(Service* _service, const Config& config, boost::asio::ssl::context &ssl_context, Authenticator *auth, const std::string &plain_http_response):
    SocketSession(_service, config),
    status(HANDSHAKE),
    auth(auth),
    plain_http_response(plain_http_response),
    live_socket(_service->get_io_context(), ssl_context),
    gc_timer(_service->get_io_context()),
    ssl_context(ssl_context){

    sending_data_cache.set_async_writer([this](const boost::asio::streambuf& data, SentHandler handler) {
        if(status == DESTROY){
            return;
        }

        auto self = shared_from_this();
        boost::asio::async_write(live_socket, data.data(), [this, self, handler](const boost::system::error_code ec, size_t) {
            if (ec) {
                output_debug_info_ec(ec);
                destroy();
                return;
            }
            handler(ec);
        });
    });
}

tcp::socket& PipelineSession::accept_socket(){
    return (tcp::socket&)live_socket.next_layer();
}

void PipelineSession::start(){
    boost::system::error_code ec;
    start_time = time(nullptr);
    timer_async_wait();
    in_endpoint = live_socket.next_layer().remote_endpoint(ec);
    if (ec) {
        output_debug_info_ec(ec);
        destroy();
        return;
    }
    auto self = shared_from_this();
    live_socket.async_handshake(stream_base::server, [this, self](const boost::system::error_code error) {
        if (error) {
            _log_with_endpoint(in_endpoint, "SSL handshake failed: " + error.message(), Log::ERROR);
            if (error.message() == "http request" && plain_http_response.empty()) {
                recv_len += plain_http_response.length();
                boost::asio::async_write(accept_socket(), boost::asio::buffer(plain_http_response), [this, self](const boost::system::error_code ec, size_t) {
                    output_debug_info_ec(ec);
                    destroy();
                });
                return;
            }
            output_debug_info();
            destroy();
            return;
        }
        in_async_read();
    });
}

void PipelineSession::in_async_read(){
    _guard_read_buf_begin(in_read_buf);
    auto self = shared_from_this();
    live_socket.async_read_some(in_read_buf.prepare(MAX_BUF_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        _guard_read_buf_end(in_read_buf);
        if (error) {
            output_debug_info_ec(error);
            destroy();
            return;
        }
        in_read_buf.commit(length);
        in_recv(streambuf_to_string_view(in_read_buf));
    });
}

void PipelineSession::in_recv(const string_view &) {
    if(status == HANDSHAKE){
        string_view data = streambuf_to_string_view(in_read_buf);
        size_t npos = data.find("\r\n");
        if(npos == string::npos){
            in_async_read();
            return;
        }

        if(data.substr(0, npos) != config.password.cbegin()->first){
            _log_with_endpoint(in_endpoint, "PipelineSession error password", Log::ERROR);
            destroy();
            return;
        }else{
            _log_with_endpoint(in_endpoint, "PipelineSession handshake done!", Log::INFO);
        }

        gc_timer.cancel();
        status = STREAMING;
        in_read_buf.consume(npos + 2);
        process_streaming_data();        
    }else if(status == STREAMING){
        process_streaming_data();
    }
}

void PipelineSession::in_send(PipelineRequest::Command cmd, ServerSession& session, const std::string_view& session_data, SentHandler&& sent_handler){
    auto found = find_and_process_session(session.get_session_id(), [&](SessionsList::iterator&){
        _log_with_endpoint_ALL(in_endpoint, "PipelineSession session_id: " + to_string(session.get_session_id()) + " <-- send cmd: " + 
            PipelineRequest::get_cmd_string(cmd) + " length:" + to_string(session_data.length()) + " checksum: " + to_string(get_checksum(session_data)));
        sending_data_cache.push_data([&](boost::asio::streambuf& buf){PipelineRequest::generate(buf, cmd, session.get_session_id(), session_data);}, move(sent_handler));
    });

    if(!found){
        _log_with_endpoint(in_endpoint, "PipelineSession can't find the session " + to_string(session.get_session_id()) + " to sent", Log::WARN);
        session.destroy(true);
    }
}

bool PipelineSession::find_and_process_session(PipelineComponent::SessionIdType session_id, std::function<void(SessionsList::iterator&)> processor){
    for(auto it = sessions.begin(); it != sessions.end();it++){
        if(it->get()->get_session_id() == session_id){
            processor(it);
            return true;
        }
    }
    return false;
}

void PipelineSession::process_streaming_data(){

    while(in_read_buf.size() != 0){
        PipelineRequest req;
        int ret = req.parse(streambuf_to_string_view(in_read_buf));
        if(ret == -1){
            break;
        }

        if(ret == -2){
            _log_with_endpoint(in_endpoint, "PipelineSession error request format", Log::ERROR);
            destroy();
            return;
        }

        _log_with_endpoint_ALL(in_endpoint, "PipelineSession session_id: " + to_string(req.session_id) + " --> recv cmd: " + 
            req.get_cmd_string() + " length:" + to_string(req.packet_data.length()) + " checksum: " + to_string(get_checksum(req.packet_data)));

        if(req.command == PipelineRequest::CONNECT){
            find_and_process_session(req.session_id, [this](SessionsList::iterator& it){
                it->get()->destroy(true);
                sessions.erase(it);
            });

            auto session = make_shared<ServerSession>(service, config, ssl_context, auth, plain_http_response);
            session->set_pipeline_session(shared_from_this());
            session->get_pipeline_component().set_session_id(req.session_id);
            session->get_pipeline_component().set_use_pipeline();            
            session->in_endpoint = in_endpoint;
            session->start();
            sessions.emplace_back(session);
            _log_with_endpoint_ALL(in_endpoint, "PipelineSession starts a session " + to_string(req.session_id) + ", now remain " + to_string(sessions.size()));
        }else if(req.command == PipelineRequest::DATA){
            auto found = find_and_process_session(req.session_id, [&](SessionsList::iterator& it){ 
                it->get()->get_pipeline_component().pipeline_in_recv(req.packet_data);
            });

            if(!found){
                _log_with_endpoint(in_endpoint, "PipelineSession cann't find a session " + to_string(req.session_id) + " to process" , Log::WARN);
            }
        }else if(req.command == PipelineRequest::CLOSE){
            auto found = find_and_process_session(req.session_id, [this](SessionsList::iterator& it){ 
                if(it->get()->get_pipeline_component().is_async_writing_data()){
                    it->get()->get_pipeline_component().set_write_close_future(true);
                }else{
                    it->get()->destroy(true);   
                    sessions.erase(it);
                }
            });

            if(!found){
                _log_with_endpoint(in_endpoint, "PipelineSession cann't find a session " + to_string(req.session_id) + " to destroy" , Log::WARN);
            }
        }else if(req.command == PipelineRequest::ACK){
            auto found = find_and_process_session(req.session_id, [](SessionsList::iterator& it){ 
                auto session = it->get();
                session->recv_ack_cmd();
                if(session->get_pipeline_component().is_wait_for_pipeline_ack()){
                    it->get()->out_async_read();
                }
            });

            if(!found){
                _log_with_endpoint(in_endpoint, "PipelineSession cann't find a session " + to_string(req.session_id) + " to ACK" , Log::WARN);
            }
        }else if(req.command == PipelineRequest::ICMP){
            if(icmp_processor){
                icmp_processor->server_out_send(string(req.packet_data), shared_from_this());
            }
        }else{
            _log_with_endpoint(in_endpoint, "PipelineSession error command", Log::ERROR);
            destroy();
            return;
        }

        in_read_buf.consume(req.consume_length);
    }    

    in_async_read();
}

void PipelineSession::session_write_ack(ServerSession& session, SentHandler&& sent_handler){
    in_send(PipelineRequest::ACK, session, "", move(sent_handler));
}

void PipelineSession::session_write_data(ServerSession& session, const std::string_view& session_data, SentHandler&& sent_handler){
    in_send(PipelineRequest::DATA, session, session_data, move(sent_handler));
}

void PipelineSession::session_write_icmp(const std::string_view& data, SentHandler&& sent_handler){
    _log_with_endpoint_ALL(in_endpoint, "PipelineSession <-- send cmd: ICMP length:" + to_string(data.length()));
    sending_data_cache.push_data([&](boost::asio::streambuf& buf){PipelineRequest::generate(buf, PipelineRequest::ICMP, 0, data);}, move(sent_handler));
}

void PipelineSession::timer_async_wait(){
    gc_timer.expires_after(chrono::seconds(3));
    auto self = shared_from_this();
    gc_timer.async_wait([this, self](const boost::system::error_code error) {
        if (!error) {
            _log_with_endpoint(in_endpoint, "PipelineSession wait for password timeout");
            destroy();
        }
    });
}

void PipelineSession::remove_session_after_destroy(ServerSession& session){
    if(status != DESTROY){
        find_and_process_session(session.get_session_id(), [this, &session](SessionsList::iterator& it){
            in_send(PipelineRequest::CLOSE, session, "",[](const boost::system::error_code){});
            sessions.erase(it);
            _log_with_endpoint_ALL(in_endpoint, "PipelineSession remove session " + to_string(session.get_session_id()) + ", now remain " + to_string(sessions.size()));
        });
    }    
}

void PipelineSession::destroy(bool /*pipeline_call = false*/){
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    gc_timer.cancel();

    _log_with_endpoint(in_endpoint, "PipelineSession remove all sessions: " + to_string(sessions.size()), Log::INFO);

    // clear all sessions which attached this PipelineSession
    for(auto it = sessions.begin(); it != sessions.end();it++){
        it->get()->destroy(true);
    }
    sessions.clear();    
    shutdown_ssl_socket(this, live_socket);
}