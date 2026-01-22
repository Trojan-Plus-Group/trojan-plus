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

#include "service.h"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <thread>

#include "mem/memallocator.h"
#include "session/clientsession.h"
#include "session/forwardsession.h"
#include "session/natsession.h"
#include "session/pipelinesession.h"
#include "session/serversession.h"
#include "utils.h"

#include "tun/dnsserver.h"
#include "tun/tundev.h"

using namespace boost::asio::ip;
using namespace boost::asio::ssl;

Service::Service(Config& config, bool test)
    : socket_acceptor(io_context),
      ssl_context(context::sslv23),
      udp_socket(io_context),
      pipeline_select_idx(0),
      config(config) {

    _guard;
#ifndef ENABLE_NAT
    if (config.get_run_type() == Config::NAT) {
        throw std::runtime_error("NAT is not supported");
    }
#endif // ENABLE_NAT

    if (!test) {
        if (config.get_run_type() == Config::CLIENT_TUN || config.get_run_type() == Config::SERVERT_TUN) {
            m_tundev = TP_MAKE_SHARED(TUNDev, this, config.get_tun().tun_name, config.get_tun().net_ip,
              config.get_tun().net_mask, config.get_tun().mtu, config.get_tun().tun_fd);
        }

        if (config.get_run_type() != Config::CLIENT_TUN) {
            tcp::resolver resolver(io_context);
            tcp::endpoint listen_endpoint =
              *resolver.resolve(config.get_local_addr(), tp::to_string(config.get_local_port())).begin();
            socket_acceptor.open(listen_endpoint.protocol());
            socket_acceptor.set_option(tcp::acceptor::reuse_address(true));

            if (config.get_run_type() == Config::NAT && config.get_tcp().use_tproxy) {
                bool is_ipv4 = listen_endpoint.protocol().family() == boost::asio::ip::tcp::v4().family();
                if (!prepare_transparent_socket((int)socket_acceptor.native_handle(), is_ipv4)) {
                    _log_with_date_time("[nat] [tcp] setsockopt IP_TRANSPARENT failed!", Log::FATAL);
                } else {
                    _log_with_date_time("[nat] [tcp] to process TPROXY tcp message", Log::WARN);
                }
            }

            if (config.get_tcp().reuse_port) {
#ifdef ENABLE_REUSE_PORT
                socket_acceptor.set_option(reuse_port(true));
#else  // ENABLE_REUSE_PORT
                _log_with_date_time("SO_REUSEPORT is not supported", Log::WARN);
#endif // ENABLE_REUSE_PORT
            }

            socket_acceptor.bind(listen_endpoint);
            socket_acceptor.listen();
            prepare_icmpd(config, listen_endpoint.address().is_v4());

            if (config.get_run_type() == Config::FORWARD || config.get_run_type() == Config::NAT) {
                auto udp_bind_endpoint = udp::endpoint(listen_endpoint.address(), listen_endpoint.port());
                auto udp_protocol      = udp_bind_endpoint.protocol();
                udp_socket.open(udp_protocol);

                if (config.get_run_type() == Config::NAT) {
                    bool is_ipv4 = udp_protocol.family() == boost::asio::ip::tcp::v4().family();
                    bool recv_ttl =
                      config.get_run_type() == Config::NAT && config.get_experimental().pipeline_proxy_icmp;
                    if (!prepare_nat_udp_bind((int)udp_socket.native_handle(), is_ipv4, recv_ttl)) {
                        stop();
                        return;
                    }
                }
                set_udp_send_recv_buf((int)udp_socket.native_handle(), config.get_udp_forward_socket_buf());

                udp_socket.bind(udp_bind_endpoint);
            }

            if (config.get_tcp().no_delay) {
                socket_acceptor.set_option(tcp::no_delay(true));
            }
            if (config.get_tcp().keep_alive) {
                socket_acceptor.set_option(boost::asio::socket_base::keep_alive(true));
            }
            if (config.get_tcp().fast_open) {
#ifdef TCP_FASTOPEN
                using fastopen = boost::asio::detail::socket_option::integer<IPPROTO_TCP, TCP_FASTOPEN>;
                boost::system::error_code ec;
                socket_acceptor.set_option(fastopen(config.get_tcp().fast_open_qlen), ec);
                if (ec) {
                    _log_with_date_time("Enabling TCP_FASTOPEN is failed, " + ec.message(), Log::ERROR);
                }
#else  // TCP_FASTOPEN
                _log_with_date_time("TCP_FASTOPEN is not supported", Log::WARN);
#endif // TCP_FASTOPEN
#ifndef TCP_FASTOPEN_CONNECT
                _log_with_date_time("TCP_FASTOPEN_CONNECT is not supported", Log::WARN);
#endif // TCP_FASTOPEN_CONNECT
            }
        }
    }

    config.prepare_ssl_context(ssl_context, plain_http_response);

#ifndef __ANDROID__
    if (!test && config.get_dns().enabled) {
        if (config.get_run_type() == Config::SERVER || config.get_run_type() == Config::FORWARD) {
            _log_with_date_time("[dns] dns server cannot run in type 'server' or 'forward'", Log::ERROR);
        } else {
            if (DNSServer::get_dns_lock()) {
                m_dns_server = TP_MAKE_SHARED(DNSServer, this);
                if (m_dns_server->start()) {
                    _log_with_date_time(
                      "[dns] start local dns server at 0.0.0.0:" + tp::to_string(config.get_dns().port), Log::WARN);
                }
            } else {
                _log_with_date_time("[dns] dns server has been created in other process.", Log::WARN);
            }
        }
    }
#endif // __ANDROID__

    _unguard;
}

void Service::prepare_icmpd(Config& config, bool is_ipv4) {
    _guard;

    if (config.try_prepare_pipeline_proxy_icmp(is_ipv4)) {
        _log_with_date_time("Pipeline will proxy ICMP message", Log::WARN);
        icmp_processor = TP_MAKE_SHARED(icmpd, io_context);
        icmp_processor->set_service(this, config.get_run_type() == Config::NAT);
        icmp_processor->start_recv();
    }

    _unguard;
}

void Service::run() {
    _guard;

    tp::string rt;
    if (config.get_run_type() == Config::SERVER) {
        rt = "server";
    } else if (config.get_run_type() == Config::FORWARD) {
        rt = "forward";
    } else if (config.get_run_type() == Config::NAT) {
        rt = "nat";
    } else if (config.get_run_type() == Config::CLIENT) {
        rt = "client";
    } else if (config.get_run_type() == Config::CLIENT_TUN) {
        rt = "client tun";
    } else if (config.get_run_type() == Config::SERVERT_TUN) {
        rt = "server tun";
    } else {
        throw std::logic_error(tp::string("unknow run type error").c_str());
    }

    if (config.get_experimental().pipeline_num > 0) {
        rt += " in pipeline mode";
    }

    if (config.get_run_type() != Config::CLIENT_TUN) {
        async_accept();
        if (config.get_run_type() == Config::FORWARD || config.get_run_type() == Config::NAT) {
            udp_async_read();
        }
        tcp::endpoint local_endpoint = socket_acceptor.local_endpoint();

        _log_with_date_time(tp::string("trojan plus service (") + rt + ") started at " +
                              local_endpoint.address().to_string() + ':' + tp::to_string(local_endpoint.port()),
          Log::FATAL);
    } else {
        _log_with_date_time(tp::string("trojan plus service (") + rt + ") started at [" + config.get_tun().tun_name + "] " +
                              config.get_tun().net_ip + "/" + config.get_tun().net_mask,
          Log::FATAL);
    }
    io_context.run();
    _log_with_date_time("trojan service stopped", Log::WARN);

    _unguard;
}

void Service::stop() {
    _guard;

// don't destroy all components in order to speed up Android disconnection
// this progress will be killed in Android
#ifndef __ANDROID__

    if (m_tundev) {
        m_tundev->destroy();
    }

    if (m_dns_server) {
        m_dns_server->destroy();
    }

    if (!pipelines.empty()) {
        clear_weak_ptr_list(pipelines);
        _log_with_date_time("[pipeline] destroy all " + tp::to_string(pipelines.size()) + " pipelines");
        for (auto& it : pipelines) {
            it.lock()->destroy();
        }
        pipelines.clear();
    }

    boost::system::error_code ec;
    socket_acceptor.cancel(ec);
    if (udp_socket.is_open()) {
        udp_socket.cancel(ec);
        udp_socket.close(ec);
    }

#endif

    io_context.stop();
    _unguard;
}

void Service::prepare_pipelines() {
    _guard;

    if (config.get_run_type() != Config::SERVER && config.get_experimental().pipeline_num > 0) {

        bool changed = clear_weak_ptr_list(pipelines);

        size_t curr_num = 0;
        for (const auto& p : pipelines) {
            if (p.lock()->get_config() == config) {
                curr_num++;
            }
        }

        _log_with_date_time("[pipeline] current exist pipelines: " + tp::to_string(curr_num), Log::INFO);

        for (; curr_num < config.get_experimental().pipeline_num; curr_num++) {
            auto pipeline = TP_MAKE_SHARED(Pipeline, this, config, ssl_context);
            pipeline->start();
            pipelines.emplace_back(pipeline);
            changed = true;

            if (icmp_processor) {
                pipeline->set_icmpd(icmp_processor);
            }
            _log_with_date_time("[pipeline] start new pipeline, current: " + tp::to_string(pipelines.size()) +
                                  " std::max:" + tp::to_string(config.get_experimental().pipeline_num),
              Log::INFO);
        }

        if (!config.get_experimental().pipeline_loadbalance_configs.empty()) {
            for (size_t i = 0; i < config.get_experimental()._pipeline_loadbalance_configs.size(); i++) {

                auto config_file    = config.get_experimental().pipeline_loadbalance_configs[i];
                auto balance_config = config.get_experimental()._pipeline_loadbalance_configs[i];
                auto balance_ssl    = config.get_experimental()._pipeline_loadbalance_context[i];

                size_t curr_num = 0;
                for (const auto& it : pipelines) {
                    if (&(it.lock()->get_config()) == balance_config.get()) {
                        curr_num++;
                    }
                }

                for (; curr_num < config.get_experimental().pipeline_num; curr_num++) {
                    auto pipeline = TP_MAKE_SHARED(Pipeline, this, *balance_config, *balance_ssl);
                    pipeline->start();
                    pipelines.emplace_back(pipeline);
                    changed = true;

                    _log_with_date_time(tp::string("[pipeline] start a balance pipeline: ") + config_file +
                                          " current:" + tp::to_string(pipelines.size()) +
                                          " std::max:" + tp::to_string(config.get_experimental().pipeline_num),
                      Log::INFO);
                }
            }

            if (changed) {
                // for default polling balance algorithm,
                // need to arrage the pipeine from 00000011111122222333333... to 012301230123...
                size_t config_idx  = 0;
                size_t all_configs = config.get_experimental()._pipeline_loadbalance_configs.size() + 1;

                auto curr = pipelines.begin();
                while (curr != pipelines.end()) {
                    auto next = curr;
                    next++;

                    while (next != pipelines.end()) {
                        bool found                   = false;
                        const auto* const config_ptr = &(next->lock()->get_config());
                        if (config_idx == 0) {
                            found = config_ptr == &config;
                        } else {
                            found = config_ptr ==
                                    config.get_experimental()._pipeline_loadbalance_configs[config_idx - 1].get();
                        }

                        if (found) {
                            std::iter_swap(curr, next);
                            if (++config_idx >= all_configs) {
                                config_idx = 0;
                            }
                            break;
                        }

                        next++;
                    }

                    curr++;
                }

                // auto it = pipelines.begin();
                // while (it != pipelines.end()) {
                //     _log_with_date_time("after arrage:" + tp::to_string(it->lock()->config.remote_port));
                //     ++it;
                // }
            }
        }
    }

    _unguard;
}

void Service::start_session(const std::shared_ptr<Session>& session, SentHandler&& started_handler) {
    _guard;

    if (config.get_experimental().pipeline_num > 0 && config.get_run_type() != Config::SERVER) {

        prepare_pipelines();

        if (pipelines.empty()) {
            throw std::logic_error(tp::string("pipeline is empty after preparing!").c_str());
        }

        auto it       = pipelines.begin();
        auto pipeline = std::shared_ptr<Pipeline>(nullptr);

        if (pipeline_select_idx >= pipelines.size()) {
            pipeline_select_idx = 0;
            pipeline            = it->lock();
        }

        if (!pipeline || !pipeline->is_connected()) {
            pipeline   = it->lock();
            size_t idx = 0;
            while (it != pipelines.end()) {
                auto sel_pp = it->lock();
                if (idx >= pipeline_select_idx) {
                    if (sel_pp->is_connected()) {
                        pipeline = sel_pp;
                        break;
                    }
                    pipeline_select_idx++;
                }
                ++it;
                ++idx;
            }
            pipeline_select_idx++;
        }

        if (!pipeline) {
            throw std::logic_error(tp::string("pipeline fatal logic!").c_str());
        }

        _log_with_date_time("pipeline " + tp::to_string(pipeline->get_pipeline_id()) +
                              " start session_id: " + tp::to_string(session->get_session_id()),
          Log::INFO);
        session->get_pipeline_component().set_use_pipeline();
        pipeline->session_start(*(session.get()), std::move(started_handler));
    } else {
        started_handler(boost::system::error_code());
    }

    _unguard;
}

void Service::session_async_send_to_pipeline(Session& session, PipelineRequest::Command cmd,
  const std::string_view& data, SentHandler&& sent_handler, size_t ack_count /* = 0*/) {

    _guard;

    if (config.get_experimental().pipeline_num > 0 && config.get_run_type() != Config::SERVER) {

        Pipeline* pipeline = nullptr;
        auto it            = pipelines.begin();
        while (it != pipelines.end()) {
            if (it->expired()) {
                it = pipelines.erase(it);
            } else {
                auto p = it->lock();
                if (p->is_in_pipeline(session)) {
                    pipeline = p.get();
                    break;
                }
                ++it;
            }
        }

        if (pipeline == nullptr) {
            _log_with_date_time("pipeline is broken, destory session", Log::WARN);
            sent_handler(boost::asio::error::broken_pipe);
        } else {
            pipeline->session_async_send_cmd(cmd, session, data, std::move(sent_handler), ack_count);
        }
    } else {
        _log_with_date_time("can't send data via pipeline!", Log::FATAL);
    }

    _unguard;
}

void Service::session_async_send_to_pipeline_icmp(
  const std::string_view& data, std::function<void(boost::system::error_code ec)>&& sent_handler) {
    _guard;
    if (config.get_experimental().pipeline_num > 0 && config.get_run_type() != Config::SERVER) {
        Pipeline* pipeline = search_default_pipeline();
        if (pipeline == nullptr) {
            _log_with_date_time("pipeline is broken, destory session", Log::WARN);
            sent_handler(boost::asio::error::broken_pipe);
        } else {
            pipeline->session_async_send_icmp(data, std::move(sent_handler));
        }
    } else {
        _log_with_date_time("can't send data via pipeline!", Log::FATAL);
    }
    _unguard;
}

void Service::session_destroy_in_pipeline(Session& session) {
    _guard;
    auto it = pipelines.begin();
    while (it != pipelines.end()) {
        if (it->expired()) {
            it = pipelines.erase(it);
        } else {
            auto p = it->lock();
            if (p->is_in_pipeline(session)) {
                _log_with_date_time("pipeline " + tp::to_string(p->get_pipeline_id()) +
                                    " destroy session_id:" + tp::to_string(session.get_session_id()));
                p->session_destroyed(session);
                break;
            }
            ++it;
        }
    }
    _unguard;
}

Pipeline* Service::search_default_pipeline() {
    _guard;
    prepare_pipelines();

    if (pipelines.empty()) {
        throw std::logic_error(tp::string("pipeline is empty after preparing!").c_str());
    }

    Pipeline* pipeline = nullptr;
    auto it            = pipelines.begin();
    while (it != pipelines.end()) {
        if (it->expired()) {
            it = pipelines.erase(it);
        } else {
            auto p = it->lock();
            if (&(p->get_config()) == (&config)) { // find the default pipeline, cannot use load-balance server
                pipeline = p.get();
                break;
            }
            ++it;
        }
    }

    return pipeline;
    _unguard;
}
void Service::async_accept() {
    _guard;

    std::shared_ptr<SocketSession> session(nullptr);

    if (config.get_run_type() == Config::SERVER) {
        if (config.get_experimental().pipeline_num > 0) {
            // start a pipeline mode in server run_type
            auto pipeline = TP_MAKE_SHARED(PipelineSession, this, config, ssl_context, plain_http_response);
            pipeline->set_icmpd(icmp_processor);

            session = pipeline;
        } else {
            session = TP_MAKE_SHARED(ServerSession, this, config, ssl_context, plain_http_response);
        }
    } else {
        if (config.get_run_type() == Config::FORWARD) {
            session = TP_MAKE_SHARED(ForwardSession, this, config, ssl_context);
        } else if (config.get_run_type() == Config::NAT) {
            session = TP_MAKE_SHARED(NATSession, this, config, ssl_context);
        } else {
            session = TP_MAKE_SHARED(ClientSession, this, config, ssl_context);
        }
    }

    socket_acceptor.async_accept(session->accept_socket(), [this, session](const boost::system::error_code error) {
        _guard;
        if (error == boost::asio::error::operation_aborted) {
            // got cancel signal, stop calling myself
            return;
        }

        if (!error) {
            boost::system::error_code ec;
            auto endpoint = session->accept_socket().remote_endpoint(ec);
            if (!ec) {
                _log_with_endpoint(endpoint, "incoming connection");
                start_session(session, [session](boost::system::error_code ec) {
                    if (ec) {
                        session->destroy();
                    } else {
                        session->start();
                    }
                });
            }
        }
        async_accept();
        _unguard;
    });

    _unguard;
}

void Service::udp_async_read() {
    _guard;

    auto cb = [this](const boost::system::error_code error, size_t length) {
        _guard;
        if (error == boost::asio::error::operation_aborted) {
            // got cancel signal, stop calling myself
            return;
        }
        if (error) {
            stop();
            throw std::runtime_error(error.message().c_str());
        }

        tp::pair<tp::string, uint16_t> targetdst;

        if (config.get_run_type() == Config::NAT) {
            int read_length = (int)length;
            int ttl         = -1;

            targetdst = recv_tproxy_udp_msg((int)udp_socket.native_handle(), udp_recv_endpoint,
              static_cast<char*>(boost::asio::buffer_sequence_begin(udp_read_buf.prepare(config.get_udp_recv_buf()))->data()), read_length, ttl);

            length = read_length < 0 ? 0 : read_length;
            udp_read_buf.commit(length);

            // in the first design, if we want to proxy icmp, we need to transfer TTL of udp to server and std::set TTL when
            // server sends upd out but now in most of traceroute programs just use icmp to trigger remote server back
            // instead of udp, so we don't need pass TTL to server any more we just keep this codes of retreiving TTL if
            // it will be used for some future features.
            _log_with_date_time(tp::string("[udp] get ttl:") + tp::to_string(ttl));
        } else {
            udp_read_buf.commit(length);
            targetdst = tp::make_pair(config.get_target_addr(), config.get_target_port());
        }

        if (targetdst.second != 0) {
            clear_weak_ptr_list(udp_sessions);
            for (auto& s : udp_sessions) {
                if (s.lock()->process(udp_recv_endpoint, udp_read_buf)) {
                    udp_async_read();
                    return;
                }
            }

                          _log_with_endpoint(udp_recv_endpoint, "new UDP session");
                          auto session = TP_MAKE_SHARED(UDPForwardSession,
                            this, config, ssl_context, udp_recv_endpoint, targetdst,
                            [this](const udp::endpoint& endpoint, const std::string_view& data) {                  _guard;
                  if (config.get_run_type() == Config::NAT) {
                      throw std::logic_error(tp::string("[udp] logic fatal error, cannot call in_write std::function for NAT type!").c_str());
                  }

                  boost::system::error_code ec;
                  udp_socket.send_to(boost::asio::buffer(data.data(), data.length()), endpoint, 0, ec);

                  if (ec == boost::asio::error::no_permission) {
                      _log_with_endpoint(
                        udp_recv_endpoint, "[udp] dropped a packet due to firewall policy or rate limit");
                  } else if (ec) {
                      throw std::runtime_error(ec.message().c_str());
                  }
                  _unguard;
              },
              config.get_run_type() == Config::NAT, false);

            auto data = get_sending_data_allocator().allocate(udp_read_buf);
            start_session(session, [this, session, data](boost::system::error_code ec) {
                _guard;
                if (!ec) {
                    udp_sessions.emplace_back(session);
                    session->start_udp(streambuf_to_string_view(*data));
                }
                get_sending_data_allocator().free(data);
                _unguard;
            });

        } else {
            _log_with_endpoint(udp_recv_endpoint, "cannot read original destination address!");
        }

        udp_async_read();

        _unguard;
    };

    udp_read_buf.consume_all();
    if (config.get_run_type() == Config::NAT) {
        udp_socket.async_wait(boost::asio::socket_base::wait_read, [cb](const boost::system::error_code error) {
            cb(error, 0);
        });
    } else {
        udp_socket.async_receive_from(udp_read_buf.prepare(config.get_udp_recv_buf()), udp_recv_endpoint, cb);
    }

    _unguard;
}

void Service::reload_cert() {
    _guard;

    if (config.get_run_type() == Config::SERVER) {
        _log_with_date_time("reloading certificate and private key. . . ", Log::WARN);
        ssl_context.use_certificate_chain_file(config.get_ssl().cert.c_str());
        ssl_context.use_private_key_file(config.get_ssl().key.c_str(), context::pem);
        boost::system::error_code ec;
        socket_acceptor.cancel(ec);
        async_accept();
        _log_with_date_time("certificate and private key reloaded", Log::WARN);
    } else {
        _log_with_date_time("cannot reload certificate and private key: wrong run_type", Log::ERROR);
    }
    _unguard;
}

Service::~Service() { _log_with_date_time("~Service called"); };
