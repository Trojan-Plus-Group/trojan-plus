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

#ifndef _SESSION_H_
#define _SESSION_H_

#include <ctime>
#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include "core/config.h"
#include "session/pipelinecomponent.h"

class Service;
class UDPLocalForwarder;
class Session : public std::enable_shared_from_this<Session> {

  public:
    enum {
        MAX_BUF_LENGTH = 8192,
    };

  private:
    Service* service;
    boost::asio::steady_timer udp_gc_timer;
    PipelineComponent pipeline_com;
    bool is_udp_forward;
    const Config& config;
    bytes_stat stat;

    friend class UDPLocalForwarder;
    static size_t s_total_session_count;

  public:
    Session(Service* _service, const Config& _config);

    virtual void start() = 0;
    virtual ~Session();
    virtual void destroy(bool pipeline_call = false) = 0;
    virtual void recv_ack_cmd(int ack_count) { pipeline_com.recv_ack_cmd(ack_count); }

    _define_getter(bytes_stat&, stat);

    virtual int get_udp_timer_timeout_val() const;
    void udp_timer_async_wait();
    void udp_timer_cancel();

    const Config& get_config() const { return config; }
    Service* get_service() { return service; }

    inline void set_udp_forward_session(bool udp) { is_udp_forward = udp; }
    [[nodiscard]] inline bool is_udp_forward_session() const { return is_udp_forward; }

    PipelineComponent::SessionIdType get_session_id() { return pipeline_com.get_session_id(); }
    PipelineComponent& get_pipeline_component() { return pipeline_com; }
};

#endif // _SESSION_H_
