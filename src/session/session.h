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

#ifndef _SESSION_H_
#define _SESSION_H_

#include <ctime>
#include <set>
#include <memory>
#include <stdexcept>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include "core/config.h"
#include "session/pipelinecomponent.h"

class Service;
class Session : public std::enable_shared_from_this<Session> {

public:
    enum {
        MAX_BUF_LENGTH = 8192,
    };

protected:

    Service* service; 
    const Config& config;
    PipelineComponent pipleline_com;

public:
    Session(Service* _service, const Config& _config);

    virtual void start() = 0;
    virtual ~Session();
    virtual void destroy(bool pipeline_call = false) = 0;

    PipelineComponent::SessionIdType session_id(){ return pipleline_com.get_session_id(); }
    PipelineComponent& pipeline_component(){ return pipleline_com; }
};

#endif // _SESSION_H_
