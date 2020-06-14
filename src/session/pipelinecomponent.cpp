
/*
 * This file is part of the Trojan Plus project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Trojan Plus is derived from original trojan project and writing 
 * for more experimental features.
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

#include "pipelinecomponent.h"
#include "core/service.h"

using namespace std;
PipelineComponent::SessionIdType PipelineComponent::s_session_id_counter = 0;
set<PipelineComponent::SessionIdType> PipelineComponent::s_session_used_ids;

PipelineComponent::PipelineComponent(const Config& _config): 
    m_session_id(0),
    m_is_use_pipeline(false),
    m_is_async_writing(false),
    m_write_close_future(false),
    pipeline_ack_counter(0),
    pipeline_wait_for_ack(false),
    pipeline_first_call_ack(true){
    pipeline_ack_counter = static_cast<int>(_config.experimental.pipeline_ack_window);
}

void PipelineComponent::allocate_session_id(){
    if(s_session_used_ids.size() >= numeric_limits<SessionIdType>::max()){
        throw logic_error("session id is over !! pipeline reached the session id limits !!");
    }

    do{
        m_session_id = s_session_id_counter++;        
    }while(s_session_used_ids.find(m_session_id) != s_session_used_ids.end());

    s_session_used_ids.insert(m_session_id);
}

void PipelineComponent::free_session_id(){
    s_session_used_ids.erase(m_session_id);
}

void PipelineComponent::pipeline_in_recv(const string_view &data) {
    if (!m_is_use_pipeline) {
        throw logic_error("cannot call pipeline_in_recv without pipeline!");
    }

    pipeline_data_cache.push_data(data);
}