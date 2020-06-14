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

#ifndef _PIPELINE_COMPONENT_H
#define _PIPELINE_COMPONENT_H

#include <stdint.h>
#include <set>
#include <stdexcept>

#include "core/utils.h"

class Config;
class Service;
class PipelineComponent{

public:
    typedef uint16_t SessionIdType;
    
private:

    // session id counter for pipeline mode
    static SessionIdType s_session_id_counter;
    static std::set<SessionIdType>  s_session_used_ids;

    SessionIdType m_session_id;    
    bool m_is_use_pipeline;
    bool m_is_async_writing;
    bool m_write_close_future;
public:
    PipelineComponent(const Config& _config);
    
    int pipeline_ack_counter;
    bool pipeline_wait_for_ack;
    bool pipeline_first_call_ack;

    ReadDataCache pipeline_data_cache;
    void pipeline_in_recv(const std::string_view& data);

    void allocate_session_id();
    void free_session_id();
    inline SessionIdType get_session_id() const { return m_session_id; }
    void set_session_id(SessionIdType _id) { m_session_id = _id; }
    
    inline void set_use_pipeline() { m_is_use_pipeline = true; };
    inline bool is_using_pipeline(){ return m_is_use_pipeline; }
    inline void recv_ack_cmd() { pipeline_ack_counter++; }

    inline bool is_wait_for_pipeline_ack()const { return pipeline_wait_for_ack; }    

    inline bool pre_call_ack_func(){
        if(!pipeline_first_call_ack){
            if(pipeline_ack_counter <= 0){
                pipeline_wait_for_ack = true;
                return false;
            }
            pipeline_ack_counter--;
        }
        pipeline_wait_for_ack = false;
        pipeline_first_call_ack = false;
        return true;
    }

    inline void set_async_writing_data(bool is_writing) { m_is_async_writing = is_writing; }
    inline bool canbe_closed_by_pipeline() const {
        return !m_is_async_writing && !pipeline_data_cache.has_queued_data();
    }

    inline bool is_write_close_future() const { return m_write_close_future; }
    inline void set_write_close_future(bool future_close){ m_write_close_future = future_close; }
};

#endif //_PIPELINE_COMPONENT_H