
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
#include "mem/memallocator.h"

PipelineComponent::SessionIdType PipelineComponent::s_session_id_counter = 0;
tp::set<PipelineComponent::SessionIdType> PipelineComponent::s_session_used_ids;

PipelineComponent::PipelineComponent(const Config& _config)
    : m_session_id(0),
      m_is_use_pipeline(false),
      m_is_async_writing(false),
      m_write_close_future(false),
      pipeline_ack_counter(0),
      pipeline_wait_for_ack(false),
      pipeline_first_call_ack(true) {
    _guard;
    pipeline_ack_counter = static_cast<int>(_config.get_experimental().pipeline_ack_window);
    _unguard;
}

void PipelineComponent::allocate_session_id() {
    _guard;
    if (s_session_used_ids.size() >= std::numeric_limits<SessionIdType>::max()) {
        throw std::logic_error(tp::string("session id is over !! pipeline reached the session id limits !!").c_str());
    }

    do {
        m_session_id = s_session_id_counter++;
    } while (s_session_used_ids.find(m_session_id) != s_session_used_ids.end());

    s_session_used_ids.insert(m_session_id);
    _unguard;
}

void PipelineComponent::free_session_id() {
    _guard;
    s_session_used_ids.erase(m_session_id);
    m_session_id = 0;
    _unguard;
}

void PipelineComponent::pipeline_in_recv(const std::string_view& data) {
    _guard;
    if (!m_is_use_pipeline) {
        throw std::logic_error(tp::string("cannot call pipeline_in_recv without pipeline!").c_str());
    }

    pipeline_data_cache.push_data(data);
    _unguard;
}