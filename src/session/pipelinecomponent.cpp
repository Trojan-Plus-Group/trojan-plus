
#include "pipelinecomponent.h"
#include "core/service.h"

PipelineComponent::PipelineComponent(Service* _service, const Config& _config): 
    m_is_use_pipeline(false),
    m_service(_service),
    session_id(0){
    pipeline_ack_counter = static_cast<int>(m_service->config.experimental.pipeline_ack_window);
}

void PipelineComponent::allocate_session_id(){
    if(s_session_used_ids.size() >= numeric_limits<SessionIdType>::max()){
        throw logic_error("session id is over !! pipeline reached the session id limits !!");
    }

    do{
        session_id = s_session_id_counter++;        
    }while(s_session_used_ids.find(session_id) != s_session_used_ids.end());

    s_session_used_ids.insert(session_id);
}

void PipelineComponent::free_session_id(){
    s_session_used_ids.erase(session_id);
}

void PipelineComponent::pipeline_in_recv(string &&data) {
    if (!m_is_use_pipeline) {
        throw logic_error("cannot call pipeline_in_recv without pipeline!");
    }

    if (status != DESTROY) {
        pipeline_data_cache.push_data(std::move(data));
    }
}