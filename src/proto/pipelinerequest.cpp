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

#include <string>

#include "pipelinerequest.h"
#include "core/log.h"
#include "session/pipelinecomponent.h"

using namespace std;

// please don't return uint16_t for the performance, maybe byte align problem
static 
size_t parse_uint16(int start_pos, const string_view& data){
    return size_t(uint8_t(data[0 + start_pos])) << 8 | 
           size_t(uint8_t(data[1 + start_pos]));
}

static 
void generate_uint16(boost::asio::streambuf& data, uint16_t value){
    streambuf_append(data, char(value >> 8 & 0xff));
    streambuf_append(data, char(value & 0xff));
}

static 
uint32_t parse_uint32(int start_pos, const string_view& data){
    return uint32_t(uint8_t(data[0 + start_pos])) << 24 | 
           uint32_t(uint8_t(data[1 + start_pos])) << 16 | 
           uint32_t(uint8_t(data[2 + start_pos])) << 8 | 
           uint32_t(uint8_t(data[3 + start_pos]));
}

static 
void generate_uint32(boost::asio::streambuf& data, uint32_t value){
    streambuf_append(data, char(value >> 24));
    streambuf_append(data, char(value >> 16 & 0xff));
    streambuf_append(data, char(value >> 8 & 0xff));
    streambuf_append(data, char(value & 0xff));
}

int PipelineRequest::parse(const string_view &data){
    /*
        +-------------------+-------------------------+
        | 1 byte as command | diff options by command |
        +-------------------+-------------------------+

    command list:
        +---------------------------+-----------------------+
        | CONNECT or ACK or DESTORY | 2 bytes as session id |
        +---------------------------+-----------------------+

        +------+-----------------------+------------------------+
        | DATA | 2 bytes as session id | 4 bytes as data length |
        +------+-----------------------+------------------------+

        +------+--------------------=---+------------------------+
        | ICMP | 2 bytes as data length |        data            |
        +------+-------------------==---+------------------------+
    */

    if(data.length() < 1){
        return -1;
    }

    uint8_t cmd = data[0];
    if(cmd >= MAX_COMMANDS){
        return -2;
    }

    command = (Command) cmd;

    if(command == DATA){

        const size_t DATA_CMD_HEADER_LENGTH = 7;

        if(data.length() < DATA_CMD_HEADER_LENGTH){
            return -1;
        }

        size_t trojan_request_length = parse_uint32(3, data);
        if(data.length() < DATA_CMD_HEADER_LENGTH + trojan_request_length){
            return -1;
        }

        session_id = (PipelineComponent::SessionIdType)parse_uint16(1, data);
        packet_data = data.substr(DATA_CMD_HEADER_LENGTH, trojan_request_length);
        consume_length = DATA_CMD_HEADER_LENGTH + trojan_request_length;
    }
    else if(command == ICMP){
        const size_t ICMP_CMD_HEADER_LENGTH = 3;

        if (data.length() < ICMP_CMD_HEADER_LENGTH) {
            return -1;
        }

        size_t icmp_length = parse_uint16(1, data);
        if (data.length() < ICMP_CMD_HEADER_LENGTH + icmp_length) {
            return -1;
        }

        session_id = 0;
        packet_data = data.substr(ICMP_CMD_HEADER_LENGTH, icmp_length);
        consume_length = ICMP_CMD_HEADER_LENGTH + icmp_length;
    }
    else{

        const size_t CMD_HEADER_LENGTH = 3;
        if(data.length() < CMD_HEADER_LENGTH){
            return -1;
        }
        session_id = (PipelineComponent::SessionIdType)parse_uint16(1, data);
        consume_length = CMD_HEADER_LENGTH;
        // no packet data;
    }

    return (int)packet_data.length();
}

boost::asio::streambuf& PipelineRequest::generate(boost::asio::streambuf& buf, enum Command cmd, PipelineComponent::SessionIdType session_id, const std::string_view& data){
    
    // if(session_id > MAX_SESSION_ID_LENGTH){
    //     throw logic_error("PipelineRequest::generate session_id " + to_string(session_id) + " > numeric_limits<uint16_t>::max() " + to_string(MAX_SESSION_ID_LENGTH));
    // }

    streambuf_append(buf, char(uint8_t(cmd)));
    
    if (cmd == ICMP) {
        auto data_length = data.length();
        if (data_length >= MAX_ICMP_LENGTH) {
            throw logic_error("PipelineRequest::generate data.length() " + to_string(data_length) + " > MAX_ICMP_LENGTH " + to_string(MAX_ICMP_LENGTH));
        }

        generate_uint16(buf, (uint16_t)data_length);
        streambuf_append(buf, data);

    } else {
        generate_uint16(buf, session_id);

        if (cmd == DATA) {
            auto data_length = data.length();
            if (data_length >= MAX_DATA_LENGTH) {
                throw logic_error("PipelineRequest::generate data.length() " + to_string(data_length) + " > MAX_DATA_LENGTH " + to_string(MAX_DATA_LENGTH));
            }

            generate_uint32(buf, (uint32_t)data_length);
            streambuf_append(buf, data);
        }
    }

    return buf;
}