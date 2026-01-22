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

#ifndef _PIPELINEREQUEST_H_
#define _PIPELINEREQUEST_H_

#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include "session/pipelinecomponent.h"
#include "session/session.h"
#include "mem/memallocator.h"

class PipelineRequest {
  public:
    size_t consume_length{0};
    size_t ack_count{0};
    std::string_view packet_data;
    PipelineComponent::SessionIdType session_id;
    enum Command {
        CONNECT = 0,
        DATA,
        ACK,
        CLOSE,
        ICMP,
        MAX_COMMANDS,
        MAX_ICMP_LENGTH       = std::numeric_limits<uint16_t>::max(),
        MAX_DATA_LENGTH       = std::numeric_limits<uint32_t>::max(),
        MAX_SESSION_ID_LENGTH = std::numeric_limits<PipelineComponent::SessionIdType>::max()
    } command;

    [[nodiscard]] int parse(const std::string_view& data);

    [[nodiscard]] inline const char* get_cmd_string() const { return get_cmd_string(command); }

    static inline const char* get_cmd_string(enum Command cmd) {
        switch (cmd) {
            case CONNECT:
                return "CONNECT";
            case DATA:
                return "DATA";
            case ACK:
                return "ACK";
            case CLOSE:
                return "CLOSE";
            case ICMP:
                return "ICMP";
            default:
                return "UNKNOW!!";
        }
    }

    static tp::streambuf& generate(tp::streambuf& buf, enum Command cmd,
      PipelineComponent::SessionIdType session_id, const std::string_view& data, size_t ack_count = 0);
};

#endif // _PIPELINEREQUEST_H_