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

#ifndef _LOG_H_
#define _LOG_H_

#include <cstdio>
#include <string>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#ifdef ERROR // windows.h
#undef ERROR
#endif // ERROR

class Log {
public:
    enum Level {
        ALL = 0,
        INFO = 1,
        WARN = 2,
        ERROR = 3,
        FATAL = 4,
        OFF = 5
    };
    typedef std::function<void(const std::string &, Level)> LogCallback;
    static Level level;
    static FILE *keylog;
    static void log(const std::string &message, Level level = ALL);
    static void log_with_date_time(const std::string &message, Level level = ALL);
    static void log_with_endpoint(const boost::asio::ip::tcp::endpoint &endpoint, const std::string &message, Level level = ALL);
    static void log_with_endpoint(const boost::asio::ip::udp::endpoint &endpoint, const std::string &message, Level level = ALL);
    static void redirect(const std::string &filename);
    static void redirect_keylog(const std::string &filename);
    static void set_callback(LogCallback cb);
    static void reset();
private:
    static FILE *output_stream;
    static LogCallback log_callback;
};

extern char __debug_str_buf[1024];

#if 1
    #define _write_data_to_file(...) \
        do{ if(Log::level <= Log::ALL) write_data_to_file(__VA_ARGS__); }while(false)
#else
    #define _write_data_to_file(...) {}
#endif

#define _log_with_date_time_ALL(...) \
    do{if(Log::level <= Log::ALL) { Log::log_with_date_time(__VA_ARGS__, Log::ALL); }}while(false)

#define _log_with_endpoint_ALL(...) \
    do{if(Log::level <= Log::ALL) { Log::log_with_endpoint(__VA_ARGS__, Log::ALL); }}while(false)

#define _log_with_date_time(...) \
    do{if(Log::level != Log::OFF) { Log::log_with_date_time(__VA_ARGS__); }}while(false)

#define _log_with_endpoint(...) \
    do{if(Log::level != Log::OFF) { Log::log_with_endpoint(__VA_ARGS__); }}while(false)

#define _log(...) \
    do{if(Log::level != Log::OFF) { Log::log(__VA_ARGS__); }}while(false)

#define output_debug_info_ec(ec) \
    do{if(Log::level <= Log::ALL) { Log::log_with_date_time(std::string((sprintf(__debug_str_buf, "%s:%d-<%s> ec:%s",__FILE__, __LINE__, __FUNCTION__,(ec.message().c_str())), __debug_str_buf))); }}while(false)

#define output_debug_info() \
    do{if(Log::level <= Log::ALL) { Log::log_with_date_time(std::string((sprintf(__debug_str_buf, "%s:%d-<%s>",__FILE__, __LINE__, __FUNCTION__), __debug_str_buf))); }}while(false)

#define _guard_read_buf_begin(guard_buf) \
    do{ \
        if((guard_buf##_guard)){ \
            auto info = std::string((sprintf(__debug_str_buf, "%s:%d-<%s>",__FILE__, __LINE__, __FUNCTION__), __debug_str_buf)); \
            throw std::logic_error("!! guard_read_buf failed! Cannot enter this function before _guard_read_buf_end  !! " + info); \
        } \
        (guard_buf##_guard) = true; \
    }while(false)

#define _guard_read_buf_end(guard_buf) \
    do{ \
        (guard_buf##_guard) = false; \
    }while(false)

#endif // _LOG_H_
