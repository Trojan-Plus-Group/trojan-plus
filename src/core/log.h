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

#ifndef _LOG_H_
#define _LOG_H_

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <cstdio>
#include <string>
#include <memory>
#include "mem/memallocator.h"

#ifdef ERROR // windows.h
#undef ERROR
#endif // ERROR

class Log {
  public:
    enum Level {
        ALL     = 0,
        INFO    = 1,
        WARN    = 2,
        ERROR   = 3,
        FATAL   = 4,
        OFF     = 5,
        INVALID = -1,
    };
    using LogCallback = std::function<void(const std::string&, Level)>;
    static Level level;
    static FILE* keylog;
    static void log(const std::string& message, Level level = ALL);
    static void log_with_date_time(const std::string& message, Level level = ALL);
    static void log_with_endpoint(
      const boost::asio::ip::tcp::endpoint& endpoint, const std::string& message, Level level = ALL);
    static void log_with_endpoint(
      const boost::asio::ip::udp::endpoint& endpoint, const std::string& message, Level level = ALL);
    static void redirect(const std::string& filename);
    static void redirect_keylog(const std::string& filename);
    static void set_callback(LogCallback&& cb);
    static void reset();

  private:
    static FILE* output_stream;
    static LogCallback log_callback;
};

const static size_t __max_debug_str_buf_size = 1024;
extern tp::tj_unique_ptr<char[]> __debug_str_buf;

#if 0
#define _write_data_to_file_DEBUG(...)                                                                                 \
    do {                                                                                                               \
        if (Log::level <= Log::ALL)                                                                                    \
            write_data_to_file(__VA_ARGS__);                                                                           \
    } while (false)
#else
#define _write_data_to_file_DEBUG(...)                                                                                 \
    {}
#endif

#if 0
#define _log_with_date_time_DEBUG(...)                                                                                 \
    do {                                                                                                               \
        if (Log::level <= Log::ALL) {                                                                                  \
            Log::log_with_date_time(__VA_ARGS__, Log::ALL);                                                            \
        }                                                                                                              \
    } while (false)

#define _log_with_endpoint_DEBUG(...)                                                                                  \
    do {                                                                                                               \
        if (Log::level <= Log::ALL) {                                                                                  \
            Log::log_with_endpoint(__VA_ARGS__);                                                                       \
        }                                                                                                              \
    } while (false)
#else
#define _log_with_date_time_DEBUG(...)                                                                                 \
    {}
#define _log_with_endpoint_DEBUG(...)                                                                                  \
    {}
#endif


#ifndef NO_ANY_LOGS

#define _log_with_date_time_ALL(...)                                                                                   \
    do {                                                                                                               \
        if (Log::level <= Log::ALL) {                                                                                  \
            Log::log_with_date_time(__VA_ARGS__, Log::ALL);                                                            \
        }                                                                                                              \
    } while (false)

#define _log_with_endpoint_ALL(...)                                                                                    \
    do {                                                                                                               \
        if (Log::level <= Log::ALL) {                                                                                  \
            Log::log_with_endpoint(__VA_ARGS__, Log::ALL);                                                             \
        }                                                                                                              \
    } while (false)

#define _log_with_date_time(...)                                                                                       \
    do {                                                                                                               \
        if (Log::level != Log::OFF) {                                                                                  \
            Log::log_with_date_time(__VA_ARGS__);                                                                      \
        }                                                                                                              \
    } while (false)

#define _log_with_endpoint(...)                                                                                        \
    do {                                                                                                               \
        if (Log::level != Log::OFF) {                                                                                  \
            Log::log_with_endpoint(__VA_ARGS__);                                                                       \
        }                                                                                                              \
    } while (false)

#define _log(...)                                                                                                      \
    do {                                                                                                               \
        if (Log::level != Log::OFF) {                                                                                  \
            Log::log(__VA_ARGS__);                                                                                     \
        }                                                                                                              \
    } while (false)

#define output_debug_info_ec(ec)                                                                                       \
    do {                                                                                                               \
        if (Log::level <= Log::INFO) {                                                                                 \
            Log::log_with_date_time(                                                                                   \
              std::string(__debug_str_buf.get(),                                                                       \
                snprintf(__debug_str_buf.get(), __max_debug_str_buf_size, "%s:%d-<%s> ec:%s", (const char*)__FILE__,   \
                  __LINE__, (const char*)__FUNCTION__, (ec.message().c_str()))),                                       \
              Log::INFO);                                                                                              \
        }                                                                                                              \
    } while (false)

#define output_debug_info()                                                                                            \
    do {                                                                                                               \
        if (Log::level <= Log::INFO) {                                                                                 \
            Log::log_with_date_time(std::string(__debug_str_buf.get(),                                                 \
                                      snprintf(__debug_str_buf.get(), __max_debug_str_buf_size, "%s:%d-<%s>",          \
                                        (const char*)__FILE__, __LINE__, (const char*)__FUNCTION__)),                  \
              Log::INFO);                                                                                              \
        }                                                                                                              \
    } while (false)

#else

#define _log_with_date_time_ALL(...)   
    {}
#define _log_with_endpoint_ALL(...)                                                                                    \
    {}
#define _log_with_date_time(...)                                                                                       \
    {}
#define _log_with_endpoint(...)                                                                                        \
    {}
#define _log(...)                                                                                                      \
    {}
#define output_debug_info_ec(ec)                                                                                       \
    {}
#define output_debug_info()                                                                                            \
    {}
#endif // NO_ANY_LOGS


#define _assert(exp)                                                                                                   \
    do {                                                                                                               \
        if (!(exp)) {                                                                                                  \
            throw std::runtime_error(std::string(__debug_str_buf.get(),                                                \
              snprintf(__debug_str_buf.get(), __max_debug_str_buf_size, "_assert(" #exp ") : %s:%d-<%s>",              \
                (const char*)__FILE__, __LINE__, (const char*)__FUNCTION__)));                                         \
        }                                                                                                              \
    } while (false)


#ifdef USE_GUARD_BACKSTACK

#define _guard try {
#define _unguard                                                                                                       \
    }                                                                                                                  \
    catch (const std::exception& ex) {                                                                                 \
        std::ostringstream bt;                                                                                         \
        bt << ex.what();                                                                                               \
        bt << "\n";                                                                                                    \
        bt << (const char*)__FILE__;                                                                                   \
        bt << ":" << __LINE__;                                                                                         \
        bt << "-" << (const char*)__FUNCTION__;                                                                        \
        throw std::runtime_error(bt.str());                                                                            \
    }

#else

#define _guard                                                                                                         \
    do {                                                                                                               \
    } while (false)
#define _unguard                                                                                                       \
    do {                                                                                                               \
    } while (false)

#endif // USE_GUARD_BACKSTACK


#endif // _LOG_H_
