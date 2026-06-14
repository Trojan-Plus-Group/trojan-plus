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

#include <boost/asio/signal_set.hpp>
#include <boost/program_options.hpp>
#include <boost/version.hpp>
#include <cstdlib>
#include <iostream>
#include <wolfssl/version.h>
#include <openssl/opensslv.h>

#include "core/service.h"
#include "core/version.h"
#include "mem/memallocator.h"

using namespace boost::asio;
namespace po = boost::program_options;

#ifndef DEFAULT_CONFIG
#define DEFAULT_CONFIG "config.json"
#endif // DEFAULT_CONFIG

void signal_async_wait(signal_set& sig, Service& service, bool& restart) {
    sig.async_wait(tp::bind_mem_alloc([&](const boost::system::error_code error, int signum) {
        if (error) {
            return;
        }
        _log_with_date_time("got signal: " + tp::to_string(signum), Log::WARN);
        switch (signum) {
            case SIGINT:
            case SIGTERM:
                service.stop();
                break;
#ifndef _WIN32
            case SIGUSR2: // for Android Close
                service.stop();
                break;
            case SIGHUP:
                restart = true;
                service.stop();
                break;
            case SIGUSR1:
                service.reload_cert();
                signal_async_wait(sig, service, restart);
                break;
#ifdef SIGINFO
            case SIGINFO:
                {
                    std::string stat = tp::get_tj_mem_allocator().show_stat();
                    _log_with_date_time("Memory statistics:\n" + stat, Log::WARN);
                }
                signal_async_wait(sig, service, restart);
                break;
#endif
#endif // _WIN32
        }
    }));
}

#ifndef _WIN32
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>

void crash_handler(int sig) {
    void* array[50];
    size_t size = backtrace(array, 50);
    fprintf(stderr, "Error: signal %d:\n", sig);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}
#endif

// global service to avoid calling Service::~Service for Android,
// to speed up Android VPN disconnection. io_context::~io_context might hang for 30 - 50 sec
// after disconnection, the whole process will be killed in Android
static std::shared_ptr<Service> g_service;

int main_impl(int argc, const char* argv[]) {
#ifndef _WIN32
    signal(SIGSEGV, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGILL,  crash_handler);
    signal(SIGFPE,  crash_handler);
#endif
    try {
        Log::log("Trojan Plus v" + Version::get_version() + " starts.", Log::FATAL);
        tp::string config_file;
        tp::string log_file;
        tp::string keylog_file;
        bool test;
        po::options_description desc("options");
        desc.add_options()("config,c",
          po::value<tp::string>(&config_file)->default_value(DEFAULT_CONFIG)->value_name("CONFIG"),
          "specify config file")("help,h", "print help message")("keylog,k",
          po::value<tp::string>(&keylog_file)->value_name("KEYLOG"), "specify keylog file location")(
          "log,l", po::value<tp::string>(&log_file)->value_name("LOG"), "specify log file location")(
          "test,t", po::bool_switch(&test), "test config file")("version,v", "print version and build info");
        po::positional_options_description pd;
        pd.add("config", 1);
        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc).positional(pd).run(), vm);
        po::notify(vm);
        if (vm.count("help")) {
            Log::log(tp::string("usage: ") + argv[0] + " [-htv] [-l LOG] [-k KEYLOG] [[-c] CONFIG]", Log::FATAL);
            std::cerr << desc;
            exit(EXIT_SUCCESS);
        }
        if (vm.count("version")) {
            Log::log(tp::string("Boost ") + BOOST_LIB_VERSION + ", " + OpenSSL_version(OPENSSL_VERSION), Log::FATAL);
#ifdef TCP_FASTOPEN
            Log::log(" [Enabled] TCP_FASTOPEN Support", Log::FATAL);
#else  // TCP_FASTOPEN
            Log::log("[Disabled] TCP_FASTOPEN Support", Log::FATAL);
#endif // TCP_FASTOPEN
#ifdef TCP_FASTOPEN_CONNECT
            Log::log(" [Enabled] TCP_FASTOPEN_CONNECT Support", Log::FATAL);
#else  // TCP_FASTOPEN_CONNECT
            Log::log("[Disabled] TCP_FASTOPEN_CONNECT Support", Log::FATAL);
#endif // TCP_FASTOPEN_CONNECT
#if ENABLE_SSL_KEYLOG
            Log::log(" [Enabled] SSL KeyLog Support", Log::FATAL);
#else  // ENABLE_SSL_KEYLOG
            Log::log("[Disabled] SSL KeyLog Support", Log::FATAL);
#endif // ENABLE_SSL_KEYLOG
#ifdef ENABLE_NAT
            Log::log(" [Enabled] NAT Support", Log::FATAL);
#else  // ENABLE_NAT
            Log::log("[Disabled] NAT Support", Log::FATAL);
#endif // ENABLE_NAT
#ifdef ENABLE_TLS13_CIPHERSUITES
            Log::log(" [Enabled] TLS1.3 Ciphersuites Support", Log::FATAL);
#else  // ENABLE_TLS13_CIPHERSUITES
            Log::log("[Disabled] TLS1.3 Ciphersuites Support", Log::FATAL);
#endif // ENABLE_TLS13_CIPHERSUITES
#ifdef ENABLE_REUSE_PORT
            Log::log(" [Enabled] TCP Port Reuse Support", Log::FATAL);
#else  // ENABLE_REUSE_PORT
            Log::log("[Disabled] TCP Port Reuse Support", Log::FATAL);
#endif // ENABLE_REUSE_PORT
#ifdef ENABLE_QUIC
            Log::log(" [Enabled] QUIC Support (ngtcp2 + wolfSSL)", Log::FATAL);
#else  // ENABLE_QUIC
            Log::log("[Disabled] QUIC Support (ngtcp2 + wolfSSL)", Log::FATAL);
#endif // ENABLE_QUIC
            Log::log("SSL Library Information", Log::FATAL);
            Log::log(tp::string("\tVersion: wolfSSL ") + LIBWOLFSSL_VERSION_STRING, Log::FATAL);
            exit(EXIT_SUCCESS);
        }
        if (vm.count("log")) {
            Log::redirect(log_file);
        }
        if (vm.count("keylog")) {
            Log::redirect_keylog(keylog_file);
        }
        bool restart;
        Config config;
        do {
            restart = false;
            if (config.sip003()) {
                _log_with_date_time("SIP003 is loaded", Log::WARN);
            } else {
                config.load(config_file);
            }
            if (config.get_log_level() == Log::ALL) {
                tp::get_tj_mem_allocator().set_trace_file_line_enable(true);
            } else {
                tp::get_tj_mem_allocator().set_trace_file_line_enable(false);
            }
            g_service = TP_MAKE_SHARED(Service, config, test);

            if (test) {
                Log::log("The config file looks good.", Log::OFF);
                g_service.reset();
                exit(EXIT_SUCCESS);
            }
            signal_set sig(g_service->get_io_context());
            sig.add(SIGINT);
            sig.add(SIGTERM);
#ifndef _WIN32
            sig.add(SIGHUP);
            sig.add(SIGUSR1);
            sig.add(SIGUSR2); // for Android Close
#ifdef SIGINFO
            sig.add(SIGINFO);
#endif
#endif                        // _WIN32
            signal_async_wait(sig, *g_service, restart);
            g_service->run();
            if (restart) {
                _log_with_date_time("trojan service restarting. . . ", Log::WARN);
            }
        } while (restart);
        _log_with_date_time("trojan service exit.", Log::WARN);
        Log::reset();

#ifndef __ANDROID__
        g_service.reset();
        exit(EXIT_SUCCESS);
#endif

    } catch (const std::exception& e) {
        _log_with_date_time(tp::string("fatal: ") + e.what(), Log::FATAL);
        _log_with_date_time("exiting. . . ", Log::FATAL);

#ifndef __ANDROID__
        g_service.reset();
        exit(EXIT_FAILURE);
#endif
    }
}

#if !defined(IOS) && !defined(BUILD_LIBRARY)
int main(int argc, const char* argv[]) {
    return main_impl(argc, argv);
}
#endif
