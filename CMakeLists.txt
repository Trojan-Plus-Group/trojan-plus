#
# This file is part of the Trojan Plus project.
# Trojan is an unidentifiable mechanism that helps you bypass GFW.
# Trojan Plus is derived from original trojan project and writing 
# for more experimental features.
# Copyright (C) 2017-2020  The Trojan Authors.
# Copyright (C) 2020 The Trojan Plus Group Authors.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

cmake_minimum_required(VERSION 3.10.2)

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 OLD)
endif()

project(trojan CXX C)
set(CMAKE_CXX_STANDARD 17)

# c++17 standard support:
# https://en.wikipedia.org/wiki/C%2B%2B17
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "7.0.0")
    message(FATAL_ERROR "Insufficient gcc version, please install higher version (minimum_required 7.0.0)")
  endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "19.14")
    message(FATAL_ERROR "Insufficient msvc version, please install higher version (minimum_required Visual Studio 2017 15.7 MSVC 19.14)")
  endif()
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_BUILD_TYPE STREQUAL Release 
    AND NOT MSVC 
    AND NOT APPLE 
    AND NOT ANDROID) # it will use POST_BUILD to strip

    # reduce the size of binary, otherwise binary file will be very big unless strip it
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")
endif()

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_WIN32_WINNT=0x0601)
    if(CMAKE_BUILD_TYPE STREQUAL Release)
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MP")
    else()
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MP")
    endif()
else()
    add_definitions(-Wall -Wextra)
endif()

if(ANDROID)
    option(ENABLE_ANDROID_LOG "Build with LogCat output" ON)
    if(ENABLE_ANDROID_LOG)
        add_definitions(-DENABLE_ANDROID_LOG=1)
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -llog")
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -llog")
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -llog")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -llog")
    endif()

    # I don't know why andorid's clang++ compiler will report :
    #   "clang++: warning: argument unused during compilation: '-llog' '-s' [-Wunused-command-line-argument]"
    # so I add this to surpass warning
    if(CMAKE_BUILD_TYPE STREQUAL Release)
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Qunused-arguments")
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Qunused-arguments")
    else()
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Qunused-arguments")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Qunused-arguments")
    endif()    
endif()

option(USE_GUARD_BACKSTACK "Build with try catch all functions" OFF)
if(USE_GUARD_BACKSTACK)
    add_definitions(-DUSE_GUARD_BACKSTACK=1)
endif()

# force 1.73 boost compiling warning note
add_definitions(-DBOOST_BIND_GLOBAL_PLACEHOLDERS=1)

# badvpn definitions for tun2socks
if(NOT MSVC)
    if(APPLE)
        add_definitions(-DBADVPN_FREEBSD=1)
    else()
        add_definitions(-DBADVPN_LINUX=1)
    endif()
endif()

add_definitions(-DBADVPN_THREADWORK_USE_PTHREAD=1 -DBADVPN_BREACTOR_BADVPN=1)
add_definitions(-D_GNU_SOURCE=1 -DBADVPN_USE_SIGNALFD=1 -DBADVPN_USE_EPOLL=1)
add_definitions(-DBADVPN_LITTLE_ENDIAN=1 -DBADVPN_THREAD_SAFE=1)

include_directories(
    src
    src/tun/lwip_custom
    badvpn/lwip/src/include
    badvpn
)

set(TROJAN_SOURCE_FILES 
    src/tun/lwip_custom/sys.c
    
    badvpn/lwip/src/core/udp.c 
    badvpn/lwip/src/core/memp.c 
    badvpn/lwip/src/core/init.c 
    badvpn/lwip/src/core/pbuf.c 
    badvpn/lwip/src/core/tcp.c 
    badvpn/lwip/src/core/tcp_out.c 
    badvpn/lwip/src/core/netif.c 
    badvpn/lwip/src/core/def.c 
    badvpn/lwip/src/core/ip.c 
    badvpn/lwip/src/core/mem.c 
    badvpn/lwip/src/core/tcp_in.c 
    badvpn/lwip/src/core/stats.c 
    badvpn/lwip/src/core/inet_chksum.c 
    badvpn/lwip/src/core/timeouts.c 
    badvpn/lwip/src/core/ipv4/icmp.c 
    badvpn/lwip/src/core/ipv4/igmp.c 
    badvpn/lwip/src/core/ipv4/ip4_addr.c 
    badvpn/lwip/src/core/ipv4/ip4_frag.c 
    badvpn/lwip/src/core/ipv4/ip4.c 
    badvpn/lwip/src/core/ipv4/autoip.c 
    badvpn/lwip/src/core/ipv6/ethip6.c 
    badvpn/lwip/src/core/ipv6/inet6.c 
    badvpn/lwip/src/core/ipv6/ip6_addr.c 
    badvpn/lwip/src/core/ipv6/mld6.c 
    badvpn/lwip/src/core/ipv6/dhcp6.c 
    badvpn/lwip/src/core/ipv6/icmp6.c 
    badvpn/lwip/src/core/ipv6/ip6.c 
    badvpn/lwip/src/core/ipv6/ip6_frag.c 
    badvpn/lwip/src/core/ipv6/nd6.c

    src/mem/memallocator.cpp
    src/core/config.cpp
    src/core/log.cpp
    src/core/service.cpp
    src/core/version.cpp
    src/core/pipeline.cpp
    src/core/icmpd.cpp
    src/core/utils.cpp
    src/main.cpp
    src/proto/socks5address.cpp
    src/proto/trojanrequest.cpp
    src/proto/udppacket.cpp
    src/proto/pipelinerequest.cpp
    src/proto/dns_header.cpp
    src/session/clientsession.cpp
    src/session/forwardsession.cpp
    src/session/natsession.cpp
    src/session/serversession.cpp
    src/session/socketsession.cpp
    src/session/session.cpp
    src/session/pipelinecomponent.cpp
    src/session/udpforwardsession.cpp
    src/session/pipelinesession.cpp
    src/ssl/ssldefaults.cpp
    src/ssl/sslsession.cpp

    src/tun/lwip_tcp_client.cpp
    src/tun/tundev.cpp
    src/tun/tunsession.cpp
    src/tun/tunproxysession.cpp
    src/tun/tunlocalsession.cpp
    src/tun/dnsserver.cpp
    src/tun/udplocalforwarder.cpp
)

if(ANDROID)
    add_library(trojan SHARED ${TROJAN_SOURCE_FILES})

    # Android GooglePlay store 16kb alignment required
    # https://developer.android.com/guide/practices/page-sizes?hl=zh-cn#cmake
    target_link_options(trojan PRIVATE "-Wl,-z,max-page-size=16384")
    target_link_options(trojan PRIVATE "-Wl,-z,common-page-size=16384")

    add_custom_command(TARGET trojan POST_BUILD
        COMMAND "/bin/cp" -f libtrojan.so "${LIB_OUTPUT_DIR}/libtrojan.so"
        COMMAND "${ANDROID_TOOLCHAIN_PREFIX}strip" -s "${LIB_OUTPUT_DIR}/libtrojan.so"
        COMMENT "Strip debug symbols done on final binary.")
else()
    add_executable(trojan ${TROJAN_SOURCE_FILES})
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(trojan ${CMAKE_THREAD_LIBS_INIT})

# https://github.com/microsoft/GSL supported
include_directories(${PROJECT_SOURCE_DIR}/GSL/include)

# for cland-tidy compiling database by default the file is small, generation is cheap
# as developer, I am always add this option...
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (ANDROID)
    set(ANDROID_MY_LIBS ${PROJECT_SOURCE_DIR}/trojan-plus-android-libs) 
    set(ANDROID_MY_LIBS_LIBRARIES 
        ${ANDROID_MY_LIBS}/lib/${ANDROID_ABI}/libssl.a 
        ${ANDROID_MY_LIBS}/lib/${ANDROID_ABI}/libcrypto.a
        ${ANDROID_MY_LIBS}/lib/${ANDROID_ABI}/libboost_system.a
        ${ANDROID_MY_LIBS}/lib/${ANDROID_ABI}/libboost_program_options.a)

    set(OPENSSL_VERSION 1.1.1)

    include_directories(${ANDROID_MY_LIBS}/include)
    target_link_libraries(trojan ${ANDROID_MY_LIBS_LIBRARIES})
else()
    find_package(Boost 1.72.0 REQUIRED COMPONENTS program_options)
    include_directories(${Boost_INCLUDE_DIR})
    target_link_libraries(trojan ${Boost_LIBRARIES})
    if(MSVC)
        add_definitions(-DBOOST_DATE_TIME_NO_LIB)
    endif()

    find_package(OpenSSL 1.1.0 REQUIRED)
    include_directories(${OPENSSL_INCLUDE_DIR})
    target_link_libraries(trojan ${OPENSSL_LIBRARIES})
endif()

if(OPENSSL_VERSION VERSION_GREATER_EQUAL 1.1.1)
    option(ENABLE_SSL_KEYLOG "Build with SSL KeyLog support" ON)
    if(ENABLE_SSL_KEYLOG)
        add_definitions(-DENABLE_SSL_KEYLOG)
    endif()

    option(ENABLE_TLS13_CIPHERSUITES "Build with TLS1.3 ciphersuites support" ON)
    if(ENABLE_TLS13_CIPHERSUITES)
        add_definitions(-DENABLE_TLS13_CIPHERSUITES)
    endif()
endif()

option(FORCE_TCP_FASTOPEN "Force build with TCP Fast Open support" OFF)
if(FORCE_TCP_FASTOPEN)
    add_definitions(-DTCP_FASTOPEN=23 -DTCP_FASTOPEN_CONNECT=30)
endif()

if(NOT ANDROID)    
    if(CMAKE_SYSTEM_NAME STREQUAL Linux)
        option(ENABLE_NAT "Build with NAT support" ON)
        if(ENABLE_NAT)
            add_definitions(-DENABLE_NAT)
        endif()

        option(ENABLE_REUSE_PORT "Build with SO_REUSEPORT support" ON)
        if(ENABLE_REUSE_PORT)
            add_definitions(-DENABLE_REUSE_PORT)
        endif()
    endif()

    if(APPLE)
        find_library(CoreFoundation CoreFoundation)
        find_library(Security Security)
        target_link_libraries(trojan ${CoreFoundation} ${Security})
    endif()

    option(ENABLE_MIMALLOC "Build with mimalloc support" ON)
    if(ENABLE_MIMALLOC)
        set(MI_BUILD_SHARED OFF CACHE BOOL "" FORCE)
        set(MI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(MI_BUILD_OBJECT OFF CACHE BOOL "" FORCE)
        set(MI_INSTALL OFF CACHE BOOL "" FORCE)
        set(MI_OVERRIDE OFF CACHE BOOL "" FORCE)
        set(MI_OSX_ZONE OFF CACHE BOOL "" FORCE)
        set(MI_OSX_INTERPOSE OFF CACHE BOOL "" FORCE)
        add_subdirectory(mimalloc EXCLUDE_FROM_ALL)
        target_include_directories(trojan BEFORE PRIVATE mimalloc/include)
        target_link_libraries(trojan mimalloc-static)
        add_definitions(-DENABLE_MIMALLOC)
        message(STATUS "mimalloc will be built from source (API only) and linked statically")
    endif()

    if(WIN32)
        target_link_libraries(trojan wsock32 ws2_32 crypt32)
    else()
        set(SYSTEMD_SERVICE AUTO CACHE STRING "Install systemd service")
        set_property(CACHE SYSTEMD_SERVICE PROPERTY STRINGS AUTO ON OFF)
        set(SYSTEMD_SERVICE_PATH /lib/systemd/system CACHE PATH "Systemd service path")
        if(SYSTEMD_SERVICE STREQUAL AUTO)
            if(EXISTS /usr/lib/systemd/system)
                set(SYSTEMD_SERVICE ON)
                set(SYSTEMD_SERVICE_PATH /usr/lib/systemd/system CACHE PATH "Systemd service path" FORCE)
            elseif(EXISTS /lib/systemd/system)
                set(SYSTEMD_SERVICE ON)
                set(SYSTEMD_SERVICE_PATH /lib/systemd/system CACHE PATH "Systemd service path" FORCE)
            endif()
        endif()

        include(GNUInstallDirs)
        install(TARGETS trojan DESTINATION ${CMAKE_INSTALL_BINDIR})
        install(FILES examples/server.json-example DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/trojan RENAME config.json)
        set(DEFAULT_CONFIG ${CMAKE_INSTALL_FULL_SYSCONFDIR}/trojan/config.json CACHE STRING "Default config path")
        add_definitions(-DDEFAULT_CONFIG="${DEFAULT_CONFIG}")
        install(FILES docs/trojan.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
        install(DIRECTORY docs/ DESTINATION ${CMAKE_INSTALL_DOCDIR} FILES_MATCHING PATTERN "*.md")
        install(DIRECTORY examples DESTINATION ${CMAKE_INSTALL_DOCDIR} FILES_MATCHING PATTERN "*.json-example")
        if(SYSTEMD_SERVICE STREQUAL ON)
            set(CONFIG_NAME config)
            configure_file(examples/trojan.service-example trojan.service)
            set(CONFIG_NAME %i)
            configure_file(examples/trojan.service-example trojan@.service)
            install(FILES ${CMAKE_BINARY_DIR}/trojan.service ${CMAKE_BINARY_DIR}/trojan@.service DESTINATION ${SYSTEMD_SERVICE_PATH})
        endif()

        enable_testing()
    endif()
endif()



