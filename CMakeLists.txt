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

cmake_minimum_required(VERSION 3.7.2)

project(trojan CXX C)
set(CMAKE_CXX_STANDARD 17)
set(ANDROID false)

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

if(CMAKE_BUILD_TYPE STREQUAL Release AND NOT MSVC AND NOT APPLE)
    # reduce the sizeof binary, otherwise binary file will be very big
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s")

        # I don't know why andorid's clang++ compiler will report "clang++: warning: argument unused during compilation: '-s' [-Wunused-command-line-argument]"
        # so I add this to surpass warning
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -Qunused-arguments")
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Qunused-arguments")
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
endif()

# force 1.73 boost compiling warning note
add_definitions(-DBOOST_BIND_GLOBAL_PLACEHOLDERS=1)

include_directories(
    src
)

set(TROJAN_SOURCE_FILES 
    
    src/core/authenticator.cpp
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

)


    add_executable(trojan ${TROJAN_SOURCE_FILES})

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(trojan ${CMAKE_THREAD_LIBS_INIT})


# https://github.com/microsoft/GSL supported
#find_package(Microsoft.GSL CONFIG REQUIRED)
if(${Microsoft.GSL_FOUND})
  message(STATUS "Found the Guidelines Support Library: ${Microsoft.GSL_DIR}")
  target_link_libraries(trojan INTERFACE Microsoft.GSL::GSL)
else()
  set(GSL_URL https://github.com/Microsoft/GSL)
  set(GSL_VERSION 0f6dbc9)
  message(STATUS "Using and shipping ${GSL_URL} version ${GCL_VERSION}")
  set(GSL_DIR ${CMAKE_CURRENT_BINARY_DIR}/external/GSL)
  if(NOT EXISTS ${GSL_DIR})
    execute_process(COMMAND git clone ${GSL_URL} ${GSL_DIR})
  endif()
  execute_process(COMMAND git checkout ${GSL_VERSION} WORKING_DIRECTORY ${GSL_DIR})
  #install(DIRECTORY ${GSL_DIR}/gsl DESTINATION include)
  #install(FILES ${GSL_DIR}/LICENSE DESTINATION include/gsl/LICENSE)
  set(GSL_INCLUDE_DIR NAMES ${GSL_DIR})
  if(GSL_INCLUDE_DIR)
    set(GSL_INCLUDE_DIRS ${GSL_INCLUDE_DIR}/include)
    include_directories(${GSL_INCLUDE_DIRS})
    set(GSL_FOUND TRUE)
  endif()
endif()
 
# for cland-tidy compiling database by default the file is small, generation is cheap
# as developer, I am always add this option...
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

    find_package(Boost 1.66.0 REQUIRED COMPONENTS system program_options)
    include_directories(${Boost_INCLUDE_DIR})
    target_link_libraries(trojan ${Boost_LIBRARIES})
    if(MSVC)
        add_definitions(-DBOOST_DATE_TIME_NO_LIB)
    endif()

    find_package(OpenSSL 1.1.0 REQUIRED)
    include_directories(${OPENSSL_INCLUDE_DIR})
    target_link_libraries(trojan ${OPENSSL_LIBRARIES})

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

    option(ENABLE_MYSQL "Build with MySQL support" ON)
    if(ENABLE_MYSQL)
        find_package(MySQL REQUIRED)
        include_directories(${MYSQL_INCLUDE_DIR})
        target_link_libraries(trojan ${MYSQL_LIBRARIES})
        add_definitions(-DENABLE_MYSQL)
        if(APPLE)
            target_link_libraries(trojan iconv)
        else()
            target_link_libraries(trojan dl)
        endif()
    endif()

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
        add_test(NAME LinuxSmokeTest-basic
                COMMAND bash ${CMAKE_SOURCE_DIR}/tests/LinuxSmokeTest/basic.sh ${CMAKE_BINARY_DIR}/trojan)
        add_test(NAME LinuxSmokeTest-fake-client
                COMMAND bash ${CMAKE_SOURCE_DIR}/tests/LinuxSmokeTest/fake-client.sh ${CMAKE_BINARY_DIR}/trojan)
    endif()


