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

cmake_minimum_required(VERSION 3.20)

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 OLD)
endif()

project(trojan CXX C)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# c++23 standard support (required for QUIC integration via ngtcp2 examples patterns):
# https://en.cppreference.com/w/cpp/compiler_support/23
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "13.0.0")
    message(FATAL_ERROR "Insufficient gcc version, please install higher version (minimum_required 13.0.0 for C++23)")
  endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "16.0.0")
    message(FATAL_ERROR "Insufficient clang version, please install higher version (minimum_required 16.0.0 for C++23)")
  endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "19.34")
    message(FATAL_ERROR "Insufficient msvc version, please install higher version (minimum_required Visual Studio 2022 17.4 MSVC 19.34 for C++23)")
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
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_WIN32_WINNT=0x0601 -DTROJAN_EXPORTS)
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

if(IOS)
    add_definitions(-DIOS)
    option(ENABLE_IOS_LOG "Build with iOS unified logging" ON)
    if(ENABLE_IOS_LOG)
        add_definitions(-DENABLE_IOS_LOG=1)
    endif()

    # Suppress unused argument warnings like Android
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
    src/platform_exports.cpp
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

# QUIC transport via ngtcp2 + wolfSSL (default ON)
option(ENABLE_QUIC "Build QUIC transport via ngtcp2 + wolfSSL" ON)
if(ENABLE_QUIC)
    list(APPEND TROJAN_SOURCE_FILES
        src/quic/quic_tls_ctx.cpp
        src/quic/quic_endpoint.cpp
        src/quic/quic_server_endpoint.cpp
        src/quic/quic_client_endpoint.cpp
        src/quic/quic_connection.cpp
        src/quic/quic_session.cpp
        src/quic/outbound_transport.cpp
    )
endif()

# Option to build as a library (without main function) instead of executable
option(BUILD_LIBRARY "Build as a static library (excluding main function)" OFF)

if(ANDROID)
    # Build as static library without main function (for embedding in other projects)
    add_definitions(-DBUILD_LIBRARY)
    add_library(trojan SHARED ${TROJAN_SOURCE_FILES})

    # Android GooglePlay store 16kb alignment required
    # https://developer.android.com/guide/practices/page-sizes?hl=zh-cn#cmake
    target_link_options(trojan PRIVATE "-Wl,-z,max-page-size=16384")
    target_link_options(trojan PRIVATE "-Wl,-z,common-page-size=16384")

    add_custom_command(TARGET trojan POST_BUILD
        COMMAND "/bin/cp" -f libtrojan.so "${LIB_OUTPUT_DIR}/libtrojan.so"
        COMMAND "${ANDROID_TOOLCHAIN_PREFIX}strip" -s "${LIB_OUTPUT_DIR}/libtrojan.so"
        COMMENT "Strip debug symbols done on final binary.")
elseif(IOS OR (APPLE AND BUILD_LIBRARY))
    # Build as static library without main function (for embedding in other projects)
    add_definitions(-DBUILD_LIBRARY)
    add_library(trojan STATIC ${TROJAN_SOURCE_FILES})

    set_target_properties(trojan PROPERTIES
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ""
        XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED NO
        XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED NO
        XCODE_ATTRIBUTE_ENABLE_BITCODE NO
    )

    add_custom_command(TARGET trojan POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:trojan> "${LIB_OUTPUT_DIR}/libtrojan.a"
        COMMAND strip -x "${LIB_OUTPUT_DIR}/libtrojan.a"
        COMMENT "Strip debug symbols from static library")
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

# ===== wolfSSL configuration (replaces OpenSSL) =====
# wolfSSL is built from source as a static library via add_subdirectory.
# The WOLFSSL_ASIO option enables Boost.Asio compatibility and automatically
# enables OPENSSL_EXTRA and OPENSSL_ALL for the OpenSSL compatibility layer.
set(WOLFSSL_ASIO "yes" CACHE STRING "" FORCE)
set(WOLFSSL_TLS13 "yes" CACHE STRING "" FORCE)
set(WOLFSSL_ALPN "yes" CACHE STRING "" FORCE)
set(WOLFSSL_SNI "yes" CACHE STRING "" FORCE)
set(WOLFSSL_SESSION_TICKET "yes" CACHE STRING "" FORCE)
set(WOLFSSL_HARDEN "yes" CACHE STRING "" FORCE)
set(WOLFSSL_HARDEN_TLS "128" CACHE STRING "" FORCE)  # TLS protocol-layer hardening (128-bit security)
set(WOLFSSL_KEYLOG_EXPORT "no" CACHE STRING "" FORCE)  # Disabled by default; enables SSLKEYLOGFILE export which exposes master secrets
set(WOLFSSL_SINGLE_THREADED "no" CACHE STRING "" FORCE)
set(WOLFSSL_EXAMPLES "no" CACHE STRING "" FORCE)
set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "" FORCE)
set(WOLFSSL_INSTALL "no" CACHE STRING "" FORCE)
set(WOLFSSL_CURVE25519 "yes" CACHE STRING "" FORCE)
set(WOLFSSL_CURVE448 "yes" CACHE STRING "" FORCE)
set(WOLFSSL_ECC "yes" CACHE STRING "" FORCE)
# Note: HAVE_AESGCM / HAVE_SUPPORTED_CURVES / HAVE_ECC are C preprocessor macros,
# not wolfSSL CMake options — define them via target_compile_definitions below.

# Required by ngtcp2_crypto_wolfssl: enables wolfSSL_set_quic_method and the
# QUIC encryption-level callbacks (header in wolfssl/wolfssl/quic.h).
if(ENABLE_QUIC)
    set(WOLFSSL_QUIC "yes" CACHE STRING "" FORCE)
endif()

# Disable ASM for cross-compilation safety
if(ANDROID OR IOS)
    set(WOLFSSL_ASM "no" CACHE STRING "" FORCE)
endif()

# Force wolfSSL to build as static library regardless of parent project setting.
# Save and restore BUILD_SHARED_LIBS so subsequent add_subdirectory calls
# (e.g. mimalloc) are not affected by this override.
set(BUILD_SHARED_LIBS_SAVED ${BUILD_SHARED_LIBS})
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
add_subdirectory(wolfssl EXCLUDE_FROM_ALL)
set(BUILD_SHARED_LIBS ${BUILD_SHARED_LIBS_SAVED} CACHE BOOL "" FORCE)

# wolfSSL 5.9.1 does not expose secure renegotiation as a CMake option (listed as TODO).
# Enable it only when requested: it adds RFC 5746 renegotiation_info to ServerHello
# (required for SSL Labs A rating) but increases code size and attack surface.
# RFC 7627 Extended Master Secret must accompany it; wolfssl's CMake option handles that.
option(ENABLE_SECURE_RENEGOTIATION "Build with RFC 5746 secure renegotiation support (enables SSL Labs A rating)" OFF)
if(ENABLE_SECURE_RENEGOTIATION)
    set(WOLFSSL_EXTENDED_MASTER "yes" CACHE STRING "" FORCE)
    target_compile_definitions(wolfssl PRIVATE HAVE_SECURE_RENEGOTIATION)
    message(STATUS "Secure renegotiation (RFC 5746) enabled")
else()
    message(STATUS "Secure renegotiation (RFC 5746) disabled (use -DENABLE_SECURE_RENEGOTIATION=ON to enable)")
endif()

message(STATUS "wolfSSL will be built from source and linked statically")

# ===== ngtcp2 (QUIC) configuration =====
# ngtcp2 ships its own CMakeLists.txt; it locates wolfSSL via find_package, which
# would normally scan the system. We pre-seed the cache with paths into the
# in-tree wolfSSL submodule and the CMake target name, so the bundled
# Findwolfssl.cmake module short-circuits to our local build.
if(ENABLE_QUIC)
    # wolfSSL is built via add_subdirectory above; ngtcp2's bundled Findwolfssl
    # uses these vars, and ngtcp2/crypto/wolfssl pulls in <wolfssl/options.h>
    # which is generated into the build tree, so the include list must contain
    # both the source dir and the build dir.
    set(WOLFSSL_INCLUDE_DIR  "${CMAKE_SOURCE_DIR}/wolfssl" CACHE PATH   "" FORCE)
    set(WOLFSSL_LIBRARY      wolfssl                       CACHE STRING "" FORCE)
    set(WOLFSSL_LIBRARIES    wolfssl                       CACHE STRING "" FORCE)
    set(WOLFSSL_INCLUDE_DIRS
        "${CMAKE_SOURCE_DIR}/wolfssl"
        "${CMAKE_BINARY_DIR}/wolfssl"
        CACHE STRING "" FORCE)

    set(ENABLE_LIB_ONLY     ON  CACHE BOOL "" FORCE)
    set(ENABLE_STATIC_LIB   ON  CACHE BOOL "" FORCE)
    set(ENABLE_SHARED_LIB   OFF CACHE BOOL "" FORCE)
    set(ENABLE_WOLFSSL      ON  CACHE BOOL "" FORCE)
    set(ENABLE_OPENSSL      OFF CACHE BOOL "" FORCE)
    set(ENABLE_GNUTLS       OFF CACHE BOOL "" FORCE)
    set(ENABLE_BORINGSSL    OFF CACHE BOOL "" FORCE)
    set(ENABLE_PICOTLS      OFF CACHE BOOL "" FORCE)
    set(BUILD_TESTING       OFF CACHE BOOL "" FORCE)

    add_subdirectory(ngtcp2 EXCLUDE_FROM_ALL)

    # ngtcp2/crypto/wolfssl/wolfssl.c includes <wolfssl/options.h>, which is
    # generated into the wolfSSL build tree (not the source tree). Patch the
    # include search path on the static crypto target.
    target_include_directories(ngtcp2_crypto_wolfssl_static PRIVATE
        ${CMAKE_BINARY_DIR}/wolfssl
        ${CMAKE_SOURCE_DIR}/wolfssl
    )

    target_compile_definitions(trojan PRIVATE ENABLE_QUIC)
    target_include_directories(trojan PRIVATE
        ${CMAKE_SOURCE_DIR}/ngtcp2/lib/includes
        ${CMAKE_SOURCE_DIR}/ngtcp2/crypto/includes
        ${CMAKE_BINARY_DIR}/ngtcp2/lib/includes
        ${CMAKE_BINARY_DIR}/ngtcp2/crypto/includes
    )

    message(STATUS "ngtcp2 (QUIC) will be built from source and linked statically against wolfSSL")
endif()

# wolfSSL OpenSSL compat headers: make #include <openssl/ssl.h> resolve to
# wolfssl/wolfssl/openssl/ssl.h (BEFORE any system OpenSSL headers)
target_include_directories(trojan BEFORE PRIVATE
    ${CMAKE_SOURCE_DIR}/wolfssl/wolfssl
    ${CMAKE_CURRENT_BINARY_DIR}/wolfssl
)

# Boost.Asio SSL layer needs this to work with wolfSSL.
# WOLFSSL_CUSTOM_CONFIG suppresses "No configuration detected" warning from settings.h.
# TFM_TIMING_RESISTANT / ECC_TIMING_RESISTANT / WC_RSA_BLINDING mirror WOLFSSL_HARDEN=yes
# so that settings.h's harden-check sees them when trojan TUs include wolfSSL headers.
# (These are defined in options.h generated by wolfSSL's CMake, but we avoid force-including
# that file because it can interfere with glibc feature-test macros on older Linux toolchains.)
target_compile_definitions(trojan PRIVATE
    BOOST_ASIO_USE_WOLFSSL
    OPENSSL_EXTRA
    OPENSSL_ALL
    HAVE_EX_DATA
    WOLFSSL_IGNORE_FILE_WARN
    WOLFSSL_CUSTOM_CONFIG     # Suppress: "No configuration for wolfSSL detected"
    TFM_TIMING_RESISTANT      # Mirror WOLFSSL_HARDEN=yes: timing-resistant big-integer ops
    ECC_TIMING_RESISTANT      # Mirror WOLFSSL_HARDEN=yes: timing-resistant ECC ops
    WC_RSA_BLINDING           # Mirror WOLFSSL_HARDEN=yes: RSA blinding
    $<$<BOOL:${ENABLE_SECURE_RENEGOTIATION}>:HAVE_SECURE_RENEGOTIATION>  # RFC 5746 (SSL Labs A, -DENABLE_SECURE_RENEGOTIATION=ON)
    $<$<BOOL:${ENABLE_SECURE_RENEGOTIATION}>:HAVE_EXTENDED_MASTER>      # RFC 7627, required with secure renegotiation
    NO_WC_SSIZE_TYPE         # Avoid ssize_t redefinition conflict with lwip
    OPENSSL_NO_SSL2          # wolfSSL does not support SSLv2
    OPENSSL_NO_SSL3          # wolfSSL does not support SSLv3
    OPENSSL_VERSION_NUMBER=0x10100000L  # Boost.Asio needs >= 1.1.0 for modern API paths
    SSL_TXT_TLSV1_2          # Needed by WOLFSSL_ASIO mode
    HAVE_ECC                 # Enable ECC compat macros (SSL_CTX_set1_curves_list)
)
target_link_libraries(trojan wolfssl)

if(ENABLE_QUIC)
    target_link_libraries(trojan ngtcp2_static ngtcp2_crypto_wolfssl_static)
endif()

# ===== Boost dependency (per-platform) =====
if (ANDROID)
    set(ANDROID_MY_LIBS ${PROJECT_SOURCE_DIR}/trojan-plus-android-libs)
    set(ANDROID_MY_LIBS_LIBRARIES
        ${ANDROID_MY_LIBS}/lib/${ANDROID_ABI}/libboost_system.a
        ${ANDROID_MY_LIBS}/lib/${ANDROID_ABI}/libboost_program_options.a)

    include_directories(${ANDROID_MY_LIBS}/include)
    target_link_libraries(trojan ${ANDROID_MY_LIBS_LIBRARIES})
elseif(IOS)
    set(IOS_MY_LIBS ${PROJECT_SOURCE_DIR}/trojan-plus-ios-libs)

    # Determine device vs simulator
    if(CMAKE_OSX_SYSROOT MATCHES "[Ii][Pp][Hh][Oo][Nn][Ee][Oo][Ss]")
        set(IOS_PLATFORM "iphoneos")
    else()
        set(IOS_PLATFORM "iphonesimulator")
    endif()

    # Determine architecture
    if(CMAKE_OSX_ARCHITECTURES MATCHES "arm64")
        set(IOS_ARCH "arm64")
    elseif(CMAKE_OSX_ARCHITECTURES MATCHES "x86_64")
        set(IOS_ARCH "x86_64")
    endif()

    message(STATUS "iOS Build Configuration:")
    message(STATUS "  CMAKE_OSX_SYSROOT: ${CMAKE_OSX_SYSROOT}")
    message(STATUS "  CMAKE_OSX_ARCHITECTURES: ${CMAKE_OSX_ARCHITECTURES}")
    message(STATUS "  IOS_PLATFORM: ${IOS_PLATFORM}")
    message(STATUS "  IOS_ARCH: ${IOS_ARCH}")

    set(IOS_MY_LIBS_LIBRARIES
        ${IOS_MY_LIBS}/lib/${IOS_PLATFORM}/${IOS_ARCH}/libboost_system.a
        ${IOS_MY_LIBS}/lib/${IOS_PLATFORM}/${IOS_ARCH}/libboost_program_options.a)

    message(STATUS "  Library paths:")
    foreach(lib ${IOS_MY_LIBS_LIBRARIES})
        message(STATUS "    ${lib}")
    endforeach()

    include_directories(${IOS_MY_LIBS}/include)
    target_link_libraries(trojan ${IOS_MY_LIBS_LIBRARIES})
else()
    if(APPLE)
        find_path(BOOST_ROOT boost/program_options.hpp
            PATHS
                /opt/homebrew/opt/boost
                /usr/local/opt/boost
            NO_DEFAULT_PATH
        )
        if(BOOST_ROOT)
            set(Boost_USE_STATIC_LIBS ON)
            set(BOOST_INCLUDEDIR ${BOOST_ROOT}/include)
            set(BOOST_LIBRARYDIR ${BOOST_ROOT}/lib)
            find_package(Boost 1.72.0 REQUIRED COMPONENTS program_options)
        else()
            set(Boost_USE_STATIC_LIBS ON)
            find_package(Boost 1.72.0 REQUIRED COMPONENTS program_options)
        endif()
        include_directories(${Boost_INCLUDE_DIR})
        target_link_libraries(trojan ${Boost_LIBRARIES})
    elseif(LINUX)
        set(Boost_USE_STATIC_LIBS ON)
        find_package(Boost 1.72.0 REQUIRED COMPONENTS program_options)
        include_directories(${Boost_INCLUDE_DIR})
        target_link_libraries(trojan ${Boost_LIBRARIES})
    else()
        # Windows and other platforms
        set(Boost_USE_STATIC_LIBS ON)
        find_package(Boost 1.72.0 REQUIRED COMPONENTS program_options)
        include_directories(${Boost_INCLUDE_DIR})
        target_link_libraries(trojan ${Boost_LIBRARIES})
        if(MSVC)
            add_definitions(-DBOOST_DATE_TIME_NO_LIB)
        endif()
    endif()

    if(UNIX AND NOT APPLE)
        target_link_libraries(trojan dl)
    endif()
endif()

option(ENABLE_SSL_KEYLOG "Build with SSL KeyLog support (DEBUG ONLY - exposes TLS master secrets)" OFF)
if(ENABLE_SSL_KEYLOG)
    add_definitions(-DENABLE_SSL_KEYLOG)
endif()

option(ENABLE_TLS13_CIPHERSUITES "Build with TLS1.3 ciphersuites support" ON)
if(ENABLE_TLS13_CIPHERSUITES)
    add_definitions(-DENABLE_TLS13_CIPHERSUITES)
endif()


option(FORCE_TCP_FASTOPEN "Force build with TCP Fast Open support" OFF)
if(FORCE_TCP_FASTOPEN)
    add_definitions(-DTCP_FASTOPEN=23 -DTCP_FASTOPEN_CONNECT=30)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL Linux AND NOT ANDROID)
    option(ENABLE_NAT "Build with NAT support" ON)
    if(ENABLE_NAT)
        add_definitions(-DENABLE_NAT)
    endif()

    option(ENABLE_REUSE_PORT "Build with SO_REUSEPORT support" ON)
    if(ENABLE_REUSE_PORT)
        add_definitions(-DENABLE_REUSE_PORT)
    endif()
endif()

if(APPLE AND NOT IOS AND NOT ANDROID)
    find_library(CoreFoundation CoreFoundation)
    find_library(Security Security)
    target_link_libraries(trojan ${CoreFoundation} ${Security})
endif()

option(ENABLE_MIMALLOC "Build with mimalloc support" ON)
if(ENABLE_MIMALLOC)
    set(MI_BUILD_SHARED OFF CACHE BOOL "" FORCE)
    set(MI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(MI_BUILD_OBJECT OFF CACHE BOOL "" FORCE)
    set(MI_BUILD_STATIC ON CACHE BOOL "Enable static library" FORCE)
    set(MI_BUILD_TESTS OFF CACHE BOOL "Disable tests" FORCE)
    set(MI_INSTALL OFF CACHE BOOL "" FORCE)
    set(MI_OVERRIDE OFF CACHE BOOL "" FORCE)
    set(MI_OSX_ZONE OFF CACHE BOOL "" FORCE)
    set(MI_OSX_INTERPOSE OFF CACHE BOOL "" FORCE)
    if(ANDROID)
        # Use local-dynamic TLS model for Android to avoid dlopen TLS symbol resolution issues
        set(MI_LOCAL_DYNAMIC_TLS ON CACHE BOOL "" FORCE)
    endif()
    add_subdirectory(mimalloc EXCLUDE_FROM_ALL)
    target_include_directories(trojan BEFORE PRIVATE mimalloc/include)
    target_link_libraries(trojan mimalloc-static)
    add_definitions(-DENABLE_MIMALLOC)
    message(STATUS "mimalloc will be built from source (API only) and linked statically")
endif()

if(WIN32)
    target_link_libraries(trojan wsock32 ws2_32 crypt32)
elseif(NOT ANDROID)
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



