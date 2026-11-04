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

cmake_minimum_required(VERSION 3.22)

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 OLD)
endif()

cmake_policy(SET CMP0091 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0091 NEW)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
if(ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Android" OR CMAKE_TOOLCHAIN_FILE MATCHES "android.toolchain.cmake$")
    if(DEFINED ANDROID_STL AND NOT ANDROID_STL STREQUAL "c++_static")
        message(FATAL_ERROR "Android requires ANDROID_STL=c++_static")
    endif()
    set(ANDROID_STL c++_static CACHE STRING "Android static C++ runtime" FORCE)
endif()
if(BUILD_SHARED_LIBS)
    message(FATAL_ERROR "Dependencies must be static: BUILD_SHARED_LIBS must be OFF")
endif()
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static dependencies" FORCE)
set(Boost_USE_STATIC_LIBS ON)

project(trojan CXX C)
if(MSVC)
    set(Boost_USE_STATIC_RUNTIME ON)
endif()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options("$<$<COMPILE_LANGUAGE:C,CXX>:/W3>" "$<$<COMPILE_LANGUAGE:C,CXX>:/utf-8>")
endif()

## 2. Fix ngtcp2 _Generic issue without touching the original source.
# We copy ngtcp2 to the build directory, patch it there, and use that version.
set(NGTCP2_SRC_DIR "${CMAKE_SOURCE_DIR}/ngtcp2")
set(NGTCP2_PATCHED_DIR "${CMAKE_BINARY_DIR}/ngtcp2_patched")

# Always perform copy/patch to ensure consistency if the submodule changed
message(STATUS "Ensuring patched copy of ngtcp2 in ${NGTCP2_PATCHED_DIR}")
file(COPY "${NGTCP2_SRC_DIR}/" DESTINATION "${NGTCP2_PATCHED_DIR}")
include("${CMAKE_SOURCE_DIR}/src/quic/ngtcp2_recovery.cmake")
include("${CMAKE_SOURCE_DIR}/src/quic/ngtcp2_fingerprint.cmake")

if(MSVC)
    # Patch ngtcp2_macro.h in the copy: Replace _Generic with ternary for MSVC
    set(PATCH_MACRO_H "${NGTCP2_PATCHED_DIR}/lib/ngtcp2_macro.h")
    if(EXISTS "${PATCH_MACRO_H}")
        file(READ "${PATCH_MACRO_H}" CONTENT)
        set(MSVC_MACRO_FIX "
#ifdef _MSC_VER
#  define ngtcp2_max(A, B) ((A) > (B) ? (A) : (B))
#  define ngtcp2_min(A, B) ((A) < (B) ? (A) : (B))
#else
")
        string(REPLACE "#define ngtcp2_max(A, B)" "${MSVC_MACRO_FIX}#define ngtcp2_max(A, B)" CONTENT "${CONTENT}")
        set(CONTENT "${CONTENT}\n#endif\n")
        file(WRITE "${PATCH_MACRO_H}" "${CONTENT}")
    endif()

    # Patch ngtcp2_fmt.h in the copy: Remove redundant signed char associations
    set(PATCH_FMT_H "${NGTCP2_PATCHED_DIR}/lib/ngtcp2_fmt.h")
    if(EXISTS "${PATCH_FMT_H}")
        file(READ "${PATCH_FMT_H}" CONTENT)
        string(REPLACE "signed char: ngtcp2_fmt_hex_signed_char_init," "" CONTENT "${CONTENT}")
        string(REPLACE "signed char: ngtcp2_fmt_hexw_signed_char_init," "" CONTENT "${CONTENT}")
        string(REPLACE "signed char: ngtcp2_fmt_write_int64," "" CONTENT "${CONTENT}")
        file(WRITE "${PATCH_FMT_H}" "${CONTENT}")
    endif()
endif()

# C++20 is sufficient: ngtcp2 is a C library; only its examples use C++23.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "7.0.0")
    message(FATAL_ERROR "Insufficient gcc version, please install higher version (minimum_required 7.0.0 for C++17)")
  endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "5.0.0")
    message(FATAL_ERROR "Insufficient clang version, please install higher version (minimum_required 5.0.0 for C++17)")
  endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "19.14")
    message(FATAL_ERROR "Insufficient msvc version, please install higher version (minimum_required Visual Studio 2017 15.7 MSVC 19.14 for C++17)")
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
    add_compile_definitions(
        "$<$<COMPILE_LANGUAGE:C,CXX>:_CRT_SECURE_NO_WARNINGS>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:_WIN32_WINNT=0x0601>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:TROJAN_EXPORTS>"
    )
    if(CMAKE_BUILD_TYPE STREQUAL Release)
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MP")
    else()
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MP")
    endif()
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
    src/quic/outbound_transport.cpp

    src/tun/lwip_tcp_client.cpp
    src/tun/tundev.cpp
    src/tun/tunsession.cpp
    src/tun/tunproxysession.cpp
    src/tun/tunlocalsession.cpp
    src/tun/dnsserver.cpp
    src/tun/udplocalforwarder.cpp
)

# QUIC transport via ngtcp2 + BoringSSL (default ON)
option(ENABLE_QUIC "Build QUIC transport via ngtcp2 + BoringSSL" ON)
if(ENABLE_QUIC)
    list(APPEND TROJAN_SOURCE_FILES
        src/quic/quic_tls_ctx.cpp
        src/quic/quic_endpoint.cpp
        src/quic/quic_server_endpoint.cpp
        src/quic/quic_client_endpoint.cpp
        src/quic/quic_connection.cpp
        src/quic/quic_session.cpp
        src/quic/h1_upstream/quic_session_upstream.cpp
        src/quic/h1_upstream/quic_http1_upstream_conn.cpp
        src/quic/h1_upstream/quic_to_http3_connect.cpp
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

    if(NOT IOS)
        add_custom_command(TARGET trojan POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:trojan> "${LIB_OUTPUT_DIR}/libtrojan.a"
            COMMAND strip -x "${LIB_OUTPUT_DIR}/libtrojan.a"
            COMMENT "Strip debug symbols from static library")
    endif()
else()
    add_executable(trojan ${TROJAN_SOURCE_FILES})
endif()

if(NOT MSVC)
    target_compile_options(trojan PRIVATE -Wall -Wextra)
endif()

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(trojan ${CMAKE_THREAD_LIBS_INIT})

# https://github.com/microsoft/GSL supported
include_directories(${PROJECT_SOURCE_DIR}/GSL/include)

# for cland-tidy compiling database by default the file is small, generation is cheap
# as developer, I am always add this option...
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ===== BoringSSL (static libraries from the pinned submodule) =====
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
add_subdirectory(boringssl EXCLUDE_FROM_ALL)
set(BROTLI_BUILD_TOOLS OFF CACHE BOOL "Build Brotli tools" FORCE)
set(BROTLI_DISABLE_TESTS ON CACHE BOOL "Disable Brotli tests" FORCE)
add_subdirectory(brotli EXCLUDE_FROM_ALL)
target_sources(trojan PRIVATE src/ssl/chrome_profile.cpp)
target_link_libraries(trojan ssl crypto brotlidec)
target_include_directories(trojan BEFORE PRIVATE "${CMAKE_SOURCE_DIR}/boringssl/include")
target_compile_definitions(trojan PRIVATE BOOST_ASIO_NO_DEPRECATED)

# ===== ngtcp2 (QUIC) configuration =====
if(ENABLE_QUIC)
    set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
    set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
    set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
    set(ENABLE_BORINGSSL ON CACHE BOOL "" FORCE)
    set(BORINGSSL_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/boringssl/include" CACHE PATH "" FORCE)
    set(BORINGSSL_LIBRARIES ssl crypto CACHE STRING "" FORCE)
    # In-tree targets are not available to configure-time try_compile.
    set(HAVE_BORINGSSL TRUE CACHE INTERNAL "Bundled BoringSSL")
    # ngtcp2 defaults ENABLE_OPENSSL to ON, which calls find_package(OpenSSL).
    # Force it off so QUIC crypto stays on the in-tree BoringSSL provider.
    set(ENABLE_OPENSSL      OFF CACHE BOOL "" FORCE)
    set(BUILD_TESTING       OFF CACHE BOOL "" FORCE)

    # Use the patched copy in the build directory
    add_subdirectory("${NGTCP2_PATCHED_DIR}" "${CMAKE_BINARY_DIR}/ngtcp2" EXCLUDE_FROM_ALL)

    target_compile_definitions(trojan PRIVATE ENABLE_QUIC)
    target_include_directories(trojan PRIVATE
        ${NGTCP2_PATCHED_DIR}/lib/includes
        ${NGTCP2_PATCHED_DIR}/crypto/includes
        ${CMAKE_BINARY_DIR}/ngtcp2/lib/includes
        ${CMAKE_BINARY_DIR}/ngtcp2/crypto/includes
    )

    message(STATUS "ngtcp2 (QUIC) will be built from a patched copy in the build tree")

    # ===== nghttp3 (HTTP/3 decoding) =====
    set(NGHTTP3_SRC_DIR "${CMAKE_SOURCE_DIR}/nghttp3")

    set(ENABLE_LIB_ONLY     ON  CACHE BOOL "" FORCE)
    set(ENABLE_STATIC_LIB   ON  CACHE BOOL "" FORCE)
    set(ENABLE_SHARED_LIB   OFF CACHE BOOL "" FORCE)
    set(BUILD_TESTING       OFF CACHE BOOL "" FORCE)

    add_subdirectory("${NGHTTP3_SRC_DIR}" "${CMAKE_BINARY_DIR}/nghttp3" EXCLUDE_FROM_ALL)

    target_include_directories(trojan PRIVATE
        ${NGHTTP3_SRC_DIR}/lib/includes
        ${CMAKE_BINARY_DIR}/nghttp3/lib/includes
    )

    target_link_libraries(trojan nghttp3_static)

    message(STATUS "nghttp3 (HTTP/3) will be built from submodule and linked statically")
endif()

# MSVC already treats missing return values (C4716) as errors.
if(NOT MSVC)
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-Werror=return-type" HAVE_WERROR_RETURN_TYPE)
    if(HAVE_WERROR_RETURN_TYPE)
        target_compile_options(trojan PRIVATE -Werror=return-type)
    endif()
endif()
if(ENABLE_QUIC)
    target_link_libraries(trojan ngtcp2_static ngtcp2_crypto_boringssl_static)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT ANDROID)
    target_link_options(trojan PRIVATE -static-libstdc++ -static-libgcc)
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
            find_package(Boost 1.77.0 REQUIRED COMPONENTS program_options)
        else()
            set(Boost_USE_STATIC_LIBS ON)
            find_package(Boost 1.77.0 REQUIRED COMPONENTS program_options)
        endif()
        include_directories(${Boost_INCLUDE_DIR})
        target_link_libraries(trojan ${Boost_LIBRARIES})
    elseif(LINUX)
        set(Boost_USE_STATIC_LIBS ON)
        find_package(Boost 1.77.0 REQUIRED COMPONENTS program_options)
        include_directories(${Boost_INCLUDE_DIR})
        target_link_libraries(trojan ${Boost_LIBRARIES})
    else()
        # Windows and other platforms
        set(Boost_USE_STATIC_LIBS ON)
        find_package(Boost 1.77.0 REQUIRED COMPONENTS program_options)
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

# Reject shared imports even when a package ignores the static selection hint.
foreach(dependency ssl crypto brotlidec brotlicommon ngtcp2_static ngtcp2_crypto_boringssl_static nghttp3_static Boost::program_options)
    if(TARGET ${dependency})
        get_target_property(dependency_type ${dependency} TYPE)
        if(NOT dependency_type MATCHES "^(STATIC_LIBRARY|UNKNOWN_LIBRARY)$")
            message(FATAL_ERROR "${dependency} must be a static library (got ${dependency_type})")
        endif()
        foreach(config "" _RELEASE _DEBUG _RELWITHDEBINFO _MINSIZEREL)
            get_target_property(location ${dependency} IMPORTED_LOCATION${config})
            if(location AND location MATCHES "\\.(so(\\.[0-9.]+)?|dylib|dll)$")
                message(FATAL_ERROR "Shared dependency is not allowed: ${location}")
            endif()
        endforeach()
    endif()
endforeach()

option(ENABLE_SSL_KEYLOG "Build with SSL KeyLog support (DEBUG ONLY - exposes TLS master secrets)" OFF)
if(ENABLE_SSL_KEYLOG)
    add_definitions(-DENABLE_SSL_KEYLOG)
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
    get_target_property(mimalloc_type mimalloc-static TYPE)
    if(NOT mimalloc_type STREQUAL "STATIC_LIBRARY")
        message(FATAL_ERROR "mimalloc must be static")
    endif()
    target_link_libraries(trojan mimalloc-static)
    add_definitions(-DENABLE_MIMALLOC)
    message(STATUS "mimalloc will be built from source (API only) and linked statically")
endif()

# Static archives do not absorb linked libraries. Package all iOS dependencies
# into the archive consumed by make_ios.sh and its XCFramework.
if(IOS)
    set(IOS_ARCHIVES $<TARGET_FILE:ssl> $<TARGET_FILE:crypto>
        $<TARGET_FILE:brotlidec> $<TARGET_FILE:brotlicommon>)
    if(ENABLE_QUIC)
        list(APPEND IOS_ARCHIVES $<TARGET_FILE:ngtcp2_static>
            $<TARGET_FILE:ngtcp2_crypto_boringssl_static> $<TARGET_FILE:nghttp3_static>)
    endif()
    if(ENABLE_MIMALLOC)
        list(APPEND IOS_ARCHIVES $<TARGET_FILE:mimalloc-static>)
    endif()
    add_custom_command(TARGET trojan POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "${LIB_OUTPUT_DIR}"
        COMMAND /usr/bin/libtool -static -o "${LIB_OUTPUT_DIR}/libtrojan.a"
            $<TARGET_FILE:trojan> ${IOS_ARCHIVES} ${IOS_MY_LIBS_LIBRARIES}
        COMMAND strip -x "${LIB_OUTPUT_DIR}/libtrojan.a"
        COMMENT "Package iOS static archive with TLS, QUIC and Boost dependencies"
        VERBATIM)
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



