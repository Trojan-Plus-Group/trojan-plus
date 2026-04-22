#!/bin/sh

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

if [ ! -n "$1" ]; then
    echo "Usage: $0 <ndk_path> [-r] [-d]"
    echo "  -r  : clean rebuild"
    echo "  -d  : debug build (with symbols, no strip)"
    exit 1;
fi

clean_build=0
debug_build=0

for arg in "$@"; do
    if [ "$arg" == "-r" ]; then
        clean_build=1
    elif [ "$arg" == "-d" ]; then
        debug_build=1
    fi
done

# Re-parse NDK path (first positional argument)
ANDROID_NDK_HOME=`realpath $1`

trojan_path=`realpath .`

# Set the Android API levels
ANDROID_API=31

android_architectures=(
    arm64-v8a
    x86_64
)

for i in "${!android_architectures[@]}"
do
    arch=${android_architectures[$i]}
    output_path=${trojan_path}/android_lib/${arch}
    build_path=${trojan_path}/android-build-${arch}
    mkdir -p ${build_path}
    mkdir -p ${output_path}

    if [ ${clean_build} = "1" ]; then
        rm -rf ${build_path}/*
    fi

    cd ${build_path}

    # Determine build type
    if [ ${debug_build} = "1" ]; then
        build_type="Debug"
    else
        build_type="Release"
    fi

    # https://developer.android.google.cn/ndk/guides/cmake
    cmake -DENABLE_ANDROID_LOG=ON \
          -DUSE_GUARD_BACKSTACK=ON \
          -DLIB_OUTPUT_DIR=${output_path} \
          -DCMAKE_BUILD_TYPE=${build_type} \
          -DMI_LOCAL_DYNAMIC_TLS=ON \
          -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
          -DANDROID_NDK=${ANDROID_NDK_HOME} \
          -DANDROID_PLATFORM=${ANDROID_API} \
          -DANDROID_SUPPORT_16KB_PAGE_SIZE=ON \
          -DANDROID_TOOLCHAIN_PREFIX=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm- \
          -DANDROID_ABI="${arch}" ..

    make -j$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 2)

    # Debug build: copy unstripped library to android_lib debug folder
    if [ ${debug_build} = "1" ]; then
        debug_output_path=${trojan_path}/android_lib/${arch}_debug
        mkdir -p ${debug_output_path}
        cp -f ${output_path}/libtrojan.so ${debug_output_path}/
        echo "Debug library copied to ${debug_output_path}/libtrojan.so"
    fi
done



