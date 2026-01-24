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
    echo "Please append android NDK home path with this script!";
    exit 1;
fi

clean_build=0

if [ -n "$2" ] && [ "$2" == "-r" ] ; then
    clean_build=1
fi

ANDROID_NDK_HOME=`realpath $1`

trojan_path=`realpath .`

# Set the Android API levels
ANDROID_API=31

android_architectures=(
    arm64-v8a
    x86
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

    # https://developer.android.google.cn/ndk/guides/cmake
    cmake -DENABLE_ANDROID_LOG=ON \
          -DUSE_GUARD_BACKSTACK=ON \
          -DLIB_OUTPUT_DIR=${output_path} \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
          -DANDROID_NDK=${ANDROID_NDK_HOME} \
          -DANDROID_PLATFORM=${ANDROID_API} \
          -DANDROID_SUPPORT_16KB_PAGE_SIZE=ON \
          -DANDROID_TOOLCHAIN_PREFIX=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm- \
          -DANDROID_ABI="${arch}" ..

    make -j$(nproc)
done



