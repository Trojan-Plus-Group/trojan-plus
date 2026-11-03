#!/usr/bin/env bash
set -euo pipefail

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

if [ "$#" -eq 0 ]; then
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

# Resolve paths without requiring GNU realpath on macOS.
ANDROID_NDK_HOME=$(cd -- "$1" && pwd -P)
trojan_path=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

case "$(uname -s)" in
    Linux) host_os=linux ;;
    Darwin) host_os=darwin ;;
    *) echo "Unsupported host OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    arm64|aarch64) host_arch=arm64 ;;
    x86_64|amd64) host_arch=x86_64 ;;
    *) echo "Unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac
ndk_prebuilt="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/${host_os}-${host_arch}"
# Some NDKs ship only x86_64 host tools, including Apple Silicon installs.
if [ "$host_arch" = arm64 ] && [ ! -d "$ndk_prebuilt" ]; then
    ndk_prebuilt="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/${host_os}-x86_64"
fi
if [ ! -x "${ndk_prebuilt}/bin/llvm-readelf" ]; then
    echo "NDK host tools missing: ${ndk_prebuilt}/bin" >&2
    exit 1
fi

# Set the Android API levels
ANDROID_API=31

android_architectures=(
    arm64-v8a
    x86_64
)

for arch in "${android_architectures[@]}"; do
    output_path="${trojan_path}/android_lib/${arch}"
    build_path="${trojan_path}/android-build-${arch}"
    if [ "$clean_build" = "1" ]; then
        rm -rf -- "$build_path"
    fi
    mkdir -p -- "$build_path" "$output_path"

    # Determine build type
    if [ ${debug_build} = "1" ]; then
        build_type="Debug"
    else
        build_type="Release"
    fi

    # https://developer.android.google.cn/ndk/guides/cmake
    cmake -S "$trojan_path" -B "$build_path" \
          -DENABLE_ANDROID_LOG=ON \
          -DUSE_GUARD_BACKSTACK=ON \
          "-DLIB_OUTPUT_DIR=${output_path}" \
          "-DCMAKE_BUILD_TYPE=${build_type}" \
          -DMI_LOCAL_DYNAMIC_TLS=ON \
          "-DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake" \
          "-DANDROID_NDK=${ANDROID_NDK_HOME}" \
          "-DANDROID_PLATFORM=${ANDROID_API}" \
          -DANDROID_SUPPORT_16KB_PAGE_SIZE=ON \
          "-DANDROID_TOOLCHAIN_PREFIX=${ndk_prebuilt}/bin/llvm-" \
          "-DANDROID_ABI=${arch}"

    cmake --build "$build_path" --parallel "$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 2)"

    # Debug build: copy unstripped library to android_lib debug folder
    if [ ${debug_build} = "1" ]; then
        debug_output_path="${trojan_path}/android_lib/${arch}_debug"
        mkdir -p -- "$debug_output_path"
        cp -f -- "${output_path}/libtrojan.so" "${debug_output_path}/"
        echo "Debug library copied to ${debug_output_path}/libtrojan.so"
    fi
done



