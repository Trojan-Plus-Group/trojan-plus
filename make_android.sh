#!/bin/sh

if [ ! -n "$1" ]; then
    echo "Please append android NDK home path with this script!";
    exit 1;
fi

ANDROID_NDK_HOME=`realpath $1`

trojan_path=`realpath .`
build_path=${trojan_path}/android-build
mkdir -p ${trojan_path}

cd ${build_path}

# Set the Android API levels
ANDROID_API=24

android_architectures=(
    armeabi-v7a
    arm64-v8a
    x86
    x86_64
)

for i in "${!android_architectures[@]}"
do
    rm -rf ${build_path}/*

    arch=${android_architectures[$i]};

    output_path=${trojan_path}/android_lib/${arch}
    mkdir -p ${output_path}

    cmake -DENABLE_ANDROID_LOG=ON -DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK_HOME}/build/cmake/android.toolchain.cmake \
        -DANDROID_NDK=${ANDROID_NDK_HOME} -DCMAKE_BUILD_TYPE=Release -DANDROID_PLATFORM=${ANDROID_API} -DANDROID_ABI="${arch}" ..

    make -j4

    \cp -f trojan ${output_path}/libtrojan.so
done



