#!/bin/sh

if [ ! -n "$1" ]; then
    echo "Usage: $0 <xcode_path> [-r]";
    echo "Example: $0 /Applications/Xcode.app -r";
    exit 1;
fi

clean_build=0
if [ -n "$2" ] && [ "$2" == "-r" ]; then
    clean_build=1
fi

XCODE_PATH="$1"
DEVELOPER_DIR="${XCODE_PATH}/Contents/Developer"
export DEVELOPER_DIR

trojan_path=$(realpath .)

# Calculate optimal thread count (total cores - 1, minimum 1)
TOTAL_CORES=$(sysctl -n hw.ncpu)
BUILD_THREADS=$((TOTAL_CORES - 1))
if [ ${BUILD_THREADS} -lt 1 ]; then
    BUILD_THREADS=1
fi
echo "Detected ${TOTAL_CORES} CPU cores, using ${BUILD_THREADS} threads for compilation"

# iOS deployment target
IOS_DEPLOYMENT_TARGET=12.0

# Architectures to build
# Device architectures
device_architectures=(
    arm64
)

# Simulator architectures
simulator_architectures=(
    arm64
    x86_64
)

# Build for device
for arch in "${device_architectures[@]}"
do
    output_path="${trojan_path}/ios_lib/iphoneos/${arch}"
    build_path="${trojan_path}/ios-build-device-${arch}"
    mkdir -p "${build_path}"
    mkdir -p "${output_path}"

    if [ ${clean_build} = "1" ]; then
        rm -rf "${build_path}"/*
    fi

    cd "${build_path}"

    cmake -G Xcode \
          -DCMAKE_SYSTEM_NAME=iOS \
          -DCMAKE_OSX_DEPLOYMENT_TARGET=${IOS_DEPLOYMENT_TARGET} \
          -DCMAKE_OSX_ARCHITECTURES="${arch}" \
          -DCMAKE_OSX_SYSROOT=iphoneos \
          -DCMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH=NO \
          -DCMAKE_IOS_INSTALL_COMBINED=NO \
          -DENABLE_IOS_LOG=ON \
          -DLIB_OUTPUT_DIR="${output_path}" \
          -DCMAKE_BUILD_TYPE=Release \
          -DIOS=ON \
          ..

    cmake --build . --config Release -- -jobs ${BUILD_THREADS}
done

# Build for simulator
for arch in "${simulator_architectures[@]}"
do
    output_path="${trojan_path}/ios_lib/iphonesimulator/${arch}"
    build_path="${trojan_path}/ios-build-simulator-${arch}"
    mkdir -p "${build_path}"
    mkdir -p "${output_path}"

    if [ ${clean_build} = "1" ]; then
        rm -rf "${build_path}"/*
    fi

    cd "${build_path}"

    cmake -G Xcode \
          -DCMAKE_SYSTEM_NAME=iOS \
          -DCMAKE_OSX_DEPLOYMENT_TARGET=${IOS_DEPLOYMENT_TARGET} \
          -DCMAKE_OSX_ARCHITECTURES="${arch}" \
          -DCMAKE_OSX_SYSROOT=iphonesimulator \
          -DCMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH=NO \
          -DCMAKE_IOS_INSTALL_COMBINED=NO \
          -DENABLE_IOS_LOG=ON \
          -DLIB_OUTPUT_DIR="${output_path}" \
          -DCMAKE_BUILD_TYPE=Release \
          -DIOS=ON \
          ..

    cmake --build . --config Release -- -jobs ${BUILD_THREADS}
done

echo "iOS build complete!"
echo "Device libraries: ${trojan_path}/ios_lib/iphoneos/"
echo "Simulator libraries: ${trojan_path}/ios_lib/iphonesimulator/"

echo ""
echo "Creating fat library for iOS simulator..."
lipo -create \
    "${trojan_path}/ios_lib/iphonesimulator/arm64/libtrojan.a" \
    "${trojan_path}/ios_lib/iphonesimulator/x86_64/libtrojan.a" \
    -output "${trojan_path}/ios_lib/iphonesimulator/libtrojan.a"

echo "Creating iOS XCFramework..."
if [ -d "${trojan_path}/ios_lib/trojan.xcframework" ]; then
    rm -rf "${trojan_path}/ios_lib/trojan.xcframework"
fi

xcodebuild -create-xcframework \
    -library "${trojan_path}/ios_lib/iphoneos/arm64/libtrojan.a" \
    -library "${trojan_path}/ios_lib/iphonesimulator/libtrojan.a" \
    -output "${trojan_path}/ios_lib/trojan.xcframework"

echo ""
echo "iOS XCFramework created successfully!"
echo "Output: ${trojan_path}/ios_lib/trojan.xcframework"
