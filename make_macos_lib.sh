#!/bin/sh

# If no Xcode path provided, use default
if [ ! -n "$1" ]; then
    XCODE_PATH="/Applications/Xcode.app"
    clean_build=1
    echo "No Xcode path provided, using default: ${XCODE_PATH} with clean build (-r)"
else
    XCODE_PATH="$1"
    clean_build=0
    if [ -n "$2" ] && [ "$2" == "-r" ]; then
        clean_build=1
    fi
fi
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

# macOS deployment target
MACOS_DEPLOYMENT_TARGET=10.15

# Detect current architecture
CURRENT_ARCH=$(uname -m)
echo "Detected architecture: ${CURRENT_ARCH}"

# Architectures to build (current architecture only)
macos_architectures=(
    ${CURRENT_ARCH}
)

echo "Building for architecture: ${macos_architectures[@]}"
echo ""
echo "Note: To build for both arm64 and x86_64, run this script on both types of Macs."
echo ""

# Build for macOS
for arch in "${macos_architectures[@]}"
do
    output_path="${trojan_path}/macos_lib/${arch}"
    build_path="${trojan_path}/macos-build-${arch}"
    mkdir -p "${build_path}"
    mkdir -p "${output_path}"

    if [ ${clean_build} = "1" ]; then
        rm -rf "${build_path}"/*
    fi

    cd "${build_path}"

    cmake -G Xcode \
          -DCMAKE_SYSTEM_NAME=Darwin \
          -DCMAKE_OSX_DEPLOYMENT_TARGET=${MACOS_DEPLOYMENT_TARGET} \
          -DCMAKE_OSX_ARCHITECTURES="${arch}" \
          -DCMAKE_XCODE_ATTRIBUTE_ONLY_ACTIVE_ARCH=NO \
          -DLIB_OUTPUT_DIR="${output_path}" \
          -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_LIBRARY=ON \
          ..

    cmake --build . --config Release -- -jobs ${BUILD_THREADS}
done

echo "macOS build complete!"
echo "macOS libraries: ${trojan_path}/macos_lib/"

echo ""
# Check how many architectures were built
arch_count=${#macos_architectures[@]}

if [ ${arch_count} -gt 1 ]; then
    echo "Creating fat library for macOS (${arch_count} architectures)..."

    # Build lipo command with all architectures
    lipo_args=""
    for arch in "${macos_architectures[@]}"
    do
        lipo_args="${lipo_args} \"${trojan_path}/macos_lib/${arch}/libtrojan.a\""
    done

    eval lipo -create ${lipo_args} -output \"${trojan_path}/macos_lib/libtrojan.a\"

    echo "Creating macOS XCFramework..."
    if [ -d "${trojan_path}/macos_lib/trojan.xcframework" ]; then
        rm -rf "${trojan_path}/macos_lib/trojan.xcframework"
    fi

    xcodebuild -create-xcframework \
        -library "${trojan_path}/macos_lib/libtrojan.a" \
        -output "${trojan_path}/macos_lib/trojan.xcframework"
else
    echo "Single architecture build (${macos_architectures[0]}), skipping fat library creation..."

    echo "Creating macOS XCFramework..."
    if [ -d "${trojan_path}/macos_lib/trojan.xcframework" ]; then
        rm -rf "${trojan_path}/macos_lib/trojan.xcframework"
    fi

    xcodebuild -create-xcframework \
        -library "${trojan_path}/macos_lib/${macos_architectures[0]}/libtrojan.a" \
        -output "${trojan_path}/macos_lib/trojan.xcframework"
fi

echo ""
echo "macOS XCFramework created successfully!"
echo "Output: ${trojan_path}/macos_lib/trojan.xcframework"
