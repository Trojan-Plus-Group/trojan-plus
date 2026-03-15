#!/bin/sh

trojan_path=$(realpath .)
output_path="${trojan_path}/xcframework"

# Remove existing xcframework if it exists
if [ -d "${output_path}/trojan.xcframework" ]; then
    rm -rf "${output_path}/trojan.xcframework"
fi

mkdir -p "${output_path}"

# Check if all required libraries exist
required_libs=(
    "ios_lib/iphoneos/arm64/libtrojan.a"
    "ios_lib/iphonesimulator/arm64/libtrojan.a"
    "ios_lib/iphonesimulator/x86_64/libtrojan.a"
    "macos_lib/arm64/libtrojan.a"
    "macos_lib/x86_64/libtrojan.a"
)

echo "Checking for required libraries..."
for lib in "${required_libs[@]}"
do
    if [ ! -f "${trojan_path}/${lib}" ]; then
        echo "Error: ${lib} not found!"
        echo "Please run make_ios.sh and make_macos.sh first."
        exit 1
    fi
    echo "  Found: ${lib}"
done

echo ""
echo "Creating fat libraries for multi-architecture platforms..."

# Create fat library for iOS simulator (arm64 + x86_64)
lipo -create \
    "${trojan_path}/ios_lib/iphonesimulator/arm64/libtrojan.a" \
    "${trojan_path}/ios_lib/iphonesimulator/x86_64/libtrojan.a" \
    -output "${trojan_path}/ios_lib/iphonesimulator/libtrojan.a"

# Create fat library for macOS (arm64 + x86_64)
lipo -create \
    "${trojan_path}/macos_lib/arm64/libtrojan.a" \
    "${trojan_path}/macos_lib/x86_64/libtrojan.a" \
    -output "${trojan_path}/macos_lib/libtrojan.a"

echo "Creating XCFramework..."

# Create XCFramework combining iOS and macOS
xcodebuild -create-xcframework \
    -library "${trojan_path}/ios_lib/iphoneos/arm64/libtrojan.a" \
    -library "${trojan_path}/ios_lib/iphonesimulator/libtrojan.a" \
    -library "${trojan_path}/macos_lib/libtrojan.a" \
    -output "${output_path}/trojan.xcframework"

echo ""
echo "XCFramework created successfully!"
echo "Output: ${output_path}/trojan.xcframework"
