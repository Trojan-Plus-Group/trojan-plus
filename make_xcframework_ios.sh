#!/bin/sh

trojan_path=$(realpath .)
output_path="${trojan_path}/xcframework"

# Remove existing xcframework if it exists
if [ -d "${output_path}/trojan-ios.xcframework" ]; then
    rm -rf "${output_path}/trojan-ios.xcframework"
fi

mkdir -p "${output_path}"

# Check if all required iOS libraries exist
required_libs=(
    "ios_lib/iphoneos/arm64/libtrojan.a"
    "ios_lib/iphonesimulator/arm64/libtrojan.a"
    "ios_lib/iphonesimulator/x86_64/libtrojan.a"
)

echo "Checking for required iOS libraries..."
for lib in "${required_libs[@]}"
do
    if [ ! -f "${trojan_path}/${lib}" ]; then
        echo "Error: ${lib} not found!"
        echo "Please run make_ios.sh first."
        exit 1
    fi
    echo "  Found: ${lib}"
done

echo ""
echo "Creating fat library for iOS simulator (arm64 + x86_64)..."

# Create fat library for iOS simulator (arm64 + x86_64)
lipo -create \
    "${trojan_path}/ios_lib/iphonesimulator/arm64/libtrojan.a" \
    "${trojan_path}/ios_lib/iphonesimulator/x86_64/libtrojan.a" \
    -output "${trojan_path}/ios_lib/iphonesimulator/libtrojan.a"

echo "Creating iOS XCFramework..."

# Create XCFramework for iOS only
xcodebuild -create-xcframework \
    -library "${trojan_path}/ios_lib/iphoneos/arm64/libtrojan.a" \
    -library "${trojan_path}/ios_lib/iphonesimulator/libtrojan.a" \
    -output "${output_path}/trojan-ios.xcframework"

echo ""
echo "iOS XCFramework created successfully!"
echo "Output: ${output_path}/trojan-ios.xcframework"
