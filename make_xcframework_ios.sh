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
echo "Merging dependencies into fat libraries..."

# iOS libraries path
ios_libs_path="${trojan_path}/trojan-plus-ios-libs/lib"

# Function to merge libraries for a specific platform and architecture
merge_libraries() {
    local platform=$1
    local arch=$2
    local trojan_lib="${trojan_path}/ios_lib/${platform}/${arch}/libtrojan.a"
    local output_lib="${trojan_path}/ios_lib/${platform}/${arch}/libtrojan-merged.a"

    echo "  Merging ${platform}/${arch}..."

    # Check if Boost libraries exist
    local boost_system_lib="${ios_libs_path}/${platform}/${arch}/libboost_system.a"
    local boost_po_lib="${ios_libs_path}/${platform}/${arch}/libboost_program_options.a"

    # Use libtool to merge all static libraries into one
    libtool -static -o "${output_lib}" \
        "${trojan_lib}" \
        "${boost_system_lib}" \
        "${boost_po_lib}"

    echo "    Created: ${output_lib}"
}

# Merge libraries for each architecture
merge_libraries "iphoneos" "arm64"
merge_libraries "iphonesimulator" "arm64"
merge_libraries "iphonesimulator" "x86_64"

echo ""
echo "Creating fat library for iOS simulator (arm64 + x86_64)..."

# Create fat library for iOS simulator (arm64 + x86_64)
lipo -create \
    "${trojan_path}/ios_lib/iphonesimulator/arm64/libtrojan-merged.a" \
    "${trojan_path}/ios_lib/iphonesimulator/x86_64/libtrojan-merged.a" \
    -output "${trojan_path}/ios_lib/iphonesimulator/libtrojan-merged.a"

echo "Creating iOS XCFramework..."

# Create XCFramework for iOS only (using merged libraries)
xcodebuild -create-xcframework \
    -library "${trojan_path}/ios_lib/iphoneos/arm64/libtrojan-merged.a" \
    -library "${trojan_path}/ios_lib/iphonesimulator/libtrojan-merged.a" \
    -output "${output_path}/trojan-ios.xcframework"

echo ""
echo "iOS XCFramework created successfully!"
echo "Output: ${output_path}/trojan-ios.xcframework"
