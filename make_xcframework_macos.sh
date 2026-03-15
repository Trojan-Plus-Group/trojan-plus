#!/bin/sh

trojan_path=$(realpath .)
output_path="${trojan_path}/xcframework"

# Remove existing xcframework if it exists
if [ -d "${output_path}/trojan-macos.xcframework" ]; then
    rm -rf "${output_path}/trojan-macos.xcframework"
fi

mkdir -p "${output_path}"

# Check which macOS architectures are available
available_archs=()
if [ -f "${trojan_path}/macos_lib/arm64/libtrojan.a" ]; then
    available_archs+=("arm64")
fi
if [ -f "${trojan_path}/macos_lib/x86_64/libtrojan.a" ]; then
    available_archs+=("x86_64")
fi

if [ ${#available_archs[@]} -eq 0 ]; then
    echo "Error: No macOS libraries found!"
    echo "Please run make_macos.sh first."
    exit 1
fi

echo "Found macOS architectures: ${available_archs[@]}"

# Create fat library if multiple architectures are available
if [ ${#available_archs[@]} -gt 1 ]; then
    echo ""
    echo "Creating fat library for macOS (${available_archs[@]})..."

    # Build lipo command with all available architectures
    lipo_args=""
    for arch in "${available_archs[@]}"
    do
        lipo_args="${lipo_args} \"${trojan_path}/macos_lib/${arch}/libtrojan.a\""
    done

    eval lipo -create ${lipo_args} -output \"${trojan_path}/macos_lib/libtrojan.a\"

    echo "Creating macOS XCFramework..."
    xcodebuild -create-xcframework \
        -library "${trojan_path}/macos_lib/libtrojan.a" \
        -output "${output_path}/trojan-macos.xcframework"
else
    echo ""
    echo "Single architecture build (${available_archs[0]}), creating XCFramework..."

    xcodebuild -create-xcframework \
        -library "${trojan_path}/macos_lib/${available_archs[0]}/libtrojan.a" \
        -output "${output_path}/trojan-macos.xcframework"
fi

echo ""
echo "macOS XCFramework created successfully!"
echo "Output: ${output_path}/trojan-macos.xcframework"
