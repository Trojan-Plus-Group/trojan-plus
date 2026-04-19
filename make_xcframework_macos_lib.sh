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

# Detect OpenSSL and Boost library paths
echo ""
echo "Detecting OpenSSL and Boost library paths..."

# Try to find OpenSSL (prefer openssl@3, fallback to openssl)
OPENSSL_PREFIX=""
if command -v brew >/dev/null 2>&1; then
    OPENSSL_PREFIX=$(brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null)
fi

if [ -z "${OPENSSL_PREFIX}" ]; then
    # Fallback to common locations
    if [ -d "/opt/homebrew/opt/openssl@3" ]; then
        OPENSSL_PREFIX="/opt/homebrew/opt/openssl@3"
    elif [ -d "/usr/local/opt/openssl@3" ]; then
        OPENSSL_PREFIX="/usr/local/opt/openssl@3"
    elif [ -d "/opt/homebrew/opt/openssl" ]; then
        OPENSSL_PREFIX="/opt/homebrew/opt/openssl"
    elif [ -d "/usr/local/opt/openssl" ]; then
        OPENSSL_PREFIX="/usr/local/opt/openssl"
    fi
fi

if [ -z "${OPENSSL_PREFIX}" ]; then
    echo "Error: OpenSSL not found!"
    echo "Please install OpenSSL via Homebrew: brew install openssl@3"
    exit 1
fi

echo "  OpenSSL: ${OPENSSL_PREFIX}"

# Try to find Boost
BOOST_PREFIX=""
if command -v brew >/dev/null 2>&1; then
    BOOST_PREFIX=$(brew --prefix boost 2>/dev/null)
fi

if [ -z "${BOOST_PREFIX}" ]; then
    # Fallback to common locations
    if [ -d "/opt/homebrew/opt/boost" ]; then
        BOOST_PREFIX="/opt/homebrew/opt/boost"
    elif [ -d "/usr/local/opt/boost" ]; then
        BOOST_PREFIX="/usr/local/opt/boost"
    fi
fi

if [ -z "${BOOST_PREFIX}" ]; then
    echo "Error: Boost not found!"
    echo "Please install Boost via Homebrew: brew install boost"
    exit 1
fi

echo "  Boost: ${BOOST_PREFIX}"

# Check if static libraries exist
if [ ! -f "${OPENSSL_PREFIX}/lib/libssl.a" ] || [ ! -f "${OPENSSL_PREFIX}/lib/libcrypto.a" ]; then
    echo "Error: OpenSSL static libraries not found in ${OPENSSL_PREFIX}/lib/"
    exit 1
fi

# Check if boost_system is header-only (libboost_system.a doesn't exist in Boost 1.70+)
BOOST_HAS_SYSTEM_LIB=0
if [ -f "${BOOST_PREFIX}/lib/libboost_system.a" ]; then
    BOOST_HAS_SYSTEM_LIB=1
fi

if [ ! -f "${BOOST_PREFIX}/lib/libboost_program_options.a" ]; then
    echo "Error: Boost static library libboost_program_options.a not found in ${BOOST_PREFIX}/lib/"
    exit 1
fi

# Find mimalloc library from the build directory
MIMALLOC_LIB=""
if [ -f "${trojan_path}/macos-build-x86_64/mimalloc/Release/libmimalloc.a" ]; then
    MIMALLOC_LIB="${trojan_path}/macos-build-x86_64/mimalloc/Release/libmimalloc.a"
elif [ -f "${trojan_path}/macos-build-arm64/mimalloc/Release/libmimalloc.a" ]; then
    MIMALLOC_LIB="${trojan_path}/macos-build-arm64/mimalloc/Release/libmimalloc.a"
fi

if [ -z "${MIMALLOC_LIB}" ]; then
    echo "Error: mimalloc library not found!"
    echo "Please ensure the build completed successfully."
    exit 1
fi

echo "  mimalloc: ${MIMALLOC_LIB}"

echo ""
echo "Merging dependencies into fat libraries..."

# Function to merge libraries for a specific architecture
merge_libraries() {
    local arch=$1
    local trojan_lib="${trojan_path}/macos_lib/${arch}/libtrojan.a"
    local output_lib="${trojan_path}/macos_lib/${arch}/libtrojan-merged.a"

    echo "  Merging ${arch}..."

    # Extract architecture-specific libraries from universal binaries if needed
    local ssl_lib="${OPENSSL_PREFIX}/lib/libssl.a"
    local crypto_lib="${OPENSSL_PREFIX}/lib/libcrypto.a"
    local boost_system_lib="${BOOST_PREFIX}/lib/libboost_system.a"
    local boost_po_lib="${BOOST_PREFIX}/lib/libboost_program_options.a"

    # Check if libraries are universal binaries and extract specific architecture
    local temp_dir="${trojan_path}/macos_lib/${arch}/temp_libs"
    mkdir -p "${temp_dir}"

    # Function to extract or copy library
    extract_or_copy() {
        local src=$1
        local dst=$2
        local arch=$3

        # Check if library contains the target architecture
        if lipo -info "${src}" 2>/dev/null | grep -q "${arch}"; then
            # Check if it's a fat binary
            if lipo -info "${src}" 2>/dev/null | grep -q "Non-fat"; then
                # Single architecture, just copy
                cp "${src}" "${dst}"
            else
                # Fat binary, extract specific architecture
                lipo -thin "${arch}" "${src}" -output "${dst}"
            fi
        else
            echo "    Warning: ${src} does not contain ${arch} architecture"
            return 1
        fi
    }

    # Extract or copy each library
    extract_or_copy "${ssl_lib}" "${temp_dir}/libssl.a" "${arch}" || exit 1
    extract_or_copy "${crypto_lib}" "${temp_dir}/libcrypto.a" "${arch}" || exit 1
    if [ ${BOOST_HAS_SYSTEM_LIB} -eq 1 ]; then
        extract_or_copy "${boost_system_lib}" "${temp_dir}/libboost_system.a" "${arch}" || exit 1
    fi
    extract_or_copy "${boost_po_lib}" "${temp_dir}/libboost_program_options.a" "${arch}" || exit 1

    # Extract or copy mimalloc (may need architecture extraction if fat binary)
    extract_or_copy "${MIMALLOC_LIB}" "${temp_dir}/libmimalloc.a" "${arch}" || exit 1

    # Use libtool to merge all static libraries into one
    if [ ${BOOST_HAS_SYSTEM_LIB} -eq 1 ]; then
        libtool -static -o "${output_lib}" \
            "${trojan_lib}" \
            "${temp_dir}/libssl.a" \
            "${temp_dir}/libcrypto.a" \
            "${temp_dir}/libboost_system.a" \
            "${temp_dir}/libboost_program_options.a" \
            "${temp_dir}/libmimalloc.a"
    else
        libtool -static -o "${output_lib}" \
            "${trojan_lib}" \
            "${temp_dir}/libssl.a" \
            "${temp_dir}/libcrypto.a" \
            "${temp_dir}/libboost_program_options.a" \
            "${temp_dir}/libmimalloc.a"
    fi

    # Clean up temp directory
    rm -rf "${temp_dir}"

    echo "    Created: ${output_lib}"
}

# Merge libraries for each available architecture
for arch in "${available_archs[@]}"
do
    merge_libraries "${arch}"
done

# Create fat library if multiple architectures are available
if [ ${#available_archs[@]} -gt 1 ]; then
    echo ""
    echo "Creating fat library for macOS (${available_archs[@]})..."

    # Build lipo command with all available architectures (using merged libraries)
    lipo_args=""
    for arch in "${available_archs[@]}"
    do
        lipo_args="${lipo_args} \"${trojan_path}/macos_lib/${arch}/libtrojan-merged.a\""
    done

    eval lipo -create ${lipo_args} -output \"${trojan_path}/macos_lib/libtrojan-merged.a\"

    echo "Creating macOS XCFramework..."
    xcodebuild -create-xcframework \
        -library "${trojan_path}/macos_lib/libtrojan-merged.a" \
        -output "${output_path}/trojan-macos.xcframework"
else
    echo ""
    echo "Single architecture build (${available_archs[0]}), creating XCFramework..."

    xcodebuild -create-xcframework \
        -library "${trojan_path}/macos_lib/${available_archs[0]}/libtrojan-merged.a" \
        -output "${output_path}/trojan-macos.xcframework"
fi

echo ""
echo "macOS XCFramework created successfully!"
echo "Output: ${output_path}/trojan-macos.xcframework"
echo ""
echo "Note: The XCFramework includes all dependencies (OpenSSL, Boost, mimalloc)."
echo "Your macOS app only needs to link this single framework."
