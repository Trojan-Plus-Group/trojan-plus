# iOS Pre-built Libraries

This directory should contain pre-built Boost and OpenSSL libraries for iOS.

## Directory Structure

```
trojan-plus-ios-libs/
├── include/
│   ├── boost/          # Boost headers
│   └── openssl/        # OpenSSL headers
├── lib/
│   ├── iphoneos/
│   │   └── arm64/
│   │       ├── libssl.a
│   │       ├── libcrypto.a
│   │       ├── libboost_system.a
│   │       └── libboost_program_options.a
│   └── iphonesimulator/
│       ├── arm64/      # Apple Silicon simulators
│       │   ├── libssl.a
│       │   ├── libcrypto.a
│       │   ├── libboost_system.a
│       │   └── libboost_program_options.a
│       └── x86_64/     # Intel simulators
│           ├── libssl.a
│           ├── libcrypto.a
│           ├── libboost_system.a
│           └── libboost_program_options.a
├── make_openssl_ios.sh
└── make_boost_ios.sh
```

## Building Dependencies

You need to build or obtain pre-built libraries for:
- OpenSSL 1.1.1 or later
- Boost 1.72.0 or later (system and program_options components)

### Building OpenSSL for iOS

You can use scripts like:
- https://github.com/x2on/OpenSSL-for-iPhone
- https://github.com/leenjewel/openssl_for_ios_and_android

### Building Boost for iOS

You can use scripts like:
- https://github.com/faithfracture/Apple-Boost-BuildScript
- https://github.com/danoli3/ofxiOSBoost

## Requirements

- iOS deployment target: 12.0+
- Architectures:
  - Device: arm64
  - Simulator: arm64 (Apple Silicon), x86_64 (Intel)
- Static libraries (.a files)

## Notes

This follows the same pattern as `trojan-plus-android-libs` for consistency.
