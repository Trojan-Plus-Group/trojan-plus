# iOS Pre-built Libraries

This directory should contain pre-built Boost libraries for iOS.

## Directory Structure

```
trojan-plus-ios-libs/
├── include/
│   └── boost/          # Boost headers
├── lib/
│   ├── iphoneos/
│   │   └── arm64/
│   │       ├── libboost_system.a
│   │       └── libboost_program_options.a
│   └── iphonesimulator/
│       ├── arm64/      # Apple Silicon simulators
│       │   ├── libboost_system.a
│       │   └── libboost_program_options.a
│       └── x86_64/     # Intel simulators
│           ├── libboost_system.a
│           └── libboost_program_options.a
└── make_boost_ios.sh
```

## Building Dependencies

You need to build or obtain pre-built libraries for:
- Boost 1.72.0 or later (system and program_options components)

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
