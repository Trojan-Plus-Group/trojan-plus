/*
 * This file is part of the Trojan Plus project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Trojan Plus is derived from original trojan project and writing
 * for more experimental features.
 * Copyright (C) 2020 The Trojan Plus Group Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef PLATFORM_EXPORTS_H
#define PLATFORM_EXPORTS_H

#include <stddef.h>

// Platform export macro definitions
#if defined(_WIN32)
    #ifdef TROJAN_EXPORTS
        #define TROJAN_API __declspec(dllexport)
    #else
        #define TROJAN_API __declspec(dllimport)
    #endif
#elif defined(__APPLE__) || defined(__linux__)
    #define TROJAN_API __attribute__((visibility("default")))
#else
    #define TROJAN_API
#endif

// Android JNI exports
#ifdef __ANDROID__
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

// Global JNI variables
extern JNIEnv* g_android_java_env;
extern jclass g_android_java_service_class;
extern jmethodID g_android_java_protect_socket;

// Android JNI exported functions (keep original names for compatibility)
JNIEXPORT void JNICALL Java_com_trojan_1plus_android_TrojanPlusVPNService_runMain(
  JNIEnv* env, jclass service_class, jstring configPath);

JNIEXPORT void JNICALL Java_com_trojan_1plus_android_TrojanPlusVPNService_stopMain(JNIEnv*, jclass);

JNIEXPORT jstring JNICALL Java_com_trojan_1plus_android_TrojanPlusVPNService_getVersion(JNIEnv* env, jclass);

// Android socket protection helper
void android_protect_socket(int fd);

#ifdef __cplusplus
} // extern "C"
#endif

#else

// Stub for non-Android platforms
void android_protect_socket(int fd);

#endif // __ANDROID__

// Cross-platform unified C interface for iOS/macOS/Windows
#ifdef __cplusplus
extern "C" {
#endif

// Unified API for all platforms
TROJAN_API void trojan_run_main(const char* config_path);
TROJAN_API void trojan_stop_main(void);
TROJAN_API const char* trojan_get_version(void);

// See docs/native-logging.md for threading, lifetime and shutdown contract.
// Bytes exclude trailing NUL; callback must not throw or retain message pointer.
// Returns 0 on success, -1 inside callback (no change), -2 on native failure.
typedef void (*trojan_log_callback)(const char* message, size_t length, int level, void* context);
TROJAN_API int trojan_set_log_callback(trojan_log_callback callback, void* context);

#ifdef __cplusplus
}
#endif

#endif // PLATFORM_EXPORTS_H
