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

#include "platform_exports.h"
#include "core/service.h"
#include "core/version.h"
#include "mem/memallocator.h"

#include <signal.h>

// Forward declaration of main_impl function
extern int main_impl(int argc, const char* argv[]);

// ============================================================================
// Android JNI Exports
// ============================================================================

#ifdef __ANDROID__

JNIEnv* g_android_java_env              = NULL;
jclass g_android_java_service_class     = NULL;
jmethodID g_android_java_protect_socket = NULL;

extern "C" {

JNIEXPORT void JNICALL Java_com_trojan_1plus_android_TrojanPlusVPNService_runMain(
  JNIEnv* env, jclass service_class, jstring configPath) {
    g_android_java_env           = env;
    g_android_java_service_class = service_class;
    g_android_java_protect_socket =
      g_android_java_env->GetStaticMethodID(g_android_java_service_class, "protectSocket", "(I)V");

    const char* path   = g_android_java_env->GetStringUTFChars(configPath, 0);
    const char* args[] = {"trojan", "-c", path};
    main_impl(3, args);
    g_android_java_env->ReleaseStringUTFChars(configPath, path);
    g_android_java_env            = NULL;
    g_android_java_service_class  = NULL;
    g_android_java_protect_socket = NULL;
}

JNIEXPORT void JNICALL Java_com_trojan_1plus_android_TrojanPlusVPNService_stopMain(JNIEnv*, jclass) {
    raise(SIGUSR2);
}

JNIEXPORT jstring JNICALL Java_com_trojan_1plus_android_TrojanPlusVPNService_getVersion(JNIEnv* env, jclass) {
    return env->NewStringUTF(Version::get_version().c_str());
}

void android_protect_socket(int fd) {
    if (g_android_java_env != NULL && g_android_java_service_class != NULL && g_android_java_protect_socket != NULL) {
        g_android_java_env->CallStaticVoidMethod(g_android_java_service_class, g_android_java_protect_socket, fd);
    }
}

} // extern "C"

#else

void android_protect_socket(int){}

#endif // __ANDROID__

// ============================================================================
// Cross-Platform Unified C Interface (iOS/macOS/Windows/Linux)
// ============================================================================

extern "C" {

TROJAN_API void trojan_run_main(const char* config_path) {
    const char* args[] = {"trojan", "-c", config_path};
    main_impl(3, args);
}

TROJAN_API void trojan_stop_main(void) {
#ifdef _WIN32
    raise(SIGTERM);
#else
    raise(SIGUSR2);
#endif
}

TROJAN_API const char* trojan_get_version(void) {
    static tp::string version = Version::get_version();
    return version.c_str();
}

} // extern "C"
