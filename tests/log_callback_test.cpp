// Compile with production core/log.cpp and mem/memallocator.cpp; see test_log_callback.py.
#ifdef NDEBUG
#undef NDEBUG // Assertions drive this standalone regression executable.
#endif
#include "core/log.h"
#include "platform_exports.h"
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

#ifdef TEST_ANDROID_LOG
#include <android/log.h>
#include <cstdarg>
#include <cstring>
std::atomic<int> platform_calls{0};
thread_local std::string platform_message;
extern "C" int __android_log_print(int priority, const char* tag, const char* format, ...) {
    assert(priority == ANDROID_LOG_DEBUG);
    assert(std::strcmp(tag, "trojan") == 0 && std::strcmp(format, "%s\n") == 0);
    va_list arguments;
    va_start(arguments, format);
    platform_message = va_arg(arguments, const char*);
    va_end(arguments);
    ++platform_calls;
    return 1;
}
#endif

namespace {
constexpr char bytes[] = "native-log UTF-8: \xe4\xb8\xad\xf0\x9f\x99\x82\0tail";
const tp::string text(bytes, sizeof(bytes) - 1);
std::atomic<int> calls{0};
void receive(const char* data, size_t length, int level, void* context) {
    assert(context == &calls);
    assert(length == text.size() && tp::string(data, length) == text);
    assert(level == Log::INFO);
#ifdef TEST_ANDROID_LOG
    assert(platform_calls > calls);
    assert(platform_message == std::string(bytes)); // Platform preserves existing NUL-terminated output.
#endif
    ++calls;
    assert(trojan_set_log_callback(nullptr, nullptr) == -1);
    Log::log("recursive logcat only", Log::INFO);
}
std::mutex gate;
std::condition_variable changed;
bool entered = false, release_callback = false;
void blocked(const char*, size_t, int, void*) {
    std::unique_lock<std::mutex> lock(gate);
    entered = true;
    changed.notify_all();
    changed.wait(lock, [] { return release_callback; });
}
void throwing(const char*, size_t, int, void*) { throw std::runtime_error("contained"); }
}
int main() {
    Log::level = Log::INFO;
    assert(trojan_set_log_callback(receive, &calls) == 0);
    Log::log(text, Log::ALL);
    assert(calls == 0);
    Log::log(text, Log::INFO);
    assert(calls == 1);
    Log::reset();
    Log::log(text, Log::INFO); // reset does not silently release managed ownership
    assert(calls == 2);
    assert(trojan_set_log_callback(blocked, nullptr) == 0);
    std::thread logger([] { Log::log("blocking", Log::INFO); });
    {
        std::unique_lock<std::mutex> lock(gate);
        changed.wait(lock, [] { return entered; });
    }
    std::atomic<bool> unregister_started{false}, unregistered{false};
    std::thread unregister([&] {
        unregister_started = true;
        assert(trojan_set_log_callback(nullptr, nullptr) == 0);
        unregistered = true;
    });
    while (!unregister_started) { std::this_thread::yield(); }
    assert(!unregistered);
    {
        std::lock_guard<std::mutex> lock(gate);
        release_callback = true;
    }
    changed.notify_all();
    logger.join();
    unregister.join();
    assert(unregistered);
    Log::log("absent", Log::INFO);
    auto* owned = new int(0);
    assert(trojan_set_log_callback([](const char*, size_t, int, void* context) {
        ++*static_cast<int*>(context);
    }, owned) == 0);
    Log::log("owned", Log::INFO);
    assert(*owned == 1);
    assert(trojan_set_log_callback(throwing, nullptr) == 0);
    delete owned; // Replacement must release every reference to previous context.
    Log::log("replacement", Log::INFO);
    Log::log("exception", Log::INFO);
    assert(trojan_set_log_callback(receive, &calls) == 0);
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([] {
            for (int j = 0; j < 200; ++j) {
                assert(trojan_set_log_callback(receive, &calls) == 0);
                Log::log(text, Log::INFO);
                assert(trojan_set_log_callback(nullptr, nullptr) == 0);
            }
        });
    }
    for (auto& thread : threads) { thread.join(); }
    assert(trojan_set_log_callback(nullptr, nullptr) == 0);
    const int before = calls;
    Log::log(text, Log::INFO);
    assert(calls == before);
    threads.clear();
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([] {
            for (int j = 0; j < 100; ++j) {
                Log::log_with_date_time("thread timestamp UTF-8: \xe4\xb8\xad", Log::INFO);
            }
        });
    }
    for (auto& thread : threads) { thread.join(); }
    Log::reset();
}
