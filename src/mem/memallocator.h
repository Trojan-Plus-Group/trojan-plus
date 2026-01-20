#pragma once
#include <atomic>
#include <algorithm>
#include <chrono>
#include <map>
#include <mutex>
#include <unordered_map>
#include <string>
#include <sstream>
#include <memory>
#include <cstdlib>
#include <new>
#include <vector>

namespace tp{

class mem_allocator {
    
    bool trace_file_line_{true};
    bool mem_stat_{true};
    bool mimalloc_{false};

    std::atomic<uint64_t> total_object_counter_{0};
    std::atomic<uint64_t> total_memory_{0};

    void *malloc_impl(size_t size);
    void *malloc_aligned_impl(size_t size, size_t align);
    void *realloc_impl(void *ptr, size_t new_size);
    void free_impl(void *ptr);
    void free_aligned_impl(void *ptr);

    void record_malloc(void *ptr, size_t size, size_t offset, const char *file, int line);
    void *record_free(void *ptr);

    struct memory_recorder_header {
        inline static constexpr uint32_t dont_trace_file_line = 0xD197653D;

        uint32_t size;
        uint32_t stat_index;
        uint32_t start_offset;
    };

    static const size_t memory_recorder_header_size = sizeof(memory_recorder_header);
    static size_t cantor_paring_normalize(const int x) {
        return x >= 0 ? (static_cast<size_t>(x) << 1) : ~(static_cast<size_t>(x) << 1);
    }

    static size_t cantor_paring(const size_t a, const size_t b) { return (((a + b) * (a + b + 1)) >> 1) + b; }

    static size_t cantor_paring(const int x, const int y) {
        const auto a = cantor_paring_normalize(x);
        const auto b = cantor_paring_normalize(y);
        return cantor_paring(a, b);
    }

    static size_t cantor_paring(const int x, const int y, const int z) {
        const auto a = cantor_paring_normalize(x);
        const auto b = cantor_paring_normalize(y);
        const auto c = cantor_paring_normalize(z);
        return cantor_paring(cantor_paring(a, b), c);
    }

    static size_t cantor_paring(const int x, const int y, const int z, const int w) {
        const auto a = cantor_paring_normalize(x);
        const auto b = cantor_paring_normalize(y);
        const auto c = cantor_paring_normalize(z);
        const auto d = cantor_paring_normalize(w);
        return cantor_paring(cantor_paring(a, b), cantor_paring(c, d));
    }

    class cantor_paring_feeder {
        size_t hash_{0};

    public:
        void feed(const uint64_t v) { hash_ = cantor_paring(hash_, std::hash<uint64_t>{}(v)); }

        void feed(const int v) {
            const auto a = cantor_paring_normalize(v);
            hash_ = cantor_paring(hash_, a);
        }

        void reset() { hash_ = 0; }

        size_t digest() { return hash_; }
    };

    struct code_location {
        const char *file;
        int line;
    };

    struct alloc_stat {
        uint64_t size;
        uint32_t count;
    };

    struct pair_hash {
        size_t operator()(const code_location &p) const {
            cantor_paring_feeder f;

            f.feed((uint64_t)p.file);
            f.feed(p.line);

            return f.digest();
        }
    };

    struct pair_equal {
        bool operator()(const code_location &lhs, const code_location &rhs) const {
            return lhs.file == rhs.file && lhs.line == rhs.line;
        }
    };

    struct memory_tag_stat {
        std::mutex alloc_stat_lock;
        std::vector<alloc_stat> alloc_stat_list;
        std::unordered_map<code_location, int, pair_hash, pair_equal> code_pos_to_stat_index;
    };

    memory_tag_stat tag_stat_;

    uint32_t record_mcontainer_alloc(size_t size, const char *file, int line);
    void record_mcontainer_free(size_t size, uint32_t stat_index);

    inline static const uint64_t MB = 1024 * 1024;
    inline static const uint64_t KB = 1024;

    inline static const char *MB_Unit = "MB";
    inline static const char *KB_Unit = "KB";
    inline static const char *Byte_Unit = "B";

public:

    mem_allocator(bool mem_stat = true, bool trace_file_line = true, bool mimalloc = false);

    void *malloc(size_t size, const char *file = nullptr, int line = 0);
    void *malloc_aligned(size_t size, size_t align, const char *file = nullptr, int line = 0);
    void *realloc(void *ptr, size_t new_size, const char *file = nullptr, int line = 0);
    void free(void *ptr);
    void free_aligned(void *ptr);

    std::string show_stat(int top_count = 20);

    uint64_t get_total_memory() { return total_memory_.load(std::memory_order_relaxed); }
    uint64_t get_total_object_counter() { return total_object_counter_.load(std::memory_order_relaxed); }
    bool is_trace_file_line() const { return trace_file_line_; }

    void set_trace_file_line_enable(bool enable) {
        std::lock_guard<std::mutex> lock(tag_stat_.alloc_stat_lock);
        if (trace_file_line_ != enable) {
            tag_stat_.alloc_stat_list.clear();
            tag_stat_.code_pos_to_stat_index.clear();
            trace_file_line_ = enable;
        }
    }

    bool is_enable_mem_stat() const { return mem_stat_; }
    bool is_use_mimalloc() const { return mimalloc_; }

public:
    static std::string get_size_string(uint64_t size) {
        if (size > MB) {
            float s = ((float)size) / MB;
            char b[32];
            snprintf(b, sizeof(b), "%.2f%s", s, MB_Unit);
            return b;
        }

        if (size > KB) {
            float s = ((float)size) / KB;
            char b[32];
            snprintf(b, sizeof(b), "%.2f%s", s, KB_Unit);
            return b;
        } else {
            return std::to_string(size) + Byte_Unit;
        }
    }

    template <typename T>
    static inline constexpr int kExtraSpaceForArray = (int)std::max(alignof(std::remove_extent_t<T>), sizeof(size_t));

    template <typename T>
    void delete_object(T *ptr) {
        if (!ptr)
            return;

        if (!std::is_trivially_destructible_v<T>) {
            ptr->~T();
        }

        free_aligned((void *)ptr);
    }

    template <typename T>
    void delete_array_object(T *ptr) {
        if (!ptr)
            return;

        void *raw_memory = (uint8_t *)ptr - kExtraSpaceForArray<T>;
        if constexpr (!std::is_trivially_destructible_v<T>) {
            int size = *(int *)raw_memory;
            for (int i = 0; i < size; ++i)
                ptr[i].~T();
        }

        free_aligned(raw_memory);
    }

    template <typename T>
    std::remove_extent_t<T> *new_array_object(size_t num, const char *file, int line) {
        using Element = std::remove_extent_t<T>;
        void *raw_memory = malloc_aligned(sizeof(Element) * num + kExtraSpaceForArray<T>,
                                          std::max(alignof(Element), alignof(size_t)),
                                          file,
                                          line);
        *(size_t *)raw_memory = num;
        Element *ptr = (Element *)((uint8_t *)raw_memory + kExtraSpaceForArray<T>);
        if constexpr (!std::is_trivially_default_constructible_v<Element>)
            for (size_t i = 0; i < num; ++i)
                ::new ((void *)(ptr + i)) Element();
        return ptr;
    }

    template <typename T, typename V, typename H, typename E, typename A>
    static inline size_t get_unordered_map_size(const std::unordered_map<T, V, H, E, A> &m) {
#if defined(_WIN32)
        size_t size = sizeof(std::list<V>::iterator) * 2 * m.bucket_count();
        size += (sizeof(V) + 2 * sizeof(void *)) * m.size();
        return size;
#else
        const size_t n = m.bucket_count();
        const size_t elements = m.size();
        const size_t buckets_memory = n * sizeof(void *);

        const size_t elements_memory = elements * sizeof(std::pair<const T, V>);
        return buckets_memory + elements_memory;
#endif
    }

    template <typename T, typename A>
    static inline size_t get_vector_size(const std::vector<T, A> &v) {
        return sizeof(v) + v.capacity() * sizeof(T);
    }

};


mem_allocator &get_tj_mem_allocator();

template <typename T>
struct tj_deleter
{
    void operator()(std::remove_extent_t<T>* ptr) const
    {
        if constexpr (std::is_array_v<T>)
            get_tj_mem_allocator().delete_array_object(ptr);
        else
            get_tj_mem_allocator().delete_object(ptr);
    }
};

template <typename T>
using tj_unique_ptr = std::unique_ptr<T, tj_deleter<T>>;

template <typename T, typename... Args>
inline std::enable_if_t<!std::is_array_v<T>, tj_unique_ptr<T>> make_tj_unique(const char* file, int line, Args&&... args)
{
    auto *ptr =
        ::new (get_tj_mem_allocator().malloc_aligned(sizeof(T), alignof(T), file, line)) T(std::forward<Args>(args)...);
    return tj_unique_ptr<T>(ptr);
}

template <typename T>
inline std::enable_if_t<std::is_array_v<T>, tj_unique_ptr<T>> make_tj_unique(const char* file, int line, size_t num)
{
    return tj_unique_ptr<T>(get_tj_mem_allocator().new_array_object<T>(num, file, line));
}
}


#define TP_NEW_ARR(T, num) tp::get_tj_mem_allocator().new_array_object<T>(num, __FILE__, __LINE__)
#define TP_DELETE_ARR(ptr) \
    do { \
        tp::get_tj_mem_allocator().delete_array_object(ptr); \
    } while (false)

#define TP_NEW(T, ...) \
    ::new (tp::get_tj_mem_allocator().malloc_aligned(sizeof(T), alignof(T), __FILE__, __LINE__)) T(__VA_ARGS__)
#define TP_DELETE(ptr) \
    do { \
        tp::get_tj_mem_allocator().delete_object(ptr); \
    } while (false)

#define TP_MALLOC(size) tp::get_tj_mem_allocator().malloc(size, __FILE__, __LINE__)
#define TP_MALLOC_ALIGNED(size, align) tp::get_tj_mem_allocator().malloc_aligned(size, align, __FILE__, __LINE__)
#define TP_FREE(ptr) tp::get_tj_mem_allocator().free(ptr)
#define TP_FREE_ALIGNED(ptr) tp::get_tj_mem_allocator().free_aligned(ptr)

#define TP_MAKE_UNIQUE(T, ...) tp::make_tj_unique<T>(__FILE__, __LINE__, ##__VA_ARGS__)
#define TP_MAKE_SHARED(T, ...) \
    std::shared_ptr<T>( \
        ::new (tp::get_tj_mem_allocator().malloc_aligned(sizeof(T), alignof(T), __FILE__, __LINE__)) T(__VA_ARGS__), \
        [](T *ptr) { tp::get_tj_mem_allocator().delete_object(ptr); })

