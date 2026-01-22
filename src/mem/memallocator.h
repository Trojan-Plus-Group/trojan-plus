#pragma once
#include <atomic>
#include <algorithm>
#include <chrono>
#include <map>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <charconv>
#include <sstream>
#include <memory>
#include <cstdlib>
#include <new>
#include <vector>
#include <list>
#include <deque>
#include <set>
#include <fstream>
#include <queue>
#include <stack>
#include <cwchar>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/associated_allocator.hpp>
#include <boost/version.hpp>

#if BOOST_VERSION >= 107700
#include <boost/asio/bind_allocator.hpp>
#endif

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
        std::unordered_map<code_location, uint32_t, pair_hash, pair_equal> code_pos_to_stat_index;
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


namespace tp 
{
// tp allocator for std
template <typename T>
struct tp_std_allocator {
     using value_type = T;
     tp_std_allocator() = default;
     template <typename U> tp_std_allocator(const tp_std_allocator<U>&) {}

     T* allocate(std::size_t n) {
         // 调用项目自定义的带统计的对齐分配
         return static_cast<T*>(get_tj_mem_allocator().malloc_aligned(
             n * sizeof(T), alignof(T), "tp_std_allocator", 0));
     }

     void deallocate(T* p, std::size_t) {
         get_tj_mem_allocator().free_aligned(p);
     }

     // 支持与不同类型的 allocator 相互比较
     template <typename U> bool operator==(const tp_std_allocator<U>&) const { return true; }
     template <typename U> bool operator!=(const tp_std_allocator<U>&) const { return false; }
};

using streambuf = boost::asio::basic_streambuf<tp::tp_std_allocator<char>>;

using string = std::basic_string<char, std::char_traits<char>, tp_std_allocator<char>>;
using wstring = std::basic_string<wchar_t, std::char_traits<wchar_t>, tp_std_allocator<wchar_t>>;

template <typename T>
string to_string(T value) {
    if constexpr (std::is_same_v<T, bool>) {
        return value ? string("true") : string("false");
    } else if constexpr (std::is_enum_v<T>) {
        return to_string(static_cast<std::underlying_type_t<T>>(value));
    } else {
        char buf[24]; 
        auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), value);
        if (ec == std::errc{}) {
            return string(buf, static_cast<std::size_t>(ptr - buf));
        }
        return string("", 0);
    }
}

inline string to_string(double value) {
    char buf[64]; 
    auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf), value);
    if (ec == std::errc{}) {
        return string(buf, static_cast<std::size_t>(ptr - buf));
    }
    return string("", 0);
}

template <typename T>
using vector = ::std::vector<T, tp_std_allocator<T>>;

template <typename T>
using list = ::std::list<T, tp_std_allocator<T>>;

template <typename K, typename V, typename Compare = ::std::less<K>>
using map = ::std::map<K, V, Compare, tp_std_allocator<::std::pair<const K, V>>>;

template <typename K, typename V, typename Compare = ::std::less<K>>
using multimap = ::std::multimap<K, V, Compare, tp_std_allocator<::std::pair<const K, V>>>;

template <typename K, typename Compare = ::std::less<K>>
using set = ::std::set<K, Compare, tp_std_allocator<K>>;

template <typename K, typename V, typename Hash = ::std::hash<K>, typename KeyEqual = ::std::equal_to<K>>
using unordered_map = ::std::unordered_map<K, V, Hash, KeyEqual, tp_std_allocator<::std::pair<const K, V>>>;

template <typename K, typename Hash = ::std::hash<K>, typename KeyEqual = ::std::equal_to<K>>
using unordered_set = ::std::unordered_set<K, Hash, KeyEqual, tp_std_allocator<K>>;

template <typename T>
using deque = ::std::deque<T, tp_std_allocator<T>>;

template <typename T1, typename T2>
using pair = ::std::pair<T1, T2>;

using ::std::make_pair;

template <typename T, typename Container = tp::deque<T>>
using queue = ::std::queue<T, Container>;

template <typename T, typename Container = tp::deque<T>>
using stack = ::std::stack<T, Container>;

template <typename T, typename Container = tp::vector<T>, typename Compare = ::std::less<typename Container::value_type>>
using priority_queue = ::std::priority_queue<T, Container, Compare>;


template <typename Handler>
struct handler_alloc_wrapper {
    Handler handler;
    using allocator_type = tp_std_allocator<void>;

    handler_alloc_wrapper(Handler h) : handler(std::move(h)) {}

    allocator_type get_allocator() const noexcept {
        return allocator_type();
    }

    template <typename... Args>
    void operator()(Args&&... args) {
        handler(std::forward<Args>(args)...);
    }
};

template <typename Handler>
auto bind_mem_alloc(Handler&& handler) {
#if BOOST_VERSION >= 107700
    return boost::asio::bind_allocator(tp_std_allocator<void>(), std::forward<Handler>(handler));
#else
    return handler_alloc_wrapper<std::decay_t<Handler>>(std::forward<Handler>(handler));
#endif
}

using ifstream = ::std::ifstream;
using ofstream = ::std::ofstream;
using fstream = ::std::fstream;

using stringbuf = ::std::basic_stringbuf<char, ::std::char_traits<char>, tp_std_allocator<char>>;
using wstringbuf = ::std::basic_stringbuf<wchar_t, ::std::char_traits<wchar_t>, tp_std_allocator<wchar_t>>;

using stringstream = ::std::basic_stringstream<char, ::std::char_traits<char>, tp_std_allocator<char>>;
using wstringstream = ::std::basic_stringstream<wchar_t, ::std::char_traits<wchar_t>, tp_std_allocator<wchar_t>>;

using ostringstream = ::std::basic_ostringstream<char, ::std::char_traits<char>, tp_std_allocator<char>>;
using wostringstream = ::std::basic_ostringstream<wchar_t, ::std::char_traits<wchar_t>, tp_std_allocator<wchar_t>>;

using istringstream = ::std::basic_istringstream<char, ::std::char_traits<char>, tp_std_allocator<char>>;
using wistringstream = ::std::basic_istringstream<wchar_t, ::std::char_traits<wchar_t>, tp_std_allocator<wchar_t>>;



#define STD_STRING(T) std::basic_string<T, std::char_traits<T>, std::allocator<T>>	
#define TP_STRING(T) std::basic_string<T, std::char_traits<T>, tp_std_allocator<T>>

template <typename T>
bool operator<(const TP_STRING(T)& lhs, const STD_STRING(T)& rhs)
{
    return lhs.compare(0, lhs.length(), rhs.c_str(), rhs.length()) < 0;
}

template <typename T>
bool operator<(const STD_STRING(T)& lhs, const TP_STRING(T)& rhs)
{
    return lhs.compare(0, lhs.length(), rhs.c_str(), rhs.length()) < 0;
}
template <typename T>
bool operator<=(const TP_STRING(T)& lhs, const STD_STRING(T)& rhs)
{
    return lhs.compare(0, lhs.length(), rhs.c_str(), rhs.length()) <= 0;
}
template <typename T>
bool operator<=(const STD_STRING(T)& lhs, const TP_STRING(T)& rhs)
{
    return lhs.compare(0, lhs.length(), rhs.c_str(), rhs.length()) <= 0;
}
template <typename T>
bool operator>(const TP_STRING(T)& lhs, const STD_STRING(T)& rhs)
{
    return lhs.compare(0, lhs.length(), rhs.c_str(), rhs.length()) > 0;
}
template <typename T>
bool operator>(const STD_STRING(T)& lhs, const TP_STRING(T)& rhs)
{
    return lhs.compare(0, lhs.length(), rhs.c_str(), rhs.length()) > 0;
}
template <typename T>
bool operator>=(const TP_STRING(T)& lhs, const STD_STRING(T)& rhs)
{
    return lhs.compare(0, lhs.length(), rhs.c_str(), rhs.length()) >= 0;
}
template <typename T>
bool operator>=(const STD_STRING(T)& lhs, const TP_STRING(T)& rhs)
{
    return lhs.compare(0, lhs.length(), rhs.c_str(), rhs.length()) >= 0;
}
template <typename T>
bool operator==(const TP_STRING(T)& lhs, const STD_STRING(T)& rhs)
{
    return lhs.compare(0, lhs.length(), rhs.c_str(), rhs.length()) == 0;
}
template <typename T>
bool operator==(const STD_STRING(T)& lhs, const TP_STRING(T)& rhs)
{
    return lhs.compare(0, lhs.length(), rhs.c_str(), rhs.length()) == 0;
}
template <typename T>
bool operator!=(const TP_STRING(T)& lhs, const STD_STRING(T)& rhs)
{
    return lhs.compare(0, lhs.length(), rhs.c_str(), rhs.length()) != 0;
}
template <typename T>
bool operator!=(const STD_STRING(T)& lhs, const TP_STRING(T)& rhs)
{
    return lhs.compare(0, lhs.length(), rhs.c_str(), rhs.length()) != 0;
}
template <typename T>
TP_STRING(T) operator+=(const TP_STRING(T)& lhs, const STD_STRING(T)& rhs)
{
    return TP_STRING(T)(lhs) += rhs.c_str();
}
template <typename T>
TP_STRING(T) operator+=(const STD_STRING(T)& lhs, const TP_STRING(T)& rhs)
{
    return TP_STRING(T)(lhs.c_str()) += rhs.c_str();
}
template <typename T>
TP_STRING(T) operator+(const TP_STRING(T)& lhs, const STD_STRING(T)& rhs)
{
    return TP_STRING(T)(lhs) += rhs.c_str();
}
template <typename T>
TP_STRING(T) operator+(const STD_STRING(T)& lhs, const TP_STRING(T)& rhs)
{
    return TP_STRING(T)(lhs.c_str()) += rhs.c_str();
}
template <typename T>
TP_STRING(T) operator+(const T* lhs, const TP_STRING(T)& rhs)
{
    return TP_STRING(T)(lhs) += rhs;
}

#undef STD_STRING
#undef TP_STRING

}

namespace std
{
	template<>
	struct hash<tp::string>{
		size_t operator()(const tp::string& str) const{
			// FNV hash
			size_t hash = std::conditional_t<
				sizeof(size_t) == 4,
				std::integral_constant<uint32_t, 0x811c9dc5>,
				std::integral_constant<uint64_t, 0xcbf29ce484222325>>::value;
			for(char ch : str){
				hash ^= static_cast<unsigned char>(ch);
				hash *= std::conditional_t<
					sizeof(size_t) == 4,
					std::integral_constant<uint32_t, 16777619u>,
					std::integral_constant<uint64_t, 1099511628211ull>>::value;
			}
			return hash;
		}
	};
}