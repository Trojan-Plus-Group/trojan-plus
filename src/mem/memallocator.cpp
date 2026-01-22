
#ifdef ENABLE_MIMALLOC
#include <mimalloc.h>
#endif
#include "mem/memallocator.h"

namespace tp {

struct miallocator {
public:
    static void *malloc(size_t size) {
#ifdef ENABLE_MIMALLOC
        void* ptr = mi_malloc(size);
        return ptr;
#else
        return nullptr;
#endif
    }
    static void *malloc_aligned(size_t size, size_t align) {
#ifdef ENABLE_MIMALLOC
        void* ptr = mi_malloc_aligned(size, align);
        return ptr;
#else
        return nullptr;
#endif
    }
    static void free(void *ptr) {
#ifdef ENABLE_MIMALLOC
        mi_free(ptr);
#endif
    }
    static void *realloc(void *ptr, size_t new_size) {
#ifdef ENABLE_MIMALLOC
        void* ret = mi_realloc(ptr, new_size);
        return ret;
#else
        return nullptr;
#endif
    }
};

mem_allocator::mem_allocator(bool mem_stat, bool trace_file_line, bool mimalloc)

    : trace_file_line_(trace_file_line), mem_stat_(mem_stat), mimalloc_(mimalloc) {}

void *mem_allocator::malloc(size_t size, const char *file, int line) {
    if (mem_stat_) {
        auto *ptr = malloc_impl(size + memory_recorder_header_size);
        record_malloc(ptr, size, memory_recorder_header_size, file, line);

        return (char *)ptr + memory_recorder_header_size;
    }

    return malloc_impl(size);
}

void *mem_allocator::malloc_aligned(size_t size, size_t align, const char *file, int line) {
    if (mem_stat_) {
        int offset = std::max(memory_recorder_header_size, align);
        int real_align = std::max(alignof(memory_recorder_header), align);
        auto *ptr = malloc_aligned_impl(size + offset, real_align);
        record_malloc(ptr, size, offset, file, line);

        return (char *)ptr + offset;
    }

    return malloc_aligned_impl(size, align);
}

void *mem_allocator::realloc(void *ptr, size_t new_size, const char *file, int line) {
    if (mem_stat_) {
        if (ptr) {
            ptr = record_free(ptr);
        }

        ptr = realloc_impl(ptr, new_size + memory_recorder_header_size);
        record_malloc(ptr, new_size, memory_recorder_header_size, file, line);
        return (char *)ptr + memory_recorder_header_size;
    }

    return realloc_impl(ptr, new_size);
}

void mem_allocator::free(void *ptr) {
    if (mem_stat_) {
        if (ptr) {
            ptr = record_free(ptr);
        }
    }

    free_impl(ptr);
}

void mem_allocator::free_aligned(void *ptr) {
    if (mem_stat_) {
        if (ptr) {
            ptr = record_free(ptr);
        }
    }

    free_aligned_impl(ptr);
}

void *mem_allocator::malloc_impl(size_t size) {
    if (mimalloc_) {
        return miallocator::malloc(size);
    } else {
        return ::malloc(size);
    }
}

// find a size which is power of 2 and is greater than or equals n
size_t next_power_of_two(size_t n) {
    if ((n & (n - 1)) == 0) {
        return n;
    }

    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;

    if (sizeof(size_t) > 4) {
        n |= n >> 32;
    }

    return n + 1;
}

auto mini_pointer_size = sizeof(void *);

void *mem_allocator::malloc_aligned_impl(size_t size, size_t align) {
    if (mimalloc_) {
        return miallocator::malloc_aligned(size, align);
    } else {
        if (align < mini_pointer_size) {
            // we all run in 64bit OS, it MUST be greater than sizeof(void*)
            align = mini_pointer_size;
        }

        // must be power of two
        align = next_power_of_two(align);

#ifdef _WIN32
        return ::_aligned_malloc(size, align);
#else
        void *ptr;
        ::posix_memalign(&ptr, align, size);
        return ptr;
#endif
    }
}

void *mem_allocator::realloc_impl(void *ptr, size_t new_size) {
    if (mimalloc_) {
        return miallocator::realloc(ptr, new_size);
    } else {
        return ::realloc(ptr, new_size);
    }
}

void mem_allocator::free_impl(void *ptr) {
    if (!ptr)
        return;

    if (mimalloc_) {
        miallocator::free(ptr);
    } else {
        ::free(ptr);
    }
}

void mem_allocator::free_aligned_impl(void *ptr) {
    if (!ptr)
        return;

    if (mimalloc_) {
        miallocator::free(ptr);
    } else {
#ifdef _WIN32
        ::_aligned_free(ptr);
#else
        ::free(ptr);
#endif
    }
}

std::string mem_allocator::show_stat(int top_count) {
    if (mem_stat_) {
        uint64_t total = get_total_memory();
        uint64_t total_count = get_total_object_counter();

        std::ostringstream result;
        result << "memory: " << get_size_string(total) << "(" << total_count << ")"
               << ", trace: " << (trace_file_line_ ? "ON" : "OFF")
               << ", mimalloc: " << (mimalloc_ ? "ON" : "OFF") << "\n";

        if (trace_file_line_) {
            uint64_t extra = 0;
            uint64_t extra_count = 0;
            struct alloc_info {
                code_location location;
                alloc_stat stat;
            };
            std::vector<alloc_info> size_rank;
            {
                std::lock_guard<std::mutex> lock(tag_stat_.alloc_stat_lock);
                if (!tag_stat_.alloc_stat_list.empty()) {
                    extra = get_unordered_map_size(tag_stat_.code_pos_to_stat_index);
                    extra += get_vector_size(tag_stat_.alloc_stat_list);

                    size_rank.reserve(tag_stat_.code_pos_to_stat_index.size());
                    for (const auto &[
                        location, index
                    ] : tag_stat_.code_pos_to_stat_index) {
                        const auto &stat = tag_stat_.alloc_stat_list[index];
                        if (stat.count <= 0)
                            continue;
                        size_rank.push_back({location, stat});
                        extra_count += stat.count;
                    }
                }
            }

            size_t count = (top_count >= 0 && (size_t)top_count > size_rank.size()) ? size_rank.size() : (size_t)(std::max(0, top_count));

            if (size_rank.empty()) {
                result << " Empty Traced";
            } else {
                std::sort(size_rank.begin(), size_rank.end(), [](auto &&lhs, auto &&rhs) {
                    return lhs.stat.size > rhs.stat.size;
                });

                result << " Traced (top " << top_count << "):\n";

                uint64_t total_traced = 0;
                int total_count_traced = 0;

                for (const auto &[location, stat] : size_rank) {
                    total_traced += stat.size;
                    total_count_traced += stat.count;

                    if (count > 0) {
                        result << "  " << location.file << ":" << location.line << "  " << get_size_string(stat.size)
                               << " (" << stat.count << ")\n";

                        count--;
                    }
                }

                result << " traced: " << get_size_string(total_traced) << " (" << total_count_traced
                       << ") untraced: " << get_size_string(total - total_traced) << " ("
                       << total_count - total_count_traced << ")"
                       << " extra: " << get_size_string(extra) << " (" << extra_count << ")";
            }
        }

        return result.str();
    }

    return "memory statistics is disabled.";
}

void mem_allocator::record_malloc(void *ptr, size_t size, size_t offset, const char *file, int line) {
    auto *header = (memory_recorder_header *)((uint8_t *)ptr + offset - memory_recorder_header_size);
    header->size = size;
    header->start_offset = offset;

    total_object_counter_.fetch_add(1, std::memory_order_relaxed);
    total_memory_.fetch_add(size, std::memory_order_relaxed);

    if (trace_file_line_) {
        header->stat_index = record_mcontainer_alloc(size, file, line);
    } else {
        header->stat_index = memory_recorder_header::dont_trace_file_line;
    }
}

void *mem_allocator::record_free(void *ptr) {
    auto *header = (memory_recorder_header *)((uint8_t *)ptr - memory_recorder_header_size);

    total_object_counter_.fetch_sub(1, std::memory_order_relaxed);
    total_memory_.fetch_sub(header->size, std::memory_order_relaxed);

    if (trace_file_line_) {
        record_mcontainer_free(header->size, header->stat_index);
    }
    return (uint8_t *)ptr - header->start_offset;
}

uint32_t mem_allocator::record_mcontainer_alloc(size_t size, const char *file, int line) {
    if (file == nullptr)
        return memory_recorder_header::dont_trace_file_line;
    const std::lock_guard<std::mutex> lock(tag_stat_.alloc_stat_lock);
    code_location location{file, line};
    auto [it, inserted] = tag_stat_.code_pos_to_stat_index.try_emplace(location, static_cast<int>(tag_stat_.alloc_stat_list.size()));
    if (!inserted) {
        auto &&stat = tag_stat_.alloc_stat_list[it->second];
        stat.size += size;
        stat.count++;
    } else {
        tag_stat_.alloc_stat_list.push_back({size, 1});
    }
    return it->second;
}

void mem_allocator::record_mcontainer_free(size_t size, uint32_t stat_index) {
    if (stat_index == memory_recorder_header::dont_trace_file_line)
        return;
    std::lock_guard<std::mutex> lock(tag_stat_.alloc_stat_lock);
    auto &&stat = tag_stat_.alloc_stat_list[stat_index];
    stat.size -= size;
    stat.count--;
}

mem_allocator &get_tj_mem_allocator() {
#ifdef ENABLE_MIMALLOC
    static mem_allocator allocator(true, false, true);
#else
    static mem_allocator allocator(true, false, false);
#endif
    return allocator;
}

}