// ResettableArenaResource.hpp
#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory_resource>
#include <new>
#include <span>
#include <stdexcept>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

// ============================
// ResettableArenaResource (PMR)
// ============================

class ResettableArenaResource final : public std::pmr::memory_resource {
public:
    ResettableArenaResource(void* buffer, std::size_t capacity)
        : base_(static_cast<std::byte*>(buffer))
        , cap_(capacity)
        , off_(0)
    {
    }

    void reset() noexcept { off_ = 0; }

    // Optional: mark/rewind for inner loops
    std::size_t mark() const noexcept { return off_; }
    void rewind(std::size_t m) noexcept { off_ = m; }

    // Diagnostics/helpers
    std::size_t capacity_bytes() const noexcept { return cap_; }
    std::size_t used_bytes() const noexcept { return off_; }
    std::size_t remaining_bytes() const noexcept { return (off_ <= cap_) ? (cap_ - off_) : 0; }

private:
    void* do_allocate(std::size_t bytes, std::size_t align) override
    {
        // align should be power-of-two for normal C++ allocations.
        assert(align != 0 && (align & (align - 1)) == 0);

        std::size_t const p = off_;
        std::size_t const aligned = (p + (align - 1)) & ~(align - 1);

        // Overflow-safe bounds checks:
        if (aligned < p)
            throw std::bad_alloc {}; // wrap
        if (bytes > cap_)
            throw std::bad_alloc {};
        if (aligned > cap_ - bytes)
            throw std::bad_alloc {}; // aligned+bytes > cap_

        off_ = aligned + bytes;
        return base_ + aligned;
    }

    void do_deallocate(void*, std::size_t, std::size_t) override
    {
        // monotonic: no per-allocation free
    }

    bool do_is_equal(std::pmr::memory_resource const& other) const noexcept override
    {
        return this == &other;
    }

    std::byte* base_;
    std::size_t cap_;
    std::size_t off_;
};

// =======================================
// Result wrapper that remembers residence
// =======================================

enum class BufId : uint8_t { A, B };

template <class T>
struct BufferSpan {
    BufId where; // which backing buffer owns the allocations
    std::span<T> view; // view into that buffer
};

inline BufId other(BufId b) { return (b == BufId::A) ? BufId::B : BufId::A; }

// ===========================
// Large VM-backed allocation
// ===========================
//
// This reserves and commits a contiguous region suitable for multi-GiB arenas.
// - Windows: VirtualAlloc(MEM_RESERVE|MEM_COMMIT)
// - POSIX:   mmap(PROT_READ|PROT_WRITE)
//
// You can optionally "prefault" pages to force actual commit/touch early.

namespace arena_vm {

inline std::size_t page_size() noexcept
{
#if defined(_WIN32)
    SYSTEM_INFO si {};
    ::GetSystemInfo(&si);
    return static_cast<std::size_t>(si.dwPageSize);
#else
    long ps = ::sysconf(_SC_PAGESIZE);
    return (ps > 0) ? static_cast<std::size_t>(ps) : 4096u;
#endif
}

// Round up to a multiple of page size (helps on some OSes; harmless elsewhere)
inline std::size_t round_up_to_pages(std::size_t bytes) noexcept
{
    std::size_t const ps = page_size();
    std::size_t const rem = bytes % ps;
    if (rem == 0)
        return bytes;
    std::size_t const add = ps - rem;
    // overflow-safe:
    if (bytes > (std::numeric_limits<std::size_t>::max)() - add)
        return bytes; // best effort
    return bytes + add;
}

// Touch one byte per page to ensure the mapping is actually backed.
// Useful if you want to fail immediately instead of later during first write.
inline void prefault_pages(void* p, std::size_t bytes) noexcept
{
    if (!p || bytes == 0)
        return;
    std::size_t const ps = page_size();
    std::byte volatile* b = static_cast<std::byte volatile*>(p);
    for (std::size_t i = 0; i < bytes; i += ps) {
        b[i] = b[i]; // touch
    }
}

struct HugeBuffer {
    void* ptr = nullptr;
    std::size_t size = 0;

    HugeBuffer() = default;

    // If prefault==true, touches each page right after allocation (slower startup, earlier
    // failure).
    explicit HugeBuffer(std::size_t bytes, bool prefault = false)
        : ptr(nullptr)
        , size(round_up_to_pages(bytes))
    {
        if (size == 0)
            return;

#if defined(_WIN32)
        ptr = ::VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!ptr)
            throw std::bad_alloc {};
#else
        void* p = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            throw std::bad_alloc {};
        ptr = p;
#endif

        if (prefault) {
            prefault_pages(ptr, size);
        }
    }

    HugeBuffer(HugeBuffer const&) = delete;
    HugeBuffer& operator=(HugeBuffer const&) = delete;

    HugeBuffer(HugeBuffer&& o) noexcept : ptr(o.ptr), size(o.size)
    {
        o.ptr = nullptr;
        o.size = 0;
    }
    HugeBuffer& operator=(HugeBuffer&& o) noexcept
    {
        if (this == &o)
            return *this;
        this->~HugeBuffer();
        ptr = o.ptr;
        size = o.size;
        o.ptr = nullptr;
        o.size = 0;
        return *this;
    }

    ~HugeBuffer()
    {
#if defined(_WIN32)
        if (ptr)
            ::VirtualFree(ptr, 0, MEM_RELEASE);
#else
        if (ptr)
            ::munmap(ptr, size);
#endif
        ptr = nullptr;
        size = 0;
    }

    std::byte* bytes() noexcept { return static_cast<std::byte*>(ptr); }
    std::byte const* bytes() const noexcept { return static_cast<std::byte const*>(ptr); }
};

} // namespace arena_vm

// ====================================
// TwoResources + allocation helpers
// ====================================
//
// This bundles:
// - two VM-backed huge buffers (A and B)
// - two ResettableArenaResource instances built on top of them
//
// Typical usage in runner:
//   auto mem = TwoResources::allocate_vm(3ull<<30, 3ull<<30, /*prefault=*/false);
//   mem.a.reset(); mem.b.reset();
//   ... use &mem.a / &mem.b as pmr::memory_resource* ...

struct TwoResources {
    // Owning VM buffers (must be declared before arenas so they outlive them)
    arena_vm::HugeBuffer bufA;
    arena_vm::HugeBuffer bufB;

    // PMR arenas over those buffers
    ResettableArenaResource a;
    ResettableArenaResource b;

    // Construct from existing buffers (rarely used directly)
    TwoResources(arena_vm::HugeBuffer&& A, arena_vm::HugeBuffer&& B)
        : bufA(std::move(A))
        , bufB(std::move(B))
        , a(bufA.ptr, bufA.size)
        , b(bufB.ptr, bufB.size)
    {
    }

    // Main helper: allocate two VM-backed buffers and build arenas on top
    static TwoResources allocate_vm(std::size_t bytes_per_resource, bool prefault = true)
    {
        arena_vm::HugeBuffer A(bytes_per_resource, prefault);
        arena_vm::HugeBuffer B(bytes_per_resource, prefault);
        return TwoResources(std::move(A), std::move(B));
    }

    ResettableArenaResource& arena(BufId id) { return (id == BufId::A) ? a : b; }
    ResettableArenaResource const& arena(BufId id) const { return (id == BufId::A) ? a : b; }

    std::pmr::memory_resource* mr(BufId id) { return &arena(id); }
    void reset(BufId id) { arena(id).reset(); }
};

// ============================
// Optional sizing helpers
// ============================
//
// These are convenience helpers to compute required bytes for a single
// "out + tmp" stage when allocating T[num] in one arena and T[num] in the other.
//
// Example for Xs_Candidate:
//   num = 1ull << k
//   bytes_per_arena_min = num * sizeof(Xs_Candidate)   (2 GiB at k=28)
//   total_stage = 2 * bytes_per_arena_min

template <class T>
inline std::size_t bytes_for_n(std::size_t n)
{
    if (n == 0)
        return 0;
    if (n > (std::numeric_limits<std::size_t>::max)() / sizeof(T)) {
        throw std::overflow_error("bytes_for_n overflow");
    }
    return n * sizeof(T);
}
