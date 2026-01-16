#pragma once

#include <bit> // std::has_single_bit
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <memory_resource>
#include <span>
#include <thread> // added

// =====================================================================================
// Minimal monotonic arena (PMR) used for scratch within a region of the main buffer.
// =====================================================================================
class ResettableArenaResource final : public std::pmr::memory_resource {
public:
    ResettableArenaResource() = default;

    ResettableArenaResource(void* buffer, std::size_t capacity) { rebind(buffer, capacity); }

    // Point this arena at a new region [buffer, buffer + capacity)
    void rebind(void* buffer, std::size_t capacity)
    {
        base_ = static_cast<std::byte*>(buffer);
        cap_ = capacity;
        off_ = 0;
        high_watermark_ = 0;
        // NOTE: lifetime_high_watermark_ is intentionally NOT reset here.
#ifndef NDEBUG
        has_owner_ = false;
#endif
    }

    void reset() noexcept
    {
        off_ = 0;
        high_watermark_ = 0;
        // NOTE: lifetime_high_watermark_ is intentionally NOT reset here.
#ifndef NDEBUG
        has_owner_ = false;
#endif
    }

    // ---- mark/rewind -------------------------------------------------
    using Marker = std::size_t;

    // Capture the current allocation position.
    Marker mark() const noexcept { return off_; }

    // Rewind allocations back to a previously captured marker.
    void rewind(Marker m) noexcept
    {
        assert(m <= off_);
        off_ = m;
    }
    // ----------------------------------------------------------------

    std::size_t capacity_bytes() const noexcept { return cap_; }
    std::size_t used_bytes() const noexcept { return off_; }
    std::size_t remaining_bytes() const noexcept { return (off_ <= cap_) ? (cap_ - off_) : 0; }

    // Peak value of used_bytes() since the last reset() or rebind().
    // (Not a lifetime maximum unless you never reset/rebind.)
    std::size_t high_watermark_bytes() const noexcept { return high_watermark_; }

    // Peak value of used_bytes() ever observed for this arena object (across reset()/rebind()).
    std::size_t lifetime_high_watermark_bytes() const noexcept { return lifetime_high_watermark_; }

private:
    struct DetailedBadAlloc final : std::bad_alloc {
        enum class Reason : std::uint8_t {
            AlignmentOverflow,
            OutOfCapacity,
        };

        std::array<char, 256> msg {};

        DetailedBadAlloc(Reason reason,
            std::size_t bytes,
            std::size_t align,
            std::size_t p,
            std::size_t aligned,
            std::size_t cap) noexcept
        {
            char const* r
                = (reason == Reason::AlignmentOverflow) ? "alignment overflow" : "out of capacity";
            std::snprintf(msg.data(),
                msg.size(),
                "ResettableArenaResource allocation failed (%s): bytes=%zu align=%zu off=%zu "
                "aligned=%zu cap=%zu",
                r,
                bytes,
                align,
                p,
                aligned,
                cap);
        }

        char const* what() const noexcept override { return msg.data(); }
    };

    void* do_allocate(std::size_t bytes, std::size_t align) override
    {
        assert(base_ != nullptr || cap_ == 0);

#ifndef NDEBUG
        // Detect accidental concurrent use of a single bump arena across threads.
        // If this ever trips, you either need per-thread arenas or locking.
        if (!has_owner_) {
            owner_ = std::this_thread::get_id();
            has_owner_ = true;
        }
        else {
            assert(owner_ == std::this_thread::get_id());
        }
#endif

        if (align == 0) {
            align = 1; // defensive
        }

        std::size_t p = off_;
        std::size_t aligned = 0;

        assert(std::has_single_bit(align));
        aligned = (p + (align - 1)) & ~(align - 1);

        // If (p + (align-1)) overflowed, aligned can wrap below p.
        if (aligned < p) {
            throw DetailedBadAlloc(
                DetailedBadAlloc::Reason::AlignmentOverflow, bytes, align, p, aligned, cap_);
        }

        // Also guards against (aligned + bytes) overflow.
        if (aligned > cap_ || bytes > (cap_ - aligned)) {
            throw DetailedBadAlloc(
                DetailedBadAlloc::Reason::OutOfCapacity, bytes, align, p, aligned, cap_);
        }

        off_ = aligned + bytes;
        if (off_ > high_watermark_) {
            high_watermark_ = off_;
        }
        if (off_ > lifetime_high_watermark_) {
            lifetime_high_watermark_ = off_;
        }
        assert(off_ <= cap_);
        return base_ + aligned;
    }

    void do_deallocate(void*, std::size_t, std::size_t) override
    {
        // monotonic: nothing to do
    }

    bool do_is_equal(std::pmr::memory_resource const& other) const noexcept override
    {
        return this == &other;
    }

    std::byte* base_ = nullptr;
    std::size_t cap_ = 0;
    std::size_t off_ = 0;

    // Tracks the maximum bump offset observed since last reset()/rebind().
    std::size_t high_watermark_ = 0;

    // Tracks the maximum bump offset observed over the lifetime of this arena object.
    std::size_t lifetime_high_watermark_ = 0;

#ifndef NDEBUG
    std::thread::id owner_ {};
    bool has_owner_ = false;
#endif
};

template <class T>
static T* arena_alloc_n(std::pmr::memory_resource* mr, std::size_t n)
{
    std::pmr::polymorphic_allocator<T> a(mr);
    return a.allocate(n); // uninitialized storage
}

// =====================================================================================
// LayoutPlanner
//
// Owns (or wraps) a single contiguous buffer and gives you:
//   - typed spans at byte offsets
//   - scratch PMR arenas bound to subregions
//
// Overlaps are allowed as long as you know what you’re doing.
// We only check bounds, not aliasing.
// =====================================================================================
class LayoutPlanner {
public:
    // ---------------------------------------------
    // Constructors
    // ---------------------------------------------

    // Allocate the backing buffer ourselves via new[].
    explicit LayoutPlanner(std::size_t total_bytes)
        : owned_storage_(new std::byte[total_bytes])
        , base_(owned_storage_.get())
        , size_(total_bytes)
    {
        zeroAll(); // for consistent memory usage and making sure all memory is accessible
    }

    // Wrap an externally-provided buffer (you keep it alive).
    LayoutPlanner(void* buffer, std::size_t total_bytes)
        : base_(static_cast<std::byte*>(buffer))
        , size_(total_bytes)
    {
        zeroAll(); // for consistent memory usage and making sure all memory is accessible
    }

    // Non-copyable, movable if you want (can default move):
    LayoutPlanner(LayoutPlanner&&) = default;
    LayoutPlanner& operator=(LayoutPlanner&&) = default;

    LayoutPlanner(LayoutPlanner const&) = delete;
    LayoutPlanner& operator=(LayoutPlanner const&) = delete;

    // ---------------------------------------------
    // Basic info
    // ---------------------------------------------
    void* data() noexcept { return base_; }
    void const* data() const noexcept { return base_; }

    std::size_t size_bytes() const noexcept { return size_; }

    // ---------------------------------------------
    // Region = [offset, offset+bytes) inside buffer
    // ---------------------------------------------
    struct Region {
        std::byte* base = nullptr; // base pointer of region
        std::size_t bytes = 0; // size of region in bytes

        bool valid() const noexcept { return base != nullptr && bytes > 0; }

        template <class T>
        std::span<T> as_span(std::size_t count) const
        {
            assert(count * sizeof(T) <= bytes);
            return std::span<T>(reinterpret_cast<T*>(base), count);
        }

        template <class T>
        std::span<T const> as_cspan(std::size_t count) const
        {
            assert(count * sizeof(T) <= bytes);
            return std::span<T const>(reinterpret_cast<T const*>(base), count);
        }

        // Create a scratch arena *inside this region*.
        // Typically used for temp allocations (radix buffers, prefix arrays, etc.).
        ResettableArenaResource make_arena() const { return ResettableArenaResource(base, bytes); }
    };

    void zeroAll() noexcept
    {
        if (base_ != nullptr && size_ > 0) {
            std::fill_n(base_, size_, std::byte(0));
        }
    }

    // Get a Region at [offset_bytes, offset_bytes + bytes)
    // Caller is responsible for ensuring overlaps are intentional.
    Region region(std::size_t offset_bytes, std::size_t bytes) const
    {
        assert(offset_bytes <= size_);
        assert(offset_bytes + bytes <= size_);
        Region r;
        r.base = base_ + offset_bytes;
        r.bytes = bytes;
        return r;
    }

    // Convenience: typed span starting at offset_bytes, with given element count.
    template <class T>
    std::span<T> span(std::size_t offset_bytes, std::size_t count) const
    {
        Region r = region(offset_bytes, count * sizeof(T));
        return r.as_span<T>(count);
    }

    template <class T>
    std::span<T const> cspan(std::size_t offset_bytes, std::size_t count) const
    {
        Region r = region(offset_bytes, count * sizeof(T));
        return r.as_cspan<T>(count);
    }

    // Convenience: make a scratch arena over [offset_bytes, offset_bytes + bytes).
    ResettableArenaResource make_arena(std::size_t offset_bytes, std::size_t bytes) const
    {
        Region r = region(offset_bytes, bytes);
        return r.make_arena();
    }

private:
    std::unique_ptr<std::byte[]> owned_storage_; // null if we wrap external memory
    std::byte* base_ = nullptr;
    std::size_t size_ = 0;
};
