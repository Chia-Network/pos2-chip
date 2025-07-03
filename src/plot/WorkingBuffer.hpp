// ─── working_buffer.hpp ───────────────────────────────────────────────────────
#pragma once
#include <cstddef>
#include <new>
#include <memory_resource>
#include <mutex>

class WorkingBuffer
{
public:
    explicit WorkingBuffer(std::size_t bytes,
                           std::size_t align = alignof(std::max_align_t))
        : bytes_(roundUp(bytes, align)),
          align_(align),
          base_(static_cast<std::byte*>(
              ::operator new (bytes_, std::align_val_t(align_)))),
          upstream_(base_, bytes_) {}            // bump resource only

    ~WorkingBuffer() { ::operator delete(base_, std::align_val_t(align_)); }

    WorkingBuffer(const WorkingBuffer&)            = delete;
    WorkingBuffer& operator=(const WorkingBuffer&) = delete;

    /// resets the whole arena (O(1))
    void reset()                     { std::scoped_lock lk(m_); upstream_.reset(); }

    /// returns a `memory_resource` clients can pass to pmr containers
    std::pmr::memory_resource* resource() noexcept { return &upstream_; }

    /// optional:  thread-safe wrapper for “allocate raw bytes”
    void* allocateRaw(std::size_t n, std::size_t al = alignof(std::max_align_t))
    {
        std::scoped_lock lk(m_);
        return upstream_.allocate(n, al);
    }

    /// record your current allocation offset (bytes used)
    std::size_t checkpoint() const noexcept { return upstream_.bytesAllocated(); }

    /// release all allocations made after the given checkpoint
    void release(std::size_t cp) noexcept { std::scoped_lock lk(m_); upstream_.rewind(cp); }

    /// RAII guard: automatically release to the checkpoint on destruction
    class CheckpointGuard {
    public:
        explicit CheckpointGuard(WorkingBuffer& wb) noexcept
            : wb_(wb), cp_(wb.checkpoint()) {}
        ~CheckpointGuard() noexcept { wb_.release(cp_); }
        CheckpointGuard(const CheckpointGuard&) = delete;
        CheckpointGuard& operator=(const CheckpointGuard&) = delete;
    private:
        WorkingBuffer& wb_;
        std::size_t    cp_;
    };

    std::size_t capacity()   const noexcept { return bytes_;          }
    std::size_t bytesUsed()  const noexcept { return upstream_.bytesAllocated(); }

private:
    static std::size_t roundUp(std::size_t n, std::size_t a) noexcept
    { return (n + a - 1) & ~(a - 1); }

    // --- tiny bump upstream that lets us query stats -------------------------
    class Bump : public std::pmr::memory_resource
    {
    public:
        Bump(std::byte* b, std::size_t len) : first_(b), cur_(b), last_(b + len) {}
        void reset() noexcept { cur_ = first_; }
        std::size_t bytesAllocated() const noexcept { return cur_ - first_; }
        /// rewind back to a previous allocation offset
        void rewind(std::size_t bytes) noexcept { cur_ = first_ + bytes; }
    private:
        void* do_allocate(std::size_t n, std::size_t al) override
        {
            void* p = cur_;
            std::size_t space = last_ - cur_;
            void* res = std::align(al, n, p, space);
            if (!res || n > space) throw std::bad_alloc{};
            cur_ = static_cast<std::byte*>(res) + n;
            return res;
        }
        void do_deallocate(void*, std::size_t, std::size_t) noexcept override {}
        bool do_is_equal(const std::pmr::memory_resource& o) const noexcept override
        { return this == &o; }
        std::byte* first_;
        std::byte* cur_;
        std::byte* last_;
    };

    std::size_t                      bytes_;
    std::size_t                      align_;
    std::byte*                       base_;
    Bump                              upstream_;
    std::mutex                       m_;        // protects allocate/reset if shared
};
