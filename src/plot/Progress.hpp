// progress.hpp
#pragma once
#include <atomic>
#include <chrono>
#include <cstddef> // size_t
#include <cstdint>
#include <iostream> // VerboseConsoleSink uses std::cout/cerr
#include <type_traits>

enum class EventKind : uint8_t {
    PlotBegin,
    PlotEnd,
    AllocationBegin,
    AllocationEnd,
    TableBegin,
    TableEnd,
    SectionBegin,
    SectionEnd,
    MatchKeyBegin,
    MatchKeyEnd,
    PostSortBegin,
    PostSortEnd,
    Note,
    Warning,
    Error,
};

enum class NoteId : uint8_t {
    None = 0,
    LayoutTotalBytesAllocated,
    HasAESHardware,
    TableCapacityUsed
};

struct ProgressEvent {
    EventKind kind;
    NoteId note_id = NoteId::None; // optional, for Note events

    uint8_t table_id = 0;
    uint8_t section_l = 0;
    uint8_t section_r = 0;
    uint32_t match_key = 0;
    uint32_t processed_match_keys = 0;
    uint32_t match_keys_total = 0;

    uint64_t items_l = 0;
    uint64_t items_r = 0;
    uint64_t num_items_in = 0;
    uint64_t produced = 0;

    // generic fields for various uses
    uint64_t u64_0 = 0;
    uint64_t u64_1 = 0;
    double f64_0 = 0.0;

    // C-ABI friendly: elapsed time in nanoseconds (for *End events* usually).
    uint64_t elapsed = 0;

    // C-ABI friendly: optional null-terminated message string (may be nullptr).
    char const* msg = nullptr;
};

// Ensure C/tooling ABI friendliness.
static_assert(std::is_standard_layout_v<ProgressEvent>);
static_assert(std::is_trivially_copyable_v<ProgressEvent>);

// POD function table for tooling / C ABI.
struct ProgressSinkProcs {
    using OnEventProc = int32_t (*)(ProgressEvent const*);
    OnEventProc on_event_proc = nullptr;
};

// For C/tooling ABI, the important properties are standard-layout + trivially-copyable.
static_assert(std::is_standard_layout_v<ProgressSinkProcs>);
static_assert(std::is_trivially_copyable_v<ProgressSinkProcs>);

// C++ sink interface:
// - Still virtual (for C++ side)
// - Optionally forwards to `on_event_proc` if set (for tooling bridges).
// - Tooling-facing POD structs should avoid virtuals and use explicit C function pointers instead.
struct IProgressSink : ProgressSinkProcs {
    virtual ~IProgressSink() = default;

    virtual bool on_event(ProgressEvent const& e) noexcept
    {
        if (on_event_proc != nullptr) {
            return on_event_proc(&e) == 0;
        }
        return true;
    }
};

// default no-op sink
struct NullProgressSink final : IProgressSink {
    bool on_event(ProgressEvent const&) noexcept override { return true; }
};

inline IProgressSink& null_progress_sink()
{
    static NullProgressSink s;
    return s;
}

class ScopedEvent {
public:
    ScopedEvent(IProgressSink& sink, ProgressEvent begin)
        : sink_(sink)
        , ev_(begin)
        , start_(std::chrono::steady_clock::now())
    {
        cancelled_ = !sink_.on_event(ev_);
    }

    ~ScopedEvent()
    {
        if (cancelled_)
            return;

        ev_.elapsed = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - start_)
                .count());

        // Convert Begin->End event kind:
        ev_.kind = end_kind(ev_.kind);
        sink_.on_event(ev_);
    }

    bool cancelled() const noexcept { return cancelled_; }

private:
    static EventKind end_kind(EventKind k)
    {
        switch (k) {
        case EventKind::PlotBegin:
            return EventKind::PlotEnd;
        case EventKind::AllocationBegin:
            return EventKind::AllocationEnd;
        case EventKind::TableBegin:
            return EventKind::TableEnd;
        case EventKind::SectionBegin:
            return EventKind::SectionEnd;
        case EventKind::MatchKeyBegin:
            return EventKind::MatchKeyEnd;
        case EventKind::PostSortBegin:
            return EventKind::PostSortEnd;
        default:
            return k;
        }
    }

    IProgressSink& sink_;
    ProgressEvent ev_;
    std::chrono::steady_clock::time_point start_;
    bool cancelled_ = false;
};

// Coarse-grained state for polling UIs (progress bars, etc.)
enum class PlotState : uint8_t {
    Idle = 0,
    Plotting,
    Allocating,
    Matching,
    PostSort,
    Finished,
    Error,
};

// Return a null-terminated string literal so consumers can print it directly without copying
// into a new buffer to add a 0-terminator.
inline char const* plot_state_name(PlotState s) noexcept
{
    switch (s) {
    case PlotState::Idle:
        return "idle";
    case PlotState::Plotting:
        return "plot";
    case PlotState::Allocating:
        return "alloc";
    case PlotState::Matching:
        return "matching";
    case PlotState::PostSort:
        return "postsort";
    case PlotState::Finished:
        return "done";
    case PlotState::Error:
        return "error";
    }
    return "unknown";
}

struct AtomicProgressSnapshot {
    double fraction = 0.0; // 0..1
    PlotState state = PlotState::Idle;
    uint8_t table_id = 0;
};

// Minimal sink: store progress atomically for polling UIs.
class AtomicProgressSink final : public IProgressSink {
public:
    AtomicProgressSink() = default;

    AtomicProgressSnapshot snapshot() const noexcept
    {
        AtomicProgressSnapshot s;
        s.fraction = fraction_.load();
        s.state = static_cast<PlotState>(state_.load());
        s.table_id = table_id_.load();
        return s;
    }

    bool on_event(ProgressEvent const& e) noexcept override
    {
        switch (e.kind) {
        case EventKind::PlotBegin:
            store_state_(PlotState::Plotting);
            store_fraction_(0.0);
            break;

        case EventKind::AllocationBegin:
            store_state_(PlotState::Allocating);
            break;

        case EventKind::TableBegin:
            table_id_.store(e.table_id, std::memory_order_relaxed);
            store_state_(PlotState::Matching);
            store_fraction_(table_base_(e.table_id));
            break;

        case EventKind::MatchKeyEnd:
            if (e.match_keys_total > 0) {
                double p = double(e.processed_match_keys + 1) / double(e.match_keys_total);
                if (p < 0.0)
                    p = 0.0;
                if (p > 1.0)
                    p = 1.0;
                store_fraction_(table_base_(e.table_id) + table_weight_(e.table_id) * p);
            }
            break;

        case EventKind::PostSortBegin:
            store_state_(PlotState::PostSort);
            break;

        case EventKind::PostSortEnd:
            store_state_(PlotState::Plotting);
            store_fraction_(table_base_(e.table_id) + table_weight_(e.table_id));
            break;

        case EventKind::TableEnd:
            table_id_.store(e.table_id, std::memory_order_relaxed);
            store_state_(PlotState::Plotting);
            store_fraction_(table_base_(e.table_id) + table_weight_(e.table_id));
            break;

        case EventKind::Error:
            store_state_(PlotState::Error);
            break;

        case EventKind::PlotEnd:
            store_state_(PlotState::Finished);
            store_fraction_(1.0);
            break;

        default:
            break;
        }
        return true;
    }

private:
    // Simple fixed weights: small allocation phase + 3 tables.
    static constexpr double kAllocWeight = 0.03;
    static constexpr double kTablesWeight = 1.0 - kAllocWeight;
    static constexpr double kPerTable = kTablesWeight / 3.0;

    static double table_base_(uint8_t table_id) noexcept
    {
        // Treat allocation as happening before tables.
        if (table_id <= 1)
            return kAllocWeight + 0.0 * kPerTable;
        if (table_id == 2)
            return kAllocWeight + 1.0 * kPerTable;
        if (table_id == 3)
            return kAllocWeight + 2.0 * kPerTable;
        return 0.0;
    }

    static double table_weight_([[maybe_unused]] uint8_t table_id) noexcept
    {
        (void)table_id;
        return kPerTable;
    }

    void store_state_(PlotState s) noexcept
    {
        state_.store(static_cast<uint8_t>(s), std::memory_order_relaxed);
    }

    void store_fraction_(double f) noexcept
    {
        if (f < 0.0)
            f = 0.0;
        if (f > 1.0)
            f = 1.0;
        fraction_.store(f, std::memory_order_relaxed);
    }

private:
    std::atomic<double> fraction_ { 0.0 };
    std::atomic<uint8_t> state_ { static_cast<uint8_t>(PlotState::Idle) };
    std::atomic<uint8_t> table_id_ { 0 };
};

class VerboseConsoleSink final : public IProgressSink {
public:
    bool on_event(ProgressEvent const& e) noexcept override
    {
        switch (e.kind) {
        case EventKind::PlotBegin:
            std::cout << "Plotting started...\n";
            break;
        case EventKind::PlotEnd:
            std::cout << "Plotting ended. Total time: "
                      << std::chrono::duration<double, std::milli>(
                             std::chrono::nanoseconds(e.elapsed))
                             .count()
                      << " ms\n";
            break;
        case EventKind::AllocationBegin:
            std::cout << "Allocating memory for plotting...\n";
            break;
        case EventKind::AllocationEnd:
            std::cout << "Memory allocation completed. Time: "
                      << std::chrono::duration<double, std::milli>(
                             std::chrono::nanoseconds(e.elapsed))
                             .count()
                      << " ms\n";
            break;
        case EventKind::TableBegin:
            std::cout << "Constructing Table " << int(e.table_id) << " from " << int(e.num_items_in)
                      << " items...\n";
            break;
        case EventKind::TableEnd:
            std::cout << "Table " << int(e.table_id) << " constructed. Time: "
                      << std::chrono::duration<double, std::milli>(
                             std::chrono::nanoseconds(e.elapsed))
                             .count()
                      << " ms\n";
            break;
        case EventKind::SectionBegin:
            std::cout << "  T" << int(e.table_id) << " section " << int(e.section_l) << "-"
                      << int(e.section_r) << " started...\n";
            break;
        case EventKind::SectionEnd:
            std::cout << "  T" << int(e.table_id) << " section " << int(e.section_l) << "-"
                      << int(e.section_r) << " time: "
                      << std::chrono::duration<double, std::milli>(
                             std::chrono::nanoseconds(e.elapsed))
                             .count()
                      << " ms\n";
            break;
        case EventKind::MatchKeyBegin:
            std::cout << "    T" << int(e.table_id) << " matching key " << e.match_key
                      << " (section " << int(e.section_l) << "-" << int(e.section_r) << ")\n";
            break;
        case EventKind::MatchKeyEnd:
            std::cout << "    T" << int(e.table_id) << " matching key " << e.match_key
                      << " completed. Time: "
                      << std::chrono::duration<double, std::milli>(
                             std::chrono::nanoseconds(e.elapsed))
                             .count()
                      << " ms\n";
            break;
        case EventKind::PostSortBegin:
            std::cout << "  T" << int(e.table_id) << " post-sort started...\n";
            break;
        case EventKind::PostSortEnd:
            std::cout << "  T" << int(e.table_id) << " post-sort completed. Time: "
                      << std::chrono::duration<double, std::milli>(
                             std::chrono::nanoseconds(e.elapsed))
                             .count()
                      << " ms\n";
            break;
        case EventKind::Note:
            switch (e.note_id) {
            case NoteId::LayoutTotalBytesAllocated:
                std::cout << "Note: Total bytes allocated for layout: " << e.u64_0 << " bytes\n";
                break;
            case NoteId::TableCapacityUsed:
                std::cout << "Note: Table " << int(e.table_id)
                          << " capacity used: " << e.f64_0 * 100.0 << "%\n";
                break;
            case NoteId::HasAESHardware:
                std::cout << "Note: AES hardware acceleration is "
                          << (e.u64_0 ? "available" : "not available") << "\n";
                break;
            default:
                if (e.msg != nullptr && e.msg[0] != '\0')
                    std::cout << "Note: " << e.msg << "\n";
                break;
            }
            break;

        case EventKind::Warning:
            std::cerr << "Warning: " << (e.msg ? e.msg : "") << "\n";
            break;
        case EventKind::Error:
            std::cerr << "Error: " << (e.msg ? e.msg : "") << "\n";
            break;

        default:
            break;
        }
        return true;
    }
};
