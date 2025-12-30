// progress.hpp
#pragma once
#include <chrono>
#include <cstdint>
#include <string_view>

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

enum class NoteId : uint8_t { None = 0, LayoutTotalBytesAllocated, TableCapacityUsed };

struct ProgressEvent {
    EventKind kind;
    NoteId note_id = NoteId::None; // optional, for Note events

    uint8_t table_id = 0;
    uint8_t section_l = 0;
    uint8_t section_r = 0;
    uint32_t match_key = 0;
    uint32_t match_keys_total = 0;

    uint64_t items_l = 0;
    uint64_t items_r = 0;
    uint64_t num_items_in = 0;
    uint64_t produced = 0;

    // generic fields for various uses
    uint64_t u64_0 = 0;
    uint64_t u64_1 = 0;
    double f64_0 = 0.0;

    std::chrono::nanoseconds elapsed {}; // for *End events* usually

    std::string_view msg {}; // optional (should be static or caller-owned)
};

// return false to request cancellation (optional)
struct IProgressSink {
    virtual ~IProgressSink() = default;
    virtual bool on_event(ProgressEvent const& e) noexcept = 0;
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
        ev_.elapsed = std::chrono::steady_clock::now() - start_;
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
