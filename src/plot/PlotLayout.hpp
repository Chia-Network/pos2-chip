#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream> // added
#include <span>
#include <type_traits>

#include "LayoutPlanner.hpp"

// forward decls
struct Xs_Candidate;
struct T1Pairing;
struct T2Pairing;
struct T3Pairing;

struct PlotLayout {
    std::size_t max_section_pairs = 0;
    std::size_t num_sections = 0;
    std::size_t max_pairs = 0;

    std::size_t max_element_bytes = 0;
    std::size_t minor_scratch_bytes = 0;

    std::size_t num_blocks = 32;
    std::size_t block_size_bytes = 0;
    std::size_t total_bytes = 0;

    // ---- storage ----
    LayoutPlanner mem;
    ResettableArenaResource minor_scratch;
    ResettableArenaResource target_scratch;

    static constexpr std::size_t kPlanAlign = 64;

    static constexpr std::size_t align_up(std::size_t x, std::size_t a)
    {
        return (x + (a - 1)) & ~(a - 1);
    }

    // ============================================================
    // 1) Named slots: a single source of truth for block usage
    // ============================================================
    enum class BlockSlot : std::uint8_t {
        // primary outputs (often share block 0)
        PrimaryOut, // block used for “out” spans (t1/t2/t3 all reuse)
        XsPostSortTmp, // Xs phase
        T1PostSortTmp, // T1 phase
        T1TargetScratch, // start block of target scratch for T1
        T2PostSortTmp, // T2 phase
        T2TargetScratch, // start block of target scratch for T2
        T3PostSortTmp, // T3 phase
        T3TargetScratch, // start block of target scratch for T3
        _Count
    };

    static constexpr std::size_t kNumSlots = static_cast<std::size_t>(BlockSlot::_Count);

    static constexpr std::size_t to_index(BlockSlot s) { return static_cast<std::size_t>(s); }

    // This table determines whole layout
    static constexpr std::array<std::size_t, kNumSlots> kSlotToBlock = {
        /* PrimaryOut      */ 0,
        /* XsPostSortTmp   */ 24,
        /* T1PostSortTmp   */ 14,
        /* T1TargetScratch */ 20,
        /* T2PostSortTmp   */ 16,
        /* T2TargetScratch */ 26,
        /* T3PostSortTmp   */ 8,
        /* T3TargetScratch */ 8, // target scratch not used once post sort tmp kicks in
    };

    std::size_t block_pos(std::size_t block_index) const { return block_index * block_size_bytes; }

    std::size_t slot_pos(BlockSlot slot) const { return block_pos(kSlotToBlock[to_index(slot)]); }

    // ============================================================
    // Phase view structs
    // ============================================================
    struct XsViews {
        std::span<Xs_Candidate> out;
        std::span<Xs_Candidate> post_sort_tmp;
        ResettableArenaResource& minor;
    };

    struct T1Views {
        std::span<T1Pairing> out;
        std::span<T1Pairing> post_sort_tmp;
        ResettableArenaResource& target;
        ResettableArenaResource& minor;
    };

    struct T2Views {
        std::span<T2Pairing> out;
        std::span<T2Pairing> post_sort_tmp;
        ResettableArenaResource& target;
        ResettableArenaResource& minor;
    };

    struct T3Views {
        std::span<T3Pairing> out;
        std::span<T3Pairing> post_sort_tmp;
        ResettableArenaResource& target;
        ResettableArenaResource& minor;
    };

    PlotLayout(std::size_t max_section_pairs_,
        std::size_t num_sections_,
        std::size_t max_element_bytes_,
        std::size_t minor_scratch_bytes_,
        std::size_t num_blocks_ = 32)
        : max_section_pairs(max_section_pairs_)
        , num_sections(num_sections_)
        , max_pairs(max_section_pairs_ * num_sections_)
        , max_element_bytes(max_element_bytes_)
        , minor_scratch_bytes(minor_scratch_bytes_)
        , num_blocks(num_blocks_)
        , block_size_bytes(0)
        , total_bytes(0)
        , mem(0) // replaced below
        , minor_scratch()
        , target_scratch()
    {
        // Your original sizing, but aligned up so typed spans are more likely aligned.
        std::size_t raw_block = (max_section_pairs * max_element_bytes) / 4;
        block_size_bytes = align_up(raw_block, kPlanAlign);

        total_bytes = block_size_bytes * num_blocks + minor_scratch_bytes;

        mem = LayoutPlanner(total_bytes);

        // bind minor scratch once at end
        auto minor_off = total_bytes - minor_scratch_bytes;
        minor_scratch.rebind(static_cast<std::byte*>(mem.data()) + minor_off, minor_scratch_bytes);

        // target_scratch is rebound per phase
        target_scratch.rebind(mem.data(), 0);
    }

    // ============================================================
    // Phase accessors
    // ============================================================
    XsViews xs()
    {
        auto out = mem.span<Xs_Candidate>(slot_pos(BlockSlot::PrimaryOut), max_pairs);
        auto post_sort_tmp = mem.span<Xs_Candidate>(slot_pos(BlockSlot::XsPostSortTmp), max_pairs);

        minor_scratch.reset();
        return { out, post_sort_tmp, minor_scratch };
    }

    T1Views t1()
    {
        auto out = mem.span<T1Pairing>(slot_pos(BlockSlot::PrimaryOut), max_pairs);
        auto post_sort_tmp = mem.span<T1Pairing>(slot_pos(BlockSlot::T1PostSortTmp), max_pairs);

        target_scratch.rebind(
            static_cast<std::byte*>(mem.data()) + slot_pos(BlockSlot::T1TargetScratch),
            block_size_bytes * 4);
        target_scratch.reset();
        minor_scratch.reset();

        return { out, post_sort_tmp, target_scratch, minor_scratch };
    }

    T2Views t2()
    {
        auto out = mem.span<T2Pairing>(slot_pos(BlockSlot::PrimaryOut), max_pairs);
        auto post_sort_tmp = mem.span<T2Pairing>(slot_pos(BlockSlot::T2PostSortTmp), max_pairs);

        target_scratch.rebind(
            static_cast<std::byte*>(mem.data()) + slot_pos(BlockSlot::T2TargetScratch),
            block_size_bytes * 6);
        target_scratch.reset();
        minor_scratch.reset();

        return { out, post_sort_tmp, target_scratch, minor_scratch };
    }

    T3Views t3()
    {
        auto out = mem.span<T3Pairing>(slot_pos(BlockSlot::PrimaryOut), max_pairs);
        auto post_sort_tmp = mem.span<T3Pairing>(slot_pos(BlockSlot::T3PostSortTmp), max_pairs);

        target_scratch.rebind(
            static_cast<std::byte*>(mem.data()) + slot_pos(BlockSlot::T3TargetScratch),
            block_size_bytes * 8);
        target_scratch.reset();
        minor_scratch.reset();

        return { out, post_sort_tmp, target_scratch, minor_scratch };
    }

    // ============================================================
    // Debug: memory stats
    // ============================================================
    void print_mem_stats(std::ostream& os = std::cout, char const* header = nullptr) const
    {
        auto pct = [](std::size_t used, std::size_t cap) -> double {
            return cap ? (100.0 * static_cast<double>(used) / static_cast<double>(cap)) : 0.0;
        };

        if (header) {
            os << header << "\n";
        }

        os << "PlotLayout memory stats:\n";
        os << "  block_size_bytes             : " << block_size_bytes << " bytes\n";
        os << "  num_blocks                   : " << num_blocks << "\n";
        os << "  minor_scratch_bytes          : " << minor_scratch_bytes << " bytes\n";
        os << "  total_bytes                  : " << total_bytes << " bytes\n";
        os << "----- lifetime high watermarks -----\n";
        os << "  Lifetime minor scratch max used : "
           << minor_scratch.lifetime_high_watermark_bytes() << " bytes\n";
        os << "  Lifetime minor scratch % used   : "
           << pct(minor_scratch.lifetime_high_watermark_bytes(), minor_scratch.capacity_bytes())
           << "%\n";
        os << "  Lifetime target scratch max used: "
           << target_scratch.lifetime_high_watermark_bytes() << " bytes\n";
        os << "  Lifetime target scratch % used  : "
           << pct(target_scratch.lifetime_high_watermark_bytes(), target_scratch.capacity_bytes())
           << "%\n";
    }

    // call after construction
    std::size_t total_bytes_allocated() const noexcept { return mem.size_bytes(); }
};
