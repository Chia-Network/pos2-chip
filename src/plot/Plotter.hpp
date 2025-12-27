#pragma once

#include <array>
#include <cstdint>
#include <iostream>
#include <memory_resource>
#include <optional>
#include <string>
#include <vector>

#include "LayoutPlanner.hpp"
#include "PlotData.hpp"
#include "TableConstructorGeneric.hpp"
#include "common/Timer.hpp"
#include "pos/ProofCore.hpp"

#define DEBUG_MEMORY_USAGE_PLOTTING 0

class Plotter {
public:
    // Construct with a hexadecimal plot ID, k parameter, and sub-k parameter
    Plotter(ProofParams const& proof_params)
        : proof_params_(proof_params)
        , fragment_codec_(proof_params)
        , validator_(proof_params)
    {
    }

    // Execute the plotting pipeline
    PlotData run()
    {
        Timer totalPlotTimer;
        totalPlotTimer.start();
        std::cout << "Starting plotter..." << std::endl;
        proof_params_.debugPrint();

#if HAVE_AES
        std::cout << "Using AES hardware acceleration for hashing." << std::endl;
#else
        std::cout << "AES hardware acceleration not available. Using software hashing."
                  << std::endl;
#endif

        Timer allocationTimer;
        allocationTimer.debugOut = true;
        // size_t max_pairs = max_pairs_per_table_possible(proof_params_);
        size_t max_section_pairs = max_pairs_per_section_possible(proof_params_);
        size_t num_sections = static_cast<size_t>(proof_params_.get_num_sections());
        size_t max_pairs = max_section_pairs * num_sections;

        size_t max_element_bytes = std::max(
            { sizeof(Xs_Candidate), sizeof(T1Pairing), sizeof(T2Pairing), sizeof(T3Pairing) });

        size_t minor_scratch_bytes = 512 * 1024; // 512 KiB for minor scratch

        // will split memory into 32 blocks, using pattern outlined in documentation.
        size_t num_blocks = 32;
        size_t block_size_bytes = max_section_pairs * max_element_bytes / 4;
        size_t total_memory_needed = block_size_bytes * num_blocks + minor_scratch_bytes;

        // use a lambda for a local helper
        auto get_block_pos = [block_size_bytes](size_t block_index) -> size_t {
            return block_index * block_size_bytes;
        };

#if DEBUG_MEMORY_USAGE_PLOTTING
        std::cout << "Planning memory for plotting:" << std::endl;
        std::cout << "  Max pairs per section: " << max_section_pairs << std::endl;
        std::cout << "  Number of sections: " << num_sections << std::endl;
        std::cout << "  Max element size: " << max_element_bytes << " bytes" << std::endl;
        std::cout << "  Number of blocks: " << num_blocks << std::endl;
        std::cout << "  Minor scratch bytes: " << minor_scratch_bytes << " bytes" << std::endl;
        std::cout << "  Block size bytes: " << block_size_bytes << " bytes" << std::endl;
        std::cout << "  Total memory needed: " << total_memory_needed << " bytes" << std::endl;
#endif
        allocationTimer.start("Allocating Buffers: " + std::to_string(total_memory_needed));
        LayoutPlanner mem(total_memory_needed);
        allocationTimer.stop();

        // views:
        auto xs_out = mem.span<Xs_Candidate>(get_block_pos(0), max_pairs);
        auto xs_tmp = mem.span<Xs_Candidate>(get_block_pos(24), max_pairs);
        auto minor_scratch_arena
            = mem.make_arena(total_memory_needed - minor_scratch_bytes, minor_scratch_bytes);

        minor_scratch_arena.reset(); // before use.
        XsConstructor xs_gen_ctor(proof_params_);
        auto xs_candidates = xs_gen_ctor.construct(xs_out, xs_tmp, minor_scratch_arena);
        xs_gen_ctor.timings.show();
        std::cout << "Constructed " << xs_candidates.size() << " Xs candidates.\n";
#if DEBUG_MEMORY_USAGE_PLOTTING
        std::cout << "  Scratch arena size: " << minor_scratch_arena.capacity_bytes() << " bytes\n";
        std::cout << "  Scratch arena max used: " << minor_scratch_arena.high_watermark_bytes()
                  << " bytes\n";
        std::cout << "  Scratch arena % used: "
                  << (100.0 * static_cast<double>(minor_scratch_arena.high_watermark_bytes())
                         / static_cast<double>(minor_scratch_arena.capacity_bytes()))
                  << "%\n";
        print_rss("[After Xs Generation]");
#endif

        assert(xs_candidates.data() == xs_tmp.data());
        // 2) Table 1
        if (xs_candidates.data() == xs_out.data()) {
            std::cout
                << "Sub-optimal: copying Xs candidates to tmp buffer for Table 1 construction.\n";
            std::copy(xs_out.begin(), xs_out.end(), xs_tmp.begin());
            xs_candidates = xs_tmp.first(xs_candidates.size());
        }

        std::span<T1Pairing> t1_out = mem.span<T1Pairing>(get_block_pos(0), max_pairs);
        std::span<T1Pairing> t1_tmp = mem.span<T1Pairing>(get_block_pos(14), max_pairs);
        auto target_scratch_arena = mem.make_arena(get_block_pos(20), block_size_bytes * 4);

        Table1Constructor t1_ctor(proof_params_, target_scratch_arena, minor_scratch_arena);
        auto t1_pairs = t1_ctor.construct(xs_candidates, t1_out, t1_tmp);
        t1_ctor.timings.show("Table 1 Timings");
#if DEBUG_MEMORY_USAGE_PLOTTING
        std::cout << "Constructed " << t1_pairs.size() << " T1 entries\n";
        std::cout << "  Target scratch arena size      : " << target_scratch_arena.capacity_bytes()
                  << " bytes\n";
        std::cout << "  Target scratch arena max used  : "
                  << target_scratch_arena.high_watermark_bytes() << " bytes\n";
        std::cout << "  Target scratch arena % used    : "
                  << (100.0 * static_cast<double>(target_scratch_arena.high_watermark_bytes())
                         / static_cast<double>(target_scratch_arena.capacity_bytes()))
                  << "%\n";
#endif
        assert(t1_pairs.data() == t1_tmp.data());
        assert(t1_pairs.size() <= max_pairs);
        if (t1_pairs.data() == t1_out.data()) {
            std::cout << "Sub-optimal: copying T1 pairs to tmp buffer for Table 1 construction.\n";
            std::copy(t1_out.begin(), t1_out.end(), t1_tmp.begin());
            t1_pairs = t1_tmp.first(t1_pairs.size());
        }

#ifdef RETAIN_X_VALUES
        if (validate_) {
            for (auto const& pair: t1_pairs) {
                uint32_t xs[2] = { static_cast<uint32_t>(pair.meta >> proof_params_.get_k()),
                    static_cast<uint32_t>(pair.meta & ((1 << proof_params_.get_k()) - 1)) };
                auto result = validator_.validate_table_1_pair(xs);
                if (!result.has_value()) {
                    std::cerr << "Validation failed for Table 1 pair: [" << xs[0] << ", " << xs[1]
                              << "]\n";
                    exit(23);
                }
            }
            std::cout << "Table 1 pairs validated successfully." << std::endl;
        }
#endif

        // 3) Table 2
        std::cout << "Starting Table2 construction" << std::endl;

        // t1 pairs will be overwritten by t2 pairs, but those t1 pairs would not be needed by the
        // time overwrites happen.
        std::span<T2Pairing> t2_out = mem.span<T2Pairing>(get_block_pos(0), max_pairs);
        std::span<T2Pairing> t2_tmp = mem.span<T2Pairing>(get_block_pos(16), max_pairs);
        target_scratch_arena
            = mem.make_arena(get_block_pos(26), block_size_bytes * 6); // our t1 scratch bytes
        minor_scratch_arena.reset();

        Table2Constructor t2_ctor(proof_params_, target_scratch_arena, minor_scratch_arena);
        auto t2_pairs = t2_ctor.construct(t1_pairs, t2_out, t2_tmp);
        t2_ctor.timings.show("Table 2 Timings:");
        std::cout << "Constructed " << t2_pairs.size() << " Table 2 pairs.\n";

#if DEBUG_MEMORY_USAGE_PLOTTING
        std::cout << "  Minor scratch arena size      : " << minor_scratch_arena.capacity_bytes()
                  << " bytes\n";
        std::cout << "  Minor scratch arena max used  : "
                  << minor_scratch_arena.high_watermark_bytes() << " bytes\n";
        std::cout << "  Minor scratch arena % used    : "
                  << (100.0 * static_cast<double>(minor_scratch_arena.high_watermark_bytes())
                         / static_cast<double>(minor_scratch_arena.capacity_bytes()))
                  << "%\n";
        std::cout << "  Target scratch arena size      : " << target_scratch_arena.capacity_bytes()
                  << " bytes\n";
        std::cout << "  Target scratch arena max used  : "
                  << target_scratch_arena.high_watermark_bytes() << " bytes\n";
        std::cout << "  Target scratch arena % used    : "
                  << (100.0 * static_cast<double>(target_scratch_arena.high_watermark_bytes())
                         / static_cast<double>(target_scratch_arena.capacity_bytes()))
                  << "%\n";
        print_rss("[After Table2]");
#endif

#ifdef RETAIN_X_VALUES
        if (validate_) {
            for (auto const& pair: t2_pairs) {
                auto result = validator_.validate_table_2_pairs(pair.xs);
                if (!result.has_value()) {
                    std::cerr << "Validation failed for Table 2 pair: [" << pair.xs[0] << ", "
                              << pair.xs[1] << ", " << pair.xs[2] << ", " << pair.xs[3] << "]\n";
                    exit(23);
                }
            }
            std::cout << "Table 2 pairs validated successfully." << std::endl;
        }
#endif

        assert(t2_pairs.data() == t2_tmp.data());
        assert(t2_pairs.size() <= max_pairs);
        if (t2_pairs.data() == t2_out.data()) {
            std::cout << "Sub-optimal: copying T2 pairs to tmp buffer for Table 2 construction.\n";
            std::copy(t2_out.begin(), t2_out.end(), t2_tmp.begin());
            t2_pairs = t2_tmp.first(t2_pairs.size());
        }

        // 4) Table 3
        std::cout << "Starting Table3 construction" << std::endl;
        std::span<T3Pairing> t3_out = mem.span<T3Pairing>(get_block_pos(0), max_pairs);
        std::span<T3Pairing> t3_tmp = mem.span<T3Pairing>(get_block_pos(8), max_pairs);
        target_scratch_arena
            = mem.make_arena(get_block_pos(8), block_size_bytes * 8); // our t2 scratch bytes
        minor_scratch_arena.reset();

        Table3Constructor t3_ctor(proof_params_, target_scratch_arena, minor_scratch_arena);
        auto t3_results = t3_ctor.construct(t2_pairs, t3_out, t3_tmp);
        t3_ctor.timings.show("Table 3 Timings:");
        std::cout << "Constructed " << t3_results.size() << " Table 3 entries.\n";

#if DEBUG_MEMORY_USAGE_PLOTTING
        std::cout << "  Minor scratch arena size      : " << minor_scratch_arena.capacity_bytes()
                  << " bytes\n";
        std::cout << "  Minor scratch arena max used  : "
                  << minor_scratch_arena.high_watermark_bytes() << " bytes\n";
        std::cout << "  Minor scratch arena % used    : "
                  << (100.0 * static_cast<double>(minor_scratch_arena.high_watermark_bytes())
                         / static_cast<double>(minor_scratch_arena.capacity_bytes()))
                  << "%\n";
        std::cout << "  Target scratch arena size      : " << target_scratch_arena.capacity_bytes()
                  << " bytes\n";
        std::cout << "  Target scratch arena max used  : "
                  << target_scratch_arena.high_watermark_bytes() << " bytes\n";
        std::cout << "  Target scratch arena % used    : "
                  << (100.0 * static_cast<double>(target_scratch_arena.high_watermark_bytes())
                         / static_cast<double>(target_scratch_arena.capacity_bytes()))
                  << "%\n";
        std::cout << "----- lifetime high watermarks -----\n";
        std::cout << "  Lifetime minor scratch arena max used  : "
                  << minor_scratch_arena.lifetime_high_watermark_bytes() << " bytes\n";
        std::cout << "  Lifetime Minor scratch arena % used    : "
                  << (100.0
                         * static_cast<double>(minor_scratch_arena.lifetime_high_watermark_bytes())
                         / static_cast<double>(minor_scratch_arena.capacity_bytes()))
                  << "%\n";
        std::cout << "  Lifetime Target scratch arena max used     : "
                  << target_scratch_arena.lifetime_high_watermark_bytes() << " bytes\n";
        std::cout << "  Lifetime Target scratch arena % used    : "
                  << (100.0
                         * static_cast<double>(target_scratch_arena.lifetime_high_watermark_bytes())
                         / static_cast<double>(target_scratch_arena.capacity_bytes()))
                  << "%\n";

        print_rss("[After Table3]");
#endif

#if AES_COUNT_HASHES
        showHashCounts();
#endif

#ifdef RETAIN_X_VALUES
        if (validate_) {
            for (auto const& t3_pair: t3_results) {
                auto const& xs_array = t3_pair.xs;
                auto result = validator_.validate_table_3_pairs(xs_array.data());
                if (!result.has_value()) {
                    std::cerr << "Validation failed for Table 3 pair: [" << xs_array[0] << ", "
                              << xs_array[1] << ", " << xs_array[2] << ", " << xs_array[3] << ", "
                              << xs_array[4] << ", " << xs_array[5] << ", " << xs_array[6] << ", "
                              << xs_array[7] << "]\n";
                    exit(23);
                }
            }
            std::cout << "Table 3 pairs validated successfully." << std::endl;
        }
#endif

        decltype(t1_ctor)::Timings total_timings;
        total_timings.hash_time_ms = xs_gen_ctor.timings.hash_time_ms + t1_ctor.timings.hash_time_ms
            + t2_ctor.timings.hash_time_ms + t3_ctor.timings.hash_time_ms;
        total_timings.sort_time_ms = xs_gen_ctor.timings.sort_time_ms + t1_ctor.timings.sort_time_ms
            + t2_ctor.timings.sort_time_ms + t3_ctor.timings.sort_time_ms;
        total_timings.find_pairs_time_ms = t1_ctor.timings.find_pairs_time_ms
            + t2_ctor.timings.find_pairs_time_ms + t3_ctor.timings.find_pairs_time_ms;
        total_timings.post_sort_time_ms = t1_ctor.timings.post_sort_time_ms
            + t2_ctor.timings.post_sort_time_ms + t3_ctor.timings.post_sort_time_ms;
        total_timings.misc_time_ms = t1_ctor.timings.misc_time_ms + t2_ctor.timings.misc_time_ms
            + t3_ctor.timings.misc_time_ms;
        total_timings.show("Total Plotting Timings:");

        std::cout << "Total plotting time: " << totalPlotTimer.stop() << " ms." << std::endl;

        auto dummy_data = PlotData {};
        // Return a default-constructed PlotData to avoid relying on specific member names here.
        std::vector<ProofFragment> t3_proof_fragments;
        t3_proof_fragments.reserve(t3_results.size());
        for (auto const& t3_pair: t3_results) {
            t3_proof_fragments.push_back(t3_pair.proof_fragment);
        }
        dummy_data.t3_proof_fragments = t3_proof_fragments;

        print_rss("[After Dummy]");

        return dummy_data;
    }

    ProofParams getProofParams() const { return proof_params_; }

    void setValidate(bool validate) { validate_ = validate; }

private:
    ProofParams proof_params_;
    ProofFragmentCodec fragment_codec_;

    // Timing utility
    Timer timer_;

    // Debugging: validate as we go
    bool validate_ = true;
    ProofValidator validator_;
};

// Helper: convert hex string to 32-byte array
inline std::array<uint8_t, 32> hexToBytes(std::string const& hex)
{
    std::array<uint8_t, 32> bytes {};
    for (size_t i = 0; i < bytes.size(); ++i) {
        auto byte_str = hex.substr(2 * i, 2);
        bytes[i] = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
    }
    return bytes;
}
