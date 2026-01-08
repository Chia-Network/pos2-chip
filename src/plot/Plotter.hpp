#pragma once

#include <algorithm> // std::max, std::copy
#include <array>
#include <cassert> // assert
#include <cstdint>
#include <cstdlib> // std::exit, std::strtol
#include <iostream>
#include <memory_resource>
#include <optional>
#include <stdexcept> // std::runtime_error
#include <string>
#include <vector>

#include "PlotData.hpp"
#include "PlotLayout.hpp"
#include "Progress.hpp"
#include "TableConstructorGeneric.hpp" // must come before PlotLayout.hpp (defines Xs_Candidate)
#include "common/Timer.hpp"
#include "pos/ProofCore.hpp"

#define DEBUG_MEMORY_USAGE_PLOTTING 0
#define DEVELOPER_PERFORMANCE_TIMINGS 0

class Plotter {
public:
    struct Options {
        bool validate = false;
        bool verbose = false; // (kept for API compatibility; Plotter no longer prints)
        IProgressSink* sink = &null_progress_sink(); // optional
    };

    // Construct with a hexadecimal plot ID, k parameter, and sub-k parameter
    Plotter(ProofParams const& proof_params)
        : proof_params_(proof_params)
        , fragment_codec_(proof_params)
        , validator_(proof_params)
    {
    }

    // Default options overload
    PlotData run() { return run(Options {}); }

    // Execute the plotting pipeline
    PlotData run(Options opts)
    {
        IProgressSink& sink = *opts.sink;

        ScopedEvent plot_scope(sink, ProgressEvent { .kind = EventKind::PlotBegin });
        if (plot_scope.cancelled())
            return {};

#if HAVE_AES
        ProgressEvent aes_event {
            .kind = EventKind::Note, .note_id = NoteId::HasAESHardware, .u64_0 = 1
        };
        sink.on_event(aes_event);
#else
        ProgressEvent aes_event {
            .kind = EventKind::Note, .note_id = NoteId::HasAESHardware, .u64_0 = 0
        };
        sink.on_event(aes_event);
#endif

        size_t max_section_pairs = max_pairs_per_section_possible(proof_params_);
        size_t num_sections = static_cast<size_t>(proof_params_.get_num_sections());
        size_t max_pairs = max_section_pairs * num_sections;

        size_t max_element_bytes = std::max(
            { sizeof(Xs_Candidate), sizeof(T1Pairing), sizeof(T2Pairing), sizeof(T3Pairing) });

        size_t minor_scratch_bytes = 2048 * 1024;

        // Allocate layout under a scoped progress event + timer, without making PlotLayout a
        // pointer.
        auto layout = [&]() -> PlotLayout {
            ScopedEvent alloc_scope(sink, ProgressEvent { .kind = EventKind::AllocationBegin });
            if (alloc_scope.cancelled())
                return PlotLayout(0, 0, 0, 0); // or handle via exception/early return policy

            PlotLayout l(max_section_pairs, num_sections, max_element_bytes, minor_scratch_bytes);

            ProgressEvent alloc_end_event {
                .kind = EventKind::Note,
                .note_id = NoteId::LayoutTotalBytesAllocated,
                .u64_0 = l.total_bytes_allocated(), // add generic fields, see below
            };
            sink.on_event(alloc_end_event);

            return l; // NRVO/move
        }();

        auto xsV = layout.xs();
        XsConstructor xs_gen_ctor(proof_params_, sink);
        auto xs_candidates = xs_gen_ctor.construct(xsV.out, xsV.post_sort_tmp, xsV.minor);
#if DEVELOPER_PERFORMANCE_TIMINGS
        xs_gen_ctor.timings.show();
#endif

        // shouldn't happen for k28, but can happen on smaller k sizes.
        if (xs_candidates.data() == xsV.out.data()) {
            sink.on_event(ProgressEvent {
                .kind = EventKind::Warning,
                .msg = sv_lit(
                    "Sub-optimal: copying Xs candidates to tmp buffer for Table 1 construction."),
            });
            std::copy(xsV.out.begin(), xsV.out.end(), xsV.post_sort_tmp.begin());
            xs_candidates = xsV.post_sort_tmp.first(xs_candidates.size());
        }

        auto t1V = layout.t1();
        Table1Constructor t1_ctor(proof_params_, t1V.target, t1V.minor, sink);
        auto t1_pairs = t1_ctor.construct(xs_candidates, t1V.out, t1V.post_sort_tmp);
#if DEVELOPER_PERFORMANCE_TIMINGS
        t1_ctor.timings.show("Table 1 Timings");
        std::cout << "Percentage of Table 1 output capacity used: "
                  << t1_ctor.percentage_capacity_used << " %\n";
#endif

        assert(t1_pairs.size() <= max_pairs);
        if (t1_pairs.size() > max_pairs) {
            throw std::runtime_error("Table 1 construction exceeded allocated capacity.");
        }
        if (t1_pairs.data() == t1V.out.data()) {
#if DEVELOPER_PERFORMANCE_TIMINGS
            std::cout << "Sub-optimal: copying T1 pairs to tmp buffer for Table 1 construction.\n";
#endif
            std::copy(t1V.out.begin(), t1V.out.end(), t1V.post_sort_tmp.begin());
            t1_pairs = t1V.post_sort_tmp.first(t1_pairs.size());
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

        // Table 2
        auto t2V = layout.t2();
        Table2Constructor t2_ctor(proof_params_, t2V.target, t2V.minor, sink);
        auto t2_pairs = t2_ctor.construct(t1_pairs, t2V.out, t2V.post_sort_tmp);
#if DEVELOPER_PERFORMANCE_TIMINGS
        t2_ctor.timings.show("Table 2 Timings");
        std::cout << "Percentage of Table 2 output capacity used: "
                  << t2_ctor.percentage_capacity_used << " %\n";
        std::cout << "Constructed " << t2_pairs.size() << " Table 2 pairs.\n";
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

        assert(t2_pairs.size() <= max_pairs);
        if (t2_pairs.data() == t2V.out.data()) {
#if DEVELOPER_PERFORMANCE_TIMINGS
            std::cout << "NOTE Sub-optimal: copying T2 pairs to tmp buffer for Table 2 "
                         "construction.\n";
#endif
            std::copy(t2V.out.begin(), t2V.out.end(), t2V.post_sort_tmp.begin());
            t2_pairs = t2V.post_sort_tmp.first(t2_pairs.size());
        }

        // Table 3
        auto t3V = layout.t3();
        Table3Constructor t3_ctor(proof_params_, t3V.target, t3V.minor, sink);
        auto t3_results = t3_ctor.construct(t2_pairs, t3V.out, t3V.post_sort_tmp);
#if DEVELOPER_PERFORMANCE_TIMINGS
        t3_ctor.timings.show("Table 3 Timings:");
        std::cout << "Percentage of Table 3 output capacity used: "
                  << t3_ctor.percentage_capacity_used << " %\n";
        layout.print_mem_stats();
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

        // Show total timings
#if DEVELOPER_PERFORMANCE_TIMINGS
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
#endif

        auto plot_data = PlotData {};
        // copy out the proof fragments
        std::vector<ProofFragment> t3_proof_fragments;
        t3_proof_fragments.reserve(t3_results.size());
        for (auto const& t3_pair: t3_results) {
            t3_proof_fragments.push_back(t3_pair.proof_fragment);
        }
        plot_data.t3_proof_fragments = t3_proof_fragments;

        return plot_data;
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
