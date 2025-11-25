#pragma once

#include <vector>
#include <array>
#include "pos/ProofCore.hpp"

struct Range {
    uint64_t start;
    uint64_t end;

    // ranges are INCLUSIVE
    bool isInRange(uint64_t value) const {
        return value >= start && value <= end;
    }

    bool operator==(const Range& other) const = default;
};

// plot structure with absolute indexed back pointers into t3 (i.e. the actual fragment_index_l/r values into t3)
struct PlotData {
    std::vector<ProofFragment> t3_proof_fragments;
    #ifdef RETAIN_X_VALUES_TO_T3
    std::vector<std::array<uint32_t, 8>> xs_correlating_to_proof_fragments;
    #endif

    bool operator==(PlotData const& other) const = default;
};


struct ChunkedProofFragments {
    std::vector<std::vector<ProofFragment>> proof_fragments_chunks;

    static PlotData convertToPlotData(ChunkedProofFragments const& chunked_data) {
        PlotData plot_data;
        plot_data.t3_proof_fragments.clear();

        for (const auto& chunk : chunked_data.proof_fragments_chunks) {
            plot_data.t3_proof_fragments.insert(
                plot_data.t3_proof_fragments.end(),
                chunk.begin(),
                chunk.end()
            );
        }

        return plot_data;
    }

    // Static factory: computes num_spans automatically from data + scan_span.
    static ChunkedProofFragments convertToChunkedProofFragments(PlotData const& plot_data,
                                                    uint64_t avg_elements_per_partition)
    {
        if (avg_elements_per_partition == 0) {
            throw std::invalid_argument("avg_elements_per_partition must be > 0");
        }

        ChunkedProofFragments partitioned_data;

        if (plot_data.t3_proof_fragments.empty()) {
            // nothing to do
            return partitioned_data;
        }

        // Because t3_proof_fragments are sorted, we can just look at the last one
        uint64_t max_value = plot_data.t3_proof_fragments.back();
        uint64_t num_spans = max_value / avg_elements_per_partition + 1;
        std::cout << "Max value was: " << max_value << ", num_spans: " << num_spans << std::endl;

        partitioned_data.proof_fragments_chunks.resize(
            static_cast<std::size_t>(num_spans)
        );

        std::size_t current_span = 0;
        uint64_t current_span_end = avg_elements_per_partition;

        for (const ProofFragment& fragment : plot_data.t3_proof_fragments) {
    
            // advance span until fragment fits in [current_span * scan_span, current_span_end)
            while (fragment >= current_span_end) {
                ++current_span;
                current_span_end += avg_elements_per_partition;

                // safety: this should never trigger if num_spans was computed correctly
                if (current_span >= num_spans) {
                    throw std::runtime_error("span index out of range while bucketing fragments");
                }
            }

            partitioned_data.proof_fragments_chunks[current_span].push_back(fragment);
        }

        return partitioned_data;
    }


    bool operator==(ChunkedProofFragments const& other) const = default;
};
