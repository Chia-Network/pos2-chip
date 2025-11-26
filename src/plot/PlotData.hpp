#pragma once

#include <vector>
#include <array>
#include "pos/ProofCore.hpp"

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
                                                    uint64_t range_per_chunk)
    {
        if (range_per_chunk == 0) {
            throw std::invalid_argument("range_per_chunk must be > 0");
        }

        ChunkedProofFragments chunked_data;

        if (plot_data.t3_proof_fragments.empty()) {
            // nothing to do
            return chunked_data;
        }

        // Because t3_proof_fragments are sorted, we can just look at the last one
        uint64_t max_value = plot_data.t3_proof_fragments.back();
        uint64_t num_spans = max_value / range_per_chunk + 1;
        std::cout << "Max value was: " << max_value << ", num_spans: " << num_spans << std::endl;

        chunked_data.proof_fragments_chunks.resize(
            static_cast<std::size_t>(num_spans)
        );

        std::size_t current_span = 0;
        uint64_t current_span_end = range_per_chunk;

        for (const ProofFragment& fragment : plot_data.t3_proof_fragments) {
    
            // advance span until fragment fits in [current_span * scan_span, current_span_end)
            while (fragment >= current_span_end) {
                ++current_span;
                current_span_end += range_per_chunk;

                // safety: this should never trigger if num_spans was computed correctly
                if (current_span >= num_spans) {
                    throw std::runtime_error("span index out of range while bucketing fragments");
                }
            }

            chunked_data.proof_fragments_chunks[current_span].push_back(fragment);
        }

        return chunked_data;
    }


    bool operator==(ChunkedProofFragments const& other) const = default;
};
