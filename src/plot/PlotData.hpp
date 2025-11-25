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
