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

using T4ToT3LateralPartitionRanges = std::vector<Range>;

struct T4PlotBackPointers {
    uint32_t l;
    uint32_t r;
    #ifdef RETAIN_X_VALUES
    uint32_t xs[16];
    #endif

    bool operator==(T4PlotBackPointers const &o) const = default;
};

struct T5PlotBackPointers {
    uint32_t l;
    uint32_t r;
    #ifdef RETAIN_X_VALUES
    uint32_t xs[32];
    #endif

    bool operator==(T5PlotBackPointers const &o) const = default;
};

// plot structure with absolute indexed back pointers into t3 (i.e. the actual fragment_index_l/r values into t3)
struct PlotData {
    std::vector<ProofFragment> t3_proof_fragments;
    T4ToT3LateralPartitionRanges t4_to_t3_lateral_ranges; // the range of t3 indexes that get referenced by the l pointers in a t4 partition.
    std::vector<std::vector<T4PlotBackPointers>> t4_to_t3_back_pointers;
    std::vector<std::vector<T5PlotBackPointers>> t5_to_t4_back_pointers;
    #ifdef RETAIN_X_VALUES_TO_T3
    std::vector<std::array<uint32_t, 8>> xs_correlating_to_proof_fragments;
    #endif

    bool operator==(PlotData const& other) const = default;
};
