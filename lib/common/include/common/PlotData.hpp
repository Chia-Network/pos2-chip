#pragma once

#include <pos/ProofCore.hpp>
#include <vector>
#include <array>

struct Range {
    uint64_t start;
    uint64_t end;

    bool operator==(const Range& other) const {
        return start == other.start && end == other.end;
    }
};

using T4ToT3LateralPartitionRanges = std::vector<Range>;

// plot structure with absolute indexed back pointers into t3 (i.e. the actual encx_index_l/r values into t3)
struct PlotData {
    std::vector<uint64_t> t3_encrypted_xs;
    T4ToT3LateralPartitionRanges t4_to_t3_lateral_ranges; // the range of t3 indexes that get referenced by the l pointers in a t4 partition.
    std::vector<std::vector<T4BackPointers>> t4_to_t3_back_pointers;
    std::vector<std::vector<T5Pairing>> t5_to_t4_back_pointers;
    #ifdef RETAIN_X_VALUES_TO_T3
    std::vector<std::array<uint32_t, 8>> xs_correlating_to_encrypted_xs;
    #endif

    bool operator==(PlotData const& other) const = default;
};