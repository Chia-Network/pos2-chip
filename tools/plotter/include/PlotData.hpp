#pragma once

#include <pos/ProofCore.hpp>
#include <vector>

// plot structure with absolute indexed back pointers into t3 (i.e. the actual encx_index_l/r values into t3)
struct PlotData {
    std::vector<uint64_t> t3_encrypted_xs;
    std::vector<std::vector<T4BackPointers>> t4_to_t3_back_pointers;
    std::vector<std::vector<T5Pairing>> t5_to_t4_back_pointers;
    #ifdef RETAIN_X_VALUES
    std::vector<std::array<uint32_t, 8>> xs_correlating_to_encrypted_xs;
    #endif

    bool operator==(PlotData const& other) const = default;
};