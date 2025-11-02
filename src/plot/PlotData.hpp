#pragma once

#include <vector>
#include <array>
#include "pos/ProofCore.hpp"

struct Range {
    uint32_t start;
    uint32_t end;

    // ranges are INCLUSIVE
    bool isInRange(uint32_t value) const {
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

struct PartitionedBackPointer {
    private:
    uint32_t l;
    uint32_t r;

    public:

    struct Input {
        uint32_t l_absolute_t3_index;
        uint32_t r_absolute_t3_index;
        uint32_t t3_l_partition_range_start;
        uint32_t t3_r_partition;
        uint32_t t3_r_partition_range_start;
        int num_partition_bits;
    };

    // l between 0...partition_size always maps to r between partition_size+1 to 2*partition_size
    // when setting pointer, save 1 bit by reducing r partition by num_partitions if it's > num_partitions.
    void setPointer(const Input& input) {
        // both l and r partitions will be even or odd exclusively
        // so we can set r partition to even value, then halve it. 
        // Reconstruct with get function based on the l partition parity
        l = input.l_absolute_t3_index - input.t3_l_partition_range_start;
        uint32_t num_partitions = 1 << input.num_partition_bits;
        uint32_t r_mapped = input.t3_r_partition >= num_partitions ?
                           input.t3_r_partition - num_partitions :
                           input.t3_r_partition;
        //bool r_is_even = (input.t3_r_partition % 2) == 0;
        //uint32_t mapped_r_t3_partition = r_is_even ? input.t3_r_partition / 2 : (input.t3_r_partition - 1) / 2;
        //r = ((input.r_absolute_t3_index - input.t3_r_partition_range_start) << input.num_partition_bits) + mapped_r_t3_partition;
        r = ((input.r_absolute_t3_index - input.t3_r_partition_range_start) << (input.num_partition_bits)) + r_mapped;
    }

    struct Result {
        uint32_t l_in_partition;
        uint32_t r_in_partition;
        uint32_t r_t3_partition;
    };

    // need l partition to reconstruct r t3 partition. r partition will be in opposite half of l partition, so add num_partitions if needed.
    Result getPointer(uint32_t l_partition, const int num_partition_bits) const {
        uint32_t l_in_partition = l;
        uint32_t num_partitions = 1 << num_partition_bits;

        //uint32_t r_in_partition = r >> (num_partition_bits + 1);
        //uint32_t r_t3_partition = (r & ((1 << (num_partition_bits + 1)) - 1));
        
        uint32_t r_in_partition = r >> num_partition_bits;
        uint32_t r_t3_partition = (r & ((1 << num_partition_bits) - 1));

        if (l_partition < num_partitions) {
            // l partition is low, so r partition is high
            r_t3_partition += num_partitions;
        }
        return { l_in_partition, r_in_partition, r_t3_partition};
        /*uint32_t r_t3_partition = 2 * (r & ((1 << num_partition_bits) - 1));
        if (l_partition % 2 == 0) {
            r_t3_partition += 1;
        }
        uint32_t r_in_partition = r >> num_partition_bits;
        return {l_in_partition, r_in_partition, r_t3_partition};*/
    }

    bool operator==(PartitionedBackPointer const &o) const {
        return (l == o.l) && (r == o.r);
    }
};

struct PartitionedPlotData {
    std::vector<std::vector<ProofFragment>> t3_proof_fragments;
    std::vector<std::vector<PartitionedBackPointer>> t4_to_t3_back_pointers;
    // these pointers are encoded where r is max(l)+r.
    std::vector<std::vector<T5PlotBackPointers>> t5_to_t4_back_pointers;
    
    #ifdef RETAIN_X_VALUES_TO_T3
    std::vector<std::array<uint32_t, 8>> xs_correlating_to_proof_fragments;
    #endif

    bool operator==(PartitionedPlotData const& other) const = default;
};


