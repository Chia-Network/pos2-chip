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

    std::vector<ProofFragment> getT3ProofFragments(int partition) const {
        auto t3_partition_range = t4_to_t3_lateral_ranges[partition];
        std::cout << "T3 partition " << partition << " range: [" << t3_partition_range.start << ", " << t3_partition_range.end << "]" << std::endl;
        
        std::vector<ProofFragment> t3_proof_fragments_partition;
        for (uint32_t i = t3_partition_range.start; i <= t3_partition_range.end; ++i) {
            t3_proof_fragments_partition.push_back(t3_proof_fragments[i]);
        }
        return t3_proof_fragments_partition;
    }

    // Moved from Prover:
    std::vector<QualityLink> getFirstQualityLinks(FragmentsParent /*parent*/, FragmentsPattern required_pattern,
                                                  uint32_t t3_fragment_index, uint32_t t4_partition) const {
        std::vector<QualityLink> links;
        const auto& t3_pf = t3_proof_fragments;
        const auto& t4_bp = t4_to_t3_back_pointers[t4_partition];
        const auto& t5_bp = t5_to_t4_back_pointers[t4_partition];

        for (uint32_t t4_index = 0; t4_index < t4_bp.size(); ++t4_index) {
            const T4PlotBackPointers entry = t4_bp[t4_index];
            if (entry.r == t3_fragment_index) {
                for (size_t t5_index = 0; t5_index < t5_bp.size(); ++t5_index) {
                    const T5PlotBackPointers t5_entry = t5_bp[t5_index];
                    if ((required_pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR) && (t5_entry.l == t4_index)) {
                        QualityLink link;
                        link.fragments[0] = t3_pf[entry.l]; // LL
                        link.fragments[1] = t3_pf[entry.r]; // LR
                        T4PlotBackPointers other_entry = t4_bp[t5_entry.r];
                        link.fragments[2] = t3_pf[other_entry.l]; // RL
                        link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR;
                        link.outside_t3_index = other_entry.r; // RR
                        links.push_back(link);
                    } else if ((required_pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR) && (t5_entry.r == t4_index)) {
                        QualityLink link;
                        T4PlotBackPointers other_entry = t4_bp[t5_entry.l];
                        link.fragments[0] = t3_pf[other_entry.l]; // LL
                        link.fragments[1] = t3_pf[entry.l];       // RL
                        link.fragments[2] = t3_pf[entry.r];       // RR
                        link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR;
                        link.outside_t3_index = other_entry.r;    // LR
                        links.push_back(link);
                    }
                }
            }
        }
        return links;
    }

    std::vector<QualityLink> getQualityLinks(uint32_t partition_A, uint32_t partition_B) const {
        std::vector<QualityLink> other_partition_links =
            getQualityLinksFromT4PartitionToT3Partition(partition_B, partition_A, FragmentsParent::PARENT_NODE_IN_OTHER_PARTITION);
        std::vector<QualityLink> challenge_partition_links =
            getQualityLinksFromT4PartitionToT3Partition(partition_A, partition_B, FragmentsParent::PARENT_NODE_IN_CHALLENGE_PARTITION);

        std::vector<QualityLink> links;
        links.reserve(other_partition_links.size() + challenge_partition_links.size());
        links.insert(links.end(), other_partition_links.begin(), other_partition_links.end());
        links.insert(links.end(), challenge_partition_links.begin(), challenge_partition_links.end());
        return links;
    }

    std::vector<QualityLink> getQualityLinksFromT4PartitionToT3Partition(uint32_t partition_parent_t4,
                                                                         uint32_t partition_t3,
                                                                         FragmentsParent /*parent*/) const {
        std::vector<QualityLink> links;
        Range t3_partition_range = t4_to_t3_lateral_ranges[partition_t3];
        const auto& t3_pf = t3_proof_fragments;
        const auto& t4_bp = t4_to_t3_back_pointers[partition_parent_t4];
        const auto& t5_bp = t5_to_t4_back_pointers[partition_parent_t4];

        for (size_t t4_index = 0; t4_index < t4_bp.size(); ++t4_index) {
            T4PlotBackPointers entry = t4_bp[t4_index];
            if (!t3_partition_range.isInRange(entry.r)) continue;

            for (size_t t5_index = 0; t5_index < t5_bp.size(); ++t5_index) {
                T5PlotBackPointers t5_entry = t5_bp[t5_index];
                if (t5_entry.l == t4_index) {
                    QualityLink link;
                    T4PlotBackPointers other_entry = t4_bp[t5_entry.r];
                    link.fragments[0] = t3_pf[entry.l];       // LL
                    link.fragments[1] = t3_pf[entry.r];       // LR
                    link.fragments[2] = t3_pf[other_entry.l]; // RL
                    link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR;
                    link.outside_t3_index = other_entry.r;    // RR
                    links.push_back(link);
                }
                if (t5_entry.r == t4_index) {
                    QualityLink link;
                    T4PlotBackPointers other_entry = t4_bp[t5_entry.l];
                    link.fragments[0] = t3_pf[other_entry.l]; // LL
                    link.fragments[1] = t3_pf[entry.l];       // RL
                    link.fragments[2] = t3_pf[entry.r];       // RR
                    link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR;
                    link.outside_t3_index = other_entry.r;    // LR
                    links.push_back(link);
                }
            }
        }
        return links;
    }

    std::vector<uint64_t> getAllProofFragmentsForProof(const QualityChain& chain) const {
        std::vector<uint64_t> out;
        for (const QualityLink& link : chain.chain_links) {
            if (link.pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR) {
                out.push_back(link.fragments[0]); // LL
                uint64_t outside_fragment = t3_proof_fragments[link.outside_t3_index]; // RR
                out.push_back(outside_fragment); // LR
                out.push_back(link.fragments[1]); // RL
                out.push_back(link.fragments[2]); // RR
            } else if (link.pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR) {
                out.push_back(link.fragments[0]); // LL
                out.push_back(link.fragments[1]); // LR
                out.push_back(link.fragments[2]); // RL
                uint64_t outside_fragment = t3_proof_fragments[link.outside_t3_index]; // RR
                out.push_back(outside_fragment); // RR
            } else {
                // unknown pattern: skip or handle
            }
        }
        return out;
    }

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

    // num_partitions is the partition bits
    static size_t map_t4_to_t3_lateral_partition(size_t t4_partition, size_t num_partitions) {
        return (t4_partition < num_partitions) ? (t4_partition * 2) : ((t4_partition - num_partitions) * 2 + 1);
    }

    static size_t map_t3_lateral_partition_to_t4(size_t t3_lateral_partition, size_t num_partitions) {
        return (t3_lateral_partition % 2 == 0) ? (t3_lateral_partition / 2) : (num_partitions + (t3_lateral_partition - 1) / 2);
    }

    static PartitionedPlotData convertFromPlotData(const PlotData &plot_data, const ProofParams &params) {
        //auto map_t4_to_t3_lateral_partition = [](size_t t4_partition, size_t num_partitions) -> size_t {
        //    return (t4_partition < num_partitions)
        //        ? (t4_partition * 2)
        //        : ((t4_partition - num_partitions) * 2 + 1);
        //};

        PartitionedPlotData partitioned_data;
        const size_t num_partitions = params.get_num_partitions();
        const size_t outer = num_partitions * 2;

        partitioned_data.t3_proof_fragments.resize(outer);
        partitioned_data.t4_to_t3_back_pointers.resize(outer);
        partitioned_data.t5_to_t4_back_pointers.resize(outer);

        // Distribute t3 proof fragments into partitions
        for (size_t t4_partition_id = 0; t4_partition_id < outer; ++t4_partition_id) {
            const Range& range = plot_data.t4_to_t3_lateral_ranges[t4_partition_id];
            for (uint32_t t3_index = range.start; t3_index <= range.end; ++t3_index) {
                partitioned_data.t3_proof_fragments[t4_partition_id].push_back(plot_data.t3_proof_fragments[t3_index]);
            }
        }

        // Process t4->t3 back pointers into partitioned format
        for (size_t partition_id = 0; partition_id < outer; ++partition_id) {
            const size_t expected_t3_l_partition = map_t4_to_t3_lateral_partition(partition_id, num_partitions);
            (void)expected_t3_l_partition; // kept for parity with original, not used later

            Range t3_partition_range = plot_data.t4_to_t3_lateral_ranges[partition_id];

            for (const auto& t4_entry : plot_data.t4_to_t3_back_pointers[partition_id]) {
                // find t3_r partition by scanning ranges
                uint32_t mapped_r_partition = 0;
                uint32_t t3_r_partition_start_value = 0;

                for (size_t range_index = 0; range_index < plot_data.t4_to_t3_lateral_ranges.size(); ++range_index) {
                    const auto& range = plot_data.t4_to_t3_lateral_ranges[range_index];
                    if (range.isInRange(t4_entry.r)) {
                        // Note: Preserve original behavior by using the t4 range_index, not the mapped t3 partition.
                        mapped_r_partition = static_cast<uint32_t>(range_index);
                        t3_r_partition_start_value = range.start;
                        break;
                    }
                }

                PartitionedBackPointer partitioned_back_pointer;
                PartitionedBackPointer::Input input;
                input.l_absolute_t3_index = t4_entry.l;
                input.r_absolute_t3_index = t4_entry.r;
                input.t3_l_partition_range_start = t3_partition_range.start;
                input.t3_r_partition = mapped_r_partition;
                input.t3_r_partition_range_start = t3_r_partition_start_value;
                input.num_partition_bits = params.get_num_partition_bits();
                partitioned_back_pointer.setPointer(input);

                partitioned_data.t4_to_t3_back_pointers[partition_id].push_back(partitioned_back_pointer);
            }
        }

        // t5 partitions stay the same
        partitioned_data.t5_to_t4_back_pointers = plot_data.t5_to_t4_back_pointers;

        return partitioned_data;
    }

    bool operator==(PartitionedPlotData const& other) const = default;
};


