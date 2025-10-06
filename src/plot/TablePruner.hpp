#include <iostream>
#include <vector>
#include <cstdint>

#include "pos/ProofCore.hpp"
#include "PlotData.hpp"

class TablePruner
{
public:
    #ifdef RETAIN_X_VALUES_TO_T3
    std::vector<std::array<uint32_t, 8>> &xs_correlating_to_proof_fragments;
    #endif
private:
    // t3 proof fragments (to be pruned later)
    std::vector<uint64_t> &t3_proof_fragments;

   


    // Bitmask for t3 used entries (each bit represents whether an entry is used)
    std::vector<uint8_t> t3_used_entries_bitmask;

    // Mapping for t3: maps original t3 index to new (pruned) index.
    std::vector<int64_t> t3_new_mapping;

    ProofParams params_;

    // Helper function: set the bit at position index in a given bitmask.
    void setBitmask(std::vector<uint8_t> &bitmask, size_t index)
    {
        bitmask[index / 8] |= static_cast<uint8_t>(1 << (index % 8));
    }

    // Helper function: test if bit at position index is set in a given bitmask.
    bool isUsed(const std::vector<uint8_t> &bitmask, size_t index) const
    {
        return (bitmask[index / 8] & (1 << (index % 8))) != 0;
    }

public:
    #ifdef RETAIN_X_VALUES_TO_T3
    TablePruner(const ProofParams &proof_params, std::vector<uint64_t> &t3, std::vector<std::array<uint32_t, 8>> &xs)
    : t3_proof_fragments(t3),
        xs_correlating_to_proof_fragments(xs),
        params_(proof_params),
{
    size_t num_bitmask_bytes = (t3_proof_fragments.size() + 7) / 8;
    t3_used_entries_bitmask.assign(num_bitmask_bytes, 0);
}
    #else
    TablePruner(const ProofParams &proof_params, std::vector<uint64_t> &t3)
    : t3_proof_fragments(t3),
      params_(proof_params)
{
    size_t num_bitmask_bytes = (t3_proof_fragments.size() + 7) / 8;
    t3_used_entries_bitmask.assign(num_bitmask_bytes, 0);
}
    #endif

    struct PrunedStats
    {
        uint32_t original_count;
        uint32_t pruned_count;
    };

    // -------------------------------------------------------------------------
    // prune_t4_and_update_t5:
    //   Given a partition’s t4 pointers and t5 back pointers:
    //     - computes a bitmask for used t4 entries based on t5 data,
    //     - creates a new mapping for t4 entries (pruning unused),
    //     - updates t5 entries to refer to pruned t4 indexes,
    //     - and calls prune_t4_partition() to update t4 pointers.
    // -------------------------------------------------------------------------
    PrunedStats prune_t4_and_update_t5(
        std::vector<T4BackPointers> &t4_partition_pointers_to_t3,
        std::vector<T5Pairing> &t5_partition_back_pointers_to_t4)
    {
        size_t num_bitmask_bytes = (t4_partition_pointers_to_t3.size() + 7) / 8;
        std::vector<uint8_t> t4_used_entries_bitmask(num_bitmask_bytes, 0);

        // Mark all t4 entries that are referenced by t5.
        for (const auto &pairing : t5_partition_back_pointers_to_t4)
        {
            setBitmask(t4_used_entries_bitmask, pairing.t4_index_l);
            setBitmask(t4_used_entries_bitmask, pairing.t4_index_r);
        }

        // Create a new mapping from original t4 indices to pruned indices.
        int t4_pruned_index = 0;
        std::vector<int> t4_new_mapping(t4_partition_pointers_to_t3.size(), -1);
        for (size_t i = 0; i < t4_partition_pointers_to_t3.size(); ++i)
        {
            if (isUsed(t4_used_entries_bitmask, i))
            {
                t4_new_mapping[i] = t4_pruned_index;
                ++t4_pruned_index;
            }
        }

        // std::cout << "Pruned t4, original length: " << t4_partition_pointers_to_t3.size()
        //           << " pruned length: " << t4_pruned_index << std::endl;

        // Update t5 entries with the new t4 indexes.
        for (auto &pairing : t5_partition_back_pointers_to_t4)
        {
            pairing.t4_index_l = static_cast<uint32_t>(t4_new_mapping[pairing.t4_index_l]);
            pairing.t4_index_r = static_cast<uint32_t>(t4_new_mapping[pairing.t4_index_r]);
        }

        // Process the t4 partition pointers.
        return prune_t4_partition(t4_used_entries_bitmask, t4_partition_pointers_to_t3);
    }

    // -------------------------------------------------------------------------
    // prune_t4_partition:
    //   For a given t4 partition:
    //     - Scans through its pointers,
    //     - For each used t4 entry (as determined by the provided bitmask),
    //         * tags t3 entries (in t3_used_entries_bitmask) as used,
    //         * and compacts the vector in place.
    // -------------------------------------------------------------------------
    PrunedStats prune_t4_partition(
        const std::vector<uint8_t> &t4_used_entries_bitmask,
        std::vector<T4BackPointers> &t4_partition_back_pointers_to_t3)
    {
        size_t last_used_t4_index = 0;
        for (size_t i = 0; i < t4_partition_back_pointers_to_t3.size(); ++i)
        {
            if (isUsed(t4_used_entries_bitmask, i))
            {
                // Mark the referenced t3 entries as used.
                setBitmask(t3_used_entries_bitmask, t4_partition_back_pointers_to_t3[i].fragment_index_l);
                setBitmask(t3_used_entries_bitmask, t4_partition_back_pointers_to_t3[i].fragment_index_r);
                // Move this t4 pointer to the next position in the compacted array.
                t4_partition_back_pointers_to_t3[last_used_t4_index] = t4_partition_back_pointers_to_t3[i];
                last_used_t4_index++;
            }
        }

        PrunedStats stats = {
            .original_count = (uint32_t)t4_partition_back_pointers_to_t3.size(),
            .pruned_count = (uint32_t)last_used_t4_index};

        // Remove unused t4 entries.
        t4_partition_back_pointers_to_t3.erase(
            t4_partition_back_pointers_to_t3.begin() + last_used_t4_index,
            t4_partition_back_pointers_to_t3.end());

        return stats;
    }

    // -------------------------------------------------------------------------
    // prepare_t3_mappings_for_t4:
    //   After all t4 partitions have been processed and have tagged t3 used entries,
    //   creates a new mapping for t3 indices and prints the pruned counts.
    // -------------------------------------------------------------------------
    T4ToT3LateralPartitionRanges finalize_t3_and_prepare_mappings_for_t4()
    {
        size_t t3_pruned_index = 0;
        t3_new_mapping.clear();
        t3_new_mapping.resize(t3_proof_fragments.size(), -1);

        // Prepare lateral partition ranges
        T4ToT3LateralPartitionRanges ranges(params_.get_num_partitions() * 2, {t3_proof_fragments.size(), 0});
        ProofFragmentCodec fragment_codec(params_);

        for (size_t i = 0; i < t3_proof_fragments.size(); ++i)
        {
            
            if (isUsed(t3_used_entries_bitmask, i))
            {
                t3_new_mapping[i] = t3_pruned_index;
                t3_proof_fragments[t3_pruned_index] = t3_proof_fragments[i];
                #ifdef RETAIN_X_VALUES_TO_T3
                xs_correlating_to_proof_fragments[t3_pruned_index] = xs_correlating_to_proof_fragments[i];
                #endif

                // classify lateral partition
                uint32_t lateral = fragment_codec.get_lateral_to_t4_partition(t3_proof_fragments[t3_pruned_index]);
                
                // update this partition's range at new index
                // ranges are inclusive
                auto &r = ranges[lateral];
                r.start = std::min(r.start, (uint64_t)t3_pruned_index);
                r.end = std::max(r.end, (uint64_t)t3_pruned_index);

                ++t3_pruned_index;
            }
            else
            {
                t3_new_mapping[i] = -1;
            }
        }

        t3_proof_fragments.resize(t3_pruned_index);
        #ifdef RETAIN_X_VALUES_TO_T3
        xs_correlating_to_proof_fragments.resize(t3_pruned_index);
        #endif

        return ranges;
    }

    // -------------------------------------------------------------------------
    // finalize_t4_partition:
    //   For a given partition’s t4 pointers, update each pointer to refer to the new
    //   t3 indexes from the prepared t3_new_mapping.
    // -------------------------------------------------------------------------
    void finalize_t4_partition(std::vector<T4BackPointers> &t4_partition_back_pointers_to_t3)
    {
        for (auto &bp : t4_partition_back_pointers_to_t3)
        {
            bp.fragment_index_l = t3_new_mapping[bp.fragment_index_l];
            bp.fragment_index_r = t3_new_mapping[bp.fragment_index_r];
        }
    }

    // -------------------------------------------------------------------------
    // finalize_t3_entries:
    //   Compacts the t3_proof_fragments vector by retaining only entries that were tagged
    //   as used in the t3_used_entries_bitmask.
    // -------------------------------------------------------------------------
    void finalize_t3_entries()
    {

        ProofFragmentCodec fragment_codec(params_);
        //t3_lateral_t4_partition_index_start.resize(params_.get_num_partitions() * 2);
        //t3_lateral_t4_partition_index_end.resize(params_.get_num_partitions() * 2);

        // as we go through and finalize our t3 entries, also mark the start and end indexes for the lateral t3 boundaries
        size_t last_used_t3_index = 0;
        for (size_t i = 0; i < t3_proof_fragments.size(); ++i)
        {
            if (isUsed(t3_used_entries_bitmask, i))
            {
                t3_proof_fragments[last_used_t3_index] = t3_proof_fragments[i];
                last_used_t3_index++;

                //uint32_t lateral_partition = fragment_codec.get_lateral_to_t4_partition(t3_encrypted_xs[i]);
                //t3_lateral_t4_partition_index_start[lateral_partition] = std::min(t3_lateral_t4_partition_index_start[lateral_partition], (uint64_t)i);
                //t3_lateral_t4_partition_index_end[lateral_partition] = std::max(t3_lateral_t4_partition_index_end[lateral_partition], (uint64_t)i);
            }
        }
        t3_proof_fragments.resize(last_used_t3_index);
    }

    // these get set when finalizing t3 entries
    //std::vector<uint64_t> t3_lateral_t4_partition_index_start;
    //std::vector<uint64_t> t3_lateral_t4_partition_index_end;
};
