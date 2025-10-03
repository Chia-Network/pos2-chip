#pragma once

#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "common/Timer.hpp"
#include "pos/ProofCore.hpp"
#include "PlotData.hpp"

#include "TableConstructorGeneric.hpp"
#include "TablePruner.hpp"
// #include "TableCompressor.hpp"

namespace {
    template <typename T, size_t N>
    std::array<T, N> to_array(std::span<T const, N> input) {
        std::array<T, N> ret;
        std::copy(input.begin(), input.end(), ret.begin());
        return ret;
    }
}

class Plotter {
public:
    // Construct with a hexadecimal plot ID, k parameter, and sub-k parameter
    Plotter(const std::span<uint8_t const, 32> plot_id, int k, int strength)
      : plot_id_(to_array(plot_id)), k_(k),
        proof_params_(plot_id_.data(), k_, strength), fragment_codec_(proof_params_), validator_(proof_params_) {}

    // Execute the plotting pipeline
    PlotData run() {
        std::cout << "Starting plotter..." << std::endl;
        proof_params_.debugPrint();

        // 1) Construct Xs candidates
        XsConstructor xs_gen_ctor(proof_params_);
        timer_.start("Constructing Xs candidates");
        auto xs_candidates = xs_gen_ctor.construct();
        timer_.stop();
        std::cout << "Constructed " << xs_candidates.size() << " Xs candidates." << std::endl;

        // 2) Table1 generic
        Table1Constructor t1_ctor(proof_params_);
        timer_.start("Constructing Table 1");
        auto t1_pairs = t1_ctor.construct(xs_candidates);
        timer_.stop();
        std::cout << "Constructed " << t1_pairs.size() << " Table 1 pairs." << std::endl;

        #ifdef RETAIN_X_VALUES
        if (validate_) {
            for (const auto& pair : t1_pairs) {
                uint32_t xs[2] = { 
                    static_cast<uint32_t>(pair.meta >> proof_params_.get_k()), 
                    static_cast<uint32_t>(pair.meta & ((1 << proof_params_.get_k()) - 1)) };
                auto result = validator_.validate_table_1_pair(xs);
                if (!result.has_value()) {
                    std::cerr << "Validation failed for Table 1 pair: ["
                              << xs[0] << ", " << xs[1] << "]\n";
                    exit(23);
                }
            }
            std::cout << "Table 1 pairs validated successfully." << std::endl;
        }
        #endif

        // 3) Table2 generic
        Table2Constructor t2_ctor(proof_params_);
        timer_.start("Constructing Table 2");
        auto t2_pairs = t2_ctor.construct(t1_pairs);
        timer_.stop();
        std::cout << "Constructed " << t2_pairs.size() << " Table 2 pairs." << std::endl;

        #ifdef RETAIN_X_VALUES
        if (validate_) {
            for (const auto& pair : t2_pairs) {
                auto result = validator_.validate_table_2_pairs(pair.xs);
                if (!result.has_value()) {
                    std::cerr << "Validation failed for Table 2 pair: ["
                              << pair.xs[0] << ", " << pair.xs[1] << ", " << pair.xs[2] << ", " << pair.xs[3] << "]\n";
                    exit(23);
                }
            }
            std::cout << "Table 2 pairs validated successfully." << std::endl;
        }
        #endif

        // 4) Table3 generic
        Table3Constructor t3_ctor(proof_params_);
        timer_.start("Constructing Table 3");
        T3_Partitions_Results t3_results = t3_ctor.construct(t2_pairs);
        timer_.stop();
        std::cout << "Constructed " << t3_results.proof_fragments.size() << " Table 3 entries." << std::endl;

        #ifdef RETAIN_X_VALUES
        if (validate_) {
            for (const auto& xs_array : t3_results.xs_correlating_to_proof_fragments) {
                auto result = validator_.validate_table_3_pairs(xs_array.data());
                if (!result.has_value()) {
                    std::cerr << "Validation failed for Table 3 pair: ["
                              << xs_array[0] << ", " << xs_array[1] << ", " << xs_array[2] << ", " << xs_array[3] 
                              << ", " << xs_array[4] << ", " << xs_array[5] << ", " << xs_array[6] << ", " << xs_array[7]
                              << "]\n";
                    exit(23);
                }
            }
            std::cout << "Table 3 pairs validated successfully." << std::endl;
        }
        #endif

        // 5) Prepare pruner
        
        #ifdef RETAIN_X_VALUES_TO_T3
        TablePruner pruner(proof_params_, t3_results.proof_fragments, t3_results.xs_correlating_to_proof_fragments);
        #else
        TablePruner pruner(proof_params_, t3_results.proof_fragments);
        #endif

        // 6) Partitioned Table4 + Table5
        std::vector<std::vector<T4BackPointers>> all_t4;
        std::vector<std::vector<T5Pairing>> all_t5;
        ProofParams sub_params(plot_id_.data(), proof_params_.get_sub_k(), 2);

        for (size_t pid = 0; pid < t3_results.partitioned_pairs.size(); ++pid) {
            const auto& partition = t3_results.partitioned_pairs[pid];

            timer_.start("Building t3/4 partition " + std::to_string(pid));

            Table4PartitionConstructor t4_ctor(sub_params, proof_params_.get_k());
            T4_Partition_Result t4_res = t4_ctor.construct(partition);

            #ifdef RETAIN_X_VALUES
            if (validate_) {
                for (const auto& pair : t4_res.pairs) {
                    std::vector<T4Pairing> res = validator_.validate_table_4_pairs(pair.xs);
                    if (res.size() == 0) {
                        std::cerr << "Validation failed for Table 4 pair" << std::endl;
                        exit(23);
                    }
                }
                std::cout << "Table 4 pairs validated successfully." << std::endl;
            }
            #endif
            
            Table5GenericConstructor t5_ctor(sub_params);
            std::vector<T5Pairing> t5_pairs = t5_ctor.construct(t4_res.pairs);

            #ifdef RETAIN_X_VALUES
            if (validate_) {
                for (const auto& pair : t5_pairs) {
                    if (!validator_.validate_table_5_pairs(pair.xs)) {
                        std::cerr << "Validation failed for Table 5 pair" << std::endl;
                        exit(23);
                    }
                }
                std::cout << "Table 5 pairs validated successfully." << std::endl;
            }
            #endif
            
            TablePruner::PrunedStats stats = pruner.prune_t4_and_update_t5(t4_res.t4_to_t3_back_pointers, t5_pairs);
            
            all_t4.push_back(std::move(t4_res.t4_to_t3_back_pointers));
            all_t5.push_back(std::move(t5_pairs));

            timer_.stop();
            std::cout << "Processed partition " << pid << ": " << std::endl
                      << "  T4 size: " << all_t4.back().size() << " (before pruning: " << stats.original_count << ")" << std::endl
                      << "  T5 size: " << all_t5.back().size()
                      << std::endl;
        }

        // 7) Finalize pruning
        timer_.start("Finalizing Table 3");
        T4ToT3LateralPartitionRanges t4_to_t3_lateral_partition_ranges = pruner.finalize_t3_and_prepare_mappings_for_t4();
        timer_.stop();
        
        timer_.start("Finalizing Table 4");
        for (auto& t4bp : all_t4) pruner.finalize_t4_partition(t4bp);
        timer_.stop();

        return {
            .t3_proof_fragments = t3_results.proof_fragments,
            .t4_to_t3_lateral_ranges = t4_to_t3_lateral_partition_ranges,
            .t4_to_t3_back_pointers = all_t4,
            .t5_to_t4_back_pointers = all_t5,
            #ifdef RETAIN_X_VALUES_TO_T3
            .xs_correlating_to_proof_fragments = t3_results.xs_correlating_to_proof_fragments,
            #endif
        };
    }

    ProofParams getProofParams() const {
        return proof_params_;
    }

    ProofFragmentCodec getProofFragment() const {
        return fragment_codec_;
    }

    void setValidate(bool validate) {
        validate_ = validate;
    }

private:
    // Plot identifiers and parameters
    std::array<uint8_t, 32> plot_id_;
    int k_;

    // Core PoSpace objects
    ProofParams proof_params_;
    ProofFragmentCodec fragment_codec_;

    // Timing utility
    Timer timer_;

    // Debugging: validate as we go
    bool validate_ = true;
    ProofValidator validator_;
};

// Helper: convert hex string to 32-byte array
inline std::array<uint8_t, 32> hexToBytes(const std::string& hex) {
    std::array<uint8_t, 32> bytes{};
    for (size_t i = 0; i < bytes.size(); ++i) {
        auto byte_str = hex.substr(2 * i, 2);
        bytes[i] = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
    }
    return bytes;
}

