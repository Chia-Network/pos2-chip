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

class Plotter {
public:
    // Construct with a hexadecimal plot ID, k parameter, and sub-k parameter
    Plotter(const std::string& plot_id_hex, int k, int sub_k)
      : plot_id_(hexToBytes(plot_id_hex)), k_(k), sub_k_(sub_k),
        proof_params_(plot_id_.data(), k_, sub_k_), xs_encryptor_(proof_params_) {}

    // Execute the plotting pipeline
    PlotData run() {
        std::cout << "Starting plotter..." << std::endl;

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

        // 3) Table2 generic
        Table2Constructor t2_ctor(proof_params_);
        timer_.start("Constructing Table 2");
        auto t2_pairs = t2_ctor.construct(t1_pairs);
        timer_.stop();
        std::cout << "Constructed " << t2_pairs.size() << " Table 2 pairs." << std::endl;

        // 4) Table3 generic
        Table3Constructor t3_ctor(proof_params_);
        timer_.start("Constructing Table 3");
        auto t3_results = t3_ctor.construct(t2_pairs);
        timer_.stop();
        std::cout << "Constructed " << t3_results.encrypted_xs.size() << " Table 3 entries." << std::endl;

        // 5) Prepare pruner
        TablePruner pruner(proof_params_, t3_results.encrypted_xs);

        // 6) Partitioned Table4 + Table5
        std::vector<std::vector<T4BackPointers>> all_t4;
        std::vector<std::vector<T5Pairing>> all_t5;
        ProofParams sub_params(plot_id_.data(), sub_k_);

        for (size_t pid = 0; pid < t3_results.partitioned_pairs.size(); ++pid) {
            const auto& partition = t3_results.partitioned_pairs[pid];

            timer_.start("Building t3/4 partition " + std::to_string(pid));

            Table4PartitionConstructor t4_ctor(sub_params, proof_params_.get_k());
            auto t4_res = t4_ctor.construct(partition);
            
            Table5GenericConstructor t5_ctor(sub_params);
            auto t5_pairs = t5_ctor.construct(t4_res.pairs);
            
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
            .t3_encrypted_xs = t3_results.encrypted_xs,
            .t4_to_t3_lateral_ranges = t4_to_t3_lateral_partition_ranges,
            .t4_to_t3_back_pointers = all_t4,
            .t5_to_t4_back_pointers = all_t5,
            #ifdef RETAIN_X_VALUES_TO_T3
            .xs_correlating_to_encrypted_xs = t3_results.xs_correlating_to_encrypted_xs,
            #endif
        };
    }

    ProofParams getProofParams() const {
        return proof_params_;
    }

    XsEncryptor getXsEncryptor() const {
        return xs_encryptor_;
    }

private:
    // Helper: convert hex string to 32-byte array
    std::array<uint8_t, 32> hexToBytes(const std::string& hex) {
        std::array<uint8_t, 32> bytes{};
        for (size_t i = 0; i < bytes.size(); ++i) {
            auto byte_str = hex.substr(2 * i, 2);
            bytes[i] = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
        }
        return bytes;
    }

    // Plot identifiers and parameters
    std::array<uint8_t, 32> plot_id_;
    int k_;
    int sub_k_;

    // Core PoSpace objects
    ProofParams proof_params_;
    XsEncryptor xs_encryptor_;

    // Timing utility
    Timer timer_;
};
