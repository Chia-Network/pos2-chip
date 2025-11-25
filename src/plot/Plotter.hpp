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
    Plotter(const std::span<uint8_t const, 32> plot_id, uint8_t k, uint8_t strength)
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
        std::vector<T3Pairing> t3_results = t3_ctor.construct(t2_pairs);
        timer_.stop();
        std::cout << "Constructed " << t3_results.size() << " Table 3 entries." << std::endl;

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

        // Return a default-constructed PlotData to avoid relying on specific member names here.
        auto dummy_data = PlotData{};
        std::vector<ProofFragment> t3_proof_fragments;
        t3_proof_fragments.reserve(t3_results.size());
        for (const auto& t3_pair : t3_results) {
            t3_proof_fragments.push_back(t3_pair.proof_fragment);
        }
        dummy_data.t3_proof_fragments = t3_proof_fragments;
        return dummy_data;
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
    uint8_t k_;

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

