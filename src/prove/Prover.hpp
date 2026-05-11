#pragma once

#include "common/Utils.hpp"
#include "plot/PlotFile.hpp"
#include "pos/Chainer.hpp"
#include "pos/ProofCore.hpp"
#include "pos/ProofFragment.hpp"
#include <array>
#include <bit>
#include <bitset>
#include <iostream>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <vector>

// #define DEBUG_PROVER true

// serializes the QualityProof into the form that will be hashed together with
// the challenge to determine the quality of ths proof. The quality is used to
// check if it passes the current difficulty. The format is:
// 1 byte: plot strength
// repeat 16 times:
//   8 bytes: little-endian proof fragment
inline std::vector<uint8_t> serializeQualityProof(QualityChain const& qp, uint8_t const strength)
{

    static_assert(sizeof(ProofFragment) == 8, "proof fragments are expected to be 64 bits");

    // Each chain link has 3 proof fragments, each 64-bits wide.
    // The first byte is the strength

    std::vector<uint8_t> blob(1 + NUM_CHAIN_LINKS * 8, 0);

    size_t idx = 0;
    blob[idx++] = strength;

    for (ProofFragment const& fragment: qp.chain_links) {
        /*
                    // This requires C++23
                    if constexpr (std::endian::native == std::endian::big) {
                        const uint64_t val = std::byteswap(fragment);
                        memcpy(blob.data() + idx, &val, 8);
                    }
                    else
        */
        memcpy(blob.data() + idx, &fragment, 8);
        idx += 8;
    }
    return blob;
}

class Prover {
public:
    Prover(std::string const& plot_file_name) : plot_file_(plot_file_name) {}
    ~Prover() = default;

    std::vector<QualityChain> prove(std::span<uint8_t const, 32> const challenge)
    {
        // use proof core to find the proof fragment sets
        ProofParams const& plot_proof_params = plot_file_.getProofParams();

        ProofCore proof_core(plot_proof_params);

        ProofCore::SelectedChallengeSets selected_sets = proof_core.selectChallengeSets(challenge);

#ifdef DEBUG_PROVER
        for (int i = 0; i < NUM_CHALLENGE_SETS; ++i) {
            std::cout << "  Set " << i << ": index=" << selected_sets.fragment_set_indexes[i]
                      << ", range=[" << selected_sets.fragment_set_ranges[i].start << ", "
                      << selected_sets.fragment_set_ranges[i].end << "]\n";
        }
#endif

        // Read all NUM_CHALLENGE_SETS fragment lists from the plot.
        std::array<std::vector<ProofFragment>, NUM_CHALLENGE_SETS> proof_fragments_per_set;
        for (int i = 0; i < NUM_CHALLENGE_SETS; ++i) {
            proof_fragments_per_set[i]
                = plot_file_.getProofFragmentsInRange(selected_sets.fragment_set_ranges[i]);
        }

// check count of proof fragments
#ifdef DEBUG_PROVER
        for (int i = 0; i < NUM_CHALLENGE_SETS; ++i) {
            std::cout << "Challenge selected fragment set " << i
                      << " index: " << selected_sets.fragment_set_indexes[i] << ", range: ["
                      << selected_sets.fragment_set_ranges[i].start << ", "
                      << selected_sets.fragment_set_ranges[i].end << "]"
                      << ", count: " << proof_fragments_per_set[i].size() << std::endl;
        }
#endif

        // Build span array for the Chainer.
        std::array<std::span<ProofFragment const>, NUM_CHALLENGE_SETS> fragments_per_set;
        for (int i = 0; i < NUM_CHALLENGE_SETS; ++i) {
            fragments_per_set[i] = proof_fragments_per_set[i];
        }

        // now Chainer to find quality chains from these proof fragments
        Chainer chainer(plot_proof_params, challenge);
        std::vector<Chain> chains = chainer.find_links(fragments_per_set);
        std::vector<QualityChain> quality_chains;
        for (Chain const& chain: chains) {
            QualityChain qc;
            qc.chain_links = chain.fragments;
            quality_chains.push_back(qc);
        }
        return quality_chains;
    }

    ProofParams const& getProofParams() { return plot_file_.getProofParams(); }

private:
    PlotFile plot_file_;
    std::string plot_file_name_;
};
