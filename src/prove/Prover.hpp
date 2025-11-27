#pragma once

#include "pos/ProofCore.hpp"
#include "plot/PlotFile.hpp"
#include "common/Utils.hpp"
#include "pos/ProofFragment.hpp"
#include "pos/Chainer.hpp"
#include <bitset>
#include <set>
#include <optional>
#include <vector>
#include <array>
#include <limits>
#include <iostream>
#include <string>
#include <bit>

// #define DEBUG_PROVER true

// serializes the QualityProof into the form that will be hashed together with
// the challenge to determine the quality of ths proof. The quality is used to
// check if it passes the current difficulty. The format is:
// 1 byte: plot strength
// repeat 16 * 3 times:
//   8 bytes: little-endian proof fragment
inline std::vector<uint8_t> serializeQualityProof(QualityChain const& qp) {

    static_assert(sizeof(ProofFragment) == 8, "proof fragments are expected to be 64 bits");

    // Each chain link has 3 proof fragments, each 64-bits wide.
    // The first byte is the strength

    std::vector<uint8_t> blob(1 + NUM_CHAIN_LINKS * 8, 0);

    size_t idx = 0;
    blob[idx++] = qp.strength;

    for (const ProofFragment& fragment : qp.chain_links) {
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

class Prover
{
public:
    Prover(const std::string &plot_file_name)
        : plot_file_(plot_file_name)
    {
    }
    ~Prover() = default;

    std::vector<QualityChain> prove(const std::array<uint8_t, 32> &challenge)
    {
        // use proof core to find the proof fragment sets
        ProofParams const& plot_proof_params = plot_file_.getProofParams();

        ProofCore proof_core(plot_proof_params);

        ProofCore::SelectedChallengeSets selected_sets = proof_core.selectChallengeSets(challenge);

        #ifdef DEBUG_PROVER
        std::cout << "  Set A: index=" << selected_sets.fragment_set_A_index
                  << ", range=[" << selected_sets.fragment_set_A_range.start << ", " << selected_sets.fragment_set_A_range.end << "]\n";
        std::cout << "  Set B: index=" << selected_sets.fragment_set_B_index
                  << ", range=[" << selected_sets.fragment_set_B_range.start << ", " << selected_sets.fragment_set_B_range.end << "]\n";
        #endif

        std::vector<ProofFragment> proof_fragments_set_A = plot_file_.getProofFragmentsInRange(selected_sets.fragment_set_A_range);
        std::vector<ProofFragment> proof_fragments_set_B = plot_file_.getProofFragmentsInRange(selected_sets.fragment_set_B_range);

        // check count of proof fragments
        #ifdef DEBUG_PROVER
        std::cout << "Challenge selected fragment set A index: " << selected_sets.fragment_set_A_index
                  << ", range: [" << selected_sets.fragment_set_A_range.start << ", " << selected_sets.fragment_set_A_range.end << "]"
                  << ", count: " << proof_fragments_set_A.size() << std::endl;
        std::cout << "Challenge selected fragment set B index: " << selected_sets.fragment_set_B_index
                  << ", range: [" << selected_sets.fragment_set_B_range.start << ", " << selected_sets.fragment_set_B_range.end << "]"
                  << ", count: " << proof_fragments_set_B.size() << std::endl;
        #endif


        // now Chainer to find quality chains from these proof fragments
        Chainer chainer(plot_proof_params, challenge);
        std::vector<Chain> chains = chainer.find_links(proof_fragments_set_A, proof_fragments_set_B);
        std::vector<QualityChain> quality_chains;
        for (const Chain& chain : chains) {
            QualityChain qc;
            qc.chain_links = chain.fragments;
            qc.strength = plot_proof_params.get_strength();
            quality_chains.push_back(qc);
        }
        return quality_chains;
    }

    ProofParams const& getProofParams() {
        return plot_file_.getProofParams();
    }

private:
    PlotFile plot_file_;
    std::string plot_file_name_;
};
