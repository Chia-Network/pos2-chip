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
        PlotGroupParams const& plot_group_params = plot_file_.getGroupParams();
    
        PlotProofParams plot_proof_params = getPlotProofParams();

        SelectedChallengeSets selected_sets = ChallengeSetSelector::selectChallengeSets(
                                                plot_group_params, challenge);

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

    PlotGroupParams const& getGroupParams() { return plot_file_.getGroupParams(); }

    PlotProofParams getPlotProofParams() {
        return plot_file_.getProofParams();
    }

private:
    PlotFile plot_file_;
    std::string plot_file_name_;
};

struct PlotQualityChains {
    std::vector<QualityChain> quality_chains;
    uint16_t plot_index;
};

class GroupProver {
public:
    GroupProver(std::string const& plot_group_path)
        : plot_group_(PlotGroupFile::open(plot_group_path))
        , plot_group_path_(plot_group_path)
    {}
    ~GroupProver() = default;

    // NOTE: plot_index_base is only useful for testing single-plot groups of non-zero index.
    //       This effectively sets the PlotProofData at the expected index so that
    //       the proofs can validate properly.
    //       Normally plot groups are assumed to be packed and starting at index zero,
    //       so this is merely a workaround for testing.
    std::vector<PlotQualityChains> prove(std::span<uint8_t const, 32> const challenge, uint16_t plot_index_base = 0)
    {
        // Since this is only meant for single-plot groups, we're enforcing it here
        if (plot_index_base != 0 && plot_group_.getInfo().group_size > 1) {
            throw std::runtime_error("Non-zero plot index base for a multi-plot group");
        }

        // use proof core to find the proof fragment sets
        PlotGroupParams group_params = plot_group_.getGroupProofParams();

        std::array<std::vector<std::vector<ProofFragment>>, NUM_CHALLENGE_SETS> proof_fragments_per_set_per_plot;
        for (int i = 0; i < NUM_CHALLENGE_SETS; ++i) {
            SelectedChallengeSets selected_sets = ChallengeSetSelector::selectChallengeSets(group_params, challenge);
            proof_fragments_per_set_per_plot[i] = plot_group_.readProofsInRange(selected_sets.fragment_set_ranges[i]);
        }

        PlotGroupFile::Info info = plot_group_.getInfo();

        // now Chainer to find quality chains from these proof fragments
        std::vector<PlotQualityChains> quality_chains_per_plot(info.group_size);

        for (uint16_t plot_index = 0; plot_index < info.group_size; plot_index++) {
            std::array<std::span<ProofFragment const>, NUM_CHALLENGE_SETS> plot_chain_set;

            for (int i = 0; i < NUM_CHALLENGE_SETS; ++i) {
                plot_chain_set[i] = proof_fragments_per_set_per_plot[i][plot_index];
            }

            PlotProofParams plot_proof_params = group_params.get_plot_params_for_index(plot_index_base + plot_index);
            Chainer chainer(plot_proof_params, challenge);

            std::vector<Chain> chains = chainer.find_links(plot_chain_set);

            PlotQualityChains& pc = quality_chains_per_plot[plot_index];
            pc.plot_index = plot_index_base + plot_index;

            for (Chain const& chain: chains) {
                QualityChain qc;
                qc.chain_links = chain.fragments;
                pc.quality_chains.push_back(qc);
            }
        }

        return quality_chains_per_plot;
    }

    PlotGroupFile& getPlotGroup()
    {
        return plot_group_;
    }

private:
    PlotGroupFile plot_group_;
    std::string plot_group_path_;
};
