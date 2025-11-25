#pragma once

#include "pos/ProofCore.hpp"
#include "plot/PlotFile.hpp"
#include "common/Utils.hpp"
#include "pos/ProofFragmentScanFilter.hpp"
#include "pos/ProofFragment.hpp"
#include <bitset>
#include <set>
#include <optional>
#include <vector>
#include <array>
#include <limits>
#include <iostream>
#include <string>
#include <bit>

// #define DEBUG_CHAINING true

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

    std::vector<uint8_t> blob(1 + NUM_CHAIN_LINKS * 3 * 8, 0);

    size_t idx = 0;
    blob[idx++] = qp.strength;

    for (const QualityLink& ql : qp.chain_links) {
        for (ProofFragment fragment : ql.fragments) {
/*
            // This requires C++23
            if constexpr (std::endian::native == std::endian::big) {
                const uint64_t val = std::byteswap(fragment);
                memcpy(blob.data() + idx, &val, 8);
            }
            else
*/
            {
                memcpy(blob.data() + idx, &fragment, 8);
            }
            idx += 8;
        }
    }
    return blob;
}

class Prover
{
public:
    Prover(const std::array<uint8_t, 32> &challenge)
        : challenge_(challenge)
    {
    }
    /*Prover(const std::array<uint8_t, 32> &challenge, const std::string &plot_file_name)
        : challenge_(challenge), plot_file_name_(plot_file_name)
    {
    }

    // initializer with challenge and plot file contents for testing
    Prover(const std::array<uint8_t, 32> &challenge, const FlatPlotFile &plot_file)
        : challenge_(challenge), plot_(plot_file)
    {
    }*/

    ~Prover() = default;

    std::vector<QualityChain> prove(int proof_fragment_scan_filter_bits, FlatPlotFile &plot_file)
    {
        // Proving works as follows:
        // 1) Read plot file and get plot data and specific parameters.
        // 2) Scan the plot data for fragments that pass the Proof Fragment Scan Filter.
        // 3) For each passing fragment, get their Quality Links (if any) that seed the initial entries in the Quality Chains.
        // 4) For each Quality Chain, grow and expand the number of chains link by link until we reach the chain length limit (NUM_CHAIN_LINKS).

        auto &plot = plot_file.getContents();

        ProofCore proof_core(plot.params);

        BlakeHash::Result256 next_challenge = proof_core.hashing.challengeWithPlotIdHash(challenge_.data());

        // below is commented out, since assume harvesters already did plot id filtering
        //auto plot_id_filter_result = proof_core.check_plot_id_filter(plot_id_filter, challenge_);
        //if (!plot_id_filter_result.has_value())
        //{
        //    std::cerr << "Plot ID filter did not pass challenge.";
        //    return {}; // No chains can be created if plot ID filter fails.
        //}
        //BlakeHash::Result256 next_challenge = plot_id_filter_result.value();

        // 2) Scan the plot data for fragments that pass the Proof Fragment Scan Filter
        ProofFragmentScanFilter scan_filter(plot.params, next_challenge, proof_fragment_scan_filter_bits);
        //ProofFragmentScanFilter::ScanRange range = scan_filter.getScanRangeForFilter();
        std::vector<ProofFragmentScanFilter::ScanResult> filtered_fragments = scan_filter.scan(plot.data.t3_proof_fragments);
        /*size_t fragment_l_partition = proof_core.fragment_codec.get_lateral_to_t4_partition(range.start);
        std::vector<ProofFragment> t3_fragments_partition = plot.data.getT3ProofFragments(fragment_l_partition);
        std::cout << "Scan Range start fragment: " << range.start << " l_partition: " << fragment_l_partition << std::endl;
        std::cout << "Prover: Scan range for filter: [" << range.start << ", " << range.end << "]" << std::endl;
        //exit(23);
        std::vector<ProofFragmentScanFilter::ScanResult> filtered_fragments_check = scan_filter.scan(plot.data.t3_proof_fragments);
        std::vector<ProofFragmentScanFilter::ScanResult> filtered_fragments = scan_filter.scan(t3_fragments_partition);
        std::cout << "Prover: Number of fragments passing scan filter: " << filtered_fragments.size() << std::endl;
        std::cout << "Prover: Number of fragments passing scan filter (check): " << filtered_fragments_check.size() << std::endl;
        
        for (size_t i=0; i<filtered_fragments.size(); i++) {
            size_t fragment_l_partition = proof_core.fragment_codec.get_lateral_to_t4_partition(filtered_fragments[i].fragment);
            size_t fragment_r_partition = proof_core.fragment_codec.get_r_t4_partition(filtered_fragments[i].fragment);
            std::cout << "  Fragment " << i << ": " << std::hex << filtered_fragments[i].fragment << std::dec << " index: " << filtered_fragments[i].index << " l_partition: " << fragment_l_partition << " r_partition: " << fragment_r_partition << std::endl;
        }
        for (size_t i=0; i<filtered_fragments_check.size(); i++) {
            size_t fragment_l_partition = proof_core.fragment_codec.get_lateral_to_t4_partition(filtered_fragments_check[i].fragment);
            size_t fragment_r_partition = proof_core.fragment_codec.get_r_t4_partition(filtered_fragments_check[i].fragment);
            std::cout << "  Fragment Check " << i << ": " << std::hex << filtered_fragments_check[i].fragment << std::dec << " index: " << filtered_fragments_check[i].index << " l_partition: " << fragment_l_partition << " r_partition: " << fragment_r_partition << std::endl;
        }*/
        //exit(23);
        stats_.num_scan_filter_passed++;
        stats_.num_fragments_passed_scan_filter += filtered_fragments.size();

        // 3) For each passing fragment, get their Quality Links (if any) that seed the initial entries in the Quality Chains.
        // hand off to helper that builds and returns all quality chains
        return processFilteredFragments(plot_file, filtered_fragments, next_challenge);
    }

    std::vector<QualityChain> prove(int proof_fragment_scan_filter_bits, PartitionedPlotFile &plot_file)
    {
        // Proving works as follows:
        // 1) Read plot file and get plot data and specific parameters.
        // 2) Scan the plot data for fragments that pass the Proof Fragment Scan Filter.
        // 3) For each passing fragment, get their Quality Links (if any) that seed the initial entries in the Quality Chains.
        // 4) For each Quality Chain, grow and expand the number of chains link by link until we reach the chain length limit (NUM_CHAIN_LINKS).

        //plot_file.loadNonPartitionBody();
        std::cout << "Prover get Contents from plot." << std::endl;
        auto &plot = plot_file.getContents();

        ProofCore proof_core(plot.params);

        BlakeHash::Result256 next_challenge = proof_core.hashing.challengeWithPlotIdHash(challenge_.data());

        // 2) Scan the plot data for fragments that pass the Proof Fragment Scan Filter
        ProofFragmentScanFilter scan_filter(plot.params, next_challenge, proof_fragment_scan_filter_bits);
        ProofFragmentScanFilter::ScanRange range = scan_filter.getScanRangeForFilter();
        size_t fragment_l_partition = proof_core.fragment_codec.get_lateral_to_t4_partition(range.start);
        plot_file.ensurePartitionLoaded(fragment_l_partition);
        std::vector<ProofFragment> t3_fragments_partition = plot.data.t3_proof_fragments[fragment_l_partition];

        std::cout << "First t3 proof fragment in partition " << fragment_l_partition << ": " << t3_fragments_partition[0] << std::endl;
        std::cout << "Scan Range start fragment: " << range.start << " l_partition: " << fragment_l_partition << std::endl;
        std::cout << "Prover: Scan range for filter: [" << range.start << ", " << range.end << "]" << std::endl;
        exit(23);
        
        //std::vector<ProofFragmentScanFilter::ScanResult> filtered_fragments = scan_filter.scan(plot.data.t3_proof_fragments);
        /*size_t fragment_l_partition = proof_core.fragment_codec.get_lateral_to_t4_partition(range.start);
        std::vector<ProofFragment> t3_fragments_partition = plot.data.getT3ProofFragments(fragment_l_partition);
        std::cout << "Scan Range start fragment: " << range.start << " l_partition: " << fragment_l_partition << std::endl;
        std::cout << "Prover: Scan range for filter: [" << range.start << ", " << range.end << "]" << std::endl;
        //exit(23);
        std::vector<ProofFragmentScanFilter::ScanResult> filtered_fragments_check = scan_filter.scan(plot.data.t3_proof_fragments);
        std::vector<ProofFragmentScanFilter::ScanResult> filtered_fragments = scan_filter.scan(t3_fragments_partition);
        std::cout << "Prover: Number of fragments passing scan filter: " << filtered_fragments.size() << std::endl;
        std::cout << "Prover: Number of fragments passing scan filter (check): " << filtered_fragments_check.size() << std::endl;
        
        for (size_t i=0; i<filtered_fragments.size(); i++) {
            size_t fragment_l_partition = proof_core.fragment_codec.get_lateral_to_t4_partition(filtered_fragments[i].fragment);
            size_t fragment_r_partition = proof_core.fragment_codec.get_r_t4_partition(filtered_fragments[i].fragment);
            std::cout << "  Fragment " << i << ": " << std::hex << filtered_fragments[i].fragment << std::dec << " index: " << filtered_fragments[i].index << " l_partition: " << fragment_l_partition << " r_partition: " << fragment_r_partition << std::endl;
        }
        for (size_t i=0; i<filtered_fragments_check.size(); i++) {
            size_t fragment_l_partition = proof_core.fragment_codec.get_lateral_to_t4_partition(filtered_fragments_check[i].fragment);
            size_t fragment_r_partition = proof_core.fragment_codec.get_r_t4_partition(filtered_fragments_check[i].fragment);
            std::cout << "  Fragment Check " << i << ": " << std::hex << filtered_fragments_check[i].fragment << std::dec << " index: " << filtered_fragments_check[i].index << " l_partition: " << fragment_l_partition << " r_partition: " << fragment_r_partition << std::endl;
        }
        //exit(23);
        stats_.num_scan_filter_passed++;
        stats_.num_fragments_passed_scan_filter += filtered_fragments.size();

        // 3) For each passing fragment, get their Quality Links (if any) that seed the initial entries in the Quality Chains.
        // hand off to helper that builds and returns all quality chains
        // return empty
        */
        return {};
        //return processFilteredFragments(plot_file, filtered_fragments, next_challenge);
    }

    // Build quality chains from the filtered fragments
    std::vector<QualityChain> processFilteredFragments(
        FlatPlotFile &plotfile,
        const std::vector<ProofFragmentScanFilter::ScanResult> &filtered_fragments,
        const BlakeHash::Result256 &next_challenge)
    {
        std::vector<QualityChain> all_chains;
        const FlatPlotFile::Contents &plot = plotfile.getContents();
        ProofCore proof_core(plot.params);
        FragmentsPattern firstPattern = proof_core.requiredPatternFromChallenge(next_challenge);

        #ifdef DEBUG_CHAINING
        std::cout << "Required pattern from challenge: " << static_cast<int>(firstPattern) << std::endl;
        #endif
        // uint32_t chaining_hash_pass_threshold = proof_core.quality_chain_pass_threshold();

        std::cout << "Found fragments passing filter: " << filtered_fragments.size() << std::endl;
        for (const auto &frag_res : filtered_fragments)
        {
            uint64_t fragment = frag_res.fragment;
            uint32_t l_partition = proof_core.fragment_codec.get_lateral_to_t4_partition(fragment);
            uint32_t r_partition = proof_core.fragment_codec.get_r_t4_partition(fragment);

            // load partition data
            #ifdef DEBUG_CHAINING
            std::cout << "read partitions for file: " << plot_file_name_ << std::endl;
            #endif
            plotfile.ensurePartitionLoaded(l_partition);
            plotfile.ensurePartitionLoaded(r_partition);
            //plot_->ensurePartitionT4T5BackPointersLoaded(plot_file_name_, l_partition);
            //plot_->ensurePartitionT4T5BackPointersLoaded(plot_file_name_, r_partition);

            #ifdef DEBUG_CHAINING
            // std::cout << "          Total partitions: " << plot.params.get_num_partitions() << std::endl;
            std::cout << "          Partition A(L): " << l_partition << std::endl;
            std::cout << "          Partition R(R): " << r_partition << std::endl;
            #endif

            std::vector<QualityLink> firstLinks = plot.data.getFirstQualityLinks(
                FragmentsParent::PARENT_NODE_IN_OTHER_PARTITION,
                firstPattern,
                frag_res.index,
                r_partition);

            #ifdef DEBUG_CHAINING
            std::cout << " # First Quality Links: " << firstLinks.size() << std::endl;
            for (const auto &link : firstLinks)
            {
                std::cout << "  First Link Fragments: "
                          << std::hex << link.fragments[0] << ", "
                          << link.fragments[1] << ", "
                          << link.fragments[2] << std::dec
                          << " | Pattern: " << static_cast<int>(link.pattern);
            }
            #endif

            std::vector<QualityLink> links = plot.data.getQualityLinks(l_partition, r_partition);

            #ifdef DEBUG_CHAINING
            std::cout << " # First Quality Links: " << firstLinks.size() << std::endl;
            std::cout << " # Links: " << links.size() << std::endl;

            // output some stastistics about unique fragments and x-bits found
            // useful to check for bit drop saturation
            std::set<uint64_t> unique_fragments;
            std::set<uint64_t> unique_x_bits;
            for (const auto &link : links)
            {
                for (int i = 0; i < 3; i++)
                {
                    unique_fragments.insert(link.fragments[i]);
                    std::array<uint32_t, 4> x_bits = proof_core.fragment_codec.get_x_bits_from_proof_fragment(link.fragments[i]);
                    unique_x_bits.insert(x_bits[0]);
                    unique_x_bits.insert(x_bits[1]);
                    unique_x_bits.insert(x_bits[2]);
                    unique_x_bits.insert(x_bits[3]);
                }
            }
            std::cout << "Unique fragments found: " << unique_fragments.size() << std::endl;
            std::cout << "Unique x-bits found: " << unique_x_bits.size() << std::endl;
            
            #endif

            // 4) For each Quality Chain, grow and expand the number of chains link by link until we reach the chain length limit (NUM_CHAIN_LINKS).
            for (const auto &firstLink : firstLinks)
            {
                std::vector<QualityChain> qualityChains = createQualityChains(plotfile.getProofParams(), firstLink, links, next_challenge);
                // add to all chains
                all_chains.insert(all_chains.end(), qualityChains.begin(), qualityChains.end());
            }
        }

        return all_chains;
    }


    

    std::vector<QualityChain> createQualityChains(const ProofParams &params, const QualityLink &firstLink, const std::vector<QualityLink> &link_set, const BlakeHash::Result256 &next_challenge)
    {
        // QualityChainer quality_chainer(plot_.value().params, challenge_, chaining_hash_pass_threshold);

        std::vector<QualityChain> quality_chains;

        ProofCore proof_core_(params);

        // First, create new chain for each first link
        QualityChain chain;
        chain.strength = params.get_strength();
        chain.chain_links[0] = firstLink; // the first link is always the first in the chain

        chain.chain_hash = proof_core_.firstLinkHash(firstLink, next_challenge); // set the hash for the first link
        quality_chains.push_back(chain);

        stats_.num_first_chain_links++;


        #ifdef DEBUG_CHAINING
        std::cout << "First challenge hash: " << next_challenge.toString() << std::endl;
        #endif

        for (int depth = 1; depth < NUM_CHAIN_LINKS; ++depth)
        {
            // std::cout << "=== Depth " << depth + 1 << " ===\n";

            // If we have no chains, we cannot grow further
            if (quality_chains.empty())
            {
                // std::cout << "No chains to grow at depth " << depth + 1 << std::endl;
                break;
            }
            // std::cout << "  Current number of chains: " << quality_chains.size() << std::endl;

            std::vector<QualityChain> new_chains;
            // size_t total_hashes = 0;

            // For each chain-so-far, try appending every possible link
            for (auto &qc : quality_chains)
            {
                auto new_links = proof_core_.getNewLinksForChain(qc.chain_hash, link_set, depth);

                #ifdef DEBUG_CHAINING
                std::cout << "Next challenge hash (" << depth << "): " << qc.chain_hash.toString() << std::endl;
                #endif

                // if we have new links, create new chains
                for (const auto &new_link_result : new_links)
                {
                    QualityChain qc2 = qc; // copy old chain
                    qc2.chain_links[depth] = new_link_result.link;
                    qc2.chain_hash = new_link_result.new_hash; // update the hash
                    new_chains.push_back(std::move(qc2));
                }
            }
            // swap in the newly grown set
            quality_chains.swap(new_chains);
        }

        stats_.num_quality_chains += quality_chains.size();

        return quality_chains;
    }

    std::vector<uint64_t> getAllProofFragmentsForProof(QualityChain const& chain, FlatPlotFile &plotfile)
    {
        return plotfile.getContents().data.getAllProofFragmentsForProof(chain);
    }

    void setChallenge(const std::array<uint8_t, 32> &challenge)
    {
        challenge_ = challenge;
    }

    void showStats() const
    {
        std::cout << "Prover Stats:" << std::endl;
        std::cout << "  Number of scan filter passed: " << stats_.num_scan_filter_passed << std::endl;
        std::cout << "  Number of fragments passed scan filter: "
            << numeric_cast<double>(stats_.num_fragments_passed_scan_filter) << " ("
            << (numeric_cast<double>(stats_.num_fragments_passed_scan_filter) * 100.0 / numeric_cast<double>(stats_.num_scan_filter_passed))
            << "%)" << std::endl;
        std::cout << "  Number of first chain links: " << numeric_cast<double>(stats_.num_first_chain_links) << " ("
            << (numeric_cast<double>(stats_.num_first_chain_links) * 100.0 / numeric_cast<double>(stats_.num_fragments_passed_scan_filter))
            << "%)" << std::endl;
        std::cout << "  Number of quality chains found: " << numeric_cast<double>(stats_.num_quality_chains) << " ("
            << (numeric_cast<double>(stats_.num_quality_chains) * 100.0 / numeric_cast<double>(stats_.num_first_chain_links))
            << "%)" << std::endl;
    }

private:
    std::array<uint8_t, 32> challenge_;

    struct stats
    {
        int num_scan_filter_passed = 0;
        size_t num_fragments_passed_scan_filter = 0;
        int num_first_chain_links = 0;
        size_t num_quality_chains = 0;
    } stats_;
};
