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
    Prover(const std::array<uint8_t, 32> &challenge, const std::string &plot_file_name)
        : challenge_(challenge), plot_file_name_(plot_file_name)
    {
    }
    ~Prover() = default;

    void readPlotFileIfNeeded()
    {
        if (!plot_.has_value())
        {
            #ifdef DEBUG_PROOF_VALIDATOR
            std::cout << "Reading plot file: " << plot_file_name_ << std::endl;
            #endif
            plot_ = PlotFile::readData(plot_file_name_);
            #ifdef DEBUG_PROOF_VALIDATOR
            std::cout << "Plot file read successfully: " << plot_file_name_ << std::endl;
            plot_.value().params.debugPrint();
            #endif
        }
        else
        {
            #ifdef DEBUG_PROOF_VALIDATOR
            std::cout << "Plot file already read." << std::endl;
            #endif
        }
    }

    std::vector<QualityChain> prove(int proof_fragment_scan_filter_bits)
    {
        // Proving works as follows:
        // 1) Read plot file and get plot data and specific parameters.
        // 2) Scan the plot data for fragments that pass the Proof Fragment Scan Filter.
        // 3) For each passing fragment, get their Quality Links (if any) that seed the initial entries in the Quality Chains.
        // 4) For each Quality Chain, grow and expand the number of chains link by link until we reach the chain length limit (NUM_CHAIN_LINKS).

        // 1) Read plot file
        readPlotFileIfNeeded();

        PlotFile::PlotFileContents plot = plot_.value();

        // 2) Does it pass plot id filter?
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
        std::vector<ProofFragmentScanFilter::ScanResult> filtered_fragments = scan_filter.scan(plot.data.t3_proof_fragments);
        stats_.num_scan_filter_passed++;
        stats_.num_fragments_passed_scan_filter += filtered_fragments.size();

        // 3) For each passing fragment, get their Quality Links (if any) that seed the initial entries in the Quality Chains.
        // hand off to helper that builds and returns all quality chains
        return processFilteredFragments(plot, filtered_fragments, next_challenge);
    }

    // Build quality chains from the filtered fragments
    std::vector<QualityChain> processFilteredFragments(
        const PlotFile::PlotFileContents &plot,
        const std::vector<ProofFragmentScanFilter::ScanResult> &filtered_fragments,
        const BlakeHash::Result256 &next_challenge)
    {
        std::vector<QualityChain> all_chains;
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
            // extract R pointer
            uint32_t l_partition = proof_core.fragment_codec.get_lateral_to_t4_partition(fragment);
            uint32_t r_partition = proof_core.fragment_codec.get_r_t4_partition(fragment);

            #ifdef DEBUG_CHAINING
            // std::cout << "          Total partitions: " << plot.params.get_num_partitions() << std::endl;
            std::cout << "          Partition A(L): " << l_partition << std::endl;
            std::cout << "          Partition R(R): " << r_partition << std::endl;
            #endif

            std::vector<QualityLink> firstLinks = getFirstQualityLinks(FragmentsParent::PARENT_NODE_IN_OTHER_PARTITION, firstPattern, frag_res.index, r_partition);

            // output first links fragemnts in hex
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

            std::vector<QualityLink> links = getQualityLinks(l_partition, r_partition);

            #ifdef DEBUG_CHAINING
            std::cout << " # First Quality Links: " << firstLinks.size() << std::endl;
            std::cout << " # Links: " << links.size() << std::endl;
            #endif

            // analysis code
            if (false)
            {
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
            }

            // 4) For each Quality Chain, grow and expand the number of chains link by link until we reach the chain length limit (NUM_CHAIN_LINKS).
            for (const auto &firstLink : firstLinks)
            {
                std::vector<QualityChain> qualityChains = createQualityChains(firstLink, links, next_challenge);
                // add to all chains
                all_chains.insert(all_chains.end(), qualityChains.begin(), qualityChains.end());
            }
        }

        return all_chains;
    }

    std::vector<QualityChain> createQualityChains(const QualityLink &firstLink, const std::vector<QualityLink> &link_set, const BlakeHash::Result256 &next_challenge)
    {
        // QualityChainer quality_chainer(plot_.value().params, challenge_, chaining_hash_pass_threshold);

        std::vector<QualityChain> quality_chains;

        ProofCore proof_core_(plot_.value().params);

        // First, create new chain for each first link
        QualityChain chain;
        chain.strength = plot_.value().params.get_strength();
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

    std::vector<QualityLink> getFirstQualityLinks(FragmentsParent parent, FragmentsPattern required_pattern, uint64_t t3_fragment_index, uint32_t t4_partition)
    {
        std::vector<QualityLink> links;
        std::vector<ProofFragment> t3_proof_fragments = plot_.value().data.t3_proof_fragments;
        std::vector<T4BackPointers> t4_to_t3_back_pointers = plot_.value().data.t4_to_t3_back_pointers[t4_partition];
        std::vector<T5Pairing> t5_to_t4_back_pointers = plot_.value().data.t5_to_t4_back_pointers[t4_partition];
        // find the T4 entry that matches the t3_index
        for (size_t t4_index = 0; t4_index < t4_to_t3_back_pointers.size(); t4_index++)
        {
            T4BackPointers entry = t4_to_t3_back_pointers[t4_index];
            if (entry.fragment_index_r == t3_fragment_index)
            {
                // we found a T4 entry that matches the T3 index
                // now get it's parents and other fragments
                for (size_t t5_index = 0; t5_index < t5_to_t4_back_pointers.size(); t5_index++)
                // for (const auto &t5_entry : t5_to_t4_back_pointers)
                {
                    T5Pairing t5_entry = t5_to_t4_back_pointers[t5_index];

                    if ((required_pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR) && (t5_entry.t4_index_l == t4_index))
                    {
                        QualityLink link;
                        // LR link
                        link.fragments[0] = t3_proof_fragments[entry.fragment_index_l]; // LL
                        link.fragments[1] = t3_proof_fragments[entry.fragment_index_r]; // LR
                        T4BackPointers other_entry = t4_to_t3_back_pointers[t5_entry.t4_index_r];
                        link.fragments[2] = t3_proof_fragments[other_entry.fragment_index_l]; // RL
                        link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR;              // this is an LR link, so outside index is RR
                        link.outside_t3_index = other_entry.fragment_index_r;                 // RR

                        links.push_back(link);
                    }
                    else if ((required_pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR) && (t5_entry.t4_index_r == t4_index))
                    {
                        // RR link
                        QualityLink link;
                        T4BackPointers other_entry = t4_to_t3_back_pointers[t5_entry.t4_index_l];
                        link.fragments[0] = t3_proof_fragments[other_entry.fragment_index_l]; // LL
                        link.fragments[1] = t3_proof_fragments[entry.fragment_index_l];       // RL
                        link.fragments[2] = t3_proof_fragments[entry.fragment_index_r];       // RR
                        link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR;              // this is an RR link, so outside index is LR
                        link.outside_t3_index = other_entry.fragment_index_r;                 // LR

                        links.push_back(link);
                    }

                    /*if (t5_entry.t4_index_l == t4_index || t5_entry.t4_index_r == t4_index)
                    {

                        if (t5_entry.t4_index_l == t4_index)
                        {
                            QualityLink link;
                            // LR link
                            link.fragments[0] = t3_proof_fragments[entry.fragment_index_l]; // LL
                            link.fragments[1] = t3_proof_fragments[entry.fragment_index_r]; // LR
                            T4BackPointers other_entry = t4_to_t3_back_pointers[t5_entry.t4_index_r];
                            link.fragments[2] = t3_proof_fragments[other_entry.fragment_index_l]; // RL
                            link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR;              // this is an LR link, so outside index is RR
                            link.outside_t3_index = other_entry.fragment_index_r;                 // RR

                            if (required_pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR)
                            {
                                // we only add links that match the required pattern
                                links.push_back(link);
                            }
                        }
                        else
                        {
                            // RR link
                            QualityLink link;
                            T4BackPointers other_entry = t4_to_t3_back_pointers[t5_entry.t4_index_l];
                            link.fragments[0] = t3_proof_fragments[other_entry.fragment_index_l]; // LL
                            link.fragments[1] = t3_proof_fragments[entry.fragment_index_l];       // RL
                            link.fragments[2] = t3_proof_fragments[entry.fragment_index_r];       // RR
                            link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR;              // this is an RR link, so outside index is LR
                            link.outside_t3_index = other_entry.fragment_index_r;                 // LR

                            if (required_pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR)
                            {
                                // we only add links that match the required pattern
                                links.push_back(link);
                            }
                        }
                    }*/
                }
            }
        }
        return links;
    }

    std::vector<QualityLink> getQualityLinks(uint32_t partition_A, uint32_t partition_B)
    {

        std::vector<QualityLink> links;

        // std::vector<ProofFragment> t3_proof_fragments = plot_.value().data.t3_proof_fragments;

        std::vector<QualityLink> other_partition_links = getQualityLinksFromT4PartitionToT3Partition(partition_B, partition_A, FragmentsParent::PARENT_NODE_IN_OTHER_PARTITION);
        
        #ifdef DEBUG_CHAINING
        std::cout << "Found " << other_partition_links.size() << " links from partition B to A." << std::endl;
        #endif

        std::vector<QualityLink> challenge_partition_links = getQualityLinksFromT4PartitionToT3Partition(partition_A, partition_B, FragmentsParent::PARENT_NODE_IN_CHALLENGE_PARTITION);

        #ifdef DEBUG_CHAINING
        std::cout << "Found " << challenge_partition_links.size() << " links from partition A to B." << std::endl;
        #endif

        // combine both links
        links.reserve(other_partition_links.size() + challenge_partition_links.size());
        links.insert(links.end(), other_partition_links.begin(), other_partition_links.end());
        links.insert(links.end(), challenge_partition_links.begin(), challenge_partition_links.end());

        #ifdef DEBUG_CHAINING
        std::cout << "Total links found: " << links.size() << std::endl;
        #endif
        return links;
    }

    std::vector<QualityLink> getQualityLinksFromT4PartitionToT3Partition(uint32_t partition_parent_t4, uint32_t partition_t3, FragmentsParent parent)
    {
        std::vector<QualityLink> links;

        // 1. get t3 partition A range, and scan R side links from partitionB that link to partition_A
        Range t3_partition_range = plot_.value().data.t4_to_t3_lateral_ranges[partition_t3];
        std::vector<ProofFragment> t3_proof_fragments = plot_.value().data.t3_proof_fragments;
        #ifdef DEBUG_CHAINING
        std::cout << "Partition T3: " << partition_t3 << std::endl;
        std::cout << "t3_partition_range: " << t3_partition_range.start << " - " << t3_partition_range.end << std::endl;
        // 2. get t4 partition B, and find r links that point to t3 partition A range
        std::cout << "Partition Parent T4: " << partition_parent_t4 << std::endl;
        #endif
        std::vector<T4BackPointers> t4_b_to_t3 = plot_.value().data.t4_to_t3_back_pointers[partition_parent_t4];
        std::vector<T5Pairing> t5_b_to_t4_b = plot_.value().data.t5_to_t4_back_pointers[partition_parent_t4];
        int links_found = 0;
        for (size_t t4_index = 0; t4_index < t4_b_to_t3.size(); t4_index++)
        {
            T4BackPointers entry = t4_b_to_t3[t4_index];
            if (t3_partition_range.isInRange(entry.fragment_index_r))
            {

                // we found a link that points to partition A. Now, in T5 find the parent nodes, where either the l or r pointer points to this entry in T4 partition B.
                std::vector<T5Pairing> t5_parent_nodes;
                for (size_t t5_index = 0; t5_index < t5_b_to_t4_b.size(); t5_index++)
                // for (const auto &t5_entry : t5_b_to_t4_b)
                {
                    T5Pairing t5_entry = t5_b_to_t4_b[t5_index];
                    if (t5_entry.t4_index_l == t4_index)
                    {
                        QualityLink link;

                        // if t4 is the left pointer of t4 index, then the t3 entry is an LR link.
                        // and fragments will be 0:LL, 1:LR, 2:RL with outside index being RR.

                        // get other side child node
                        T4BackPointers other_entry = t4_b_to_t3[t5_entry.t4_index_r];
                        link.fragments[0] = t3_proof_fragments[entry.fragment_index_l];       // LL
                        link.fragments[1] = t3_proof_fragments[entry.fragment_index_r];       // LR
                        link.fragments[2] = t3_proof_fragments[other_entry.fragment_index_l]; // RL
                        link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR;              // this is an LR link, so outside index is RR
                        link.outside_t3_index = other_entry.fragment_index_r;                 // RR

                        links.push_back(link);
                    }
                    if (t5_entry.t4_index_r == t4_index)
                    {
                        // if t4 is the right pointer of t4 index, then the t3 entry is an RR link.
                        QualityLink link;

                        // get other side child node
                        T4BackPointers other_entry = t4_b_to_t3[t5_entry.t4_index_l];
                        link.fragments[0] = t3_proof_fragments[other_entry.fragment_index_l]; // LL
                        link.fragments[1] = t3_proof_fragments[entry.fragment_index_l];       // RL
                        link.fragments[2] = t3_proof_fragments[entry.fragment_index_r];       // RR
                        link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR;              // this is an RR link, so outside index is LR
                        link.outside_t3_index = other_entry.fragment_index_r;                 // LR

                        links.push_back(link);
                    }
                }

                links_found++;
            }
        }
        #ifdef DEBUG_CHAINING
        std::cout << "Found " << links_found << " links in partition B: " << partition_parent_t4 << " that point to partition A: " << partition_t3 << std::endl;
        std::cout << "Quality Links found: " << links.size() << std::endl;
        #endif

        return links;
    }

    std::vector<uint64_t> getAllProofFragmentsForProof(QualityChain chain)
    {
        std::vector<uint64_t> proof_fragments;
        #ifdef DEBUG_CHAINING
        std::cout << "Getting all proof fragments for chain with " << chain.chain_links.size() << " links." << std::endl;
        int link_id = 0;
        #endif
        for (const QualityLink &link : chain.chain_links)
        {
            if (link.pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR)
            {
                proof_fragments.push_back(link.fragments[0]);                                             // LL
                uint64_t outside_fragment = plot_.value().data.t3_proof_fragments[link.outside_t3_index]; // RR
                proof_fragments.push_back(outside_fragment);                                              // LR
                proof_fragments.push_back(link.fragments[1]);                                             // RL
                proof_fragments.push_back(link.fragments[2]);                                             // RR

                #ifdef DEBUG_CHAINING
                std::cout << "Link " << link_id << " : " << std::hex << link.fragments[0] << " " << link.fragments[1] << " " << link.fragments[2] << " [OUTSIDE_FRAGMENT_IS_LR " << outside_fragment << "]" << std::dec << std::endl;
                #endif
            }
            else if (link.pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR)
            {
                proof_fragments.push_back(link.fragments[0]);                                             // LL
                proof_fragments.push_back(link.fragments[1]);                                             // LR
                proof_fragments.push_back(link.fragments[2]);                                             // RL
                uint64_t outside_fragment = plot_.value().data.t3_proof_fragments[link.outside_t3_index]; // RR
                proof_fragments.push_back(outside_fragment);                                              // RR

                #ifdef DEBUG_CHAINING
                std::cout << "Link " << link_id << " : " << std::hex << link.fragments[0] << " " << link.fragments[1] << " " << link.fragments[2] << " [OUTSIDE_FRAGMENT_IS_RR " << outside_fragment << "]" << std::dec << std::endl;
                #endif
            }
            else
            {
                std::cerr << "Unknown fragment pattern: " << static_cast<int>(link.pattern) << std::endl;
            }
        #ifdef DEBUG_CHAINING
            ++link_id;
        #endif
        }

        return proof_fragments;
    }

    void setChallenge(const std::array<uint8_t, 32> &challenge)
    {
        challenge_ = challenge;
    }

    void showStats() const
    {
        std::cout << "Prover Stats:" << std::endl;
        std::cout << "  Number of scan filter passed: " << stats_.num_scan_filter_passed << std::endl;
        std::cout << "  Number of fragments passed scan filter: " << stats_.num_fragments_passed_scan_filter << " (" << (stats_.num_fragments_passed_scan_filter * 100.0 / stats_.num_scan_filter_passed) << "%)" << std::endl;
        std::cout << "  Number of first chain links: " << stats_.num_first_chain_links << " (" << (stats_.num_first_chain_links * 100.0 / stats_.num_fragments_passed_scan_filter) << "%)" << std::endl;
        std::cout << "  Number of quality chains found: " << stats_.num_quality_chains << " (" << (stats_.num_quality_chains * 100.0 / stats_.num_first_chain_links) << "%)" << std::endl;
    }

    ProofParams getProofParams() const
    {
        if (plot_.has_value())
        {
            return plot_.value().params;
        }
        else
        {
            throw std::runtime_error("Plot file not loaded.");
        }
    }

    void _testing_setPlotFileContents(const PlotFile::PlotFileContents &plot_contents)
    {
        plot_ = plot_contents;
    }

private:
    std::optional<PlotFile::PlotFileContents> plot_;
    std::array<uint8_t, 32> challenge_;
    std::string plot_file_name_;

    struct stats
    {
        int num_scan_filter_passed = 0;
        int num_fragments_passed_scan_filter = 0;
        int num_first_chain_links = 0;
        int num_quality_chains = 0;
    } stats_;
};
