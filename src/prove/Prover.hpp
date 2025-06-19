#pragma once

#include "pos/ProofCore.hpp"
#include "plot/PlotFile.hpp"
#include "common/Utils.hpp"
#include "pos/ProofFragmentScanFilter.hpp"
#include "pos/XsEncryptor.hpp"
#include "pos/QualityChainer.hpp"
#include <bitset>
#include <set>
#include <optional>
#include <vector>
#include <array>
#include <limits>
#include <iostream>
#include <string>



class Prover
{
public:
    Prover(const std::array<uint8_t, 32> &challenge, const std::string &plot_file_name, const int scan_filter)
        : challenge_(challenge), plot_file_name_(plot_file_name)
    {
    }
    ~Prover() = default;

    std::vector<QualityChain> prove()
    {
        // Proving works as follows:
        // 1) Read plot file and get plot data and specific parameters.
        // 2) Scan the plot data for fragments that pass the Proof Fragment Scan Filter.
        // 3) For each passing fragment, get their Quality Links (if any) that seed the initial entries in the Quality Chains.
        // 4) For each Quality Chain, grow and expand the number of chains link by link until we reach the chain length limit (NUM_CHAIN_LINKS).

        // 1) Read plot file
        if (!plot_.has_value())
        {
            std::cout << "Reading plot file: " << plot_file_name_ << std::endl;
            plot_ = PlotFile::readData(plot_file_name_);
            std::cout << "Plot file read successfully: " << plot_file_name_ << std::endl;
            plot_.value().params.debugPrint();
        }
        else
        {
            std::cout << "Plot file already read." << std::endl;
        }

        PlotFile::PlotFileContents plot = plot_.value();

        // 2) Scan the plot data for fragments that pass the Proof Fragment Scan Filter
        ProofFragmentScanFilter scan_filter(plot.params, challenge_);
        std::vector<ProofFragmentScanFilter::ScanResult> filtered_fragments = scan_filter.scan(plot.data.t3_encrypted_xs);
        stats_.num_scan_filter_passed++;
        stats_.num_fragments_passed_scan_filter += filtered_fragments.size();

        // 3) For each passing fragment, get their Quality Links (if any) that seed the initial entries in the Quality Chains.
        XsEncryptor xs_encryptor(plot.params);

        std::vector<QualityChain> all_chains; // this will hold all the quality chains found

        ProofCore proof_core(plot.params);
        uint64_t chaining_hash_pass_threshold = proof_core.quality_chain_pass_threshold();
        BlakeHash blake_hash(plot.params.get_plot_id_bytes(), plot.params.get_k());

        std::cout << "Found fragments passing filter: " << filtered_fragments.size() << std::endl;
        for (size_t i = 0; i < filtered_fragments.size(); i++)
        {
            uint64_t fragment = filtered_fragments[i].fragment;
            std::cout << "  Fragment: " << std::hex << fragment << std::dec << std::endl;
            // extract R pointer
            uint32_t l_partition = xs_encryptor.get_lateral_to_t4_partition(fragment);
            uint32_t r_partition = xs_encryptor.get_r_t4_partition(fragment);
            // std::cout << "          Total partitions: " << plot.params.get_num_partitions() << std::endl;
            std::cout << "          Partition A(L): " << l_partition << std::endl;
            std::cout << "          Partition R(R): " << r_partition << std::endl;

            std::vector<QualityLink> firstLinks = getQualityLinks(FragmentsParent::PARENT_NODE_IN_OTHER_PARTITION, filtered_fragments[i].index, r_partition);
            
            // output first links fragemnts in hex
            std::cout << " # First Quality Links: " << firstLinks.size() << std::endl;
            for (const auto &link : firstLinks)
            {
                std::cout << "  First Link Fragments: "
                          << std::hex << link.fragments[0] << ", "
                          << link.fragments[1] << ", "
                          << link.fragments[2] << std::dec
                          << " | Pattern: " << static_cast<int>(link.pattern)
                          << " | Parent: " << static_cast<int>(link.parent) << std::endl;
            }
            
            std::vector<QualityLink> links = getQualityLinks(l_partition, r_partition);
            std::cout << " # First Quality Links: " << firstLinks.size() << std::endl;
            std::cout << " # Links: " << links.size() << std::endl;

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
                        std::array<uint32_t, 4> x_bits = xs_encryptor.get_x_bits_from_encrypted_xs(link.fragments[i]);
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
                std::vector<QualityChain> qualityChains =
                    createQualityChains(firstLink,
                                        links,
                                        chaining_hash_pass_threshold,
                                        blake_hash);
                // add to all chains
                all_chains.insert(all_chains.end(), qualityChains.begin(), qualityChains.end());
            }
        }

        return all_chains;
    }

    // Build a BlakeHash pre-loaded with a 32-byte digest of (plotID||challenge)
    static BlakeHash makeSeedBlake(const ProofParams &params,
                                   const std::array<uint8_t, 32> &challenge)
    {
        // 1) First Blake round: compress plot-ID||challenge → 32-byte digest
        // note our output is desired as 32 bits (not cropped to k bits)
        BlakeHash pre(params.get_plot_id_bytes(), 32);
        // inject the 32B challenge as four 32-bit words
        for (int i = 0; i < 4; ++i)
        {
            uint32_t w =
                uint32_t(challenge[i * 4 + 0]) |
                (uint32_t(challenge[i * 4 + 1]) << 8) |
                (uint32_t(challenge[i * 4 + 2]) << 16) |
                (uint32_t(challenge[i * 4 + 3]) << 24);
            pre.set_data(i, w);
        }
        // generate a 256-bit/32-byte result
        // TODO: Currently this is only a 128 bit result, upgrade to 256 bit result
        auto digest = pre.generate_hash();

        // 2) pack those eight 32-bit words into a 32-byte array
        return newSeedBlakeFromResult(digest);
    }

    // TODO: Currently input is only 128 bits, should be upgrade to 256 bits
    static BlakeHash newSeedBlakeFromResult(BlakeHash::BlakeHashResult &result)
    {
        // 1) Pack the eight 32-bit words into a 32-byte array
        std::array<uint8_t, 32> seed_bytes;
        uint32_t words[8] = {
            result.r0, result.r1, result.r2, result.r3, 0, 0, 0, 0};

        for (int i = 0; i < 8; ++i)
        {
            seed_bytes[i * 4 + 0] = uint8_t(words[i] & 0xFF);
            seed_bytes[i * 4 + 1] = uint8_t((words[i] >> 8) & 0xFF);
            seed_bytes[i * 4 + 2] = uint8_t((words[i] >> 16) & 0xFF);
            seed_bytes[i * 4 + 3] = uint8_t((words[i] >> 24) & 0xFF);
        }

        // 3) Final BlakeHash is seeded with those 32 bytes
        return BlakeHash(seed_bytes.data(), 32);
    }

    uint64_t chainHash(uint64_t prev_chain_hash, const QualityLink &link, BlakeHash &blake_hash)
    {
        // TODO: top and bottom partition bits will be frequently re-used across fragments, so could
        // increase chain_hash bits and reduce fragment bits for hash.
        // 1) Set the data for the hash
        blake_hash.set_data(0, prev_chain_hash & 0xFFFFFFFF);
        blake_hash.set_data(1, prev_chain_hash >> 32);
        blake_hash.set_data(2, link.fragments[0] & 0xFFFFFFFF);
        blake_hash.set_data(3, link.fragments[0] >> 32);
        blake_hash.set_data(4, link.fragments[1] & 0xFFFFFFFF);
        blake_hash.set_data(5, link.fragments[1] >> 32);
        blake_hash.set_data(6, link.fragments[2] & 0xFFFFFFFF);
        blake_hash.set_data(7, link.fragments[2] >> 32);

        // 2) Generate the hash
        auto h = blake_hash.generate_hash();
        uint64_t hash_value = (static_cast<uint64_t>(h.r0) << 32) | h.r1;

        return hash_value;
    }

    std::vector<QualityChain> createQualityChains(const QualityLink &firstLink, const std::vector<QualityLink> &link_set, uint64_t chaining_hash_pass_threshold, BlakeHash &blake_hash)
    {
        std::vector<QualityChain> quality_chains;

        // First, create new chain for each first link
        QualityChain chain;
        chain.chain_links[0] = firstLink; // the first link is always the first in the chain
        chain.chain_hash = chainHash(0, firstLink, blake_hash);
        quality_chains.push_back(chain);
        stats_.num_first_chain_links++;

        std::cout << "Initial chain hash: " << std::hex << chain.chain_hash << std::dec << std::endl;

        // 3) Grow chains link by link

        for (int depth = 1; depth < NUM_CHAIN_LINKS; ++depth)
        {
            std::cout << "=== Depth " << depth + 1 << " ===\n";

            // If we have no chains, we cannot grow further
            if (quality_chains.empty())
            {
                std::cout << "No chains to grow at depth " << depth + 1 << std::endl;
                break;
            }
            std::cout << "  Current number of chains: " << quality_chains.size() << std::endl;

            std::vector<QualityChain> new_chains;
            size_t total_hashes = 0;

            // For each chain-so-far, try appending every possible link
            for (auto &qc : quality_chains)
            {
                for (int i = 0; i < link_set.size(); ++i)
                {
                    const QualityLink &link = link_set[i];
                    // update the hash
                    qc.chain_hash = chainHash(qc.chain_hash, link, blake_hash);
                    //std::cout << "   Chain hash: " << qc.chain_hash << std::endl << 
                    //             "    Threshold: " << chaining_hash_pass_threshold << std::endl << 
                    //             "    pass: " << (qc.chain_hash < chaining_hash_pass_threshold) << std::endl;

                    // if it passes, spawn a new extended chain
                    if (qc.chain_hash < chaining_hash_pass_threshold)
                    {
                        QualityChain qc2 = qc; // copy old chain
                        qc2.chain_links[depth] = link;
                        new_chains.push_back(std::move(qc2));

                        std::cout << "  New chain hash: " << qc2.chain_hash << " Passed threshold: " << std::dec << chaining_hash_pass_threshold << std::endl;
                    }
                }
            }

            // swap in the newly grown set
            quality_chains.swap(new_chains);
        }

        stats_.num_quality_chains += quality_chains.size();

        return quality_chains;
    }

    std::vector<QualityLink> getQualityLinks(FragmentsParent parent, uint64_t t3_fragment_index, uint32_t t4_partition)
    {
        std::vector<QualityLink> links;
        std::vector<uint64_t> t3_encrypted_xs = plot_.value().data.t3_encrypted_xs;
        std::vector<T4BackPointers> t4_to_t3_back_pointers = plot_.value().data.t4_to_t3_back_pointers[t4_partition];
        std::vector<T5Pairing> t5_to_t4_back_pointers = plot_.value().data.t5_to_t4_back_pointers[t4_partition];
        // find the T4 entry that matches the t3_index
        for (size_t t4_index = 0; t4_index < t4_to_t3_back_pointers.size(); t4_index++)
        {
            T4BackPointers entry = t4_to_t3_back_pointers[t4_index];
            if (entry.encx_index_r == t3_fragment_index)
            {
                // we found a T4 entry that matches the T3 index
                // now get it's parents and other fragments
                for (size_t t5_index = 0; t5_index < t5_to_t4_back_pointers.size(); t5_index++)
                //for (const auto &t5_entry : t5_to_t4_back_pointers)
                {
                    T5Pairing t5_entry = t5_to_t4_back_pointers[t5_index];
                    if (t5_entry.t4_index_l == t4_index || t5_entry.t4_index_r == t4_index)
                    {

                        if (t5_entry.t4_index_l == t4_index)
                        {
                            QualityLink link;
                            link.parent = parent; // a first quality link always starts from t3 challenge partition into the other partition
                            // LR link
                            link.fragments[0] = t3_encrypted_xs[entry.encx_index_l]; // LL
                            link.fragments[1] = t3_encrypted_xs[entry.encx_index_r]; // LR
                            T4BackPointers other_entry = t4_to_t3_back_pointers[t5_entry.t4_index_r];
                            link.fragments[2] = t3_encrypted_xs[other_entry.encx_index_l]; // RL
                            link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR;       // this is an LR link, so outside index is RR
                            link.outside_t3_index = other_entry.encx_index_r;              // RR

                            #ifdef DEBUG_QUALITY_LINK
                            link.partition = t4_partition; // partition of the T4 entry
                            link.t3_ll_index = entry.encx_index_l; // LL
                            link.t3_lr_index = entry.encx_index_r; // LR
                            link.t3_rl_index = other_entry.encx_index_l; // RL
                            link.t3_rr_index = other_entry.encx_index_r; // RR
                            link.t4_l_index = t4_index; // T4 index of the L side
                            link.t4_r_index = t5_entry.t4_index_r; // T4 index of the R side
                            link.t5_index = t5_index; // T5 index of the pairing
                            #endif
                            links.push_back(link);
                        }
                        else
                        {
                            // RR link
                            QualityLink link;
                            link.parent = parent; // a first quality link always starts from t3 challenge partition into the other partition
                            T4BackPointers other_entry = t4_to_t3_back_pointers[t5_entry.t4_index_l];
                            link.fragments[0] = t3_encrypted_xs[other_entry.encx_index_l]; // LL
                            link.fragments[1] = t3_encrypted_xs[entry.encx_index_l];       // RL
                            link.fragments[2] = t3_encrypted_xs[entry.encx_index_r];       // RR
                            link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR;       // this is an RR link, so outside index is LR
                            link.outside_t3_index = other_entry.encx_index_r;              // LR
                            #ifdef DEBUG_QUALITY_LINK
                            link.partition = t4_partition; // partition of the T4 entry
                            link.t3_ll_index = other_entry.encx_index_l; // LL
                            link.t3_lr_index = other_entry.encx_index_r; // LR
                            link.t3_rl_index = entry.encx_index_l; // RL
                            link.t3_rr_index = entry.encx_index_r; // RR
                            link.t4_l_index = t5_entry.t4_index_l; // T4 index of the L side
                            link.t4_r_index = t4_index; // T4 index of the R side
                            link.t5_index = t5_index; // T5 index of the pairing
                            #endif
                            links.push_back(link);
                        }
                    }
                }
            }
        }
        return links;
    }

    std::vector<QualityLink> getQualityLinks(uint32_t partition_A, uint32_t partition_B)
    {

        std::vector<QualityLink> links;

        std::vector<uint64_t> t3_encrypted_xs = plot_.value().data.t3_encrypted_xs;

        std::vector<QualityLink> other_partition_links = getQualityLinksFromT4PartitionToT3Partition(partition_B, partition_A, FragmentsParent::PARENT_NODE_IN_OTHER_PARTITION);
        std::cout << "Found " << other_partition_links.size() << " links from partition B to A." << std::endl;

        std::vector<QualityLink> challenge_partition_links = getQualityLinksFromT4PartitionToT3Partition(partition_A, partition_B, FragmentsParent::PARENT_NODE_IN_CHALLENGE_PARTITION);

        std::cout << "Found " << challenge_partition_links.size() << " links from partition A to B." << std::endl;

        // combine both links
        links.reserve(other_partition_links.size() + challenge_partition_links.size());
        links.insert(links.end(), other_partition_links.begin(), other_partition_links.end());
        links.insert(links.end(), challenge_partition_links.begin(), challenge_partition_links.end());
        std::cout << "Total links found: " << links.size() << std::endl;
        return links;
    }

    std::vector<QualityLink> getQualityLinksFromT4PartitionToT3Partition(uint32_t partition_parent_t4, uint32_t partition_t3, FragmentsParent parent)
    {
        std::vector<QualityLink> links;

        // 1. get t3 partition A range, and scan R side links from partitionB that link to partition_A
        Range t3_partition_range = plot_.value().data.t4_to_t3_lateral_ranges[partition_t3];
        std::vector<uint64_t> t3_encrypted_xs = plot_.value().data.t3_encrypted_xs;
        std::cout << "Partition T3: " << partition_t3 << std::endl;
        std::cout << "t3_partition_range: " << t3_partition_range.start << " - " << t3_partition_range.end << std::endl;
        // 2. get t4 partition B, and find r links that point to t3 partition A range
        std::cout << "Partition Parent T4: " << partition_parent_t4 << std::endl;
        std::vector<T4BackPointers> t4_b_to_t3 = plot_.value().data.t4_to_t3_back_pointers[partition_parent_t4];
        std::vector<T5Pairing> t5_b_to_t4_b = plot_.value().data.t5_to_t4_back_pointers[partition_parent_t4];
        int links_found = 0;
        for (size_t t4_index = 0; t4_index < t4_b_to_t3.size(); t4_index++)
        {
            T4BackPointers entry = t4_b_to_t3[t4_index];
            if (t3_partition_range.isInRange(entry.encx_index_r))
            {

                // we found a link that points to partition A. Now, in T5 find the parent nodes, where either the l or r pointer points to this entry in T4 partition B.
                std::vector<T5Pairing> t5_parent_nodes;
                for (size_t t5_index = 0; t5_index < t5_b_to_t4_b.size(); t5_index++)
                //for (const auto &t5_entry : t5_b_to_t4_b)
                {
                    T5Pairing t5_entry = t5_b_to_t4_b[t5_index];
                    if (t5_entry.t4_index_l == t4_index)
                    {
                        QualityLink link;
                        link.parent = parent; // this is a link from partition B

                        // if t4 is the left pointer of t4 index, then the t3 entry is an LR link.
                        // and fragments will be 0:LL, 1:LR, 2:RL with outside index being RR.

                        // get other side child node
                        T4BackPointers other_entry = t4_b_to_t3[t5_entry.t4_index_r];
                        link.fragments[0] = t3_encrypted_xs[entry.encx_index_l];       // LL
                        link.fragments[1] = t3_encrypted_xs[entry.encx_index_r];       // LR
                        link.fragments[2] = t3_encrypted_xs[other_entry.encx_index_l]; // RL
                        link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR;       // this is an LR link, so outside index is RR
                        link.outside_t3_index = other_entry.encx_index_r;              // RR

                        #ifdef DEBUG_QUALITY_LINK
                        link.partition = partition_parent_t4; // partition of the T4 entry
                        link.t3_ll_index = entry.encx_index_l; // LL
                        link.t3_lr_index = entry.encx_index_r; // LR
                        link.t3_rl_index = other_entry.encx_index_l; // RL
                        link.t3_rr_index = other_entry.encx_index_r; // RR
                        link.t4_l_index = t4_index; // T4 index of the L side
                        link.t4_r_index = t5_entry.t4_index_r; // T4 index of the R side
                        link.t5_index = t5_index; // T5 index of the pairing
                        #endif

                        links.push_back(link);
                    }
                    if (t5_entry.t4_index_r == t4_index)
                    {
                        // if t4 is the right pointer of t4 index, then the t3 entry is an RR link.
                        QualityLink link;
                        link.parent = parent; // this is a link from partition B
                        // get other side child node
                        T4BackPointers other_entry = t4_b_to_t3[t5_entry.t4_index_l];
                        link.fragments[0] = t3_encrypted_xs[other_entry.encx_index_l]; // LL
                        link.fragments[1] = t3_encrypted_xs[entry.encx_index_l];       // RL
                        link.fragments[2] = t3_encrypted_xs[entry.encx_index_r];       // RR
                        link.pattern = FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR;       // this is an RR link, so outside index is LR
                        link.outside_t3_index = other_entry.encx_index_r;              // LR

                        #ifdef DEBUG_QUALITY_LINK
                        link.partition = partition_parent_t4; // partition of the T4 entry
                        link.t3_ll_index = other_entry.encx_index_l; // LL
                        link.t3_lr_index = other_entry.encx_index_r; // LR
                        link.t3_rl_index = entry.encx_index_l; // RL
                        link.t3_rr_index = entry.encx_index_r; // RR
                        link.t4_l_index = t5_entry.t4_index_l; // T4 index of the L side
                        link.t4_r_index = t4_index; // T4 index of the R side
                        link.t5_index = t5_index; // T5 index of the pairing
                        #endif
                        links.push_back(link);
                    }
                }

                links_found++;
            }
        }
        std::cout << "Found " << links_found << " links in partition B: " << partition_parent_t4 << " that point to partition A: " << partition_t3 << std::endl;
        std::cout << "Quality Links found: " << links.size() << std::endl;

        return links;
    }

    std::vector<uint64_t> getAllProofFragmentsForProof(QualityChain chain) {
        std::vector<uint64_t> proof_fragments;
        #ifdef DEBUG_QUALITY_LINK
        std::vector<int> t5_indices;
        std::vector<int> t5_partitions;
        #endif
        std::cout << "Getting all proof fragments for chain with " << chain.chain_links.size() << " links." << std::endl;
        for (const auto &link : chain.chain_links)
        {
            #ifdef DEBUG_QUALITY_LINK
            t5_indices.push_back(link.t5_index);
            t5_partitions.push_back(link.partition);
            #endif
            if (link.pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_LR)
            {
                proof_fragments.push_back(link.fragments[0]); // LL
                uint64_t outside_fragment = plot_.value().data.t3_encrypted_xs[link.outside_t3_index]; // RR
                proof_fragments.push_back(outside_fragment); // LR
                proof_fragments.push_back(link.fragments[1]); // RL
                proof_fragments.push_back(link.fragments[2]); // RR
                
                #ifdef DEBUG_QUALITY_LINK
                std::cout << "Pattern: OUTSIDE_FRAGMENT_IS_LR" << std::endl;
                std::cout << "T5 index: " << link.t5_index << std::endl
                          << "T4 L index: " << link.t4_l_index << std::endl
                          << "T4 R index: " << link.t4_r_index << std::endl
                          << "T3 LL index: " << link.t3_ll_index << std::endl
                          << "T3 LR index: " << link.t3_lr_index << std::endl
                          << "T3 RL index: " << link.t3_rl_index << std::endl
                          << "T3 RR index: " << link.t3_rr_index << std::endl;
                std::cout << "Proof fragments: " << std::hex;
                uint64_t ll = proof_fragments[proof_fragments.size() - 4];
                uint64_t lr = proof_fragments[proof_fragments.size() - 3];
                uint64_t rl = proof_fragments[proof_fragments.size() - 2];
                uint64_t rr = proof_fragments[proof_fragments.size() - 1];
                std::cout << "LL: " << ll << ", LR: " << lr << ", RL: " << rl << ", RR: " << rr << std::dec << std::endl;
                if (ll != plot_.value().data.t3_encrypted_xs[link.t3_ll_index] ||
                    lr != plot_.value().data.t3_encrypted_xs[link.t3_lr_index] ||
                    rl != plot_.value().data.t3_encrypted_xs[link.t3_rl_index] ||
                    rr != plot_.value().data.t3_encrypted_xs[link.t3_rr_index])
                {
                    std::cerr << "Error: Fragment mismatch!" << std::endl;
                    std::cout << "Link pattern: " << static_cast<int>(link.pattern) << std::endl;
                    std::cout << "Expected: LL: " << plot_.value().data.t3_encrypted_xs[link.t3_ll_index]
                              << ", LR: " << plot_.value().data.t3_encrypted_xs[link.t3_lr_index]
                              << ", RL: " << plot_.value().data.t3_encrypted_xs[link.t3_rl_index]
                              << ", RR: " << plot_.value().data.t3_encrypted_xs[link.t3_rr_index] << std::endl;
                    std::cout << "Got: LL: " << ll
                              << ", LR: " << lr
                              << ", RL: " << rl
                              << ", RR: " << rr << std::endl;
                    exit(23);
                }
                std::cout << "OK!" << std::endl;
                #endif
            }
            else if (link.pattern == FragmentsPattern::OUTSIDE_FRAGMENT_IS_RR)
            {
                proof_fragments.push_back(link.fragments[0]); // LL
                proof_fragments.push_back(link.fragments[1]); // LR
                proof_fragments.push_back(link.fragments[2]); // RL
                uint64_t outside_fragment = plot_.value().data.t3_encrypted_xs[link.outside_t3_index]; // RR
                proof_fragments.push_back(outside_fragment); // RR
                
                #ifdef DEBUG_QUALITY_LINK
                std::cout << "Pattern: OUTSIDE_FRAGMENT_IS_RR" << std::endl;
                std::cout << "T5 index: " << link.t5_index << std::endl
                          << "T4 L index: " << link.t4_l_index << std::endl
                          << "T4 R index: " << link.t4_r_index << std::endl
                          << "T3 LL index: " << link.t3_ll_index << std::endl
                          << "T3 LR index: " << link.t3_lr_index << std::endl
                          << "T3 RL index: " << link.t3_rl_index << std::endl
                          << "T3 RR index: " << link.t3_rr_index << std::endl;
                std::cout << "Proof fragments: " << std::hex;
                uint64_t ll = proof_fragments[proof_fragments.size() - 4];
                uint64_t lr = proof_fragments[proof_fragments.size() - 3];
                uint64_t rl = proof_fragments[proof_fragments.size() - 2];
                uint64_t rr = proof_fragments[proof_fragments.size() - 1];
                std::cout << "LL: " << ll << ", LR: " << lr << ", RL: " << rl << ", RR: " << rr << std::dec << std::endl;
                if (ll != plot_.value().data.t3_encrypted_xs[link.t3_ll_index] ||
                    lr != plot_.value().data.t3_encrypted_xs[link.t3_lr_index] ||
                    rl != plot_.value().data.t3_encrypted_xs[link.t3_rl_index] ||
                    rr != plot_.value().data.t3_encrypted_xs[link.t3_rr_index])
                {
                    std::cerr << "Error: Fragment mismatch!" << std::endl;
                    std::cout << "Link pattern: " << static_cast<int>(link.pattern) << std::endl;
                    std::cout << "Expected: LL: " << plot_.value().data.t3_encrypted_xs[link.t3_ll_index]
                              << ", LR: " << plot_.value().data.t3_encrypted_xs[link.t3_lr_index]
                              << ", RL: " << plot_.value().data.t3_encrypted_xs[link.t3_rl_index]
                              << ", RR: " << plot_.value().data.t3_encrypted_xs[link.t3_rr_index] << std::endl;
                    std::cout << "Got: LL: " << ll
                              << ", LR: " << lr
                              << ", RL: " << rl
                              << ", RR: " << rr << std::endl;
                    exit(23);
                }
                std::cout << "OK!" << std::endl;
                #endif
            }
            else
            {
                std::cerr << "Unknown fragment pattern: " << static_cast<int>(link.pattern) << std::endl;
            }
        }

        // output t5 indices and partitions for debugging
        #ifdef DEBUG_QUALITY_LINK
        std::cout << "T5 indices: ";
        for (const auto &t5_index : t5_indices)
        {
            std::cout << t5_index << ",";
        }
        std::cout << std::endl;
        std::cout << "T5 partitions: ";
        for (const auto &t5_partition : t5_partitions)
        {
            std::cout << t5_partition << ",";
        }
        std::cout << std::endl;
        #endif
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