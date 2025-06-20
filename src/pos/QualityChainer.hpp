#pragma once

#include <cstdint>
#include <stdexcept>

#include "ProofParams.hpp"
#include "BlakeHash.hpp"
#include "ProofCore.hpp"

class QualityChainer {
public:
    // Constructor.
    // proof_params: a ProofParams instance.
    QualityChainer(const ProofParams& proof_params, const std::array<uint8_t, 32> &challenge, uint64_t chaining_hash_pass_threshold)
        : challenge_(challenge), 
        chaining_hash_pass_threshold_(chaining_hash_pass_threshold),
        blake_hash_(proof_params.get_plot_id_bytes(), 0) // k not used in retrieval of hash bits
    {
    }

    void addFirstQualityLink(const QualityLink &link)
    {
        // Initialize the first quality chain with the first link
        QualityChain chain;
        chain.chain_links[0] = link;
        chain.chain_hash = chainHash(0, link);
        quality_chains_.push_back(chain);
    }

    uint64_t firstLinkHash(const QualityLink &link)
    {
        // Calculate the hash for the first link in the chain
        return chainHash(0, link);
    }

    struct NewLinksResult {
        QualityLink link;
        uint64_t new_hash;
    };

    std::vector<NewLinksResult> getNewLinksForChain(uint64_t current_hash, const std::vector<QualityLink> &link_set)
    {
        std::vector<NewLinksResult> new_links;
        for (int i = 0; i < link_set.size(); ++i)
        {
            const QualityLink &link = link_set[i];

            // test the hash
            uint64_t new_hash = chainHash(current_hash, link);
            if (new_hash < chaining_hash_pass_threshold_) 
            {
                new_links.push_back({link, new_hash});
            }
        }
        return new_links;
    }

    uint64_t chainHash(uint64_t prev_chain_hash, const QualityLink &link)
    {
        // TODO: top and bottom partition bits will be frequently re-used across fragments, so could
        // increase chain_hash bits and reduce fragment bits for hash.
        // 1) Set the data for the hash
        blake_hash_.set_data(0, prev_chain_hash & 0xFFFFFFFF);
        blake_hash_.set_data(1, prev_chain_hash >> 32);
        blake_hash_.set_data(2, link.fragments[0] & 0xFFFFFFFF);
        blake_hash_.set_data(3, link.fragments[0] >> 32);
        blake_hash_.set_data(4, link.fragments[1] & 0xFFFFFFFF);
        blake_hash_.set_data(5, link.fragments[1] >> 32);
        blake_hash_.set_data(6, link.fragments[2] & 0xFFFFFFFF);
        blake_hash_.set_data(7, link.fragments[2] >> 32);

        // 2) Generate the hash
        auto h = blake_hash_.generate_hash();
        uint64_t hash_value = (static_cast<uint64_t>(h.r0) << 32) | h.r1;

        return hash_value;
    }

private:
    BlakeHash blake_hash_; 
    uint64_t chaining_hash_pass_threshold_; // threshold for chain hash to pass
    std::array<uint8_t, 32> challenge_; // 32-byte challenge
    std::vector<QualityChain> quality_chains_;
};
