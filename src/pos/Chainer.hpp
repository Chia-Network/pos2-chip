#pragma once

#include "pos/ProofCore.hpp"
#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

#pragma once

// Original algorithm by Sebastiano Vigna.
// See: http://xorshift.di.unimi.it/splitmix64.c
uint64_t splitmix64(uint64_t x)
{
    x += 0x9e3779b97f4a7c15ull;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
    x ^= (x >> 31);
    return x;
}

class Chainer {
public:
    int num_hashes = 0;
    Chainer(ProofParams const& params, std::span<uint8_t const, 32> const challenge)
        : proof_core_(params)
        , challenge_(challenge)
    {
    }

    std::vector<Chain> find_links(std::span<ProofFragment const> const fragments_A,
        std::span<ProofFragment const> const fragments_B)
    {

#ifdef DEBUG_CHAINER
        std::cout << "Chainer: Starting link finding with " << fragments_A.size()
                  << " fragments in A and " << fragments_B.size() << " fragments in B.\n";
#endif

        // State for the explicit stack.
        struct State {
            uint64_t fast_challenge;
            int iteration;
            std::vector<ProofFragment> fragments; // chosen fragments so far
        };

        auto challenge_round_keys = proof_core_.hashing.chainingChallengeWithPlotIdHash(challenge_);

#ifdef DEBUG_CHAINER
        std::cout << "Chainer: Initial challenge: " << initial_challenge.toString() << "\n";
#endif

        std::vector<Chain> results;
        std::vector<State> stack;
        stack.reserve(1024);

        // Start at iteration 0, no picks yet.
        stack.push_back(State { .fast_challenge = 0, .iteration = 0, .fragments = {} });

        while (!stack.empty()) {
            State st = std::move(stack.back());
            stack.pop_back();

#ifdef DEBUG_CHAINER
            std::cout << "Chainer: At iteration " << st.iteration
                      << ", current challenge: " << st.challenge.toString() << "\n";
#endif

            // If we've reached the desired length, record the chain.
            if (st.iteration == NUM_CHAIN_LINKS) {
                Chain chain;
                if (st.fragments.size() != NUM_CHAIN_LINKS) {
#ifdef DEBUG_CHAINER
                    std::cerr << "Chainer: unexpected fragment count: " << st.fragments.size()
                              << "\n";
#endif
                    continue;
                }
                for (int i = 0; i < NUM_CHAIN_LINKS; ++i) {
                    chain.fragments[i] = st.fragments[i];
                }
                results.push_back(std::move(chain));

#ifdef DEBUG_CHAINER
                std::cout << "Chainer: Found complete chain of length " << NUM_CHAIN_LINKS << "\n";
#endif
                continue;
            }

            // On first iteration use As, then Bs, alternating.
            std::span<ProofFragment const> const& current_list
                = (st.iteration % 2 == 0) ? fragments_A : fragments_B;

            // Try extending the chain with each value from the current list.
            uint64_t const mixing_challenge
                = st.fast_challenge ^ challenge_round_keys[st.iteration];
            for (ProofFragment fragment: current_list) {
                uint64_t const new_fast_challenge = splitmix64(fragment ^ mixing_challenge);
                num_hashes++;

#ifdef DEBUG_CHAINER
                std::cout << "Chainer:   Trying fragment 0x" << std::hex << fragment << std::dec
                          << ", new challenge: " << new_challenge.toString() << "\n";
#endif

                if (!passes_fast_filter(new_fast_challenge, st.iteration)) {
#ifdef DEBUG_CHAINER
                    std::cout << "Chainer:     Fragment rejected by fast filter.\n";
#endif
                    continue;
                }

                State next;
                next.fast_challenge = new_fast_challenge;

                next.iteration = st.iteration + 1;
                next.fragments = st.fragments;

                next.fragments.push_back(fragment);

                stack.push_back(std::move(next));

#ifdef DEBUG_CHAINER
                std::cout << "Chainer:     Fragment accepted, pushing to stack for iteration "
                          << next.iteration << "\n";
#endif
            }
        }

        return results;
    }

    bool passes_fast_filter(uint64_t const fast_challenge, int iteration) const
    {
        // For now accept all links
        int passing_zeros_needed = proof_core_.getProofParams().get_chaining_set_bits();
        if (iteration == 0) {
            // First iteration uses a looser filter
            passing_zeros_needed -= 2; // first chain has 4x chance of passing.
        }
        else if (iteration == NUM_CHAIN_LINKS - 1) {
            // last iteration has stricter filter
            passing_zeros_needed += 2; // last chain has 1/4x chance of passing.
            passing_zeros_needed
                += AVERAGE_PROOFS_PER_CHALLENGE_BITS; // only want 1/32 of the proofs.
        }

        uint64_t const check_value = fast_challenge & ((1ULL << passing_zeros_needed) - 1);

#ifdef DEBUG_CHAINER
        std::cout << "Chainer:       Checking fast filter with " << passing_zeros_needed
                  << " bits, check value: " << check_value << "\n";
#endif
        if (check_value != 0)
            return false;
        return true;
    }

    // TODO: make this round bits cryptographic: e.g. another blake.
    static uint64_t get_round_bits(BlakeHash::Result256 const& challenge, unsigned r)
    {
        uint32_t w0 = challenge.r[r & 7]; // first word
        uint32_t w1 = challenge.r[(r + 3) & 7]; // second word, offset by odd constant

        // Combine into 64 bits
        return (numeric_cast<uint64_t>(w0) << 32) | w1;
    }

    bool validate(Chain const& chain, Range fragment_A, Range fragments_B) const
    {
        // First check sizes
        if (chain.fragments.size() != NUM_CHAIN_LINKS) {
            return false;
        }

        // check that each fragment is from the correct set (A or B)
        for (size_t i = 0; i < chain.fragments.size(); i++) {
            ProofFragment fragment = chain.fragments[i];
            if (i % 2 == 0) {
                // from set A
                if (!fragment_A.isInRange(fragment)) {
                    return false;
                }
            }
            else {
                // from set B
                if (!fragments_B.isInRange(fragment)) {
                    return false;
                }
            }
        }

        auto challenge_round_keys = proof_core_.hashing.chainingChallengeWithPlotIdHash(challenge_);

        uint64_t challenge = 0;
        for (int i = 0; i < NUM_CHAIN_LINKS; i++) {
            challenge = splitmix64(challenge ^ chain.fragments[i] ^ challenge_round_keys[i]);
            if (!passes_fast_filter(challenge, i)) {
                return false;
            }
        }

        return true;
    }

private:
    ProofCore proof_core_;
    std::span<uint8_t const, 32> challenge_;
};
