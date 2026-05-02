#pragma once

#include "pos/ProofCore.hpp"
#include "pos/aes/AesHash.hpp"
#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

#pragma once

#define USE_AESENC_CHAINING 1

#if !USE_AESENC_CHAINING
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
#endif

class Chainer {
public:
    int num_hashes = 0;
    int num_hashes_at_chain_length[NUM_CHAIN_LINKS] = { 0 };
    Chainer(ProofParams const& params, std::span<uint8_t const, 32> const challenge)
        : proof_core_(params)
        , challenge_(challenge)
    {
    }

    std::vector<Chain> find_links(
        std::array<std::span<ProofFragment const>, NUM_CHALLENGE_SETS> const& fragments_per_set)
    {

#ifdef DEBUG_CHAINER
        std::cout << "Chainer: Starting link finding with " << NUM_CHALLENGE_SETS
                  << " challenge sets, sizes:";
        for (auto const& s: fragments_per_set) {
            std::cout << " " << s.size();
        }
        std::cout << "\n";
#endif

        // State for the explicit stack.
        struct State {
            uint64_t fast_challenge;
            int iteration;
            std::vector<ProofFragment> fragments; // chosen fragments so far
        };

        auto challenge_round_keys = proof_core_.hashing.chainingChallengeWithPlotIdHash(challenge_);

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

            // Iterate through the challenge sets in sequence: 0, 1, ..., N-1, 0, 1, ...
            std::span<ProofFragment const> const& current_list
                = fragments_per_set[st.iteration % NUM_CHALLENGE_SETS];

            // Try extending the chain with each value from the current list.
            uint64_t const mixing_challenge
                = st.fast_challenge ^ challenge_round_keys[st.iteration];
            for (ProofFragment fragment: current_list) {
#if USE_AESENC_CHAINING
                uint64_t const new_fast_challenge
                    = proof_core_.hashing.chain_hash(fragment ^ mixing_challenge);
#else
                uint64_t const new_fast_challenge = splitmix64(fragment ^ mixing_challenge);
#endif
                num_hashes++;
                num_hashes_at_chain_length[st.iteration]++;

#ifdef DEBUG_CHAINER
                std::cout << "Chainer:   Trying fragment 0x" << std::hex << fragment << std::dec
                          << ", new challenge: " << new_fast_challenge << "\n";
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
            passing_zeros_needed
                -= CHAIN_FACTOR_FRONT_LOAD_BITS; // first chain has higher chance of passing.
        }
        else if (iteration == NUM_CHAIN_LINKS - 1) {
            // last iteration has stricter filter
            passing_zeros_needed
                += CHAIN_FACTOR_FRONT_LOAD_BITS; // last chain has lower chance of passing.
        }

        uint64_t const check_value = fast_challenge & ((1ULL << passing_zeros_needed) - 1);

#ifdef DEBUG_CHAINER
        std::cout << "Chainer iteration: " << iteration << ":       Checking fast filter with "
                  << passing_zeros_needed << " bits, check value: " << check_value << "\n";
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

    bool validate(
        Chain const& chain, std::array<Range, NUM_CHALLENGE_SETS> const& fragment_set_ranges) const
    {
        // First check sizes
        if (chain.fragments.size() != NUM_CHAIN_LINKS) {
            return false;
        }

        // Each fragment must come from the matching challenge set: link i is drawn
        // from set (i % NUM_CHALLENGE_SETS).
        for (size_t i = 0; i < chain.fragments.size(); i++) {
            ProofFragment fragment = chain.fragments[i];
            Range const& expected_range = fragment_set_ranges[i % NUM_CHALLENGE_SETS];
            if (!expected_range.isInRange(fragment)) {
                return false;
            }
        }

        auto challenge_round_keys = proof_core_.hashing.chainingChallengeWithPlotIdHash(challenge_);

        uint64_t challenge = 0;
        for (int i = 0; i < NUM_CHAIN_LINKS; i++) {
#if USE_AESENC_CHAINING
            challenge = proof_core_.hashing.chain_hash(
                challenge ^ chain.fragments[i] ^ challenge_round_keys[i]);
#else
            challenge = splitmix64(challenge ^ chain.fragments[i] ^ challenge_round_keys[i]);
#endif
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
