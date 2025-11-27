#pragma once

#include "pos/ProofCore.hpp"
#include <vector>
#include <array>
#include <cstdint>
#include <iostream>

#pragma once

#define USE_FAST_CHALLENGE true

// A chain: list of challenges and the corresponding chosen proof fragments.
struct Chain
{
    std::vector<ProofFragment> fragments;      // the proof fragment used at each step
};

#ifdef USE_FAST_CHALLENGE
// Original algorithm by Sebastiano Vigna.
// See: http://xorshift.di.unimi.it/splitmix64.c
uint64_t splitmix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ull;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
    x ^= (x >> 31);
    return x;
}
#endif

class Chainer
{
public:
    int num_hashes = 0;
    Chainer(const ProofParams &params,
              const std::array<uint8_t, 32> &challenge)
        : proof_core_(params),
          challenge_(challenge)
    {
    }

    std::vector<Chain> find_links(
        const std::vector<ProofFragment> &fragments_A,
        const std::vector<ProofFragment> &fragments_B)
    {

        #ifdef DEBUG_CHAINER
        std::cout << "Chainer: Starting link finding with "
                  << fragments_A.size() << " fragments in A and "
                  << fragments_B.size() << " fragments in B.\n";
        #endif

        // State for the explicit stack.
        struct State
        {
            #ifdef USE_FAST_CHALLENGE
            uint64_t fast_challenge;
            #else
            BlakeHash::Result256 challenge;
            #endif
            int iteration;
            //std::vector<BlakeHash::Result256> challenges; // built so far
            std::vector<ProofFragment> fragments;      // chosen fragments so far
        };

        BlakeHash::Result256 initial_challenge =
            proof_core_.hashing.challengeWithPlotIdHash(challenge_.data());

        #ifdef DEBUG_CHAINER
        std::cout << "Chainer: Initial challenge: "
                  << initial_challenge.toString() << "\n";
        #endif

        std::vector<Chain> results;
        std::vector<State> stack;
        stack.reserve(1024);

        // Start at iteration 0, no picks yet.
        stack.push_back(State{
            #ifdef USE_FAST_CHALLENGE
            .fast_challenge = initial_challenge.r[0] | (static_cast<uint64_t>(initial_challenge.r[1]) << 32),
            #else
            .challenge = initial_challenge,
            #endif
            .iteration = 0,
            .fragments = {}});

        while (!stack.empty())
        {
            State st = std::move(stack.back());
            stack.pop_back();

            #ifdef DEBUG_CHAINER
            std::cout << "Chainer: At iteration " << st.iteration
                      << ", current challenge: "
                      << st.challenge.toString() << "\n";
            #endif

            // If we've reached the desired length, record the chain.
            if (st.iteration == NUM_CHAIN_LINKS)
            {
                results.push_back(Chain{
                    //.challenges = std::move(st.challenges),
                    .fragments = std::move(st.fragments)});

                #ifdef DEBUG_CHAINER
                std::cout << "Chainer: Found complete chain of length " << NUM_CHAIN_LINKS << "\n";
                #endif
                continue;
            }

            // On first iteration use As, then Bs, alternating.
            const std::vector<ProofFragment> &current_list =
                (st.iteration % 2 == 0) ? fragments_A : fragments_B;

            // Try extending the chain with each value from the current list.
            for (ProofFragment fragment : current_list)
            {
                #ifdef USE_FAST_CHALLENGE
                uint64_t new_fast_challenge = splitmix64(st.fast_challenge ^ fragment);
                #else
                BlakeHash::Result256 new_challenge = proof_core_.hashing.linkHash(st.challenge, fragment, st.iteration);
                #endif
                num_hashes++;

                #ifdef DEBUG_CHAINER
                std::cout << "Chainer:   Trying fragment 0x"
                          << std::hex << fragment << std::dec
                          << ", new challenge: "
                          << new_challenge.toString() << "\n";
                #endif

                #ifdef USE_FAST_CHALLENGE
                if (!passes_fast_filter(new_fast_challenge, st.iteration))
                {
                    #ifdef DEBUG_CHAINER
                    std::cout << "Chainer:     Fragment rejected by fast filter.\n";
                    #endif
                    continue;
                }
                #else
                if (!passes_filter(new_challenge, st.iteration))
                {
                    #ifdef DEBUG_CHAINER
                    std::cout << "Chainer:     Fragment rejected by filter.\n";
                    #endif
                    continue;
                }
                #endif

                State next;
                #ifdef USE_FAST_CHALLENGE
                next.fast_challenge = new_fast_challenge;
                #else
                next.challenge = new_challenge;
                #endif
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

    bool passes_fast_filter(const uint64_t fast_challenge, int iteration) const
    {
        // For now accept all links
        int passing_zeros_needed = proof_core_.getProofParams().get_chaining_set_bits();
        if (iteration == 0)
        {
            // First iteration uses a looser filter
            passing_zeros_needed -= 2; // first chain has 4x chance of passing.
        }
        else if (iteration == NUM_CHAIN_LINKS - 1)
        {
            // last iteration has stricter filter
            passing_zeros_needed += 2; // last chain has 1/4x chance of passing.
            passing_zeros_needed += AVERAGE_PROOFS_PER_CHALLENGE_BITS; // only want 1/32 of the proofs.
        }
    
        uint64_t check_value =
            fast_challenge & ((1ULL << passing_zeros_needed) - 1);

        #ifdef DEBUG_CHAINER
        std::cout << "Chainer:       Checking fast filter with "
                  << passing_zeros_needed << " bits, check value: "
                  << check_value << "\n";
        #endif
        if (check_value != 0)
            return false;
        return true;
    }

    bool passes_filter(const BlakeHash::Result256 &new_challenge, int iteration) const
    {
        // For now accept all links
        int passing_zeros_needed = proof_core_.getProofParams().get_chaining_set_bits();
        if (iteration == 0)
        {
            // First iteration uses a looser filter
            passing_zeros_needed -= 2; // first chain has 4x chance of passing.
        }
        else if (iteration == NUM_CHAIN_LINKS - 1)
        {
            // last iteration has stricter filter
            passing_zeros_needed += 2; // last chain has 1/4x chance of passing.
            passing_zeros_needed += AVERAGE_PROOFS_PER_CHALLENGE_BITS; // only want 1/32 of the proofs.
        }
    
        uint32_t check_value =
            new_challenge.r[0] & ((1U << passing_zeros_needed) - 1);

        #ifdef DEBUG_CHAINER
        std::cout << "Chainer:       Checking filter with "
                  << passing_zeros_needed << " bits, check value: "
                  << check_value << "\n";
        #endif
        if (check_value != 0)
            return false;
        return true;
    }

    bool validate(const Chain &chain, Range fragment_A, Range fragments_B) const
    {
        // First check sizes
        if (chain.fragments.size() != NUM_CHAIN_LINKS)
        {
            return false;
        }

        // check that each fragment is from the correct set (A or B)
        for (size_t i = 0; i < chain.fragments.size(); i++)
        {
            ProofFragment fragment = chain.fragments[i];
            if (i % 2 == 0)
            {
                // from set A
                if (!fragment_A.isInRange(fragment))
                {
                    return false;
                }
            }
            else
            {
                // from set B
                if (!fragments_B.isInRange(fragment))
                {
                    return false;
                }
            }
        }

        BlakeHash::Result256 challenge =
            proof_core_.hashing.challengeWithPlotIdHash(challenge_.data());
        #ifdef USE_FAST_CHALLENGE
        uint64_t fast_challenge = challenge.r[0] | (static_cast<uint64_t>(challenge.r[1]) << 32);
        #endif

        for (int i = 0; i < NUM_CHAIN_LINKS; i++)
        {
            #ifdef USE_FAST_CHALLENGE
            fast_challenge = splitmix64(fast_challenge ^ chain.fragments[i]);
            if (!passes_fast_filter(fast_challenge, i))
            {
                return false;
            }
            #else
            challenge = proof_core_.hashing.linkHash(challenge, chain.fragments[i], i);

            if (!passes_filter(challenge, i))
            {
                return false;
            }
            #endif

            
        }

        return true;
    }

private:
    ProofCore proof_core_;
    std::array<uint8_t, 32> challenge_;
};