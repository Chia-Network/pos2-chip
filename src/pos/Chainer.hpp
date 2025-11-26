#pragma once

#include "pos/ProofCore.hpp"
#include <vector>
#include <array>
#include <cstdint>
#include <iostream>

// A chain: list of challenges and the corresponding chosen proof fragments.
struct Chain
{
    //std::vector<BlakeHash::Result256> challenges; // new_challenge at each step
    std::vector<ProofFragment> fragments;      // the proof fragment used at each step
};

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
            BlakeHash::Result256 challenge;
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
            .challenge = initial_challenge,
            .iteration = 0,
            //.challenges = {},
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
                BlakeHash::Result256 new_challenge = proof_core_.hashing.linkHash(st.challenge, fragment, st.iteration);
                num_hashes++;

                #ifdef DEBUG_CHAINER
                std::cout << "Chainer:   Trying fragment 0x"
                          << std::hex << fragment << std::dec
                          << ", new challenge: "
                          << new_challenge.toString() << "\n";
                #endif

                if (!passes_filter(new_challenge, st.iteration))
                {
                    #ifdef DEBUG_CHAINER
                    std::cout << "Chainer:     Fragment rejected by filter.\n";
                    #endif
                    continue;
                }

                State next;
                next.challenge = new_challenge;
                next.iteration = st.iteration + 1;
                next.fragments = st.fragments;

                //next.challenges.push_back(new_challenge);
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

        for (int i = 0; i < NUM_CHAIN_LINKS; i++)
        {
            BlakeHash::Result256 new_challenge =
                proof_core_.hashing.linkHash(challenge, chain.fragments[i], i);

            if (!passes_filter(new_challenge, i))
            {
                return false;
            }

            challenge = new_challenge;
        }

        return true;
    }

private:
    ProofCore proof_core_;
    std::array<uint8_t, 32> challenge_;
};