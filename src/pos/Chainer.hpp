#pragma once

#include "pos/ProofCore.hpp"
#include "pos/aes/AesHash.hpp"
#include <array>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <vector>

#pragma once

#define USE_AESENC_CHAINING 1

// Recalibrate the final chain-link filter so the average chain count per
// challenge is ~1.0 (the original design target).
//
// With NUM_CHALLENGE_SETS = N sets each used L/N times in a chain of length L,
// and |set| ~ Poisson(2^chain_set_bits), the expected chain count is:
//     E[chains] = E[|S|^(L/N)]^N * 2^-total_filter_bits
// For the default constants (L=16, N=4, chain_set_bits=6, lambda=64), the
// Jensen bonus ratio = E[|S|^4]^4 / lambda^16 ~= 1.4401, so the average without
// compensation is ~1.4401 chains/challenge instead of the design target of 1.
//
// When this is set to 1 we apply a fractional-bit threshold to ONLY the last
// link's upper bits (which are independent of the lower zero-bit check) to
// cancel the bonus. Set to 0 to revert to the original behavior.
#define POS2_RECALIBRATE_LAST_LINK_FILTER 1

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
        // start_set is the index (0..NUM_CHALLENGE_SETS-1) of the set this chain
        // started in; the set used at chain position i is (start_set + i) mod N.
        struct State {
            uint64_t fast_challenge;
            int iteration;
            int start_set;
            std::vector<ProofFragment> fragments; // chosen fragments so far
        };

        auto challenge_round_keys = proof_core_.hashing.chainingChallengeWithPlotIdHash(challenge_);

        std::vector<Chain> results;
        std::vector<State> stack;
        stack.reserve(1024);

        // Seed the search with starter fragments. Every fragment across every set
        // is a candidate starter; the iter-0 fast filter (with
        // CHAIN_STARTER_FILTER_BITS zero bits) keeps ~1/NUM_CHALLENGE_SETS of
        // them, so on average we get ~chaining_set_size surviving starters.
        uint64_t const starter_mixing_challenge = challenge_round_keys[0];
        for (int start_set = 0; start_set < NUM_CHALLENGE_SETS; ++start_set) {
            std::span<ProofFragment const> const& starter_list = fragments_per_set[start_set];
            for (ProofFragment fragment: starter_list) {
#if USE_AESENC_CHAINING
                uint64_t const new_fast_challenge
                    = proof_core_.hashing.chain_hash(fragment ^ starter_mixing_challenge);
#else
                uint64_t const new_fast_challenge = splitmix64(fragment ^ starter_mixing_challenge);
#endif
                num_hashes++;
                num_hashes_at_chain_length[0]++;

                if (!passes_fast_filter(new_fast_challenge, 0)) {
                    continue;
                }

                State next;
                next.fast_challenge = new_fast_challenge;
                next.iteration = 1;
                next.start_set = start_set;
                next.fragments.reserve(NUM_CHAIN_LINKS);
                next.fragments.push_back(fragment);
                stack.push_back(std::move(next));
            }
        }

        while (!stack.empty()) {
            State st = std::move(stack.back());
            stack.pop_back();

#ifdef DEBUG_CHAINER
            std::cout << "Chainer: At iteration " << st.iteration << ", start_set: " << st.start_set
                      << "\n";
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

            // The set used at this iteration is determined by the chain's start
            // set: link i is drawn from set (start_set + i) mod N.
            int const current_set_idx = (st.start_set + st.iteration) % NUM_CHALLENGE_SETS;
            std::span<ProofFragment const> const& current_list = fragments_per_set[current_set_idx];

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
                next.start_set = st.start_set;
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
        int passing_zeros_needed = proof_core_.getProofParams().get_chaining_set_bits();
        if (iteration == 0) {
            // Starter filter: every fragment in every selected set is a chain
            // candidate, so we apply a probabilistic 1/NUM_CHALLENGE_SETS pass
            // rate (CHAIN_STARTER_FILTER_BITS zero bits) to keep the expected
            // surviving starter count at ~chaining_set_size, matching the
            // original "set 0 only" behavior.
            passing_zeros_needed = CHAIN_STARTER_FILTER_BITS;
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

#if POS2_RECALIBRATE_LAST_LINK_FILTER
        // Final-link fractional-bit recalibration. The lower passing_zeros_needed bits
        // of fast_challenge are already known to be zero; the upper bits are still
        // uniformly distributed (AES output) and independent of the lower bits, so
        // we use them to apply an extra fractional pass-probability of 1/jensen_bonus.
        if (iteration == NUM_CHAIN_LINKS - 1) {
            static uint64_t const extra_threshold = compute_last_link_extra_threshold();
            uint64_t const upper_bits = fast_challenge >> passing_zeros_needed;
            if (upper_bits >= extra_threshold)
                return false;
        }
#endif

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

        // Determine which selected set the chain starts in. The four selected
        // sets have non-overlapping ranges, so chain.fragments[0] belongs to at
        // most one of them.
        int start_set = -1;
        for (int s = 0; s < NUM_CHALLENGE_SETS; ++s) {
            if (fragment_set_ranges[s].isInRange(chain.fragments[0])) {
                start_set = s;
                break;
            }
        }
        if (start_set < 0) {
            return false;
        }

        // Each fragment at link i must be drawn from set (start_set + i) mod N.
        for (size_t i = 0; i < chain.fragments.size(); i++) {
            ProofFragment fragment = chain.fragments[i];
            int const expected_set = (start_set + static_cast<int>(i)) % NUM_CHALLENGE_SETS;
            Range const& expected_range = fragment_set_ranges[expected_set];
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
            // passes_fast_filter applies the iter-0 starter filter at i==0, so
            // a chain whose starter fragment failed the 25% gate here is
            // rejected even if it happens to produce a valid full chain hash.
            if (!passes_fast_filter(challenge, i)) {
                return false;
            }
        }

        return true;
    }

private:
    // Computes the upper-bits threshold used at the last chain link to cancel the
    // E[|S|^(L/N)]^N Jensen bonus from Poisson-distributed set sizes, so that
    // E[chains/challenge] -> 1.0 instead of ~jensen_bonus.
    //
    // Formula:
    //   lambda          = 2^chain_set_bits (mean size of one chaining set)
    //   reuse           = NUM_CHAIN_LINKS / NUM_CHALLENGE_SETS  (hits per set)
    //   E[X^reuse]      = sum_{j=0..reuse} S(reuse, j) * lambda^j  for X ~ Poisson(lambda),
    //                     where S is Stirling numbers of the 2nd kind
    //   bonus           = (E[X^reuse] / lambda^reuse)^N
    //   upper_bits_count= 64 - (chain_set_bits + CHAIN_FACTOR_FRONT_LOAD_BITS)
    //   threshold       = floor(2^upper_bits_count / bonus)
    static uint64_t compute_last_link_extra_threshold()
    {
        // Hardcoded Stirling numbers of the 2nd kind for reuse = 4: S(4, j) for j=0..4.
        // If the chain length / challenge-set count ratio changes, regenerate these.
        static_assert(NUM_CHAIN_LINKS / NUM_CHALLENGE_SETS == 4,
            "Update Stirling-number coefficients in "
            "compute_last_link_extra_threshold for new reuse-per-set value");
        constexpr int reuse = 4;
        double const stirling[reuse + 1] = { 0.0, 1.0, 7.0, 6.0, 1.0 };

        double const lambda = static_cast<double>(1ULL << CHAIN_SET_BITS);

        // E[X^reuse] for X ~ Poisson(lambda)
        double e_x_reuse = 0.0;
        double lpow = 1.0;
        for (int j = 0; j <= reuse; ++j) {
            e_x_reuse += stirling[j] * lpow;
            lpow *= lambda;
        }

        double lambda_pow_reuse = 1.0;
        for (int j = 0; j < reuse; ++j)
            lambda_pow_reuse *= lambda;

        double const ratio = e_x_reuse / lambda_pow_reuse;
        double bonus = 1.0;
        for (int i = 0; i < NUM_CHALLENGE_SETS; ++i)
            bonus *= ratio;

        constexpr int upper_bits_count = 64 - CHAIN_SET_BITS - CHAIN_FACTOR_FRONT_LOAD_BITS;
        static_assert(upper_bits_count > 0 && upper_bits_count <= 53,
            "upper_bits_count must be positive and fit safely in double mantissa");
        double const max_upper = std::ldexp(1.0, upper_bits_count);
        return static_cast<uint64_t>(max_upper / bonus);
    }

    ProofCore proof_core_;
    std::span<uint8_t const, 32> challenge_;
};
