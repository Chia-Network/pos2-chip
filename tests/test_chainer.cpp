#include "common/Timer.hpp"
#include "common/Utils.hpp"
#include "plot/PlotFile.hpp"
#include "plot/Plotter.hpp"
#include "pos/Chainer.hpp"
#include "pos/ProofCore.hpp"
#include "test_util.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <vector>

#define DEBUG_CHAINER true

TEST_SUITE_BEGIN("chainer");

TEST_CASE("small_lists")
{
    constexpr uint8_t k = 28;
    std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    std::string challenge_hex = "5c00000000000000000000000000000000000000000000000000000000000000";
    std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);
    ProofParams proof_params(Utils::hexToBytes(plot_id_hex).data(), k, 2, 0);
    ProofCore proof_core(proof_params);

    ProofCore::SelectedChallengeSets selected_sets = proof_core.selectChallengeSets(challenge);

#ifdef DEBUG_CHAINER
    for (int i = 0; i < NUM_CHALLENGE_SETS; ++i) {
        std::cout << "Selected fragment set " << i
                  << " index: " << selected_sets.fragment_set_indexes[i] << "\n";
        std::cout << "Fragment set " << i
                  << " range: " << selected_sets.fragment_set_ranges[i].start << " - "
                  << selected_sets.fragment_set_ranges[i].end << "\n";
    }
#endif

    std::mt19937 rng(1245); // fixed seed for reproducibility
    ProofFragment max_offset = static_cast<ProofFragment>(
        selected_sets.fragment_set_ranges[0].end - selected_sets.fragment_set_ranges[0].start);
    std::uniform_int_distribution<ProofFragment> dist(0, max_offset);

    // now create NUM_CHALLENGE_SETS lists of size chaining_set_size each
    int chaining_set_size = proof_params.get_chaining_set_size();
#ifdef DEBUG_CHAINER
    std::cout << "Creating " << NUM_CHALLENGE_SETS << " chaining lists of size "
              << chaining_set_size << " each, indexes:";
    for (int i = 0; i < NUM_CHALLENGE_SETS; ++i) {
        std::cout << " " << selected_sets.fragment_set_indexes[i];
    }
    std::cout << "\n";
#endif
    // below can test attacker times by increasing list sizes to simulate bit dropping attacks on
    // t3. chaining_set_size += chaining_set_size / 2; // add 50% extra as an attack
    // chaining_set_size += 3 * chaining_set_size / 4; // add 75% extra as an attack
    std::array<std::vector<ProofFragment>, NUM_CHALLENGE_SETS> encrypted_sets;
    for (int s = 0; s < NUM_CHALLENGE_SETS; ++s) {
        encrypted_sets[s].resize(chaining_set_size);
        for (int i = 0; i < chaining_set_size; ++i) {
            encrypted_sets[s][i] = selected_sets.fragment_set_ranges[s].start + dist(rng);
#ifdef DEBUG_CHAINER
            if ((i < 10) || (i >= chaining_set_size - 10)) {
                std::cout << "  set" << s << "[" << i << "] = " << encrypted_sets[s][i] << "\n";
            }
#endif
        }
    }
#ifdef NDEBUG
    int num_trials = 10000;
    int num_chains_validated = 0;
    size_t total_chains_found = 0;
    Timer timer;
    timer.start("Chaining trials");
    std::vector<int> trial_results;
    trial_results.reserve(num_trials);
    int total_hashes = 0;
    int total_hashes_at_chain_length[NUM_CHAIN_LINKS] = { 0 };
    for (int trial = 0; trial < num_trials; ++trial) {
        // create new random challenge each trial
        challenge[0] = static_cast<uint8_t>(trial & 0xFF);
        challenge[1] = static_cast<uint8_t>((trial >> 8) & 0xFF);
        challenge[2] = static_cast<uint8_t>((trial >> 16) & 0xFF);
        challenge[3] = static_cast<uint8_t>((trial >> 24) & 0xFF);

        Chainer chainer(proof_params, challenge);

        std::array<std::span<ProofFragment const>, NUM_CHALLENGE_SETS> fragments_per_set;
        for (int s = 0; s < NUM_CHALLENGE_SETS; ++s) {
            fragments_per_set[s] = encrypted_sets[s];
        }
        auto chains = chainer.find_links(fragments_per_set);

        if (trial % 100 == 0) {
            std::cout << "Trial " << trial << ": Found " << chains.size() << " chains\n";
        }

        total_chains_found += chains.size();

        trial_results.push_back(static_cast<int>(chains.size()));

        total_hashes += chainer.num_hashes;
        for (int i = 0; i < NUM_CHAIN_LINKS; ++i) {
            total_hashes_at_chain_length[i] += chainer.num_hashes_at_chain_length[i];
        }

        // validate chains that passed
        if (chains.size() > 0) {
            for (auto const& chain: chains) {
                bool valid = chainer.validate(chain, selected_sets.fragment_set_ranges);
                // could do more validation here if desired
                REQUIRE(valid);
                if (valid) {
                    num_chains_validated++;
                }

                // Mutate by swapping two links that belong to the same challenge set
                // (separated by NUM_CHALLENGE_SETS positions); the chain hash should fail.
                Chain mutated_chain = chain;
                size_t swap_a = trial % mutated_chain.fragments.size();
                size_t swap_b = (swap_a + NUM_CHALLENGE_SETS) % mutated_chain.fragments.size();
                std::swap(mutated_chain.fragments[swap_a], mutated_chain.fragments[swap_b]);
                bool valid_mutated
                    = chainer.validate(mutated_chain, selected_sets.fragment_set_ranges);
                if (valid_mutated) {
                    std::cout << "WARNING: Mutated chain unexpectedly validated.\n";
                    // it can happen that two elements swapped are the same, so we just invalidate
                    // this test if it is.
                    if (mutated_chain.fragments[swap_a] == mutated_chain.fragments[swap_b]) {
                        std::cout
                            << "  (Swapped fragments are identical, so mutation ineffective.)\n";
                        valid_mutated = false;
                    }
                    // show previous chain and mutated chain
                    std::cout << "Original chain fragments: ";
                    for (auto const& frag: chain.fragments) {
                        std::cout << "0x" << std::hex << frag << " ";
                    }
                    std::cout << std::dec << "\n";
                    std::cout << "Mutated chain fragments:  ";
                    for (auto const& frag: mutated_chain.fragments) {
                        std::cout << "0x" << std::hex << frag << " ";
                    }
                    std::cout << std::dec << "\n";
                }
                REQUIRE(!valid_mutated);
            }
        }
    }
    double trials_ms = timer.stop();
    std::cout << "Total chains found in " << num_trials << " trials: " << total_chains_found
              << " (validated: " << num_chains_validated << ")\n";
    std::cout << "Chaining trials took " << trials_ms << " ms"
              << " (avg: " << trials_ms / num_trials << " ms/trial)\n";

    // create and show historgram of trial_results
    std::map<int, int> histogram;
    for (int count: trial_results) {
        histogram[count]++;
    }
    std::cout << "Histogram of chains found per trial:\n";
    for (auto const& entry: histogram) {
        std::cout << "  " << entry.first << " chains: " << entry.second << " trials\n";
    }

    // calculate standard deviation and variance of results
    double mean = static_cast<double>(total_chains_found) / num_trials;
    double variance = 0.0;
    for (int count: trial_results) {
        variance += (count - mean) * (count - mean);
    }
    variance /= num_trials;
    double stddev = std::sqrt(variance);
    std::cout << "Front load bits: " << CHAIN_FACTOR_FRONT_LOAD_BITS << " ("
              << (1 << CHAIN_FACTOR_FRONT_LOAD_BITS) << ")\n";
    std::cout << "Mean chains per trial: " << mean << "\n";
    std::cout << "Standard deviation: " << stddev << "\n";
    std::cout << "Variance: " << variance << "\n";
    std::cout << "Total hashes computed: " << total_hashes
              << "  avg: " << static_cast<double>(total_hashes) / num_trials << " per trial\n";
    for (int i = 0; i < NUM_CHAIN_LINKS; ++i) {
        std::cout << "  Hashes at chain length " << i << ": " << total_hashes_at_chain_length[i]
                  << "  avg: " << static_cast<double>(total_hashes_at_chain_length[i]) / num_trials
                  << " per trial\n";
    }

    // The synthetic test uses fixed-size sets (exactly chaining_set_size each), so
    // the Jensen bonus E[|S|^(L/N)]^N / lambda^L is exactly 1.0 — no variance.
    // When the last-link recalibration is enabled, it tightens the filter by
    // 1/jensen_bonus assuming Poisson(lambda), so the synthetic mean drops by
    // that same factor (~1/1.44).
    double expected_mean = 1;
#if POS2_RECALIBRATE_LAST_LINK_FILTER
    {
        constexpr double lambda = static_cast<double>(1ULL << CHAIN_SET_BITS);
        constexpr int reuse = NUM_CHAIN_LINKS / NUM_CHALLENGE_SETS;
        static_assert(reuse == 4, "Update Stirling coefficients if reuse changes");
        // E[X^4] / lambda^4 for X ~ Poisson(lambda):
        double const ratio
            = 1.0 + 6.0 / lambda + 7.0 / (lambda * lambda) + 1.0 / (lambda * lambda * lambda);
        double bonus = 1.0;
        for (int i = 0; i < NUM_CHALLENGE_SETS; ++i)
            bonus *= ratio;
        expected_mean = 1.0 / bonus;
    }
#endif
    std::cout << "Expected mean (model): " << expected_mean << "\n";
    REQUIRE(mean > expected_mean * 0.80);
    REQUIRE(mean < expected_mean * 1.20);
#endif
}

TEST_SUITE_END();
