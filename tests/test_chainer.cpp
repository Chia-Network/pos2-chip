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
    // Counts of chains observed for each chain.fragments[0] starter set. With the
    // multi-set starter algorithm we expect every set to contribute roughly equal
    // numbers of chains; if find_links regresses to "set 0 only", three of these
    // four buckets will end up empty and the assertion below will fail.
    std::array<int, NUM_CHALLENGE_SETS> start_set_chain_counts;
    int num_cross_set_mutations = 0;
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

                // Determine which selected set this chain started in, the same way
                // validate() does, and account for it. With the multi-set starter
                // algorithm chains should originate from any of the four sets.
                int chain_start_set = -1;
                for (int s = 0; s < NUM_CHALLENGE_SETS; ++s) {
                    if (selected_sets.fragment_set_ranges[s].isInRange(chain.fragments[0])) {
                        chain_start_set = s;
                        break;
                    }
                }
                REQUIRE(chain_start_set >= 0);
                start_set_chain_counts[chain_start_set]++;

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

                // Cross-set mutation: swap chain[0] (in start_set s) with chain[1]
                // (in set (s+1) % N). After the swap, chain[0] is in set (s+1)%N so
                // validate detects start_set'=(s+1)%N and then expects chain[1] in
                // (s+2)%N — but the swapped chain[1] is in set s. The rotated range
                // check must reject this. (If start_set rotation in validate was
                // wrong this would slip through whenever the chain hash happened to
                // collide.)
                Chain xset_mutated_chain = chain;
                std::swap(xset_mutated_chain.fragments[0], xset_mutated_chain.fragments[1]);
                bool valid_xset_mutated
                    = chainer.validate(xset_mutated_chain, selected_sets.fragment_set_ranges);
                if (xset_mutated_chain.fragments[0] != xset_mutated_chain.fragments[1]) {
                    REQUIRE(!valid_xset_mutated);
                    num_cross_set_mutations++;
                }
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

    // Print the per-starter-set chain count distribution. With the new
    // multi-set starter algorithm we expect roughly equal contribution from
    // every set (uniform over NUM_CHALLENGE_SETS), since the starter filter is
    // hash-driven and the synthetic sets are identically sized.
    std::cout << "Chain starter-set distribution (chain.fragments[0] -> set):\n";
    for (int s = 0; s < NUM_CHALLENGE_SETS; ++s) {
        std::cout << "  set " << s << ": " << start_set_chain_counts[s] << " chains\n";
    }
    std::cout << "Cross-set mutations rejected by validate: " << num_cross_set_mutations << "\n";

    // Each starter set should account for at least 1/(2N) of the total — a
    // generous bound that easily passes for uniform starter selection but fires
    // loudly if find_links accidentally regresses to "set 0 only" (in which
    // case three of the four buckets would be exactly zero).
    if (total_chains_found > 0) {
        size_t const min_per_set = total_chains_found / (2 * NUM_CHALLENGE_SETS);
        for (int s = 0; s < NUM_CHALLENGE_SETS; ++s) {
            REQUIRE_MESSAGE(start_set_chain_counts[s] > static_cast<int>(min_per_set),
                "Starter set " << s << " produced only " << start_set_chain_counts[s]
                               << " chains (min expected " << min_per_set
                               << "); does find_links iterate every challenge set?");
        }
    }

    // Negative case: a chain whose first fragment is outside every selected
    // set's range must be rejected by validate (start_set detection fails).
    {
        // Pull a known-good chain from one trial and tamper its first fragment
        // by replacing it with a value far outside any selected range. Any
        // value beyond the largest set range end works; using max - 1 keeps it
        // unambiguously out of bounds.
        std::array<uint8_t, 32> probe_challenge = challenge;
        probe_challenge[0] = 0;
        probe_challenge[1] = 0;
        probe_challenge[2] = 0;
        probe_challenge[3] = 0;
        Chainer probe_chainer(proof_params, probe_challenge);
        std::array<std::span<ProofFragment const>, NUM_CHALLENGE_SETS> probe_fragments_per_set;
        for (int s = 0; s < NUM_CHALLENGE_SETS; ++s) {
            probe_fragments_per_set[s] = encrypted_sets[s];
        }
        auto probe_chains = probe_chainer.find_links(probe_fragments_per_set);
        if (!probe_chains.empty()) {
            Chain bad = probe_chains.front();
            // Set fragment[0] to a value greater than every selected range's end.
            ProofFragment max_end = 0;
            for (int s = 0; s < NUM_CHALLENGE_SETS; ++s) {
                if (selected_sets.fragment_set_ranges[s].end > max_end) {
                    max_end = static_cast<ProofFragment>(selected_sets.fragment_set_ranges[s].end);
                }
            }
            bad.fragments[0] = max_end + 1;
            REQUIRE(!probe_chainer.validate(bad, selected_sets.fragment_set_ranges));
        }
    }

    // The synthetic test uses fixed-size sets (exactly chaining_set_size each),
    // so the Jensen bonus E[|S|^(L/N)]^N / lambda^L is exactly 1.0 — no
    // variance. The last-link recalibration tightens the filter by
    // 1/jensen_bonus assuming Poisson(lambda), so the synthetic mean drops by
    // that same factor (~1/1.44).
    constexpr double lambda = static_cast<double>(1ULL << CHAIN_SET_BITS);
    constexpr int reuse = NUM_CHAIN_LINKS / NUM_CHALLENGE_SETS;
    static_assert(reuse == 4, "Update Stirling coefficients if reuse changes");
    // E[X^4] / lambda^4 for X ~ Poisson(lambda):
    double const ratio
        = 1.0 + 6.0 / lambda + 7.0 / (lambda * lambda) + 1.0 / (lambda * lambda * lambda);
    double bonus = 1.0;
    for (int i = 0; i < NUM_CHALLENGE_SETS; ++i)
        bonus *= ratio;
    double const expected_mean = 1.0 / bonus;
    std::cout << "Expected mean (model): " << expected_mean << "\n";
    REQUIRE(mean > expected_mean * 0.80);
    REQUIRE(mean < expected_mean * 1.20);
#endif
}

TEST_SUITE_END();
