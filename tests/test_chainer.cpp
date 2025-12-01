#include "test_util.h"
#include "pos/ProofCore.hpp"
#include "plot/Plotter.hpp"
#include "plot/PlotFile.hpp"
#include "common/Utils.hpp"
#include "common/Timer.hpp"
#include "pos/Chainer.hpp"

#include <cstdint>
#include <vector>
#include <iostream>
#include <iomanip>
#include <random>

// #define DEBUG_CHAINER true

TEST_SUITE_BEGIN("chainer");

double expectedBucketsFilled(int N, int M) {
    double p_empty = std::pow(1.0 - 1.0 / M, N);
    return M * (1.0 - p_empty);
}

TEST_CASE("chaining_set_sizes")
{
    // create map of expected values for each k:
    // k 28, should be set size 4096
    // k 30, should be set size 16384
    // k 32, should be set size 65536
    std::map<int, int> expected_set_sizes = {
        {18, 128},
        {20, 256},
        {22, 512},
        {24, 1024},
        {26, 2048},
        {28, 4096},
        {30, 8192},
        {32, 16384},
    };

    std::map<int, uint32_t> expected_num_sets = {
        {18, 2048},
        {20, 4096},
        {22, 8192},
        {24, 16384},
        {26, 32768},
        {28, 65536},
        {30, 131072},
        {32, 262144},
    };

    for (int k = 18; k <= 32; k+=2) {
        std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        ProofParams proof_params(Utils::hexToBytes(plot_id_hex).data(), static_cast<uint8_t>(k), 2);

        int chaining_set_size = proof_params.get_chaining_set_size();

        std::cout << "For k=" << static_cast<int>(k)
              << ", chaining set bits: " << proof_params.get_chaining_set_bits() << std::endl
              << ", chaining set size: " << chaining_set_size << std::endl 
              << ", chaining num sets: " << proof_params.get_num_chaining_sets() << std::endl
              << ", chaining set range: #" << proof_params.get_chaining_set_range(0).start << " - " << proof_params.get_chaining_set_range(0).end << std::endl;

        uint64_t solver_t2_entries_per_proof_fragment = (uint64_t(1) << (k/2)) * 4;
        std::cout << "  solver_t2_entries_per_proof_fragment: " << solver_t2_entries_per_proof_fragment << std::endl;
        int num_bit_dropped_pairs = 4 * chaining_set_size * 2;
        int solution_size = 1 << (k/2);
        std::cout << "  num_bit_dropped_pairs: " << num_bit_dropped_pairs << std::endl;
        std::cout << "  solution_size: " << solution_size << std::endl;
        double expected_filled = expectedBucketsFilled(num_bit_dropped_pairs, solution_size);
        double saturation = expected_filled / static_cast<double>(solution_size);
        std::cout << "  expected filled buckets: " << expected_filled << std::endl;
        std::cout << "  t2 bit drop saturation: " << saturation << std::endl;
        ENSURE(chaining_set_size == expected_set_sizes[k]);
        ENSURE(proof_params.get_num_chaining_sets() == expected_num_sets[k]);
        ENSURE(saturation > 0.5); // at least 50% saturation
    }
}

TEST_CASE("small_lists")
{
    constexpr uint8_t k = 28;
    std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    std::string challenge_hex = "5c00000000000000000000000000000000000000000000000000000000000000";
    std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);
    ProofParams proof_params(Utils::hexToBytes(plot_id_hex).data(), k, 2);
    ProofCore proof_core(proof_params);

    ProofCore::SelectedChallengeSets selected_sets = proof_core.selectChallengeSets(challenge);

    #ifdef DEBUG_CHAINER
    std::cout << "Selected fragment set A index: " << selected_sets.fragment_set_A_index << "\n";
    std::cout << "Selected fragment set B index: " << selected_sets.fragment_set_B_index << "\n";
    std::cout << "Fragment set A range: " << selected_sets.fragment_set_A_range.start << " - " << selected_sets.fragment_set_A_range.end << "\n";
    std::cout << "Fragment set B range: " << selected_sets.fragment_set_B_range.start << " - " << selected_sets.fragment_set_B_range.end << "\n";
    #endif
    
    std::mt19937 rng(1245); // fixed seed for reproducibility
    ProofFragment max_offset = static_cast<ProofFragment>(selected_sets.fragment_set_A_range.end - selected_sets.fragment_set_A_range.start);
    std::uniform_int_distribution<ProofFragment> dist(0, max_offset);
    
    // now create two lists of size chaining_set_size each
    int chaining_set_size = proof_params.get_chaining_set_size();
    #ifdef DEBUG_CHAINER
    std::cout << "Creating two chaining lists of size " << chaining_set_size << " each, A in index: " << selected_sets.fragment_set_A_index
              << ", B in index: " << selected_sets.fragment_set_B_index << "\n";
    #endif
    // below can test attacker times by increasing list sizes to simulate bit dropping attacks on t3.
    // chaining_set_size += chaining_set_size / 2; // add 50% extra as an attack
    // chaining_set_size += 3 * chaining_set_size / 4; // add 75% extra as an attack
    std::vector<ProofFragment> encrypted_As(chaining_set_size);
    std::vector<ProofFragment> encrypted_Bs(chaining_set_size);
    for (int i = 0; i < chaining_set_size; ++i)
    {
        encrypted_As[i] = selected_sets.fragment_set_A_range.start + dist(rng);
        encrypted_Bs[i] = selected_sets.fragment_set_B_range.start + dist(rng);
        #ifdef DEBUG_CHAINER
        if ((i < 10) || (i >= chaining_set_size - 10))
        {
            std::cout << "  A[" << i << "] = " << encrypted_As[i]
                  << ", B[" << i << "] = " << encrypted_Bs[i] << "\n";
        }
        #endif
    }
    #ifdef NDEBUG
    int num_trials = 2000;
    int num_chains_validated = 0;
    int total_chains_found = 0;
    Timer timer;
    timer.start("Chaining trials");
    std::vector<int> trial_results;
    trial_results.reserve(num_trials);
    int total_hashes = 0;
    for (int trial = 0; trial < num_trials; ++trial)
    {
        // create new random challenge each trial
        challenge[0] = static_cast<uint8_t>(trial & 0xFF);
        challenge[1] = static_cast<uint8_t>((trial >> 8) & 0xFF);
        challenge[2] = static_cast<uint8_t>((trial >> 16) & 0xFF);
        challenge[3] = static_cast<uint8_t>((trial >> 24) & 0xFF);

        Chainer chainer(proof_params, challenge);

        auto chains = chainer.find_links(encrypted_As, encrypted_Bs);

        //std::cout << "Trial " << trial << ": Found " << chains.size() << " chains\n";

        total_chains_found += chains.size();

        trial_results.push_back(static_cast<int>(chains.size()));

        total_hashes += chainer.num_hashes;

        // validate chains that passed
        if (chains.size() > 0)
        {
            for (const auto &chain : chains)
            {
                bool valid = chainer.validate(chain, selected_sets.fragment_set_A_range, selected_sets.fragment_set_B_range);
                // could do more validation here if desired
                REQUIRE(valid);
                if (valid) {
                    num_chains_validated++;
                }

                // switch two links from same set and validation should fail
                Chain mutated_chain = chain;
                std::swap(mutated_chain.fragments[trial % mutated_chain.fragments.size()], mutated_chain.fragments[(trial + 2) % mutated_chain.fragments.size()]);
                bool valid_mutated = chainer.validate(mutated_chain, selected_sets.fragment_set_A_range, selected_sets.fragment_set_B_range);
                if (valid_mutated) {
                    std::cout << "WARNING: Mutated chain unexpectedly validated.\n";
                    // it can happen that two elements swapped are the same, so we just invalidate this test if it is.
                    if (mutated_chain.fragments[trial % mutated_chain.fragments.size()] ==
                        mutated_chain.fragments[(trial + 2) % mutated_chain.fragments.size()]) {
                        std::cout << "  (Swapped fragments are identical, so mutation ineffective.)\n";
                        valid_mutated = false;
                    }
                    // show previous chain and mutated chain
                    std::cout << "Original chain fragments: ";
                    for (const auto &frag : chain.fragments) {
                        std::cout << "0x" << std::hex << frag << " ";
                    }
                    std::cout << std::dec << "\n";
                    std::cout << "Mutated chain fragments:  ";
                    for (const auto &frag : mutated_chain.fragments) {
                        std::cout << "0x" << std::hex << frag << " ";
                    }
                    std::cout << std::dec << "\n";
                }
                REQUIRE(!valid_mutated);
                
            }
        }
    }
    double trials_ms = timer.stop();
    std::cout << "Total chains found in " << num_trials << " trials: " << total_chains_found << " (validated: " << num_chains_validated << ")\n";
    std::cout << "Chaining trials took " << trials_ms << " ms\n";

    // create and show historgram of trial_results
    std::map<int, int> histogram;
    for (int count : trial_results)
    {
        histogram[count]++;
    }
    std::cout << "Histogram of chains found per trial:\n";
    for (const auto &entry : histogram)
    {
        std::cout << "  " << entry.first << " chains: " << entry.second << " trials\n";
    }

    // calculate standard deviation and variance of results
    double mean = static_cast<double>(total_chains_found) / num_trials;
    double variance = 0.0;
    for (int count : trial_results)
    {
        variance += (count - mean) * (count - mean);
    }
    variance /= num_trials;
    double stddev = std::sqrt(variance);
    std::cout << "Mean chains per trial: " << mean << "\n";
    std::cout << "Standard deviation: " << stddev << "\n";
    std::cout << "Variance: " << variance << "\n";
    std::cout << "Total hashes computed: " << total_hashes << "\n";

    // the mean should average the expected outcome +- 10%
    double expected_mean = 1 / static_cast<double>(1 << AVERAGE_PROOFS_PER_CHALLENGE_BITS);
    REQUIRE(mean > expected_mean * 0.80);
    REQUIRE(mean < expected_mean * 1.20);
    #endif

}

TEST_SUITE_END();
