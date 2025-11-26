#include "test_util.h"
#include "pos/ProofCore.hpp"
#include "plot/Plotter.hpp"
#include "plot/PlotFile.hpp"
#include "pos/ProofFragmentScanFilter.hpp"
#include "common/Utils.hpp"
#include "common/Timer.hpp"
#include "pos/Chainer.hpp"

#include <cstdint>
#include <vector>
#include <iostream>
#include <iomanip>
#include <random>

//#define DEBUG_CHAINER true

TEST_SUITE_BEGIN("chainer");

TEST_CASE("chaining_set_sizes")
{
    constexpr uint8_t k = 28;
    std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    ProofParams proof_params(Utils::hexToBytes(plot_id_hex).data(), k, 2);

    int chaining_set_size = proof_params.get_chaining_set_size();

    std::cout << "For k=" << static_cast<int>(k)
              << ", chaining set size is " << chaining_set_size << "\n";

    
    
}

TEST_CASE("small_lists")
{
    constexpr uint8_t k = 28;
    std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    std::string challenge_hex = "5c00000000000000000000000000000000000000000000000000000000000000";
    std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);
    ProofParams proof_params(Utils::hexToBytes(plot_id_hex).data(), k, 2);

    int chaining_set_size = proof_params.get_chaining_set_size();

    // TODO: calculate how many chaining sets there are
    // then, use hash on challenge to determine which two distinct sets to use (maybe part of hash picks even set, the other odd set)
    // then, find start range value for both sets
    // and generate random numbers in the range for those sets.
    
    std::mt19937 rng(1245); // fixed seed for reproducibility
    std::uniform_int_distribution<ProofFragment> dist(0, (1ULL << k) - 1);  
    // now create two lists of size chaining_set_size each
    int bitdrop_add_size = 0;
    chaining_set_size += bitdrop_add_size;
    std::cout << "Creating two chaining lists of size " << chaining_set_size << " each.\n";
    std::vector<ProofFragment> encrypted_As(chaining_set_size);
    std::vector<ProofFragment> encrypted_Bs(chaining_set_size);
    for (int i = 0; i < chaining_set_size; ++i)
    {
        encrypted_As[i] = dist(rng);
        encrypted_Bs[i] = dist(rng);
    }
    int num_trials = 1000;
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
                // just make ranges maximum uint64_t for now
                Range fragment_range_A{0, UINT64_MAX};
                Range fragment_range_B{0, UINT64_MAX};
                bool valid = chainer.validate(chain, fragment_range_A, fragment_range_B);
                // could do more validation here if desired
                REQUIRE(valid);
                if (valid) {
                    num_chains_validated++;
                }

                // switch two links from same set and validation should fail
                Chain mutated_chain = chain;
                std::swap(mutated_chain.fragments[trial % mutated_chain.fragments.size()], mutated_chain.fragments[(trial + 2) % mutated_chain.fragments.size()]);
                bool valid_mutated = chainer.validate(mutated_chain, fragment_range_A, fragment_range_B);
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
    REQUIRE(mean > expected_mean * 0.90);
    REQUIRE(mean < expected_mean * 1.10);

}

TEST_SUITE_END();
