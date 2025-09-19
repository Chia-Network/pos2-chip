#include "test_util.h"
#include "pos/ProofCore.hpp"
#include "pos/ProofFragment.hpp"
#include "prove/Prover.hpp"
#include "common/Timer.hpp"

TEST_SUITE_BEGIN("quality-chain");
/*
TEST_CASE("quality-chain-distribution")
{
    ProofParams params(Utils::hexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF").data(), 28);
    ProofCore proof_core(params);

    std::array<uint8_t, 32> challenge;
    challenge.fill(0); // Initialize challenge with zeros

    PlotData empty;
    PlotFile::PlotFileContents plot(empty, params);
    plot.params = params;
    Prover prover(challenge, "test_plot_file.dat");
    prover._testing_setPlotFileContents(plot);

    // create random quality links
    std::vector<QualityLink> links;
    int num_quality_links = (int) proof_core.expected_quality_links_set_size();
    std::cout << "Expected number of quality links: " << num_quality_links << std::endl;
    

    links.reserve(num_quality_links);
    // Generate random quality links
    //srand(static_cast<unsigned int>(time(nullptr))); // seed random number generator
    srand(23); // for reproducibility in tests
    // Generate random quality links

    for (int i = 0; i < num_quality_links; ++i)
    {
        QualityLink link;
        link.pattern = static_cast<FragmentsPattern>(rand() % 2); // Randomly choose between OUTSIDE_FRAGMENT_IS_LR and OUTSIDE_FRAGMENT_IS_RR
        for (int j = 0; j < 3; ++j)
        {
            link.fragments[j] = rand() % std::numeric_limits<uint64_t>::max();
        }
        links.push_back(link);
    }


    //uint32_t chaining_hash_pass_threshold = proof_core.quality_chain_pass_threshold();
    //std::cout << "Chaining hash pass threshold: " << chaining_hash_pass_threshold << std::endl;

    // histogram of counts
    std::vector<int> histogram(100, 0); // Histogram for counts of quality chains found
    int64_t total_chains_found = 0;
    int maximum_chains_per_trial = 0;
    double expected_avg_chains_per_trial = proof_core.expected_number_of_quality_chains_per_passing_fragment();
    std::cout << "Expected average chains per trial: " << expected_avg_chains_per_trial << std::endl;
    // Create a QualityChain with the generated links

    // start timer
    Timer timer;
    timer.start();
    double maximum_trial_time_ms = 0.0;

    size_t num_trials = 3000;
    for (int i=0;i<num_trials;i++)
    {
        Timer trial_timer;
        trial_timer.start();
        // update challenge for each trial
        challenge[0] = i & 0xFF;
        challenge[1] = (i >> 8) & 0xFF;
        challenge[2] = (i >> 16) & 0xFF;
        challenge[3] = (i >> 24) & 0xFF;
        prover.setChallenge(challenge);
        QualityLink firstLink = links[0]; 
        std::vector<QualityChain> qualityChains = prover.createQualityChains(firstLink, links);
        
        if (qualityChains.size() > 0)
        {
            std::cout << "Trial " << i << ": Found " << qualityChains.size() << " quality chains." << std::endl;
        }                                                               
        size_t qualityChainCount = qualityChains.size();
        if (qualityChainCount >= histogram.size())
        {
            //std::cerr << "Warning: Quality chain count exceeds histogram size, truncating." << std::endl;
            qualityChainCount = histogram.size() - 1; // truncate to fit in histogram
        }
        
        total_chains_found += qualityChains.size();
        if (qualityChains.size() > maximum_chains_per_trial)
        {
            maximum_chains_per_trial = qualityChains.size();
        }
        if (qualityChains.size() < histogram.size())
        {
            histogram[qualityChains.size()]++;
        }
        else {
            histogram[histogram.size() - 1]++; // increment the last bucket if it exceeds
        }

        double trial_time_ms = trial_timer.stop();
        if (trial_time_ms > maximum_trial_time_ms)
        {
            maximum_trial_time_ms = trial_time_ms;
        }
    }

    double time_taken_ms = timer.stop();
    
    // output histogram
    std::cout << "Quality Chain Distribution Histogram:" << std::endl;
    for (size_t i = 0; i < histogram.size(); ++i)
    {
        std::cout << "Quality Chains: " << i << " Count: " << histogram[i] << std::endl;
    }
    std::cout << "Total chains found: " << total_chains_found << std::endl;
    std::cout << "Time taken for " << num_trials << " trials: " << time_taken_ms << " ms" << std::endl;
    std::cout << "Average time per trial: " << (time_taken_ms / num_trials) << " ms" << std::endl;
    std::cout << "Maximum time for a single trial: " << maximum_trial_time_ms << " ms" << std::endl;
    
    std::cout << "Average chains per trial: " << static_cast<double>(total_chains_found) / num_trials << std::endl;
    std::cout << "Expected average chains per trial: " << expected_avg_chains_per_trial << std::endl;
    std::cout << "Maximum chains found in a single trial: " << maximum_chains_per_trial << std::endl;
    //std::cout << "Total blake hashes: " << stat_total_hashes << std::endl;
    //std::cout << "Total blake hashes per trial: " << static_cast<double>(stat_total_hashes) / num_trials << std::endl;

    // pass if expected average chains per trial is within 10% of the actual average
    double average_chains_per_trial = static_cast<double>(total_chains_found) / num_trials;
    double tolerance = expected_avg_chains_per_trial * 0.1; // 10% tolerance
    CHECK(average_chains_per_trial >= expected_avg_chains_per_trial - tolerance);
    CHECK(average_chains_per_trial <= expected_avg_chains_per_trial + tolerance);
}
*/
