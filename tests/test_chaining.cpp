#include <span>
#include <bit>

#include "test_util.h"
#include "pos/ProofCore.hpp"
#include "pos/ProofFragment.hpp"
#include "prove/Prover.hpp"
#include "common/Timer.hpp"

static double expected_number_of_quality_chains_per_passing_fragment()
{
    // avoid narrowing warnings by doing intermediate computation in long double
    long double expected_ld = static_cast<long double>(CHAINING_FACTORS[0]);
    for (int i = 1; i < NUM_CHAIN_LINKS - 1; ++i)
    {
        expected_ld *= static_cast<long double>(CHAINING_FACTORS[i]);
    }
    return static_cast<double>(expected_ld);
}

TEST_SUITE_BEGIN("quality-chain");

TEST_CASE("quality-chain-distribution")
{
    // This test generates random quality links and measures the distribution of quality chains formed.
    // The data generated is random, and would not correspond to valid proofs, but the assumption is due to hashing producing random outputs the correctness of data does not influence the distribution characteristics.
    // The test outputs a histogram of quality chain counts over multiple trials, along with timing information.
    // This helps verify that the chaining logic behaves as expected statistically.
    ProofParams params(Utils::hexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF").data(), 28, 2);
    ProofCore proof_core(params);

    std::array<uint8_t, 32> challenge;
    challenge.fill(0); // Initialize challenge with zeros

    // a little "hacky", we setup a bogus file name and then override the plot file contents directly for testing
    // so this won't need to create or read a plot file.
    PlotData empty;
    PlotFile::PlotFileContents plot{empty, params};
    plot.params = params;
    Prover prover(challenge, "test_plot_file.dat");
    prover._testing_setPlotFileContents(plot);

    // create random quality links
    std::vector<QualityLink> links;
    auto num_quality_links_precise = proof_core.nd_expected_quality_links_set_size();
    int num_quality_links = (int) (num_quality_links_precise.first / num_quality_links_precise.second);
    std::cout << "Expected number of quality links: " << num_quality_links << std::endl;

    links.reserve(num_quality_links);
    // Generate random quality links
    // srand(static_cast<unsigned int>(time(nullptr))); // seed random number generator
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

    // uint32_t chaining_hash_pass_threshold = proof_core.quality_chain_pass_threshold();
    // std::cout << "Chaining hash pass threshold: " << chaining_hash_pass_threshold << std::endl;

    // histogram of counts
    std::vector<int> histogram(100, 0); // Histogram for counts of quality chains found
    int64_t total_chains_found = 0;
    size_t maximum_chains_per_trial = 0;
    double expected_avg_chains_per_trial = (double) expected_number_of_quality_chains_per_passing_fragment();
    std::cout << "Expected average chains per trial: " << expected_avg_chains_per_trial << std::endl;
    // Create a QualityChain with the generated links

    // start timer
    Timer timer;
    timer.start();
    double maximum_trial_time_ms = 0.0;

    /*
    Results for 20,000 trials with k=28, strength=2:
    Quality Chains: 0 Count: 12518 Perc: 62.59%
>=50 quality chains: 44 (0.22%)
>=40 quality chains: 119 (0.595%)
>=30 quality chains: 372 (1.86%)
>=20 quality chains: 1094 (5.47%)
>=10 quality chains: 3128 (15.64%)
>=5 quality chains: 5159 (25.795%)
>=2 quality chains: 6896 (34.48%)
>=1 quality chains: 7482 (37.41%)
Total chains found: 78814
Time taken for 20000 trials: 184836 ms
Average time per trial: 9.24179 ms
Maximum time for a single trial: 150.631 ms
Average chains per trial: 3.9407
Expected average chains per trial: 4
Maximum chains found in a single trial: 122
    */
    size_t num_trials = 1000;
    for (size_t i = 0; i < num_trials; i++)
    {
        Timer trial_timer;
        trial_timer.start();
        // update challenge for each trial
        challenge[0] = i & 0xFF;
        challenge[1] = (i >> 8) & 0xFF;
        challenge[2] = (i >> 16) & 0xFF;
        challenge[3] = (i >> 24) & 0xFF;
        prover.setChallenge(challenge);

        //ProofCore proof_core(params);

        BlakeHash::Result256 next_challenge = proof_core.hashing.challengeWithPlotIdHash(challenge.data());
        QualityLink firstLink = links[0];
        std::vector<QualityChain> qualityChains = prover.createQualityChains(firstLink, links, next_challenge);

        if (qualityChains.size() > 0)
        {
            std::cout << "Trial " << i << ": Found " << qualityChains.size() << " quality chains." << std::endl;
        }
        size_t qualityChainCount = qualityChains.size();
        if (qualityChainCount >= histogram.size())
        {
            // std::cerr << "Warning: Quality chain count exceeds histogram size, truncating." << std::endl;
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
        else
        {
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
    int sum_above_50 = 0;
    int sum_above_40 = 0;
    int sum_above_30 = 0;
    int sum_above_20 = 0;
    int sum_above_10 = 0;
    int sum_above_5 = 0;
    int sum_above_2 = 0;
    int sum_above_1 = 0;

    double expected_perc_sum_above_50 = 0.22;
    double expected_perc_sum_above_40 = 0.595;
    double expected_perc_sum_above_30 = 1.86;
    double expected_perc_sum_above_20 = 5.47;
    double expected_perc_sum_above_10 = 15.64;
    double expected_perc_sum_above_5 = 25.795;
    double expected_perc_sum_above_2 = 34.48;
    double expected_perc_sum_above_1 = 37.41;

    for (size_t i = 0; i < histogram.size(); ++i)
    {
        std::cout << "Quality Chains: " << i << " Count: " << histogram[i] << " Perc: " << (static_cast<double>(histogram[i]) / num_trials * 100.0) << "%" << std::endl;
        if (i >= 1)
            sum_above_1 += histogram[i];
        if (i >= 2)
            sum_above_2 += histogram[i];
        if (i >= 5)
            sum_above_5 += histogram[i];
        if (i >= 10)
            sum_above_10 += histogram[i];
        if (i >= 20)
            sum_above_20 += histogram[i];
        if (i >= 30)
            sum_above_30 += histogram[i];
        if (i >= 40)
            sum_above_40 += histogram[i];
        if (i >= 50)
            sum_above_50 += histogram[i];
    }
    // output sums and % stats
    double actual_perc_sum_above_50 = static_cast<double>(sum_above_50) / num_trials * 100.0;
    double actual_perc_sum_above_40 = static_cast<double>(sum_above_40) / num_trials * 100.0;
    double actual_perc_sum_above_30 = static_cast<double>(sum_above_30) / num_trials * 100.0;
    double actual_perc_sum_above_20 = static_cast<double>(sum_above_20) / num_trials * 100.0;
    double actual_perc_sum_above_10 = static_cast<double>(sum_above_10) / num_trials * 100.0;
    double actual_perc_sum_above_5 = static_cast<double>(sum_above_5) / num_trials * 100.0;
    double actual_perc_sum_above_2 = static_cast<double>(sum_above_2) / num_trials * 100.0;
    double actual_perc_sum_above_1 = static_cast<double>(sum_above_1) / num_trials * 100.0;
    std::cout << "Expected vs Actual Quality Chain Percentages:" << std::endl;
    std::cout << ">=50 quality chains: Expected " << expected_perc_sum_above_50 << "%, Actual " << actual_perc_sum_above_50 << "%, diff ratio: " << (std::max(actual_perc_sum_above_50,expected_perc_sum_above_50)/std::min(actual_perc_sum_above_50,expected_perc_sum_above_50)) << std::endl;
    std::cout << ">=40 quality chains: Expected " << expected_perc_sum_above_40 << "%, Actual " << actual_perc_sum_above_40 << "%, diff ratio: " << (std::max(actual_perc_sum_above_40,expected_perc_sum_above_40)/std::min(actual_perc_sum_above_40,expected_perc_sum_above_40)) << std::endl;
    std::cout << ">=30 quality chains: Expected " << expected_perc_sum_above_30 << "%, Actual " << actual_perc_sum_above_30 << "%, diff ratio: " << (std::max(actual_perc_sum_above_30,expected_perc_sum_above_30)/std::min(actual_perc_sum_above_30,expected_perc_sum_above_30)) << std::endl;
    std::cout << ">=20 quality chains: Expected " << expected_perc_sum_above_20 << "%, Actual " << actual_perc_sum_above_20 << "%, diff ratio: " << (std::max(actual_perc_sum_above_20,expected_perc_sum_above_20)/std::min(actual_perc_sum_above_20,expected_perc_sum_above_20)) << std::endl;
    std::cout << ">=10 quality chains: Expected " << expected_perc_sum_above_10 << "%, Actual " << actual_perc_sum_above_10 << "%, diff ratio: " << (std::max(actual_perc_sum_above_10,expected_perc_sum_above_10)/std::min(actual_perc_sum_above_10,expected_perc_sum_above_10)) << std::endl;
    std::cout << ">=5 quality chains: Expected " << expected_perc_sum_above_5 << "%, Actual " << actual_perc_sum_above_5 << "%, diff ratio: " << (std::max(actual_perc_sum_above_5,expected_perc_sum_above_5)/std::min(actual_perc_sum_above_5,expected_perc_sum_above_5)) << std::endl;
    std::cout << ">=2 quality chains: Expected " << expected_perc_sum_above_2 << "%, Actual " << actual_perc_sum_above_2 << "%, diff ratio: " << (std::max(actual_perc_sum_above_2,expected_perc_sum_above_2)/std::min(actual_perc_sum_above_2,expected_perc_sum_above_2)) << std::endl;
    std::cout << ">=1 quality chains: Expected " << expected_perc_sum_above_1 << "%, Actual " << actual_perc_sum_above_1 << "%, diff ratio: " << (std::max(actual_perc_sum_above_1,expected_perc_sum_above_1)/std::min(actual_perc_sum_above_1,expected_perc_sum_above_1)) << std::endl;

    double tolerance = 0.1; // 10% tolerance
    // Check each percentage is within tolerance
    CHECK(actual_perc_sum_above_50 < 0.5);
    CHECK(actual_perc_sum_above_40 < 1.0);
    CHECK(actual_perc_sum_above_30 < 5.0);
    CHECK(actual_perc_sum_above_20 >= expected_perc_sum_above_20 * (1.0 - tolerance));
    CHECK(actual_perc_sum_above_20 <= expected_perc_sum_above_20 * (1.0 + tolerance));
    CHECK(actual_perc_sum_above_10 >= expected_perc_sum_above_10 * (1.0 - tolerance));
    CHECK(actual_perc_sum_above_10 <= expected_perc_sum_above_10 * (1.0 + tolerance));
    CHECK(actual_perc_sum_above_5 >= expected_perc_sum_above_5 * (1.0 - tolerance));
    CHECK(actual_perc_sum_above_5 <= expected_perc_sum_above_5 * (1.0 + tolerance));
    CHECK(actual_perc_sum_above_2 >= expected_perc_sum_above_2 * (1.0 - tolerance));
    CHECK(actual_perc_sum_above_2 <= expected_perc_sum_above_2 * (1.0 + tolerance));
    CHECK(actual_perc_sum_above_1 >= expected_perc_sum_above_1 * (1.0 - tolerance));
    CHECK(actual_perc_sum_above_1 <= expected_perc_sum_above_1 * (1.0 + tolerance));

    std::cout << "Total chains found: " << total_chains_found << std::endl;
    std::cout << "Time taken for " << num_trials << " trials: " << time_taken_ms << " ms" << std::endl;
    std::cout << "Average time per trial: " << (time_taken_ms / num_trials) << " ms" << std::endl;
    std::cout << "Maximum time for a single trial: " << maximum_trial_time_ms << " ms" << std::endl;

    std::cout << "Average chains per trial: " << static_cast<double>(total_chains_found) / num_trials << std::endl;
    std::cout << "Expected average chains per trial: " << expected_avg_chains_per_trial << std::endl;
    std::cout << "Maximum chains found in a single trial: " << maximum_chains_per_trial << std::endl;
    // std::cout << "Total blake hashes: " << stat_total_hashes << std::endl;
    // std::cout << "Total blake hashes per trial: " << static_cast<double>(stat_total_hashes) / num_trials << std::endl;

    // pass if expected average chains per trial is within 10% of the actual average
    double average_chains_per_trial = static_cast<double>(total_chains_found) / num_trials;
    
    CHECK(average_chains_per_trial >= expected_avg_chains_per_trial * (1.0 - tolerance));
    CHECK(average_chains_per_trial <= expected_avg_chains_per_trial * (1.0 + tolerance));

}

std::string print_bits(const std::span<uint8_t> blob)
{
    std::string ret;
    for (uint8_t b : blob)
    {
        for (int mask = 0x80; mask != 0; mask >>= 1)
        {
            if (b & mask)
                ret += '1';
            else
                ret += '0';
        }
    }
    return ret;
}

TEST_CASE("quality-proof-serialization")
{
    QualityChain qp;
    qp.strength = 0x7f;
    ProofFragment fr = 0;
    for (int i = 0; i < NUM_CHAIN_LINKS; ++i)
    {
        for (int pf = 0; pf < 3; ++pf)
        {
            qp.chain_links[i].fragments[pf] = fr++;
        }
    }

    std::vector<uint8_t> blob = serializeQualityProof(qp);
    CHECK(blob[0] == 0x7f);
    blob.erase(blob.begin());

    CHECK(blob.size() == NUM_CHAIN_LINKS * 3 * 8);

    for (int idx = 0; idx < NUM_CHAIN_LINKS * 3; ++idx)
    {
        uint64_t val;
        memcpy(&val, blob.data() + idx * 8, 8);
        /*
                // This requires C++23
                if constexpr (std::endian::native == std::endian::big) {
                    val = std::byteswap(val);
                }
        */
        CHECK(val == idx);
    }
}

TEST_CASE("quality-proof-serialization-individual-fields")
{
    QualityChain qp;
    qp.strength = 2;

    const std::string zero(64, '0');
    const std::string one(64, '1');

    for (int field = 0; field < NUM_CHAIN_LINKS * 3; ++field)
    {

        // set exactly one field of all one-bits
        int idx = 0;
        for (int i = 0; i < NUM_CHAIN_LINKS; ++i)
        {
            for (int pf = 0; pf < 3; ++pf)
            {
                qp.chain_links[i].fragments[pf] = (field == idx) ? 0xffffffffffffffff : 0;
                ++idx;
            }
        }

        std::string expected_output;
        for (int i = 0; i < field; ++i)
            expected_output += zero;
        expected_output += one;
        for (int i = field + 1; i < NUM_CHAIN_LINKS * 3; ++i)
            expected_output += zero;

        std::vector<uint8_t> blob = serializeQualityProof(qp);
        CHECK(blob[0] == 2);
        blob.erase(blob.begin());
        CHECK(print_bits(blob) == expected_output);
    }
}
