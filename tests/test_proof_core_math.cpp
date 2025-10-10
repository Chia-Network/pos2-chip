#include "test_util.h"
#include "pos/ProofCore.hpp"
#include "common/Utils.hpp"


struct QualitySetSizeTestCase {
    int k;
    int sub_k;
    double expected_quality_set_size;
    uint32_t expected_pass_threshold_first;
    uint32_t expected_pass_threshold_rest;
};

const QualitySetSizeTestCase QUALITY_SET_SIZE_TEST_CASES[] = {
    {28,  20, 6527.48, 5263856 , 1315964 },
    {30,  21, 6527.48, 5263856 , 1315964 },
    {32,  22, 6527.48, 5263856 , 1315964 },
};
// if we update main proof core chaining factors, we should update these test factors too
constexpr double TEST_CHAINING_FACTORS[NUM_CHAIN_LINKS - 1] = {
    4.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
};

double num_expected_pruned_entries_for_t3(int k)
{
    double k_entries = (double)(1UL << k);
    double t3_entries = (FINAL_TABLE_FILTER_D / 0.25) * k_entries;
    return t3_entries;
}

double entries_per_partition(const ProofParams &params)
{
    return num_expected_pruned_entries_for_t3(params.get_k()) / (double)params.get_num_partitions();
}

double expected_quality_links_set_size(const ProofParams &params)
{
    double num_entries_per_partition = entries_per_partition(params); //num_expected_pruned_entries_for_t3(params.get_k()) / (double)params.get_num_partitions();
    return 2.0 * num_entries_per_partition / (double)params.get_num_partitions();
}

static double expected_number_of_quality_chains_per_passing_fragment()
{
    double expected = TEST_CHAINING_FACTORS[0];
    for (int i = 1; i < NUM_CHAIN_LINKS - 1; ++i)
    {
        expected *= TEST_CHAINING_FACTORS[i];
    }
    return expected;
}

// link_index 0 is first quality link added by passsing fragment scan filter
// link_index 1 starts using CHAINING_FACTORS[0] and so on.
uint32_t test_quality_chain_pass_threshold(const ProofParams &params, int link_index)
{
    // 1) compute pass probability
    // pattern selection requires 2x multiplier, since there are 2 patterns (LR and RR)
    double chance = 2.0 * TEST_CHAINING_FACTORS[link_index - 1] / expected_quality_links_set_size(params);

    // 2) use long double for extra precision
    long double max_uint32 = static_cast<long double>(std::numeric_limits<uint32_t>::max());

    // 3) compute raw threshold
    long double raw = chance * max_uint32;

    // 4) clamp to avoid overflow
    if (raw >= max_uint32)
    {
        raw = max_uint32;
    }

    // 5) round to nearest integer and return
    return static_cast<uint32_t>(raw + 0.5L);
}

double bit_saturation(double num_chain_candidates, const ProofParams &params)
{
    uint64_t total_entries = (1ULL << params.get_k());
    uint64_t dropped_entries_per_fragment = (1ULL << (params.get_k() / 2)) * 4ULL * 3ULL; // each chain has 3 fragments, with 4 bit dropped entries each, dropping k/2 bits each
    uint64_t total_dropped_entries = (uint64_t) num_chain_candidates * dropped_entries_per_fragment;
    std::cout << " num_chain_candidates: " << (uint64_t) num_chain_candidates;
    std::cout << " Total entries: " << total_entries << ", total dropped entries: " << total_dropped_entries << std::endl;
    std::cout << " Dropped entries per fragment: " << dropped_entries_per_fragment << std::endl;
    double saturation = (double)total_dropped_entries / (double)total_entries;
    return saturation;
}

TEST_SUITE_BEGIN("proof-core-math");

TEST_CASE("expected-partition-sizes")
{
    // go through test case parameters and expected values
    for (const auto &test_case : QUALITY_SET_SIZE_TEST_CASES)
    {
        ProofParams params(Utils::hexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF").data(), test_case.k, 2);
        double quality_set_size = expected_quality_links_set_size(params);
        std::cout << "k=" << test_case.k << " sub_k=" << test_case.sub_k
                  << " expected quality set size: " << test_case.expected_quality_set_size
                  << " computed: " << quality_set_size << std::endl;
        CHECK(std::abs(quality_set_size - test_case.expected_quality_set_size) < 1.0);

        // check first and rest pass thresholds
        uint32_t first_threshold = test_quality_chain_pass_threshold(params, 1);
        uint32_t rest_threshold = test_quality_chain_pass_threshold(params, 2);
        std::cout << " first pass threshold expected: " << test_case.expected_pass_threshold_first
                  << " computed: " << first_threshold << std::endl;
        std::cout << " rest pass threshold expected: " << test_case.expected_pass_threshold_rest
                  << " computed: " << rest_threshold << std::endl;
        CHECK(first_threshold == test_case.expected_pass_threshold_first);
        CHECK(rest_threshold == test_case.expected_pass_threshold_rest);
    }
    /*{
        ProofParams params(Utils::hexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF").data(), k, 2);
        ProofCore proof_core(params);

        double t3_exp = proof_core.num_expected_pruned_entries_for_t3();
        double t3_test = num_expected_pruned_entries_for_t3(k);
        params.debugPrint();
        std::cout << "Num expected entries for T3: " << (uint64_t) t3_exp << " (" << t3_exp << ")" << std::endl;
        std::cout << "  Test: " << (uint64_t) t3_test << " (" << t3_test << ")" << std::endl;
        std::cout << "Num partitions: " << params.get_num_partitions() << std::endl;
        std::cout << "Entries per partition: " << (uint64_t) entries_per_partition(params) << std::endl;
        std::cout << "Expected quality links set size: " << expected_quality_links_set_size(params) << std::endl;
        std::cout << "Expected number of quality chains per passing fragment: " << expected_number_of_quality_chains_per_passing_fragment() << std::endl;
        std::cout << "Bit saturation: " << bit_saturation(expected_quality_links_set_size(params), params) << std::endl;
        for (int i = 1; i < NUM_CHAIN_LINKS; ++i)
        {
            std::cout << "Quality chain pass threshold for link " << i << ": " << test_quality_chain_pass_threshold(params, i) << std::endl;
            std::cout << "nd Quality chain threshold: " << proof_core.quality_chain_pass_threshold(i) << std::endl;
            if (i == 1)
            {
                // at k 28 we check against expected value from spreadsheet calculations
                if (k == 28) {
                    CHECK(proof_core.quality_chain_pass_threshold(i) == 5263856);
                }
                CHECK(proof_core.quality_chain_pass_threshold(i) == test_quality_chain_pass_threshold(params, i));
            }
            else
            {
                // at k 28 we check against expected value from spreadsheet calculations
                if (k == 28) {
                    CHECK(proof_core.quality_chain_pass_threshold(i) == 1315964);
                }
                CHECK(proof_core.quality_chain_pass_threshold(i) == test_quality_chain_pass_threshold(params, i));
            }
        }
    }*/
}