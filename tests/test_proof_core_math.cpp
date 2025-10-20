#include "test_util.h"
#include "pos/ProofCore.hpp"
#include "common/Utils.hpp"


struct QualitySetSizeTestCase {
    uint8_t k;
    int sub_k;
    double num_expected_t3_pruned_entries;
    double expected_quality_set_size;

    // chaining filter test thresholds
    uint32_t expected_pass_threshold_first;
    uint32_t expected_pass_threshold_rest;
};

// test cases generated from spreadsheet math
// not all cases are valid, as it checks for current sub_k values and skips cases that don't match
const QualitySetSizeTestCase QUALITY_SET_SIZE_TEST_CASES[] = {
    {18,  15, 208879.52, 6527.48, 5263856 , 1315964 },
    {20,  16, 835518.08, 6527.48, 5263856 , 1315964  },
    {22,  17, 3342072.31, 6527.48, 5263856 , 1315964   },
    {24,  18, 13368289.23, 6527.48, 5263856 , 1315964   },
    {26,  19, 53473156.93, 6527.48, 5263856 , 1315964   },
    {28,  20, 213892627.73, 6527.48, 5263856 , 1315964 },
    {30,  22, 855570510.93, 26109.94, 1315964 , 328991 },
    {32,  23, 3422282043.70, 26109.94, 1315964 , 328991 },
};
// if we update main proof core chaining factors, we should update these test factors too
constexpr double TEST_CHAINING_FACTORS[NUM_CHAIN_LINKS - 1] = {
    4.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0,
};

double num_expected_pruned_entries_for_t3(int k)
{
    double k_entries = (double)(1ULL << k);
    double t3_entries = (FINAL_TABLE_FILTER_D * 4) * k_entries;
    return t3_entries;
}

double entries_per_partition(const ProofParams &params)
{
    return num_expected_pruned_entries_for_t3(params.get_k()) / (double)params.get_num_partitions();
}

double expected_quality_links_set_size(const ProofParams &params)
{
    double num_entries_per_partition = entries_per_partition(params);
    return 2.0 * num_entries_per_partition / (double)params.get_num_partitions();
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
    int num_cases = 8; 
    int tested_cases = 0;
    for (const auto &test_case : QUALITY_SET_SIZE_TEST_CASES)
    {
        ProofParams params(Utils::hexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF").data(), test_case.k, 2);
        if (params.get_sub_k() != test_case.sub_k) {
            std::cerr << "Skipping k=" << (int) test_case.k << " sub_k=" << test_case.sub_k << " since sub_k does not match: " << params.get_sub_k() << std::endl;
            continue;
        }
        tested_cases++;
        ProofCore proof_core(params);

        // these are for debug output on checking our math
        double dbl_math_quality_set_size = expected_quality_links_set_size(params);
        double dbl_math_t3_pruned = num_expected_pruned_entries_for_t3(test_case.k);
        
        std::cout << "k=" << (int) test_case.k << " sub_k=" << test_case.sub_k << std::endl
                  << " num t3 pruned entries per partition: " << test_case.num_expected_t3_pruned_entries
                  << " computed: " << dbl_math_t3_pruned << std::endl;
        std::cout << " check dbl quality set size: " << dbl_math_quality_set_size << std::endl;
        std::cout << " check dbl t3 pruned entries: " << dbl_math_t3_pruned << std::endl;
        CHECK(std::abs(dbl_math_t3_pruned - test_case.num_expected_t3_pruned_entries) < 1.0);
        CHECK(std::abs(dbl_math_quality_set_size - test_case.expected_quality_set_size) < 1.0);

        double test_dbl_first_threshold = test_quality_chain_pass_threshold(params, 1);
        double test_dbl_rest_threshold = test_quality_chain_pass_threshold(params, 2);
        // sanity check on our math
        CHECK(std::abs(test_dbl_first_threshold - test_case.expected_pass_threshold_first) < 2.0);
        CHECK(std::abs(test_dbl_rest_threshold - test_case.expected_pass_threshold_rest) < 2.0);

        // check first and rest pass thresholds
        uint32_t first_threshold = proof_core.quality_chain_pass_threshold(1);
        uint32_t rest_threshold = proof_core.quality_chain_pass_threshold(2);
        std::cout << " first pass threshold expected: " << test_case.expected_pass_threshold_first
                  << " computed: " << first_threshold << std::endl;
        std::cout << " rest pass threshold expected: " << test_case.expected_pass_threshold_rest
                  << " computed: " << rest_threshold << std::endl;
        CHECK(first_threshold == test_case.expected_pass_threshold_first);
        CHECK(rest_threshold == test_case.expected_pass_threshold_rest);

        
    }
    // make sure we tested all cases for the k sizes 18, 28, 30, 32.  If we change sub_k values, we may skip some cases and have to introduce them to test data.
    CHECK(tested_cases == num_cases);
}