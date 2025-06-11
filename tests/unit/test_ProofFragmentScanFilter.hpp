#include "prove/ProofFragmentScanFilter.hpp"
#include "pos/ProofCore.hpp"

TEST_SUITE_BEGIN("proof-fragment-scan-filter");

TEST_CASE("lsb-from-challenge") {
    // In this test, we set all bits in a challenge to 1, then pull the least significant bits (LSB) from the challenge
    // and verify that they match the expected values.
    int k = 28;
    int sub_k = 20;
    std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    std::array<uint8_t, 32> challenge = {0};
    for (int j = 0; j < 32; ++j) {
        challenge[j] = 255;
    }
    ProofParams params(Utils::hexToBytes(plot_id_hex).data(), k, sub_k);
    
    ProofFragmentScanFilter filter(params, challenge, 1);
    // Test with various challenges
    for (int i = 0; i < 64; ++i) {
        uint64_t lsbits = filter.getLSBFromChallenge(i);
        REQUIRE(lsbits == (1ULL << i)-1);
    }
}

TEST_CASE("scan-range") {
    // Setup dummy ProofParams and challenge
    int k = 28;
    int sub_k = 20;
    std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    std::array<uint8_t, 32> challenge = {0};
    int scan_filter = 1;
    
    ProofParams params(Utils::hexToBytes(plot_id_hex).data(), k, sub_k);

    ProofFragmentScanFilter filter(params, challenge, scan_filter);

    auto range = filter.getScanRangeForFilter();

    // For all-zero challenge, scan_range_id should be 0
    int scan_range_filter_bits = k - PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS;

    uint64_t scan_range = (1ULL << (k + PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS));
    uint64_t total_ranges = 1ULL << scan_range_filter_bits;
    REQUIRE(range.start == 0);
    REQUIRE(range.end == (scan_range * 1 - 1));

    // now try with challenge of 1
    challenge[0] = 1;
    filter = ProofFragmentScanFilter(params, challenge, scan_filter);
    range = filter.getScanRangeForFilter();
    // With challenge of 1, scan_range_id should be 1
    REQUIRE(range.start == (scan_range * 1));
    REQUIRE(range.end == (scan_range * 2 - 1));
    // now try with challenge of 2
    challenge[0] = 2;
    filter = ProofFragmentScanFilter(params, challenge, scan_filter);
    range = filter.getScanRangeForFilter();
    // With challenge of 2, scan_range_id should be 2
    REQUIRE(range.start == scan_range * 2);
    REQUIRE(range.end == (scan_range * 3 - 1));

    // now try with challenge of 255
    challenge[0] = 255;
    filter = ProofFragmentScanFilter(params, challenge, scan_filter);
    range = filter.getScanRangeForFilter();
    // With challenge of 255, scan_range_id should be 255
    REQUIRE(range.start == (scan_range * 255));
    REQUIRE(range.end == (scan_range * 256 - 1));

    // now try with all bits set in challenge
    for (int i = 0; i < 32; ++i) {
        challenge[i] = 0xFF;
    }
    filter = ProofFragmentScanFilter(params, challenge, scan_filter);
    range = filter.getScanRangeForFilter();
    // With all bits set, scan_range_id should be (1 << scan_range_filter_bits) - 1
    REQUIRE(range.start == (72057594037927936 - scan_range));
    REQUIRE(range.end == (72057594037927936 - 1));
}