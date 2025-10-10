#include "test_util.h"
#include "common/Utils.hpp"
#include "pos/ProofFragmentScanFilter.hpp"
#include "pos/ProofCore.hpp"

TEST_SUITE_BEGIN("proof-fragment-scan-filter");

TEST_CASE("scan-range")
{
    // Setup dummy ProofParams and challenge
    {
        int k = 28;
        std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        //std::array<uint8_t, 32> challenge = {0};
        // challenge is blake hash
        BlakeHash::Result256 challenge = {{0, 0, 0, 0, 0, 0, 0, 0}};
        
        ProofParams params(Utils::hexToBytes(plot_id_hex).data(), k, 2);

        // debug out params
        params.debugPrint();

        uint64_t base_scan_range = (1ULL << (k + PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS));
        std::cout << "base scan range: " << base_scan_range << std::endl;

        ProofFragmentScanFilter filter(params, challenge, 5);
        auto range = filter.getScanRangeForFilter();

        // For all-zero challenge, scan_range_id should be 0
        //int scan_range_filter_bits = k - PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS;

        
        std::cout << "scan range for challenge 0: " << range.start << " - " << range.end << std::endl;
        std::cout << "expected range            : " << 0 << " - " << (base_scan_range * 1 - 1) << std::endl;

        //uint64_t total_ranges = 1ULL << scan_range_filter_bits;
        REQUIRE(range.start == 0);
        REQUIRE(range.end == (base_scan_range * 1 - 1));
        
        // now try with challenge of 1
        challenge.r[3] = 1;
        filter = ProofFragmentScanFilter(params, challenge, 5);
        range = filter.getScanRangeForFilter();

        std::cout << "scan range for challenge 1: " << range.start << " - " << range.end << std::endl;
        std::cout << "expected range            : " << (base_scan_range * 1) << " - " << (base_scan_range * 2 - 1) << std::endl;

        // With challenge of 1, scan_range_id should be 1
        REQUIRE(range.start == (base_scan_range * 1));
        REQUIRE(range.end == (base_scan_range * 2 - 1));
        // now try with challenge of 2
        challenge.r[3] = 2;
        filter = ProofFragmentScanFilter(params, challenge, 5);
        range = filter.getScanRangeForFilter();

        std::cout << "scan range for challenge 2: " << range.start << " - " << range.end << std::endl;
        std::cout << "expected range            : " << (base_scan_range * 2) << " - " << (base_scan_range * 3 - 1) << std::endl;

        // With challenge of 2, scan_range_id should be 2
        REQUIRE(range.start == base_scan_range * 2);
        REQUIRE(range.end == (base_scan_range * 3 - 1));

        // now try with challenge of 255
        challenge.r[3] = 255;
        filter = ProofFragmentScanFilter(params, challenge, 5);
        range = filter.getScanRangeForFilter();

        std::cout << "scan range for challenge 255: " << range.start << " - " << range.end << std::endl;
        std::cout << "expected range              : " << (base_scan_range * 255) << " - " << (base_scan_range * 256 - 1) << std::endl;
        // With challenge of 255, scan_range_id should be 255
        REQUIRE(range.start == (base_scan_range * 255));
        REQUIRE(range.end == (base_scan_range * 256 - 1));

        // now try with all bits set in challenge
        for (int i = 0; i < 4; ++i)
        {
            challenge.r[i] = 0xFFFFFFFF;
        }
        filter = ProofFragmentScanFilter(params, challenge, 5);
        range = filter.getScanRangeForFilter();
        // With all bits set, scan_range_id should be (1 << scan_range_filter_bits) - 1
        REQUIRE(range.start == (72057594037927936 - base_scan_range));
        REQUIRE(range.end == (72057594037927936 - 1));
    }

    /*{
        std::cout << "Testing with smaller k..." << std::endl;
        // test with smaller k
        int k = 20;
        int sub_k = 16;
        std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        std::array<uint8_t, 32> challenge = {0};
        int scan_filter = 1;
        ProofParams params(Utils::hexToBytes(plot_id_hex).data(), k, sub_k);
        ProofFragmentScanFilter filter(params, challenge);
        auto range = filter.getScanRangeForFilter();
        // For k=20, scan_range_id should be 0
        uint64_t scan_range = (1ULL << (k + PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS));
        uint64_t total_ranges = 1ULL << (k - PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS);
        REQUIRE(range.start == 0);
        REQUIRE(range.end == (scan_range * 1 - 1));
        // now try with challenge of 1
        challenge[0] = 1;
        filter = ProofFragmentScanFilter(params, challenge);
        range = filter.getScanRangeForFilter();
        // With challenge of 1, scan_range_id should be 1
        REQUIRE(range.start == (scan_range * 1));
        REQUIRE(range.end == (scan_range * 2 - 1));
        // now try with challenge of 2
        challenge[0] = 2;
        filter = ProofFragmentScanFilter(params, challenge);
        range = filter.getScanRangeForFilter();
        // With challenge of 2, scan_range_id should be 2
        REQUIRE(range.start == (scan_range * 2));
        REQUIRE(range.end == (scan_range * 3 - 1));
        // now try with all bits set in challenge
        for (int i = 0; i < 32; ++i)
        {
            challenge[i] = 0xFF;
        }
        filter = ProofFragmentScanFilter(params, challenge);
        range = filter.getScanRangeForFilter();
        // With all bits set, scan_range_id should be (1 << scan_range_filter_bits) - 1
        REQUIRE(range.start == (1099511627776 - scan_range));
        REQUIRE(range.end == (1099511627776 - 1));
    }*/
}
