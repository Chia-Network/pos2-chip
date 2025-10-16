#include "test_util.h"
#include "common/Utils.hpp"
#include "pos/ProofFragmentScanFilter.hpp"
#include "pos/ProofCore.hpp"

TEST_SUITE_BEGIN("proof-fragment-scan-filter");

TEST_CASE("scan-range")
{
    // Setup dummy ProofParams and challenge
    // k list to test:
    for (int k : {18, 20, 22, 24, 26, 28, 30, 32})
    {
        std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        //std::array<uint8_t, 32> challenge = {0};
        // challenge is blake hash
        BlakeHash::Result256 challenge = {{0, 0, 0, 0, 0, 0, 0, 0}};
        
        ProofParams params(Utils::hexToBytes(plot_id_hex).data(), static_cast<uint8_t>(k), 2);

        // debug out params
        params.debugPrint();

        std::cout << "testing k size: " << k << std::endl;
        

        uint64_t base_scan_range = (1ULL << (k + PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS));
        std::cout << "base scan range: " << base_scan_range << std::endl;

        ProofFragmentScanFilter filter(params, challenge, 5);
        uint64_t num_scan_ranges = filter.numScanRanges();

        // highest order bit of challenge is pattern, next high order bits are scan range.
        int scan_range_filter_bits = k - PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS;
        
        auto range = filter.getScanRangeForFilter();

        // For all-zero challenge, scan_range_id should be 0
        //int scan_range_filter_bits = k - PROOF_FRAGMENT_SCAN_FILTER_RANGE_BITS;
        uint64_t scan_range_id = (challenge.r[3] >> (32 - scan_range_filter_bits - 1)) & ((1U << scan_range_filter_bits) - 1);

        
        std::cout << "scan range (" << scan_range_id << ") for challenge 0: " << range.start << " - " << range.end << std::endl;
        std::cout << "expected range            : " << 0 << " - " << (base_scan_range * 1 - 1) << std::endl;

        //uint64_t total_ranges = 1ULL << scan_range_filter_bits;
        REQUIRE(scan_range_id == 0);
        REQUIRE(range.start == 0);
        REQUIRE(range.end == (base_scan_range * 1 - 1));
        
        // now try with challenge of 1
        challenge.r[3] = 1 << (32 - scan_range_filter_bits - 1);
        filter = ProofFragmentScanFilter(params, challenge, 5);
        range = filter.getScanRangeForFilter();
        scan_range_id = (challenge.r[3] >> (32 - scan_range_filter_bits - 1)) & ((1U << scan_range_filter_bits) - 1);


        std::cout << "scan range (" << scan_range_id << ") for challenge 1: " << range.start << " - " << range.end << std::endl;
        std::cout << "expected range            : " << (base_scan_range * 1) << " - " << (base_scan_range * 2 - 1) << std::endl;

        // With challenge of 1, scan_range_id should be 1
        REQUIRE(scan_range_id == 1);
        REQUIRE(range.start == (base_scan_range * 1));
        REQUIRE(range.end == (base_scan_range * 2 - 1));
        // now try with challenge of 2
        challenge.r[3] = 2 << (32 - scan_range_filter_bits - 1);
        filter = ProofFragmentScanFilter(params, challenge, 5);
        range = filter.getScanRangeForFilter();
        scan_range_id = (challenge.r[3] >> (32 - scan_range_filter_bits - 1)) & ((1U << scan_range_filter_bits) - 1);

        std::cout << "scan range (" << scan_range_id << ") for challenge 2: " << range.start << " - " << range.end << std::endl;
        std::cout << "expected range            : " << (base_scan_range * 2) << " - " << (base_scan_range * 3 - 1) << std::endl;

        // With challenge of 2, scan_range_id should be 2
        REQUIRE(scan_range_id == 2);
        REQUIRE(range.start == base_scan_range * 2);
        REQUIRE(range.end == (base_scan_range * 3 - 1));

        // now try with challenge of 255
        if (num_scan_ranges >= 255) {
            challenge.r[3] = 255 << (32 - scan_range_filter_bits - 1);
            filter = ProofFragmentScanFilter(params, challenge, 5);
            range = filter.getScanRangeForFilter();
            scan_range_id = (challenge.r[3] >> (32 - scan_range_filter_bits - 1)) & ((1U << scan_range_filter_bits) - 1);

            std::cout << "scan range (" << scan_range_id << ") for challenge 255: " << range.start << " - " << range.end << std::endl;
            std::cout << "expected range              : " << (base_scan_range * 255) << " - " << (base_scan_range * 256 - 1) << std::endl;
            // With challenge of 255, scan_range_id should be 255
            REQUIRE(scan_range_id == 255);
            REQUIRE(range.start == (base_scan_range * 255));
            REQUIRE(range.end == (base_scan_range * 256 - 1));
        }

        // now try with all bits set in challenge
        for (auto& r : challenge.r) {
            r = std::numeric_limits<uint32_t>::max();
        }
        filter = ProofFragmentScanFilter(params, challenge, 5);
        range = filter.getScanRangeForFilter();

        // with all bits set, scan range should be last range
        std::cout << "** scan range for challenge all bits set: " << range.start << " - " << range.end << std::endl;
        std::cout << "** expected range                    : " << (base_scan_range * ((1ULL << scan_range_filter_bits) - 1)) << " - " << (base_scan_range * (1ULL << scan_range_filter_bits) - 1) << std::endl;
        REQUIRE(range.start == (base_scan_range * ((1ULL << scan_range_filter_bits) - 1)));
        REQUIRE(range.end == (base_scan_range * (1ULL << scan_range_filter_bits) - 1));
        
        // should be same as last range set
        uint64_t last_range_value;
        if (k < 32) {
            last_range_value = (1ULL << (2 * k)) - 1;
        } else if (k == 32) {
            last_range_value = UINT64_MAX;
        }
        else {
            last_range_value = 0;
            // should not happen
            REQUIRE(false);
        }
        std::cout << "** last range value                  : " << last_range_value << std::endl;
        std::cout << "** base scan range                   : " << base_scan_range << std::endl;
        std::cout << "** num scan ranges                   : " << num_scan_ranges << std::endl;
        std::cout << "** calculated start                  : " << (last_range_value - base_scan_range + 1) << std::endl;
        std::cout << "** calculated end                    : " << last_range_value << std::endl;
        REQUIRE(range.end == last_range_value);
        REQUIRE(range.start == (last_range_value - base_scan_range + 1));
    }
}
