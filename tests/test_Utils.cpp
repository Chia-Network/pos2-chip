#include "test_util.h"
#include "common/Utils.hpp"
#include <vector>
#include <string>
#include <cstdint>

TEST_SUITE_BEGIN("utils");

TEST_CASE("proof-to-hex-and-back")
{
    for (int k : {18, 20, 22, 24, 26, 28, 30, 32})
    {
        std::vector<uint32_t> original_proof;
        for (int i = 0; i < 512; ++i) {
            // make random original proof in range [0, 2^k)
            if (k == 32) {
                original_proof.push_back(rand()); // full 32 bits
            }
            else {
                original_proof.push_back(rand() % (1 << k));
            }
        }
        std::string hex = Utils::kValuesToCompressedHex(k, original_proof);
        std::cout << "k=" << k << " proof to hex (" << hex.size() << "): " << hex << std::endl;
        auto recovered = Utils::compressedHexToKValues(k, hex);
        CHECK(recovered == original_proof);

        std::string hex2 = Utils::kValuesToCompressedHex(k, recovered);
        CHECK(hex2 == hex);
    }
}
