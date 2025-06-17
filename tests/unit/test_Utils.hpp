#include "common/Utils.hpp"
#include <vector>
#include <string>
#include <cstdint>

TEST_SUITE_BEGIN("utils");

TEST_CASE("proof-to-hex-and-back")
{
    for (int k : {28, 30, 32})
    {
        std::vector<uint32_t> original_proof;
        for (int i = 0; i < 512; ++i) {
            original_proof.push_back(i);
        }
        std::string hex = Utils::proofToHex(k, original_proof);
        auto recovered = Utils::hexToProof(k, hex);
        CHECK(recovered == original_proof);

        std::string hex2 = Utils::proofToHex(k, recovered);
        CHECK(hex2 == hex);
    }
}
