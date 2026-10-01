#include "common/Utils.hpp"
#include "pos/ProofFragment.hpp"
#include "pos/ProofValidator.hpp"
#include "pos/sha/sha256.hpp"
#include "solve/Solver.hpp"
#include "test_util.h"

#include <algorithm>
#include <array>

TEST_SUITE_BEGIN("solve");

TEST_CASE("solve-partial")
{
    constexpr uint8_t k = 18;
    constexpr uint8_t strength = 2;
    constexpr uint16_t plot_index = 0;
    constexpr char plot_group_id_hex[] = "da9a6a4efcadaf1e3115e79a2b7b2d17890185359f19bfaa02a2f2505a8160b5";
    constexpr char challenge_hex[] = "368d14ca70224ac4acc37f591b28ff43d05a2533d34b3a9e8baf4837aebcc783";

    // These X values come from the first quality chain in the retained k18 plot.
    std::array<uint32_t, TOTAL_XS_IN_PROOF> const expected_xs = {
        86078, 87766, 147629, 247099, 26248, 182336, 71237, 94,
        217221, 227579, 8052, 140108, 257009, 247326, 87256, 151215,
        186191, 73430, 234122, 161569, 260553, 126041, 154409, 177025,
        234349, 161808, 129613, 32373, 235421, 68091, 104106, 210828,
        95463, 171203, 40437, 169983, 143382, 30161, 164387, 222661,
        191025, 223625, 169419, 155546, 92561, 96432, 207022, 70435,
        138948, 95014, 93479, 169253, 235251, 41412, 80493, 151647,
        76953, 55943, 115216, 6501, 49304, 39508, 70380, 21210,
        113473, 30428, 257021, 125299, 69863, 14394, 109124, 202025,
        53249, 46455, 27635, 253160, 168900, 32783, 127582, 179391,
        97526, 147893, 53057, 103908, 125724, 136416, 205410, 254175,
        213984, 241384, 35440, 141824, 140866, 207008, 162224, 51053,
        254340, 20107, 32666, 203032, 155771, 43870, 67469, 24284,
        135966, 4818, 155161, 103442, 220367, 212588, 39341, 38204,
        145559, 77180, 138473, 138415, 146928, 230650, 33128, 124344,
        54790, 70202, 236020, 140819, 192031, 156089, 11616, 181551
    };

    PlotGroupParams group_params(PlotGroupId(plot_group_id_hex), k, strength, 0);
    PlotProofParams params = group_params.get_plot_params_for_index(plot_index);
    ProofFragmentCodec fragment_codec(params);

    std::array<uint32_t, TOTAL_T1_PAIRS_IN_PROOF> x_bits_list {};
    for (size_t link = 0; link < NUM_CHAIN_LINKS; ++link) {
        ProofFragment fragment = fragment_codec.encode(expected_xs.data() + link * 8);
        auto x_bits = fragment_codec.get_x_bits_from_proof_fragment(fragment);
        std::copy(x_bits.begin(), x_bits.end(), x_bits_list.begin() + link * 4);
    }

    auto challenge = Utils::hexToBytes(challenge_hex);
    ProofValidator validator(group_params, plot_index);
    REQUIRE(validator.validate_full_proof(expected_xs, challenge).has_value());

    Solver solver(params);
    solver.setUsePrefetching(true);
    auto all_proofs = solver.solve(x_bits_list, expected_xs);

    REQUIRE(!all_proofs.empty());
    CHECK(std::find(all_proofs.begin(), all_proofs.end(), expected_xs) != all_proofs.end());
}

TEST_SUITE_END();
