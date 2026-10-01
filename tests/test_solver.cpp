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
        75731, 203321, 177312, 111766, 239933, 96237, 86882, 95037,
        234290, 71079, 41831, 40953, 82786, 7607, 69383, 175869,
        11172, 235766, 73210, 187048, 22816, 230484, 196488, 208309,
        238248, 20048, 18010, 240549, 94217, 215968, 237249, 69591,
        23080, 12440, 232094, 213417, 83810, 111667, 234491, 35540,
        97825, 148843, 114321, 66156, 42079, 49170, 130176, 13727,
        157724, 131746, 71057, 239778, 240095, 21592, 204365, 227408,
        109036, 117979, 189985, 159439, 217440, 24677, 62028, 32791,
        167321, 65974, 69116, 144616, 108416, 195492, 258765, 221038,
        167463, 7400, 64292, 93580, 195451, 38466, 196458, 119928,
        28666, 9217, 240720, 51344, 261496, 80990, 162210, 120118,
        61752, 36962, 121705, 214395, 253179, 101928, 192367, 125268,
        228233, 136880, 160446, 38994, 216953, 115794, 124646, 78996,
        1668, 77712, 223511, 187152, 58798, 202015, 58458, 112268,
        165265, 246059, 222175, 3231, 108909, 107449, 85827, 105706,
        106634, 47323, 229529, 199527, 45459, 73153, 39434, 170969
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
