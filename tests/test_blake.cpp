#include "test_util.h"
#include "pos/BlakeHash.hpp"

#include "blake_test_cases.hpp"

TEST_CASE("blake3")
{
    for (TestCase const& c : test_cases) {
        BlakeHash h(c.plot_id);
        int idx = 0;
        for (uint32_t const data : c.data) {
            h.set_data(idx++, data);
        }
        auto res = h.generate_hash();

        printf("res: %08x %08x %08x %08x\n", res.r0, res.r1, res.r2, res.r3);
        printf("exp: %08x %08x %08x %08x\n", c.result[0], c.result[1], c.result[2], c.result[3]);

        CHECK(res.r0 == c.result[0]);
        CHECK(res.r1 == c.result[1]);
        CHECK(res.r2 == c.result[2]);
        CHECK(res.r3 == c.result[3]);
    }
}
