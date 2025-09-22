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

        printf("res: %08x %08x %08x %08x\n", res.r[0], res.r[1], res.r[2], res.r[3]);
        printf("exp: %08x %08x %08x %08x\n", c.result[0], c.result[1], c.result[2], c.result[3]);

        CHECK(res.r[0] == c.result[0]);
        CHECK(res.r[1] == c.result[1]);
        CHECK(res.r[2] == c.result[2]);
        CHECK(res.r[3] == c.result[3]);
    }
}
