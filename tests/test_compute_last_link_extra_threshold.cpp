#include "test_util.h"
#include "pos/Chainer.hpp"
#include "pos/sha/sha256.hpp"

// This value has been calculated ahead of time as it uses doubles.
// We add a test here to detect if the value comes out differently in some architecture.
TEST_CASE("compute_last_link_extra_threshold")
{
    uint64_t const threshold = Chainer::compute_last_link_extra_threshold();
    uint64_t const actual = Chainer::recompute_last_link_extra_threshold();
    ENSURE(threshold == actual);
}
