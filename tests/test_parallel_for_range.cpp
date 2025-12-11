#include "test_util.h"

#include "common/ParallelForRange.hpp"

#include <atomic>
#include <set>
#include <vector>

TEST_CASE("parallel_for_range on list visits each element exactly once")
{
    int const N = 10000;
    std::vector<int> items(N);
    for (int i = 0; i < N; ++i)
        items[i] = i;

    // try a variety of thread counts including 0,1,2,3,4,8,16
    std::vector<unsigned> thread_counts = { 0, 1, 2, 3, 4, 8, 16, 32, 64 };

    for (unsigned tc: thread_counts) {
        std::vector<std::atomic<int>> counts(N);
        for (int i = 0; i < N; ++i)
            counts[i].store(0, std::memory_order_relaxed);

        // call tested function with explicit thread count
        parallel_for_range(
            items.begin(),
            items.end(),
            [&](int v) { counts[v].fetch_add(1, std::memory_order_relaxed); },
            tc);

        for (int i = 0; i < N; ++i) {
            CHECK_EQ(counts[i].load(std::memory_order_relaxed), 1);
        }
    }
}

TEST_CASE("parallel_for_range on scalar range visits each element exactly once")
{
    int const N = 10000;

    // try a variety of thread counts including 0,1,2,3,4,8,16
    std::vector<unsigned> thread_counts = { 0, 1, 2, 3, 4, 8, 16, 32, 64 };

    for (unsigned tc: thread_counts) {
        std::vector<std::atomic<int>> counts(N);
        for (int i = 0; i < N; ++i)
            counts[i].store(0, std::memory_order_relaxed);

        // call tested function with explicit thread count
        parallel_for_range(
            0, N, [&](int v) { counts[v].fetch_add(1, std::memory_order_relaxed); }, tc);

        for (int i = 0; i < N; ++i) {
            CHECK_EQ(counts[i].load(std::memory_order_relaxed), 1);
        }
    }
}
