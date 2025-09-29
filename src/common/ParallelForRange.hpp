#pragma once

#include <thread>
#include <vector>
#include <iterator>
#include <algorithm>
#include <numeric>
#include <functional>
#include <cassert>
#include <thread>
#include <future>

// A small, self-contained parallel_for_range utility.
// - Iterates over [first, last) and calls fn(element) for each element.
// - Uses std::jthread when available; falls back to std::thread+join behavior.
// - Provides an overload that accepts an explicit max_threads for testing.

#if defined(__cpp_lib_jthread)
using worker_t = std::jthread;
#else
using worker_t = std::thread;
#endif

template <typename It, typename Fn>
void parallel_for_range(It first, It last, Fn fn)
{
    unsigned hw = std::thread::hardware_concurrency();
    unsigned num_threads = hw == 0 ? 4u : hw;
    parallel_for_range(first, last, fn, num_threads);
}

template <typename It, typename Fn>
void parallel_for_range(It first, It last, Fn fn, unsigned max_threads)
{
    using diff_t = typename std::iterator_traits<It>::difference_type;
    diff_t total = std::distance(first, last);
    if (total <= 0) return;

    unsigned num_threads = max_threads == 0 ? 1u : max_threads;
    num_threads = static_cast<unsigned>(std::min<diff_t>(num_threads, total));

    if (num_threads <= 1)
    {
        for (It it = first; it != last; ++it) fn(*it);
        return;
    }

    std::vector<worker_t> workers;
    workers.reserve(num_threads);

    for (unsigned t = 0; t < num_threads; ++t)
    {
        diff_t start = (total * t) / num_threads;
        diff_t end = (total * (t + 1)) / num_threads;
        It b = std::next(first, start);
        It e = std::next(first, end);

#if defined(__cpp_lib_jthread)
        workers.emplace_back([b, e, &fn]() {
            for (It it = b; it != e; ++it) fn(*it);
        });
#else
        workers.emplace_back([b, e, &fn]() {
            for (It it = b; it != e; ++it) fn(*it);
        });
#endif
    }

#if !defined(__cpp_lib_jthread)
    for (auto &w : workers)
        if (w.joinable())
            w.join();
#endif
    // if using jthread, destructor joins automatically
}