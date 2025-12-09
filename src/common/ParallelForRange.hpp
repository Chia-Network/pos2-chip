#pragma once

#include <vector>
#include <iterator>
#include <algorithm>
#include <numeric>
#include <functional>
#include <cassert>
#include <future>
#include <type_traits>

#include "common/thread.hpp"

// A small, self-contained parallel_for_range utility.
// - Iterates over [first, last) and calls fn(element) for each element.
// - Provides overloads for iterator ranges and numeric index ranges.

// Iterator-based overloads
template <typename It, typename Fn>
std::enable_if_t<!std::is_integral<It>::value, void>
parallel_for_range(It first, It last, Fn fn)
{
    unsigned hw = std::thread::hardware_concurrency();
    unsigned num_threads = hw == 0 ? 4u : hw;
    parallel_for_range(first, last, fn, num_threads);
}

template <typename It, typename Fn>
std::enable_if_t<!std::is_integral<It>::value, void>
parallel_for_range(It first, It last, Fn fn, unsigned max_threads)
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

    std::vector<thread> workers;
    workers.reserve(num_threads);

    for (unsigned t = 0; t < num_threads; ++t)
    {
        diff_t start = (total * t) / num_threads;
        diff_t end   = (total * (t + 1)) / num_threads;
        It b = std::next(first, start);
        It e = std::next(first, end);

        workers.emplace_back([b, e, &fn]() {
            for (It it = b; it != e; ++it) fn(*it);
        });
    }
}

// Numeric index range [start, stop)
template <typename T, typename Fn>
std::enable_if_t<std::is_integral_v<T>, void>
parallel_for_range(T start, T stop, Fn fn, unsigned max_threads = std::thread::hardware_concurrency())
{
    using diff_t = T;
    diff_t total = (stop > start) ? (stop - start) : 0;
    if (total <= 0) return;

    unsigned num_threads = max_threads == 0 ? 1u : max_threads;
    num_threads = static_cast<unsigned>(std::min<diff_t>(num_threads, total));

    if (num_threads <= 1)
    {
        for (T i = start; i < stop; ++i) fn(i);
        return;
    }

    std::vector<thread> workers;
    workers.reserve(num_threads);

    for (unsigned t = 0; t < num_threads; ++t)
    {
        diff_t local_start = (total * t) / num_threads;
        diff_t local_end   = (total * (t + 1)) / num_threads;
        T b = static_cast<T>(start + local_start);
        T e = static_cast<T>(start + local_end);

        workers.emplace_back([b, e, &fn]() {
            for (T i = b; i < e; ++i) fn(i);
        });
    }
}
