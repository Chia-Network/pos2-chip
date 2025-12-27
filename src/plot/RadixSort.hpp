#pragma once

#include "common/Timer.hpp"
#include "common/thread.hpp"
#include <algorithm>
#include <cstdint>
#include <iostream>
#include <memory_resource>
#include <span>
#include <thread>
#include <vector>

// A generic radix sort that works on objects of type T by extracting a key (uint32_t)
// using the provided KeyExtractor functor.
template <typename T, typename KeyType, typename KeyExtractor = decltype(&T::match_info)>
class RadixSort {
public:
    explicit RadixSort(KeyExtractor extractor) : key_extractor_(extractor) {}

    explicit RadixSort() : key_extractor_(&T::match_info) {}

    // Sort the vector 'data' in place, using 'buffer' as temporary storage.
    // Sorting is based on the key extracted by key_extractor_.
    // returns sorted span, which caller can check which of the data or buffer it is in
    std::span<T> sort(
        std::span<T> data, std::span<T> buffer, int num_bits, std::pmr::memory_resource* mr)
    {
        int const radix_bits = 10; // Process bits per pass.
        int const radix = 1 << radix_bits;
        int const radix_mask = radix - 1;
        int const num_passes = (num_bits + radix_bits - 1) / radix_bits; // Number of passes needed.

        size_t num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0)
            num_threads = 1;

        size_t const num_elements = data.size();

        Timer timer;
        if (verbose_) {
            std::cout << "RadixSort: Sorting " << num_elements << " elements with " << num_threads
                      << " threads on " << num_bits << " bits" << std::endl;
            timer.start();
        }

        std::pmr::vector<std::pmr::vector<uint32_t>> counts_by_thread(mr);
        counts_by_thread.reserve(num_threads);
        for (size_t t = 0; t < num_threads; ++t) {
            counts_by_thread.emplace_back(std::pmr::vector<uint32_t>(radix, 0u, mr));
        }

        int const num_elements_per_thread = static_cast<int>(num_elements / num_threads);

        for (int pass = 0; pass < num_passes; ++pass) {
            if (verbose_)
                std::cout << "----- Pass " << pass << " -----" << std::endl;
            int shift = pass * radix_bits;

            // Count phase: each thread counts keys.
            Timer countPhaseTimer;
            if (verbose_)
                countPhaseTimer.start("Count phase");

            {
                std::vector<thread> threads;
                for (size_t t = 0; t < num_threads; ++t) {
                    threads.emplace_back([&, t]() {
                        // Reset counts
                        for (size_t r = 0; r < radix; ++r)
                            counts_by_thread[t][r] = 0;

                        size_t start = num_elements_per_thread * t;
                        size_t end = (t == num_threads - 1) ? num_elements
                                                            : num_elements_per_thread * (t + 1);
                        for (size_t i = start; i < end; ++i) {
                            // Extract key using the provided key extractor.
                            KeyType key = (data[i].*key_extractor_ >> shift) & radix_mask;
                            counts_by_thread[t][key]++;
                        }
                    });
                }
            }

            if (verbose_) {
                countPhaseTimer.stop();
                countPhaseTimer.start("Prefix sum phase");
            }

            // Merge counts to global counts.
            std::pmr::vector<uint32_t> counts(radix, 0u, mr);
            for (size_t t = 0; t < num_threads; ++t) {
                for (size_t r = 0; r < radix; ++r)
                    counts[r] += counts_by_thread[t][r];
            }

            // Global prefix sum.
            std::vector<uint32_t> offsets(radix, 0);
            for (size_t i = 1; i < radix; ++i)
                offsets[i] = offsets[i - 1] + counts[i - 1];

            // Compute per-thread offsets.
            std::pmr::vector<std::pmr::vector<uint32_t>> offsets_for_thread(mr);
            offsets_for_thread.reserve(num_threads);
            for (size_t t = 0; t < num_threads; ++t) {
                offsets_for_thread.emplace_back(std::pmr::vector<uint32_t>(radix, 0u, mr));
            }

            for (size_t r = 0; r < radix; ++r)
                offsets_for_thread[0][r] = offsets[r];
            for (size_t t = 1; t < num_threads; ++t) {
                for (size_t r = 0; r < radix; ++r)
                    offsets_for_thread[t][r]
                        = offsets_for_thread[t - 1][r] + counts_by_thread[t - 1][r];
            }

            if (verbose_)
                countPhaseTimer.stop();

            // Redistribution phase: place elements in sorted order into buffer.
            Timer redistributionTimer;
            if (verbose_)
                redistributionTimer.start("Redistribution phase");

            {
                std::vector<thread> threads;
                for (size_t t = 0; t < num_threads; ++t) {
                    threads.emplace_back([&, t]() {
                        size_t start = num_elements_per_thread * t;
                        size_t end = (t == num_threads - 1) ? num_elements
                                                            : num_elements_per_thread * (t + 1);
                        for (size_t i = start; i < end; ++i) {
                            KeyType key = (data[i].*key_extractor_ >> shift) & radix_mask;
                            size_t outpos = offsets_for_thread[t][key]++;
                            if (outpos >= num_elements) {
                                throw std::runtime_error("RadixSort: outpos out of range");
                            }
                            assert(outpos < num_elements);
                            buffer[outpos] = data[i];
                        }
                    });
                }
            }

            redistributionTimer.stop();

            // Swap the local span views only if there is another pass.
            if (pass < num_passes - 1) {
                std::swap(data, buffer);
            }
        }

        // If an odd number of passes was performed, 'data' still points
        // to the original container and 'buffer' holds the sorted data.
        // Copy the sorted data back into the caller's container.

        if (verbose_)
            timer.stop();

        return buffer; // sorted data always in buffer, since this is swapped into at end of each
                       // loop.
    }

    void setVerbose(bool v) { verbose_ = v; }

private:
    bool verbose_ = false;
    KeyExtractor key_extractor_;
};
