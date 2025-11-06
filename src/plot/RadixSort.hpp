#pragma once

#include <span>
#include <cstdint>
#include <thread>
#include <algorithm>
#include <vector>
#include <span>
#include <iostream>
#include "common/Timer.hpp"

// A generic radix sort that works on objects of type T by extracting a key (uint32_t)
// using the provided KeyExtractor functor.
template <typename T, typename KeyType, typename KeyExtractor = decltype(&T::match_info)>
class RadixSort {
public:
    explicit RadixSort(KeyExtractor extractor)
        : key_extractor_(extractor)
    {}

    explicit RadixSort()
        : key_extractor_(&T::match_info)
    {}

    // Sort the vector 'data' in place, using 'buffer' as temporary storage.
    // Sorting is based on the key extracted by key_extractor_.
    void sort(std::span<T> data, std::span<T> buffer, int num_bits = 32, bool verbose = false) {
        const int radix_bits = 8;    // Process 8 bits per pass.
        const int radix = 1 << radix_bits;
        const int radix_mask = radix - 1;
        const int num_passes = (num_bits + radix_bits - 1) / radix_bits; // Number of passes needed.
        const size_t num_threads = std::thread::hardware_concurrency();
        const size_t num_elements = data.size();

        Timer timer;
        if (verbose) {
            std::cout << "RadixSort: Sorting " << num_elements 
                      << " elements with " << num_threads << " threads on " << num_bits << " bits" << std::endl;
            timer.start();
        }

        std::vector<std::vector<uint32_t>> counts_by_thread(num_threads, std::vector<uint32_t>(radix, 0));
        std::vector<std::thread> threads;
        const size_t num_elements_per_thread = static_cast<int>(num_elements / num_threads);

        for (int pass = 0; pass < num_passes; ++pass) {
            if (verbose)
                std::cout << "----- Pass " << pass << " -----" << std::endl;
            int shift = pass * radix_bits;

            // Count phase: each thread counts keys.
            Timer countPhaseTimer;
            if (verbose)
                countPhaseTimer.start("Count phase");

            try {
                for (size_t t = 0; t < num_threads; ++t) {
                    threads.emplace_back([&, t]() {
                        // Reset counts
                        for (size_t r = 0; r < radix; ++r)
                            counts_by_thread[t][r] = 0;
                    
                        size_t start = num_elements_per_thread * t;
                        size_t end = (t == num_threads - 1) ? num_elements : num_elements_per_thread * (t + 1);
                        for (size_t i = start; i < end; ++i) {
                            // Extract key using the provided key extractor.
                            KeyType key = (data[i].*key_extractor_ >> shift) & radix_mask;
                            counts_by_thread[t][key]++;
                        }
                    });
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Exception in Radix Sort count phase " << e.what() << std::endl;
                exit(0);
            }
            catch (...) {
                std::cerr << "Unknown exception in Radix Sort count phase" << std::endl;
                exit(0);
            }

            for (auto& th : threads)
                th.join();

            if (verbose) {
                countPhaseTimer.stop();
                countPhaseTimer.start("Prefix sum phase");
            }

            // Merge counts to global counts.
            std::vector<uint32_t> counts(radix, 0);
            for (size_t t = 0; t < num_threads; ++t) {
                for (size_t r = 0; r < radix; ++r)
                    counts[r] += counts_by_thread[t][r];
            }

            // Global prefix sum.
            std::vector<uint32_t> offsets(radix, 0);
            for (size_t i = 1; i < radix; ++i)
                offsets[i] = offsets[i - 1] + counts[i - 1];

            // Compute per-thread offsets.
            std::vector<std::vector<uint32_t>> offsets_for_thread(num_threads, std::vector<uint32_t>(radix, 0));
            for (size_t r = 0; r < radix; ++r)
                offsets_for_thread[0][r] = offsets[r];
            for (size_t t = 1; t < num_threads; ++t) {
                for (size_t r = 0; r < radix; ++r)
                    offsets_for_thread[t][r] = offsets_for_thread[t - 1][r] + counts_by_thread[t - 1][r];
            }
            
            if (verbose)
                countPhaseTimer.stop();

            threads.clear();
            // Redistribution phase: place elements in sorted order into buffer.
            Timer redistributionTimer;
            if (verbose)
                redistributionTimer.start("Redistribution phase");

            try {
                for (size_t t = 0; t < num_threads; ++t) {
                    threads.emplace_back([&, t]() {
                        size_t start = num_elements_per_thread * t;
                        size_t end = (t == num_threads - 1) ? num_elements : num_elements_per_thread * (t + 1);
                        for (size_t i = start; i < end; ++i) {
                            KeyType key = (data[i].*key_extractor_ >> shift) & radix_mask;
                            size_t outpos = offsets_for_thread[t][key]++;
                            buffer[outpos] = data[i];
                        }
                    });
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Exception in Radix Sort redistribution phase " << e.what() << std::endl;
                exit(0);
            }
            catch (...) {
                std::cerr << "Unknown exception in Radix Sort redistribution phase" << std::endl;
                exit(0);
            }

            for (auto& th : threads)
                th.join();

            redistributionTimer.stop();
            threads.clear();

            // Swap the local span views only if there is another pass.
            if (pass < num_passes - 1) {
                std::swap(data, buffer);
            }
        }

        // If an odd number of passes was performed, 'data' still points
        // to the original container and 'buffer' holds the sorted data.
        // Copy the sorted data back into the caller's container.
        if (num_passes % 2 == 1) {
            if (verbose)
                std::cout << "Copying sorted data back to original container." << std::endl;
            std::copy(buffer.begin(), buffer.end(), data.begin());
        }

        if (verbose)
            timer.stop();
    }
    
private:
    KeyExtractor key_extractor_;
};
