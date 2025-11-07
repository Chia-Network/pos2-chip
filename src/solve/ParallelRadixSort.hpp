#pragma once

#include <vector>
#include <cstdint>
#include <span>
#include <atomic>
#include "common/Timer.hpp"
#include "common/thread.hpp"

class ParallelRadixSort {
public:
    void sort(std::vector<uint32_t>& data, std::vector<uint32_t> &buffer, bool verbose=false) {
        const int num_bits = 32;  // Assuming 32-bit integers
        const int radix_bits = 8; // on pi 5: 30/10 is fastest.
        const int radix = 1 << radix_bits;    // Base (e.g., 8 bits at a time)
        const int radix_mask = radix - 1;
        const int num_passes = num_bits / radix_bits;
        const int num_threads = std::thread::hardware_concurrency();

        Timer timer;
        if (verbose) 
        {
            std::cout << "ParallelRadixSort: Sorting " << data.size() << " elements with " << num_threads << " threads" << std::endl;
            timer.start();
        }

        std::vector<std::vector<int>> counts_by_thread(num_threads, std::vector<int>(radix, 0));
        std::vector<thread> threads;
        // get each threads start and end index
        const size_t num_elements_per_thread = data.size() / num_threads;

        for (int pass = 0; pass < num_passes; ++pass) {
            if (verbose)
                std::cout << "----- Pass " << pass << " -----" << std::endl;
            int shift = pass * radix_bits;

            // Count phase
            Timer countPhaseTimer;
            if (verbose)
                countPhaseTimer.start("Count phase");

            for (int t = 0; t < num_threads; ++t) {
                threads.emplace_back([&, t]() {
                    // fill counts to zero
                    for (int r = 0; r < radix; ++r) {
                        counts_by_thread[t][r] = 0;
                    }

                    size_t start = num_elements_per_thread * t;
                    size_t end = (t == num_threads - 1) ? data.size() : num_elements_per_thread * (t + 1);

                    for (size_t i = start; i < end; ++i) {
                        uint32_t key = (data[i] >> shift) & radix_mask;
                        counts_by_thread[t][key]++;
                    }
                });
            }

            threads.clear();
            if (verbose)
            {
                countPhaseTimer.stop();
                countPhaseTimer.start("Prefix sum phase");
            }

            // now merge all counts into one global count
            std::vector<uint32_t> counts(radix, 0);
            for (int t = 0; t < num_threads; ++t) {
                for (int r = 0; r < radix; ++r) {
                    counts[r] += counts_by_thread[t][r];
                }
            }

            // Prefix sum phase
            std::vector<std::vector<int>> offsets_for_thread(num_threads, std::vector<int>(radix, 0));

            // first get global offsets
            std::vector<uint32_t> offsets(radix, 0);
            for (int i = 1; i < radix; ++i)
            {
                offsets[i] = offsets[i - 1] + counts[i - 1];
            }

            // then update offsets for each thread, with thread 0 using the global offsets and others threads building on that.
            // t 0 offsets first
            for (int r = 0; r < radix; ++r) {
                offsets_for_thread[0][r] = offsets[r];
            }
            // t > 0 offsets build on previous ones
            for (int i = 1; i < num_threads; i++)
            {
                for (int r = 0; r < radix; ++r) {
                    offsets_for_thread[i][r] = offsets_for_thread[i - 1][r] + counts_by_thread[i - 1][r];
                }
            }

            if (verbose)
            {
                countPhaseTimer.stop();
            }
            // now we know each threads own bucket counts, so when the thread scans the same data, it can place the data in the correct bucket with the offset assigned to it from all the threads.

            // Redistribution phase
            Timer redistributionTimer;
            if (verbose) redistributionTimer.start("Redistribution phase");
            for (int t = 0; t < num_threads; ++t) {
                threads.emplace_back([&, t]() {
                    size_t start = num_elements_per_thread * t;
                    size_t end = (t == num_threads - 1) ? data.size() : num_elements_per_thread * (t + 1);
                    for (size_t i = start; i < end; ++i) {
                        uint32_t key = (data[i] >> shift) & radix_mask;
                        int outpos = offsets_for_thread[t][key]++;
                        buffer[outpos] = data[i];
                    }
                });
            }

            threads.clear();
            redistributionTimer.stop();

            std::swap(data, buffer);
        }
    }

     void sortByKey(std::vector<uint32_t>& keys, std::vector<uint32_t>& values, std::vector<uint32_t>& keyBuffer, std::vector<uint32_t>& valueBuffer, int num_bits, int radix_bits = -1, bool verbose = false) {
        //num_bits = 28;  // Assuming 32-bit integers
        //radix_bits = 14; // on pi 5: 30/10 is fastest.
        if (radix_bits == -1) {
            if (num_bits == 30) {
                // on pi 5: 30/10 is fastest.
                //radix_bits = 15; // 1139ms ryzen 5600
                radix_bits = 10; // 515ms ryzen 5600
                //radix_bits = 8; // 478ms ryzen 5600
                //radix_bits = 6; // 734ms ryzen 5600
            }
            else if (num_bits == 28) {
                // on pi5 28/14 is fastest?
                radix_bits = 10; // 128ms ryzen 5600
                //radix_bits = 14; // 143ms ryzen 5600 <-- use for pi5?
                //radix_bits = 8; // 197ms ryzen 5600
                //radix_bits = 7; // 195ms ryzen 5600
            }
            else {
                radix_bits = 8;
            }
        }
        int radix = 1 << radix_bits;    // Base (e.g., 8 bits at a time)
        int radix_mask = radix - 1;
        const int num_passes = (num_bits + radix_bits - 1) / radix_bits;
        const int num_threads = std::thread::hardware_concurrency();

        if (verbose) {
            std::cout << "ParallelRadixSort: Sorting " << keys.size() << " key-value pairs with " << num_threads << " threads" << std::endl;
        }

        std::vector<std::vector<int>> counts_by_thread(num_threads, std::vector<int>(radix, 0));
        std::vector<thread> threads;
        const size_t num_elements_per_thread = keys.size() / num_threads;

        for (int pass = 0; pass < num_passes; ++pass) {
            if (verbose) {
                std::cout << "----- Pass " << pass << " -----" << std::endl;
            }
            int shift = pass * radix_bits;
            if (pass == num_passes - 1) {
                // For the last pass, we might not need all radix_bits.
                radix_bits = (num_bits - shift);
                radix = 1 << radix_bits;
                radix_mask = (1 << radix_bits) - 1;
            }

            // Count phase
            Timer countPhaseTimer;
            if (verbose)
                countPhaseTimer.start("Count phase");

            // Count phase
            for (int t = 0; t < num_threads; ++t) {
                threads.emplace_back([&, t]() {
                    for (int r = 0; r < radix; ++r) {
                        counts_by_thread[t][r] = 0;
                    }

                    size_t start = num_elements_per_thread * t;
                    size_t end = (t == num_threads - 1) ? keys.size() : num_elements_per_thread * (t + 1);

                    for (size_t i = start; i < end; ++i) {
                        uint32_t key = (keys[i] >> shift) & radix_mask;
                        counts_by_thread[t][key]++;
                    }
                });
            }

            threads.clear();

            if (verbose)
            {
                countPhaseTimer.stop();
                countPhaseTimer.start("Prefix sum phase");
            }

            // Merge counts
            std::vector<uint32_t> counts(radix, 0);
            for (int t = 0; t < num_threads; ++t) {
                for (int r = 0; r < radix; ++r) {
                    counts[r] += counts_by_thread[t][r];
                }
            }

            // Prefix sum phase
            std::vector<std::vector<int>> offsets_for_thread(num_threads, std::vector<int>(radix, 0));
            std::vector<uint32_t> offsets(radix, 0);
            for (int i = 1; i < radix; ++i) {
                offsets[i] = offsets[i - 1] + counts[i - 1];
            }

            for (int r = 0; r < radix; ++r) {
                offsets_for_thread[0][r] = offsets[r];
            }
            for (int i = 1; i < num_threads; i++) {
                for (int r = 0; r < radix; ++r) {
                    offsets_for_thread[i][r] = offsets_for_thread[i - 1][r] + counts_by_thread[i - 1][r];
                }
            }

            if (verbose)
            {
                countPhaseTimer.stop();
                countPhaseTimer.start("Redistribution phase");
            }

            // Redistribution phase
            for (int t = 0; t < num_threads; ++t) {
                threads.emplace_back([&, t]() {
                    size_t start = num_elements_per_thread * t;
                    size_t end = (t == num_threads - 1) ? keys.size() : num_elements_per_thread * (t + 1);
                    for (size_t i = start; i < end; ++i) {
                        uint32_t key = (keys[i] >> shift) & radix_mask;
                        int outpos = offsets_for_thread[t][key]++;
                        keyBuffer[outpos] = keys[i];
                        valueBuffer[outpos] = values[i];
                    }
                });
            }

            threads.clear();

            if (verbose)
            {
                countPhaseTimer.stop();
            }

            std::swap(keys, keyBuffer);
            std::swap(values, valueBuffer);
        }
    }

};
