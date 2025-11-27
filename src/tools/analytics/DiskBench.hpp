#pragma once

#include <cstdint>
#include <iostream>
#include <string>
#include <cstdlib>
#include <stdexcept>
#include "common/Utils.hpp"
#include "pos/ProofCore.hpp"
#include "prove/Prover.hpp"
#include <vector>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <random>

/*
Completed 9200 of 9216 challenges...
  Current disk % load: 6.24103%
       Max block time: 2516.31 ms (% 26.8406%)
       Min block time: 229.821 ms (% 2.45143%)
---- completed 9216 challenges ----
Plots passed filter: 395720 out of 11000 (3597.45%)
Plots passed proof fragment scan filter: 6118 out of 11000 (55.6182%)
Total time for 11000 plots: 5.39103e+06 ms
Plots passed chaining: 2305 out of 11000 (20.9545%)
Total proofs found: 24609
Average proofs per plot per challenge:2.23718
Average time per plot: 490.094 ms
Time spent passing plot id filter: 4.13386e+06 ms (% 76.6803)
Time spent passing proof fragment scan filter: 743017 ms (% 13.7825)
Time spent fetching full proofs partitions: 514152 ms (% 9.53718)
Total data bytes read: 56488493556
Average data read per plot: 5135317 bytes
Total random disk seeks: 410261
----
Plot ID filter: 256
Proof fragment scan filter: 64
Estimated HDD load for 1 challenge every 9.375 seconds: 6.23962%

Completed 9200 of 9216 challenges...
  Current disk % load: 0.680565%
       Max block time: 2476.42 ms (% 26.4151%)
       Min block time: 0 ms (% 0%)
---- completed 9216 challenges ----
Plots passed filter: 21476 out of 600 (3579.33%)
Plots passed proof fragment scan filter: 351 out of 600 (58.5%)
Total time for 600 plots: 587375 ms
Plots passed chaining: 120 out of 600 (20%)
Total proofs found: 1400
Average proofs per plot per challenge:2.33333
Average time per plot: 978.958 ms
Time spent passing plot id filter: 224347 ms (% 38.1949)
Time spent passing proof fragment scan filter: 333778 ms (% 56.8253)
Time spent fetching full proofs partitions: 29250 ms (% 4.97978)
Total data bytes read: 23,580,684,346
Average data read per plot: 39301140 bytes
Total random disk seeks: 22298
----
Plot ID filter: 256
Proof fragment scan filter: 64
Estimated HDD load for 1 challenge every 9.375 seconds: 0.679832%
       */

class DiskBench
{
public:
    DiskBench(const ProofParams &proof_params)
        : proof_params_(proof_params) {}

    // Run a simulation of disk reads for a given number of plots.
    // Outputs: total time in ms and total data read in MB.
    void simulateChallengeDiskReads(size_t plot_id_filter_bits, size_t diskTB, double diskSeekMs, double diskReadMBs) const
    {
        std::cout << "Simulating disk reads with plot ID filter bits: " << plot_id_filter_bits
                  << ", Disk size: " << diskTB << " TB, Seek time: " << diskSeekMs << " ms, Read speed: " << diskReadMBs << " MB/s\n";
        /*size_t plot_bytes = plot_size_bytes();
        size_t t3_part_bytes = t3_partition_bytes();
        size_t t4t5_part_bytes = t4t5_partition_bytes();
        size_t num_plots = (diskTB * 1000 * 1000 * 1000 * 1000) / plot_bytes;
        std::cout << "Plot size bytes: " << plot_bytes << ", Num plots per " << diskTB << "TB: " << num_plots << std::endl;
        // exit(23);

        // Simulate disk reads
        double total_time_ms = 0.0;
        size_t total_data_read_bytes = 0;
        size_t total_random_disk_seeks = 0;

        double split_disk_total_time_ms[2] = {0.0, 0.0};
        size_t split_disk_total_data_read_bytes[2] = {0, 0};
        size_t split_disk_total_random_disk_seeks[2] = {0, 0};

        double total_block_time_ms = 0.0;
        double maximum_block_time_ms = 0.0;
        double minimum_block_time_ms = std::numeric_limits<double>::max();
        double total_time_passing_plot_id_filter_ms = 0.0;
        double total_time_passing_proof_fragment_scan_ms = 0.0;
        double total_time_fetching_full_proofs_partitions_ms = 0.0;

        double split_disk_total_block_time_ms[2] = {0.0, 0.0};
        double split_disk_maximum_block_time_ms[2] = {0.0, 0.0};
        double split_disk_minimum_block_time_ms[2] = {std::numeric_limits<double>::max(), std::numeric_limits<double>::max()};
        double split_disk_total_time_passing_plot_id_filter_ms[2] = {0.0, 0.0};
        double split_disk_total_time_passing_proof_fragment_scan_ms[2] = {0.0, 0.0};
        double split_disk_total_time_fetching_full_proofs_partitions_ms[2] = {0.0, 0.0};

        // Collect per-challenge stats for histograms
        std::vector<double> block_times_ms;
        std::vector<int> proofs_per_challenge;
        std::vector<int> proofs_per_chain_fetch;
        block_times_ms.reserve(10000);
        proofs_per_challenge.reserve(10000);
        proofs_per_chain_fetch.reserve(10000);

        size_t num_plots_passed_filter = 0;
        size_t num_plots_passed_proof_fragment_scan_filter = 0;
        size_t num_plots_passed_chaining = 0;
        size_t total_proofs_found = 0;

        ProofCore proof_core(proof_params_);

        // size_t plot_bytes = proof_core.expected_plot_bytes();
        // std::cout << "ProofParams: k=" << (int)k_ << ", sub_k=" << (int)sub_k << ", num_partitions=" << num_partitions << std::endl;
        // exit(23);

        std::array<uint8_t, 32> challenge;
        challenge.fill(0); // Initialize challenge with zeros

        double time_per_block_ms = 9375.0;
        double hdd_load = total_time_ms / time_per_block_ms;

        std::cout << "---- completed " << num_challenges << " challenges ----" << std::endl;
        std::cout << "Random seed used: " << seed << std::endl;
        std::cout << "Plots passed filter: " << num_plots_passed_filter << " out of " << num_plots << " for " << num_challenges << " challenges ("
                  << (static_cast<double>(num_plots_passed_filter) * 100.0 / static_cast<double>(num_plots * num_challenges)) << "%)" << std::endl;
        double expected_plots_passing_filter = static_cast<double>(num_plots * num_challenges) / static_cast<double>(1 << plot_id_filter_bits);
        std::cout << "Expected plots passing filter: " << expected_plots_passing_filter << std::endl;
        
        std::cout << "Plots passed proof fragment scan filter: " << num_plots_passed_proof_fragment_scan_filter << " out of " << num_plots << " for " << num_challenges << " challenges ("
                  << (static_cast<double>(num_plots_passed_proof_fragment_scan_filter) * 100.0 / static_cast<double>(num_plots * num_challenges)) << "%)" << std::endl;
        double expected_plots_passing_proof_fragment_scan_filter = expected_plots_passing_filter / static_cast<double>(1 << proof_fragment_scan_filter_bits);
        std::cout << "Expected plots passing proof fragment scan filter: " << expected_plots_passing_proof_fragment_scan_filter << std::endl;

        std::cout << "Total time for " << num_plots << " plots: " << total_time_ms << " ms" << std::endl;
        std::cout << "Plots passed chaining: " << num_plots_passed_chaining << " out of " << num_plots << " for " << num_challenges << " challenges ("
                  << (static_cast<double>(num_plots_passed_chaining) * 100.0 / static_cast<double>(num_plots * num_challenges)) << "%)" << std::endl;
        
        // on average each plot passing proof fragment scan filter should produce 4 proofs
        double expected_proofs_found = expected_plots_passing_proof_fragment_scan_filter * 4;
        std::cout << "Total proofs found: " << total_proofs_found << std::endl;
        std::cout << "Expected proofs found: " << expected_proofs_found << std::endl;
        
        std::cout << "Average proofs per plot per challenge:" << (static_cast<double>(total_proofs_found) / static_cast<double>(num_plots * num_challenges)) << std::endl;

        std::cout << "Average time per plot: " << (total_time_ms / static_cast<double>(num_plots)) << " ms" << std::endl;
        std::cout << "Time spent passing plot id filter: " << total_time_passing_plot_id_filter_ms << " ms (% " << (total_time_passing_plot_id_filter_ms / total_time_ms) * 100.0 << ")" << std::endl;
        std::cout << "Time spent passing proof fragment scan filter: " << total_time_passing_proof_fragment_scan_ms << " ms (% " << (total_time_passing_proof_fragment_scan_ms / total_time_ms) * 100.0 << ")" << std::endl;
        std::cout << "Time spent fetching full proofs partitions: " << total_time_fetching_full_proofs_partitions_ms << " ms (% " << (total_time_fetching_full_proofs_partitions_ms / total_time_ms) * 100.0 << ")" << std::endl;
        std::cout << "Total data bytes read: " << total_data_read_bytes << std::endl;
        std::cout << "Average data read per plot: " << (total_data_read_bytes / num_plots) << " bytes" << std::endl;
        std::cout << "Total random disk seeks: " << total_random_disk_seeks << std::endl;

        std::cout << "Plot ID filter: " << (1 << plot_id_filter_bits) << std::endl;
        std::cout << "Proof fragment scan filter: " << (1 << proof_fragment_scan_filter_bits) << std::endl;

        std::cout << "Estimated HDD load for 1 challenge every 9.375 seconds: " << (hdd_load * 100.0 / (double)num_challenges) << "%" << std::endl;

        // Helper: print a simple ASCII histogram for double data
        auto print_double_histogram = [&](const std::string &title, const std::vector<double> &data, int bins) {
            std::cout << title << std::endl;
            if (data.empty()) { std::cout << "  (no data)\n"; return; }
            double minv = *std::min_element(data.begin(), data.end());
            double maxv = *std::max_element(data.begin(), data.end());
            if (minv == maxv) { std::cout << "  All values: " << minv << "\n"; return; }
            double range = maxv - minv;
            std::vector<size_t> counts(bins);
            for (double v : data) {
                int idx = static_cast<int>(std::floor((v - minv) / range * bins));
                if (idx < 0) idx = 0;
                if (idx >= bins) idx = bins - 1;
                counts[idx]++;
            }
            for (int b = 0; b < bins; ++b) {
                double lo = minv + (static_cast<double>(b) / bins) * range;
                double hi = minv + (static_cast<double>(b + 1) / bins) * range;
                std::cout << "  [" << lo << ", " << hi << "): " << counts[b] << " ";
                int stars = static_cast<int>(std::round(50.0 * counts[b] / data.size()));
                for (int s = 0; s < stars; ++s) std::cout << '*';
                std::cout << std::endl;
            }
        };

        // Helper: print histogram for integer data (uses discrete bins)
        auto print_int_histogram = [&](const std::string &title, const std::vector<int> &data) {
            std::cout << title << std::endl;
            if (data.empty()) { std::cout << "  (no data)\n"; return; }
            int minv = *std::min_element(data.begin(), data.end());
            int maxv = *std::max_element(data.begin(), data.end());
            if (minv == maxv) { std::cout << "  All values: " << minv << "\n"; return; }
            int range = maxv - minv + 1;
            std::vector<size_t> counts(range);
            for (int v : data) counts[v - minv]++;
            for (int i = 0; i < range; ++i) {
                int val = i + minv;
                std::cout << "  " << val << ": " << counts[i] << " ";
                int stars = static_cast<int>(std::round(50.0 * counts[i] / data.size()));
                for (int s = 0; s < stars; ++s) std::cout << '*';
                std::cout << std::endl;
            }
        };

        std::cout << "---- Histograms ----" << std::endl;
        print_double_histogram("Time per block (ms) histogram:", block_times_ms, 20);
        print_int_histogram("# Proofs found per challenge histogram:", proofs_per_challenge);
        print_int_histogram("# Proofs found per chain fetch histogram:", proofs_per_chain_fetch);*/
    }

    size_t plot_size_bytes() const
    {
        return 1;
        //size_t t3_bytes = t3_partition_bytes() * proof_params_.get_num_partitions() * 2;
        //size_t t4t5_bytes = t4t5_partition_bytes() * proof_params_.get_num_partitions() * 2;
        //return t3_bytes + t4t5_bytes;
    }

    // static helpers for partition sizes
    size_t t3_partition_bytes() const
    {
        return 0;

        //double elements_in_sub_k = FINAL_TABLE_FILTER_D * 4.0 * static_cast<double>(1ULL << (proof_params_.get_sub_k() - 1));
        //double partition_bytes_t3 = elements_in_sub_k * (static_cast<double>(proof_params_.get_k()) + 1.43) / 8.0;
        //std::cout << "t3_partition_bytes calculation: elements_in_sub_k=" << elements_in_sub_k << ", partition_bytes_t3=" << (int)partition_bytes_t3 << std::endl;
        //return static_cast<size_t>(partition_bytes_t3);
    }

    size_t t4t5_partition_bytes() const
    {
        return 0;
        // N log2 N - (1.43 + 2.04)N, where N is elements in sub_k
        /*double elements_in_sub_k = FINAL_TABLE_FILTER_D * 4.0 * static_cast<double>(1ULL << (proof_params_.get_sub_k() - 1));
        double N_log2_N = elements_in_sub_k * log2(elements_in_sub_k);
        double partition_bits_t4 = N_log2_N - (1.43 - 2.04) * elements_in_sub_k;
        double partition_bytes_t4t5 = partition_bits_t4 * 2 / 8.0;
        std::cout << "t4t5_partition_bytes calculation: elements_in_sub_k=" << elements_in_sub_k << ", N_log2_N =" << N_log2_N << ", partition_bits_t4=" << partition_bits_t4 << ", partition_bytes_t4t5=" << (int)partition_bytes_t4t5 << std::endl;
        return static_cast<size_t>(partition_bytes_t4t5);*/
    }

    double num_expected_pruned_entries_for_t3() const
    {
        double k_entries = (double)(1UL << proof_params_.get_k());
        return k_entries;
        //double t3_entries = (FINAL_TABLE_FILTER_D * 4) * k_entries;
        //return t3_entries;
    }

    double entries_per_partition() const
    {
        return 1;
        //return num_expected_pruned_entries_for_t3() / (double)proof_params_.get_num_partitions();
    }

    double expected_quality_links_set_size() const
    {
        return 1;
        //double num_entries_per_partition = entries_per_partition();
        //return 2.0 * num_entries_per_partition / (double)proof_params_.get_num_partitions();
    }

private:
    ProofParams proof_params_;
};