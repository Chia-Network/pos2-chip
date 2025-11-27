#pragma once

#include <cstdint>
#include <iostream>
#include <string>
#include <cstdlib>
#include <stdexcept>
#include "common/Utils.hpp"
#include "pos/ProofCore.hpp"
#include "pos/ProofParams.hpp"
#include "prove/Prover.hpp"
#include <vector>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <random>

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
        double bits_per_entry = 1.45 + double(proof_params_.get_k());
        size_t plot_bytes = (size_t) (bits_per_entry * (1ULL << proof_params_.get_k()) / 8);

        uint32_t chaining_set_size = proof_params_.get_chaining_set_size();
        size_t chaining_set_bytes = (size_t) ((double) chaining_set_size * bits_per_entry / 8);

        size_t num_plots = (diskTB * 1000 * 1000 * 1000 * 1000) / plot_bytes;
        std::cout << "Plot size bytes: " << plot_bytes << ", Num plots per " << diskTB << "TB: " << num_plots << std::endl;
        
        // TODO:
        // create our set of proof fragments
        // simulate random challenges
        // for each challenge, scan all proofs and test if they pass plot id filter
        // if they pass, add simulated hdd seek times OR pick big file and do random seek and read on that
        // then do chaining run with random 

        // Simulate disk reads
        /*double total_time_ms = 0.0;
        size_t total_data_read_bytes = 0;
        size_t total_random_disk_seeks = 0;

        double total_block_time_ms = 0.0;
        double maximum_block_time_ms = 0.0;
        double minimum_block_time_ms = std::numeric_limits<double>::max();
        double total_time_passing_plot_id_filter_ms = 0.0;

        // Collect per-challenge stats for histograms
        std::vector<double> block_times_ms;
        std::vector<int> proofs_per_challenge;
        std::vector<int> proofs_per_chain_fetch;
        block_times_ms.reserve(10000);
        proofs_per_challenge.reserve(10000);
        proofs_per_chain_fetch.reserve(10000);

        size_t num_plots_passed_filter = 0;

        size_t num_plots_passed_chaining = 0;
        size_t total_proofs_found = 0;

        ProofCore proof_core(proof_params_);

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

private:
    ProofParams proof_params_;
};