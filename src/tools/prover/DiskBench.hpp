#pragma once

#include <cstdint>
#include <iostream>
#include <string>
#include <cstdlib>
#include <stdexcept>
#include "common/Utils.hpp"
#include "pos/ProofCore.hpp"
#include "prove/Prover.hpp"

class DiskBench {
public:
    DiskBench(size_t k = 28,
              size_t proof_fragment_scan_filter_bits = 5,
              size_t plot_id_filter_bits = 8,
              double hdd_seek_time_ms = 10.0,
              double hdd_read_MBs = 70.0)
        : k_(k), proof_fragment_scan_filter_bits_(proof_fragment_scan_filter_bits),
          plot_id_filter_bits_(plot_id_filter_bits), hdd_seek_time_ms_(hdd_seek_time_ms),
          hdd_read_MBs_(hdd_read_MBs) {}

    // Run a simulation of disk reads for a given number of plots.
    // Outputs: total time in ms and total data read in MB.
    void simulateChallengeDiskReads(size_t num_plots) const {
        size_t t3_part_bytes = t3_partition_bytes(static_cast<int>(k_));
        size_t t4t5_part_bytes = t4t5_partition_bytes(static_cast<int>(k_));

        // Simulate disk reads
        double total_time_ms = 0.0;
        size_t total_data_read_bytes = 0;
        size_t total_random_disk_seeks = 0;


        double total_time_passing_plot_id_filter_ms = 0.0;
        double total_time_passing_proof_fragment_scan_ms = 0.0;
        double total_time_fetching_full_proofs_partitions_ms = 0.0;

        size_t num_plots_passed_filter = 0;
        size_t num_plots_passed_proof_fragment_scan_filter = 0;
        size_t num_plots_passed_chaining = 0;
        size_t total_proofs_found = 0;

        
        ProofParams params(Utils::hexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF").data(), k_, 2);
        ProofCore proof_core(params);

        std::array<uint8_t, 32> challenge;
        challenge.fill(0); // Initialize challenge with zeros
        
        // a little "hacky", we setup a bogus file name and then override the plot file contents directly for testing
        // so this won't need to create or read a plot file.
        PlotData empty;
        PlotFile::PlotFileContents plot{empty, params};
        plot.params = params;
        Prover prover(challenge, "test_plot_file.dat");
        prover._testing_setPlotFileContents(plot);

        // create random quality links
        std::vector<QualityLink> links;
        auto num_quality_links_precise = proof_core.expected_quality_links_set_size();
        int num_quality_links = (int) (num_quality_links_precise.first / num_quality_links_precise.second);
        std::cout << "Expected number of quality links: " << num_quality_links << std::endl;
        links.reserve(num_quality_links);

        // change seed for different runs
        std::srand(static_cast<unsigned int>(time(nullptr)));

        // Generate random quality links
        for (int i = 0; i < num_quality_links; ++i)
        {
            QualityLink link;
            link.pattern = static_cast<FragmentsPattern>(rand() % 2); // Randomly choose between OUTSIDE_FRAGMENT_IS_LR and OUTSIDE_FRAGMENT_IS_RR
            for (int j = 0; j < 3; ++j)
            {
                link.fragments[j] = rand() % std::numeric_limits<uint64_t>::max();
            }
            links.push_back(link);
        }

        for (size_t i = 0; i < num_plots; ++i) {
            // random chance to pass plot id filter
            uint64_t modulus = (1ULL << plot_id_filter_bits_);

            if ((std::rand() % static_cast<int>(modulus)) != 0) {
                continue; // skip this plot
            }
            
            num_plots_passed_filter++;

            // Simulate first t3 seek and read of small number of bytes
            uint64_t bytes_to_read = 32 * 1024; // 32KB
            total_data_read_bytes += bytes_to_read;
            double ms_to_read_32KB = 1000.0 * ((double) bytes_to_read / (1024.0 * 1024.0)) / hdd_read_MBs_;
            double passes_plot_id_filter_time_to_scan = hdd_seek_time_ms_ + ms_to_read_32KB; // read 8192 entries of 4 bytes each = 32KB
            std::cout << "passes_plot_id_filter_time_to_scan: " << passes_plot_id_filter_time_to_scan << " ms" << std::endl;
            total_time_passing_plot_id_filter_ms += passes_plot_id_filter_time_to_scan;
            total_time_ms += passes_plot_id_filter_time_to_scan;
            total_random_disk_seeks += 1;

            // now check if passed proof fragment scan filter
            modulus = (1ULL << proof_fragment_scan_filter_bits_);
            if ((std::rand() % static_cast<int>(modulus)) != 0) {
                continue; // skip this plot
            }

            num_plots_passed_proof_fragment_scan_filter++;

            // once passed plot filter, we read the full t3 and t4/t5 partitions, twice! Once for A and B partitions.
            size_t partition_bytes_to_read_after_proof_fragment_scan = (t3_part_bytes + t4t5_part_bytes); // one full partition
            double ms_to_read_full_partition = 1000.0 * (static_cast<double>(partition_bytes_to_read_after_proof_fragment_scan) / (1000.0 * 1000.0)) / hdd_read_MBs_;
            double passes_proof_fragment_scan_time_to_read_full_partitions = 2 * hdd_seek_time_ms_ + 2 * ms_to_read_full_partition;
            std::cout << "ms to read full partition: " << ms_to_read_full_partition << " ms" << std::endl;
            std::cout << "total_bytes_to_read_after_proof_fragment_scan: " << partition_bytes_to_read_after_proof_fragment_scan << " bytes" << std::endl;
            std::cout << "passes_proof_fragment_scan_time_to_read_A_B_full_partitions: " << passes_proof_fragment_scan_time_to_read_full_partitions << " ms" << std::endl;
            total_data_read_bytes += partition_bytes_to_read_after_proof_fragment_scan;
            total_time_passing_proof_fragment_scan_ms += passes_proof_fragment_scan_time_to_read_full_partitions;
            total_time_ms += passes_proof_fragment_scan_time_to_read_full_partitions;
            total_data_read_bytes += partition_bytes_to_read_after_proof_fragment_scan;
            total_random_disk_seeks += 2;

            // now do chaining filter simulation
            challenge[0] = rand();
            challenge[1] = rand();
            challenge[2] = rand();
            challenge[3] = rand();
            prover.setChallenge(challenge);
            BlakeHash::Result256 next_challenge = proof_core.hashing.challengeWithPlotIdHash(challenge.data());
            QualityLink firstLink = links[0];
            std::vector<QualityChain> qualityChains = prover.createQualityChains(firstLink, links, next_challenge);
            // we don't care about the actual chains, just the time taken to do the chaining filter
            std::cout << "Number of quality chains found: " << qualityChains.size() << std::endl;

            if (qualityChains.size() > 0) {
                num_plots_passed_chaining++;

                // TODO: if a lot of chains, chance same partitions might be read (N in M buckets combination probability)
                // have to fetch leaf nodes. Simple seek and scan of 32KB.
                total_data_read_bytes += 32 * 1024;
                total_random_disk_seeks += 1;
                double time_per_leaf_fetch_ms = hdd_seek_time_ms_ + ms_to_read_32KB;
                double time_for_all_chain_fetches_ms = (double) qualityChains.size() * 2 * time_per_leaf_fetch_ms;
                total_time_fetching_full_proofs_partitions_ms += time_for_all_chain_fetches_ms;
                total_time_ms += time_for_all_chain_fetches_ms;
                total_proofs_found += qualityChains.size();
            }
        }

        std::cout << "Plots passed filter: " << num_plots_passed_filter << " out of " << num_plots << " (" 
                  << (static_cast<double>(num_plots_passed_filter) * 100.0 / static_cast<double>(num_plots)) << "%)" << std::endl;
        std::cout << "Plots passed proof fragment scan filter: " << num_plots_passed_proof_fragment_scan_filter << " out of " << num_plots << " (" 
                  << (static_cast<double>(num_plots_passed_proof_fragment_scan_filter) * 100.0 / static_cast<double>(num_plots)) << "%)" << std::endl;
                  std::cout << "Total time for " << num_plots << " plots: " << total_time_ms << " ms" << std::endl;
        std::cout << "Plots passed chaining: " << num_plots_passed_chaining << " out of " << num_plots << " (" 
                  << (static_cast<double>(num_plots_passed_chaining) * 100.0 / static_cast<double>(num_plots)) << "%)" << std::endl;
        std::cout << "Total proofs found: " << total_proofs_found << std::endl;
        std::cout << "Average proofs per plot per challenge:" << (static_cast<double>(total_proofs_found) / static_cast<double>(num_plots)) << std::endl;

        std::cout << "Average time per plot: " << (total_time_ms / static_cast<double>(num_plots)) << " ms" << std::endl;
        std::cout << "Time spent passing plot id filter: " << total_time_passing_plot_id_filter_ms << " ms (% " << (total_time_passing_plot_id_filter_ms / total_time_ms)*100.0 << ")" << std::endl;
        std::cout << "Time spent passing proof fragment scan filter: " << total_time_passing_proof_fragment_scan_ms << " ms (% " << (total_time_passing_proof_fragment_scan_ms / total_time_ms)*100.0 << ")" << std::endl;
        std::cout << "Time spent fetching full proofs partitions: " << total_time_fetching_full_proofs_partitions_ms << " ms (% " << (total_time_fetching_full_proofs_partitions_ms / total_time_ms)*100.0 << ")" << std::endl;
        std::cout << "Total data bytes read: " << total_data_read_bytes << std::endl;
        std::cout << "Average data read per plot: " << (total_data_read_bytes / num_plots) << " bytes" << std::endl;
        std::cout << "Total random disk seeks: " << total_random_disk_seeks << std::endl;
        double time_per_block_ms = 9375.0;
        double hdd_load = total_time_ms / time_per_block_ms;
        std::cout << "----" << std::endl;
        std::cout << "Plot ID filter: " << (1 << plot_id_filter_bits_) << std::endl;
        std::cout << "Proof fragment scan filter: " << (1 << proof_fragment_scan_filter_bits_) << std::endl;
        std::cout << "Estimated HDD load for 1 challenge every 9.375 seconds: " << (hdd_load * 100.0) << "%" << std::endl;

    }

    // accessors
    size_t k() const { return k_; }
    size_t proofFragmentScanFilterBits() const { return proof_fragment_scan_filter_bits_; }
    size_t plotIdFilterBits() const { return plot_id_filter_bits_; }
    double hddSeekTimeMs() const { return hdd_seek_time_ms_; }
    double hddReadMBs() const { return hdd_read_MBs_; }

    // static helpers for partition sizes
    static size_t t3_partition_bytes(int k) {
        switch (k) {
            case 28: return 1536831; 
            case 30: return 3282542; 
            case 32: return 13965385; 
            default:
                throw std::invalid_argument("t3_partition_bytes: k must be even integer between 28 and 32.");
        }
    }

    static size_t t4t5_partition_bytes(int k) {
        switch (k) {
            case 28: return  1006920*2; // sub k 20
            case 30: return 2118280*2; // sub k 21
            case 32: return 9308637*2; // for sub k 23 
            default:
                throw std::invalid_argument("t4_partition_bytes: k must be even integer between 28 and 32.");
        }
    }

private:
    size_t k_;
    size_t proof_fragment_scan_filter_bits_;
    size_t plot_id_filter_bits_;
    double hdd_seek_time_ms_;
    double hdd_read_MBs_;
};