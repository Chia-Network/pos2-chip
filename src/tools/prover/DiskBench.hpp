#pragma once

#include <cstdint>
#include <iostream>
#include <string>
#include <cstdlib>
#include <stdexcept>
#include "common/Utils.hpp"
#include "pos/ProofCore.hpp"
#include "prove/Prover.hpp"

// #define DEBUG_DISK_BENCH true
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
    DiskBench(const ProofParams &proof_params,
              size_t proof_fragment_scan_filter_bits = 6,
              size_t plot_id_filter_bits = 8,
              double hdd_seek_time_ms = 10.0,
              double hdd_read_MBs = 70.0)
        : proof_params_(proof_params), proof_fragment_scan_filter_bits_(proof_fragment_scan_filter_bits),
          plot_id_filter_bits_(plot_id_filter_bits), hdd_seek_time_ms_(hdd_seek_time_ms),
          hdd_read_MBs_(hdd_read_MBs) {}

    // Run a simulation of disk reads for a given number of plots.
    // Outputs: total time in ms and total data read in MB.
    void simulateChallengeDiskReads(size_t num_plots) const
    {
        size_t plot_bytes = plot_size_bytes();
        size_t t3_part_bytes = t3_partition_bytes();
        size_t t4t5_part_bytes = t4t5_partition_bytes();
        num_plots = (20ULL * 1000 * 1000 * 1000 * 1000) / plot_bytes;
        std::cout << "Plot size bytes: " << plot_bytes << ", Num plots per 20TB: " << num_plots << std::endl;
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

        // a little "hacky", we setup a bogus file name and then override the plot file contents directly for testing
        // so this won't need to create or read a plot file.
        PlotData empty;
        PlotFile::PlotFileContents plot{empty, proof_params_};
        plot.params = proof_params_;
        Prover prover(challenge, "test_plot_file.dat");
        prover._testing_setPlotFileContents(plot);

        // create random quality links
        std::vector<QualityLink> links;
        int num_quality_links = static_cast<int>(expected_quality_links_set_size());
        //int num_quality_links = (int)(num_quality_links_precise.first / num_quality_links_precise.second);

#ifdef DEBUG_DISK_BENCH
        std::cout << "Expected number of quality links: " << num_quality_links << std::endl;
#endif
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

        size_t num_challenges = 9216;
        for (size_t nChallenges = 0; nChallenges < num_challenges; ++nChallenges)
        { // simulate a days worth of challenges
            total_block_time_ms = 0.0;
            split_disk_total_block_time_ms[0] = 0.0;
            split_disk_total_block_time_ms[1] = 0.0;
            for (size_t i = 0; i < num_plots; ++i)
            {
                // random chance to pass plot id filter
                uint64_t modulus = (1ULL << plot_id_filter_bits_);

                if ((std::rand() % static_cast<int>(modulus)) != 0)
                {
                    continue; // skip this plot
                }

                num_plots_passed_filter++;

                // Simulate first t3 seek and read of small number of bytes
                uint64_t bytes_to_read = 32 * 1024; // 32KB
                total_data_read_bytes += bytes_to_read;
                double ms_to_read_32KB = 1000.0 * ((double)bytes_to_read / (1024.0 * 1024.0)) / hdd_read_MBs_;
                double passes_plot_id_filter_time_to_scan = hdd_seek_time_ms_ + ms_to_read_32KB; // read 8192 entries of 4 bytes each = 32KB
#ifdef DEBUG_DISK_BENCH
                std::cout << "passes_plot_id_filter_time_to_scan: " << passes_plot_id_filter_time_to_scan << " ms" << std::endl;
#endif
                total_time_passing_plot_id_filter_ms += passes_plot_id_filter_time_to_scan;
                total_block_time_ms += passes_plot_id_filter_time_to_scan;
                total_time_ms += passes_plot_id_filter_time_to_scan;
                total_random_disk_seeks += 1;

                // these are for disk 1 holding t3 partitions
                split_disk_total_data_read_bytes[0] += bytes_to_read;
                split_disk_total_time_passing_plot_id_filter_ms[0] += passes_plot_id_filter_time_to_scan;
                split_disk_total_block_time_ms[0] += passes_plot_id_filter_time_to_scan;
                split_disk_total_time_ms[0] += passes_plot_id_filter_time_to_scan;
                split_disk_total_random_disk_seeks[0] += 1;

                // now check if passed proof fragment scan filter
                modulus = (1ULL << proof_fragment_scan_filter_bits_);
                if ((std::rand() % static_cast<int>(modulus)) != 0)
                {
                    continue; // skip this plot
                }

                num_plots_passed_proof_fragment_scan_filter++;

                // once passed plot filter, we read the full t3 and t4/t5 partitions, twice! Once for A and B partitions.
                size_t partition_bytes_to_read_after_proof_fragment_scan = (t3_part_bytes + t4t5_part_bytes); // one full partition
                double ms_to_read_full_partition = 1000.0 * (static_cast<double>(partition_bytes_to_read_after_proof_fragment_scan) / (1000.0 * 1000.0)) / hdd_read_MBs_;
                double passes_proof_fragment_scan_time_to_read_full_partition = hdd_seek_time_ms_ + ms_to_read_full_partition;
#ifdef DEBUG_DISK_BENCH
                std::cout << "ms to read full partition: " << ms_to_read_full_partition << " ms" << std::endl;
                std::cout << "total_bytes_to_read_after_proof_fragment_scan: " << partition_bytes_to_read_after_proof_fragment_scan << " bytes" << std::endl;
                std::cout << "passes_proof_fragment_scan_time_to_read_A_B_full_partitions: " << passes_proof_fragment_scan_time_to_read_full_partitions << " ms" << std::endl;
#endif
                total_data_read_bytes += 2 * partition_bytes_to_read_after_proof_fragment_scan;
                total_block_time_ms += 2 * passes_proof_fragment_scan_time_to_read_full_partition;
                total_time_passing_proof_fragment_scan_ms += 2 * passes_proof_fragment_scan_time_to_read_full_partition;
                total_time_ms += 2 * passes_proof_fragment_scan_time_to_read_full_partition;
                total_random_disk_seeks += 2;

                // t3 partitions are on disk 1, t4/t5 on disk 2
                split_disk_total_data_read_bytes[0] += 2 * t3_part_bytes;
                split_disk_total_data_read_bytes[1] += 2 * t4t5_part_bytes;
                double ms_to_read_t3_partition = hdd_seek_time_ms_ + 1000.0 * (static_cast<double>(t3_part_bytes) / (1000.0 * 1000.0)) / hdd_read_MBs_;
                double ms_to_read_t4t5_partition = hdd_seek_time_ms_ + 1000.0 * (static_cast<double>(t4t5_part_bytes) / (1000.0 * 1000.0)) / hdd_read_MBs_;
                split_disk_total_block_time_ms[0] += 2 * ms_to_read_t3_partition;
                split_disk_total_block_time_ms[1] += 2 * ms_to_read_t4t5_partition;
                split_disk_total_time_passing_proof_fragment_scan_ms[0] += 2 * ms_to_read_t3_partition;
                split_disk_total_time_passing_proof_fragment_scan_ms[1] += 2 * ms_to_read_t4t5_partition;
                split_disk_total_time_ms[0] += 2 * ms_to_read_t3_partition;
                split_disk_total_time_ms[1] += 2 * ms_to_read_t4t5_partition;
                split_disk_total_random_disk_seeks[0] += 2;
                split_disk_total_random_disk_seeks[1] += 2;

                // now do chaining filter simulation
                challenge[0] = rand();
                challenge[1] = rand();
                challenge[2] = rand();
                challenge[3] = rand();
                prover.setChallenge(challenge);
                BlakeHash::Result256 next_challenge = proof_core.hashing.challengeWithPlotIdHash(challenge.data());
                QualityLink firstLink = links[0];
                std::vector<QualityChain> qualityChains = prover.createQualityChains(firstLink, links, next_challenge);

#ifdef DEBUG_DISK_BENCH
                std::cout << "Number of quality chains found: " << qualityChains.size() << std::endl;
#endif

                if (qualityChains.size() > 0)
                {
                    num_plots_passed_chaining++;
                    total_proofs_found += qualityChains.size();

                    // when have to fetch full proofs, each quality link in chain needs to fetch 1 additional leaf node from T3.
                    // with 16 elements in the chain, this is 16 additional reads of 32KB each.
                    // NOTE: in real scenario, only plots passing difficulty filter for pool would need to do this. Should not be much more than 1 each block.
                    // TODO: if a lot of chains, chance same partitions might be read (N in M buckets combination probability)
                    // have to fetch leaf nodes. Simple seek and scan of 32KB.
                    /*total_data_read_bytes += qualityChains.size() * NUM_CHAIN_LINKS * 32 * 1024;
                    total_random_disk_seeks += NUM_CHAIN_LINKS * qualityChains.size();
                    double time_per_leaf_fetch_ms = hdd_seek_time_ms_ + ms_to_read_32KB;
                    double time_for_all_chain_fetches_ms = (double)qualityChains.size() * NUM_CHAIN_LINKS * time_per_leaf_fetch_ms;
                    total_block_time_ms += time_for_all_chain_fetches_ms;
                    total_time_fetching_full_proofs_partitions_ms += time_for_all_chain_fetches_ms;
                    total_time_ms += time_for_all_chain_fetches_ms;

                    // this only affects split disk 1 since leaf nodes are in t3 partitions
                    split_disk_total_data_read_bytes[0] += qualityChains.size() * NUM_CHAIN_LINKS * 32 * 1024;
                    split_disk_total_random_disk_seeks[0] += NUM_CHAIN_LINKS * qualityChains.size();
                    split_disk_total_block_time_ms[0] += time_for_all_chain_fetches_ms;
                    split_disk_total_time_fetching_full_proofs_partitions_ms[0] += time_for_all_chain_fetches_ms;
                    split_disk_total_time_ms[0] += time_for_all_chain_fetches_ms;*/
                }
            }
            if (total_block_time_ms > maximum_block_time_ms)
                maximum_block_time_ms = total_block_time_ms;
            if (total_block_time_ms < minimum_block_time_ms)
                minimum_block_time_ms = total_block_time_ms;

            if (split_disk_total_block_time_ms[0] > split_disk_maximum_block_time_ms[0])
                split_disk_maximum_block_time_ms[0] = split_disk_total_block_time_ms[0];
            if (split_disk_total_block_time_ms[0] < split_disk_minimum_block_time_ms[0])
                split_disk_minimum_block_time_ms[0] = split_disk_total_block_time_ms[0];
            if (split_disk_total_block_time_ms[1] > split_disk_maximum_block_time_ms[1])
                split_disk_maximum_block_time_ms[1] = split_disk_total_block_time_ms[1];
            if (split_disk_total_block_time_ms[1] < split_disk_minimum_block_time_ms[1])
                split_disk_minimum_block_time_ms[1] = split_disk_total_block_time_ms[1];

#ifndef DEBUG_DISK_BENCH
            if (nChallenges % 100 == 0)
            {
                std::cout << "Completed " << nChallenges << " of " << num_challenges << " challenges..." << std::endl;
                std::cout << "  Current disk % load: " << (total_time_ms / (static_cast<double>(nChallenges + 1) * 9375.0)) * 100.0 << "%" << std::endl;
                std::cout << "       Max block time: " << maximum_block_time_ms << " ms (% " << (maximum_block_time_ms / 9375.0) * 100.0 << "%)" << std::endl;
                std::cout << "       Min block time: " << minimum_block_time_ms << " ms (% " << (minimum_block_time_ms / 9375.0) * 100.0 << "%)" << std::endl;
            }
#endif
        }

        double time_per_block_ms = 9375.0;
        double hdd_load = total_time_ms / time_per_block_ms;

        std::cout << "---- completed " << num_challenges << " challenges ----" << std::endl;
        std::cout << "Plots passed filter: " << num_plots_passed_filter << " out of " << num_plots << " for " << num_challenges << " challenges ("
                  << (static_cast<double>(num_plots_passed_filter) * 100.0 / static_cast<double>(num_plots * num_challenges)) << "%)" << std::endl;
        double expected_plots_passing_filter = static_cast<double>(num_plots * num_challenges) / static_cast<double>(1 << plot_id_filter_bits_);
        std::cout << "Expected plots passing filter: " << expected_plots_passing_filter << std::endl;
        std::cout << "Plots passed proof fragment scan filter: " << num_plots_passed_proof_fragment_scan_filter << " out of " << num_plots << " for " << num_challenges << " challenges ("
                  << (static_cast<double>(num_plots_passed_proof_fragment_scan_filter) * 100.0 / static_cast<double>(num_plots * num_challenges)) << "%)" << std::endl;
        std::cout << "Total time for " << num_plots << " plots: " << total_time_ms << " ms" << std::endl;
        std::cout << "Plots passed chaining: " << num_plots_passed_chaining << " out of " << num_plots << " for " << num_challenges << " challenges ("
                  << (static_cast<double>(num_plots_passed_chaining) * 100.0 / static_cast<double>(num_plots * num_challenges)) << "%)" << std::endl;
        std::cout << "Total proofs found: " << total_proofs_found << std::endl;
        std::cout << "Average proofs per plot per challenge:" << (static_cast<double>(total_proofs_found) / static_cast<double>(num_plots * num_challenges)) << std::endl;

        std::cout << "Average time per plot: " << (total_time_ms / static_cast<double>(num_plots)) << " ms" << std::endl;
        std::cout << "Time spent passing plot id filter: " << total_time_passing_plot_id_filter_ms << " ms (% " << (total_time_passing_plot_id_filter_ms / total_time_ms) * 100.0 << ")" << std::endl;
        std::cout << "Time spent passing proof fragment scan filter: " << total_time_passing_proof_fragment_scan_ms << " ms (% " << (total_time_passing_proof_fragment_scan_ms / total_time_ms) * 100.0 << ")" << std::endl;
        std::cout << "Time spent fetching full proofs partitions: " << total_time_fetching_full_proofs_partitions_ms << " ms (% " << (total_time_fetching_full_proofs_partitions_ms / total_time_ms) * 100.0 << ")" << std::endl;
        std::cout << "Total data bytes read: " << total_data_read_bytes << std::endl;
        std::cout << "Average data read per plot: " << (total_data_read_bytes / num_plots) << " bytes" << std::endl;
        std::cout << "Total random disk seeks: " << total_random_disk_seeks << std::endl;

        std::cout << "---- Split Disk Stats ----" << std::endl;
        double perc_data_on_disk_1 = static_cast<double>(t3_part_bytes) / static_cast<double>(t3_part_bytes + t4t5_part_bytes);
        double perc_data_on_disk_2 = static_cast<double>(t4t5_part_bytes) / static_cast<double>(t3_part_bytes + t4t5_part_bytes);
        std::cout << "Percentage of data on Disk 1 (t3 partitions): " << perc_data_on_disk_1 * 100.0 << "%" << std::endl;
        std::cout << "Percentage of data on Disk 2 (t4/t5 partitions): " << perc_data_on_disk_2 * 100.0 << "%" << std::endl;
        double multipler_disk_1_load = 1.0 / perc_data_on_disk_1;
        double multipler_disk_2_load = 1.0 / perc_data_on_disk_2;
        std::cout << "Estimated Disk 1 load multiplier: " << multipler_disk_1_load << std::endl;
        std::cout << "Estimated Disk 2 load multiplier: " << multipler_disk_2_load << std::endl;
        for (int disk_idx = 0; disk_idx < 2; ++disk_idx)
        {
            std::cout << "Disk " << disk_idx + 1 << " total data bytes read: " << split_disk_total_data_read_bytes[disk_idx] << std::endl;
            std::cout << "Disk " << disk_idx + 1 << " total random disk seeks: " << split_disk_total_random_disk_seeks[disk_idx] << std::endl;
            std::cout << "Disk " << disk_idx + 1 << " total time ms: " << split_disk_total_time_ms[disk_idx] << " ms" << std::endl;
            std::cout << "Disk " << disk_idx + 1 << " average time per plot: " << (split_disk_total_time_ms[disk_idx] / static_cast<double>(num_plots)) << " ms" << std::endl;
            std::cout << "Disk " << disk_idx + 1 << " time passing plot id filter: " << split_disk_total_time_passing_plot_id_filter_ms[disk_idx] << " ms" << std::endl;
            std::cout << "Disk " << disk_idx + 1 << " time passing proof fragment scan filter: " << split_disk_total_time_passing_proof_fragment_scan_ms[disk_idx] << " ms" << std::endl;
            std::cout << "Disk " << disk_idx + 1 << " time fetching full proofs partitions: " << split_disk_total_time_fetching_full_proofs_partitions_ms[disk_idx] << " ms" << std::endl;
            std::cout << "Disk " << disk_idx + 1 << " max block time: " << split_disk_maximum_block_time_ms[disk_idx] << " ms" << std::endl;
            std::cout << "Disk " << disk_idx + 1 << " min block time: " << split_disk_minimum_block_time_ms[disk_idx] << " ms" << std::endl;
            std::cout << "------------------------" << std::endl;
            double load_multiplier = (disk_idx == 0) ? multipler_disk_1_load : multipler_disk_2_load;
            std::cout << "Estimated HDD load for Disk " << disk_idx + 1 << " for 1 challenge every 9.375 seconds: "
                      << (load_multiplier * split_disk_total_time_ms[disk_idx] * 100.0 / (static_cast<double>(num_challenges) * time_per_block_ms)) << "%" << std::endl;
        }

        std::cout << "----" << std::endl;
        std::cout << "Plot ID filter: " << (1 << plot_id_filter_bits_) << std::endl;
        std::cout << "Proof fragment scan filter: " << (1 << proof_fragment_scan_filter_bits_) << std::endl;

        std::cout << "Estimated HDD load for 1 challenge every 9.375 seconds: " << (hdd_load * 100.0 / (double)num_challenges) << "%" << std::endl;
    }

    // accessors
    size_t proofFragmentScanFilterBits() const { return proof_fragment_scan_filter_bits_; }
    size_t plotIdFilterBits() const { return plot_id_filter_bits_; }
    double hddSeekTimeMs() const { return hdd_seek_time_ms_; }
    double hddReadMBs() const { return hdd_read_MBs_; }

    size_t plot_size_bytes() const
    {
        size_t t3_bytes = t3_partition_bytes() * proof_params_.get_num_partitions() * 2;
        size_t t4t5_bytes = t4t5_partition_bytes() * proof_params_.get_num_partitions() * 2;
        return t3_bytes + t4t5_bytes;
    }

    // static helpers for partition sizes
    size_t t3_partition_bytes() const
    {

        double elements_in_sub_k = FINAL_TABLE_FILTER_D * 4.0 * static_cast<double>(1ULL << (proof_params_.get_sub_k() - 1));
        double partition_bytes_t3 = elements_in_sub_k * (static_cast<double>(proof_params_.get_k()) + 1.43) / 8.0;
        std::cout << "t3_partition_bytes calculation: elements_in_sub_k=" << elements_in_sub_k << ", partition_bytes_t3=" << (int)partition_bytes_t3 << std::endl;
        // exit(23);
        return static_cast<size_t>(partition_bytes_t3);
        /*switch (k)
        {
        case 28:
            return 1536831; // sub_k 20
        case 30:
            return 6565083; // sub_k 22
        case 32:
            return 13965385; // sub_k 23
        default:
            throw std::invalid_argument("t3_partition_bytes: k must be even integer between 28 and 32.");
        }*/
    }

    size_t t4t5_partition_bytes() const
    {
        // N log2 N - (1.43 + 2.04)N, where N is elements in sub_k
        double elements_in_sub_k = FINAL_TABLE_FILTER_D * 4.0 * static_cast<double>(1ULL << (proof_params_.get_sub_k() - 1));
        double N_log2_N = elements_in_sub_k * log2(elements_in_sub_k);
        double partition_bits_t4 = N_log2_N - (1.43 - 2.04) * elements_in_sub_k;
        double partition_bytes_t4t5 = partition_bits_t4 * 2 / 8.0;
        std::cout << "t4t5_partition_bytes calculation: elements_in_sub_k=" << elements_in_sub_k << ", N_log2_N =" << N_log2_N << ", partition_bits_t4=" << partition_bits_t4 << ", partition_bytes_t4t5=" << (int)partition_bytes_t4t5 << std::endl;
        return static_cast<size_t>(partition_bytes_t4t5);
        /*switch (k)
        {
        case 28:
            return 1006920 * 2; // sub k 20
        case 30:
            return 4445439 * 2; // sub k 22
        case 32:
            return 9308637 * 2; // for sub k 23
        default:
            throw std::invalid_argument("t4_partition_bytes: k must be even integer between 28 and 32, sub_k must be 20/22/23.");
        }*/
    }

    double num_expected_pruned_entries_for_t3() const
    {
        double k_entries = (double)(1UL << proof_params_.get_k());
        double t3_entries = (FINAL_TABLE_FILTER_D * 4) * k_entries;
        return t3_entries;
    }

    double entries_per_partition() const
    {
        return num_expected_pruned_entries_for_t3() / (double)proof_params_.get_num_partitions();
    }

    double expected_quality_links_set_size() const
    {
        double num_entries_per_partition = entries_per_partition();
        return 2.0 * num_entries_per_partition / (double)proof_params_.get_num_partitions();
    }

private:
    ProofParams proof_params_;
    size_t proof_fragment_scan_filter_bits_;
    size_t plot_id_filter_bits_;
    double hdd_seek_time_ms_;
    double hdd_read_MBs_;
};