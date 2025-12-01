#pragma once

#include <cstdint>
#include <iostream>
#include <string>
#include <cstdlib>
#include <stdexcept>
#include "common/Utils.hpp"
#include "pos/ProofCore.hpp"
#include "pos/ProofParams.hpp"
#include "pos/Chainer.hpp"
#include "prove/Prover.hpp"
#include "common/Timer.hpp"
#include <vector>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <random>

#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>

// Simple helpers for pretty printing
namespace pretty {

    constexpr int LABEL_WIDTH = 38;
    constexpr int VALUE_WIDTH = 22;

    inline void printSeparator(char ch = '-', int extra = 0) {
        int totalWidth = LABEL_WIDTH + VALUE_WIDTH + 7 + extra; // borders + spaces
        std::cout << std::string(totalWidth, ch) << "\n";
    }

    inline void printSectionHeader(const std::string& title) {
        printSeparator('=');
        std::cout << "| " << std::left << std::setw(LABEL_WIDTH + VALUE_WIDTH + 3)
                  << title << " |\n";
        printSeparator('=');
    }

    template <typename T>
    inline void printRow(const std::string& label, const T& value) {
        std::cout << "| "
                  << std::left << std::setw(LABEL_WIDTH) << label
                  << " | "
                  << std::right << std::setw(VALUE_WIDTH) << value
                  << " |\n";
    }

    inline std::string pct(double v, int precision = 2) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(precision) << v << " %";
        return oss.str();
    }

    inline std::string ms(double v, int precision = 2) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(precision) << v << " ms";
        return oss.str();
    }

    inline std::string bytes_sensible(double bytes, int precision = 2) {
        const char* sizes[] = { "B", "KB", "MB", "GB", "TB", "PB" };
        int order = 0;
        while (bytes >= 1000.0 && order < 5) {
            order++;
            bytes = bytes / 1000.0;
        }
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(precision) << bytes << " " << sizes[order];
        return oss.str();
    }

    inline std::string mb(double v, int precision = 2) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(precision) << v << " MB";
        return oss.str();
    }

    inline std::string gb(double v, int precision = 2) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(precision) << v << " GB";
        return oss.str();
    }

    inline std::string tb(double v, int precision = 1) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(precision) << v << " TB";
        return oss.str();
    }

    template <typename T>
    inline std::string num(T v, int precision = 2, bool fixed = true) {
        std::ostringstream oss;
        if constexpr (std::is_floating_point<T>::value) {
            if (fixed) oss << std::fixed;
            oss << std::setprecision(precision);
        }
        oss << v;
        return oss.str();
    }

}

using namespace pretty;

class DiskBench
{
public:
    DiskBench(const ProofParams &proof_params)
        : proof_params_(proof_params) {}

    // Run a simulation of disk reads for a given number of plots.
    // Outputs: total time in ms and total data read in MB.
    void simulateChallengeDiskReads(size_t plot_id_filter_bits, size_t num_plots_in_group, size_t diskTB, double diskSeekMs, double diskReadMBs) const
    {
        //std::cout << "Simulating disk reads with plot ID filter bits: " << plot_id_filter_bits
        //          << ", Disk size: " << diskTB << " TB, Seek time: " << diskSeekMs << " ms, Read speed: " << diskReadMBs << " MB/s\n";
        
        double bits_per_entry = 1.45 + double(proof_params_.get_k());
        size_t plot_bytes = (size_t) (bits_per_entry * (1ULL << proof_params_.get_k()) / 8);
        size_t grouped_plot_bytes = plot_bytes * num_plots_in_group;

        uint32_t chaining_set_size = proof_params_.get_chaining_set_size();
        size_t chaining_set_bytes = (size_t) (static_cast<double>(chaining_set_size) * bits_per_entry / 8);

        size_t num_plots = (diskTB * 1000 * 1000 * 1000 * 1000) / plot_bytes;
        size_t num_grouped_plots = num_plots / num_plots_in_group;
        std::cout << std::endl;
        std::cout << "------------------------------------\n";
        std::cout << "Harvester Disk Simulation Parameters:\n";
        std::cout << "------------------------------------\n";
        std::cout << "   Plot ID filter                   : " << (1 << plot_id_filter_bits) << " (bits: " << plot_id_filter_bits << ")\n";
        std::cout << "   ----------------------------------\n";
        std::cout << "   Disk capacity                    : " << diskTB << " TB\n";
        std::cout << "   Disk seek time (ms)              : " << diskSeekMs << " ms\n";
        std::cout << "   Disk read speed                  : " << diskReadMBs << " MB/s\n";
        std::cout << "   ----------------------------------\n";
        std::cout << "   Plot size bytes                  : " << bytes_sensible(static_cast<double(plot_bytes)) << std::endl;
        std::cout << "   Total plots per Disk             : " << num_plots << std::endl;
        std::cout << "   ----------------------------------\n";
        std::cout << "   Plots in group                   : " << num_plots_in_group << std::endl;
        std::cout << "   Grouped plot size bytes          : " << bytes_sensible(static_cast<double>(grouped_plot_bytes)) << std::endl;
        std::cout << "   Num grouped plots on disk        : " << num_grouped_plots << std::endl;
        std::cout << "   ----------------------------------\n";
        
        std::mt19937 rng(1245); // fixed seed for reproducibility
        std::uniform_int_distribution<uint32_t> plot_filter_dist(0, (1U << plot_id_filter_bits) - 1);
        Range fragment_set_A_range = proof_params_.get_chaining_set_range(0);
        std::uniform_int_distribution<ProofFragment> fragment_dist(0, fragment_set_A_range.end + 1);
        std::vector<ProofFragment> fragments_As(chaining_set_size);
        std::vector<ProofFragment> fragments_Bs(chaining_set_size);
        for (int i = 0; i < static_cast<int>(chaining_set_size); ++i)
        {
            fragments_As[i] = fragment_set_A_range.start + fragment_dist(rng);
            fragments_Bs[i] = fragment_set_A_range.end + 1 + fragment_dist(rng);
        }

        size_t num_challenges = 1000;//9216; // simulate 9216 challenges (about one every 9.375 seconds for 24 hours)

        // Simulate disk reads for chaining sets
        size_t total_plots_passed_filter = 0;

        constexpr uint8_t k = 28;
        std::string plot_id_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        std::string challenge_hex = "5c00000000000000000000000000000000000000000000000000000000000000";
        std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);
        uint32_t sim_challenge_id = 0;
        ProofParams proof_params(Utils::hexToBytes(plot_id_hex).data(), k, 2);
        ProofCore proof_core(proof_params);
        Timer timer;
        double total_harvesting_compute_time_ms = 0.0;
        size_t proofs_found = 0;

        const double CAP_COMPUTE_TOTAL_SIMULATION_TIME_MS = 20000.0; // cap at 20 seconds total compute time
        size_t total_challenges_before_compute_cap = 0;
        double max_compute_ms_per_challenge = 0;
        size_t max_plots_passing_filter_per_challenge = 0;

        // start progress bar output
        std::cout << std::endl;
        std::cout << "Running simulation (cap at " << std::ceil(CAP_COMPUTE_TOTAL_SIMULATION_TIME_MS / 1000.0) << "s):\n";
        int progress_bar_steps = 40;
        std::cout << "[";
        for (int i = 0; i < progress_bar_steps; ++i) std::cout << " ";
        std::cout << "]\n";
        // move cursor back to start of line
        std::cout << "\r";
        std::cout.flush();
        // move cursor up one line
        std::cout << "\033[A" << "[" << std::flush;
        
        size_t progress_bar_step_size = num_challenges / progress_bar_steps;

        bool cap_harvesting_compute_reached = false;
        for (size_t challenge_id = 0; challenge_id < num_challenges; ++challenge_id) {
            size_t challenge_plots_passed_filter = 0;
            double challenge_compute_time_ms = 0.0;
            if (total_harvesting_compute_time_ms > CAP_COMPUTE_TOTAL_SIMULATION_TIME_MS) {
                cap_harvesting_compute_reached = true;
            }
            else {
                total_challenges_before_compute_cap++;
            }
            for (size_t plot_id = 0; plot_id < num_grouped_plots; ++plot_id) {
                // Simulate whether this plot passes the plot ID filter
                
                uint32_t plot_id_filter_value = plot_filter_dist(rng);
                if (plot_id_filter_value != 0) {
                    continue; // does not pass filter
                }

                // if it passes filter, requires 2 disk seeks and 2*chaining_set_bytes read
                challenge_plots_passed_filter++;

                if (challenge_plots_passed_filter > max_plots_passing_filter_per_challenge) {
                    max_plots_passing_filter_per_challenge = challenge_plots_passed_filter;
                }

                // simulate harvester challenge compute time for chaining.
                // create new random challenge each plot passing filter
                // remember have to compute for all plots in group
                if (cap_harvesting_compute_reached) {
                    continue; // cap reached, skip further compute
                }
                
                for (size_t i = 0; i < num_plots_in_group; ++i)
                {
                    challenge[0] = static_cast<uint8_t>(sim_challenge_id & 0xFF);
                    challenge[1] = static_cast<uint8_t>((sim_challenge_id >> 8) & 0xFF);
                    challenge[2] = static_cast<uint8_t>((sim_challenge_id >> 16) & 0xFF);
                    challenge[3] = static_cast<uint8_t>((sim_challenge_id >> 24) & 0xFF);
                    sim_challenge_id++;
                    timer.start();
                    Chainer chainer(proof_params, challenge);
                    auto chains = chainer.find_links(fragments_As, fragments_Bs);
                    double elapsed_ms = timer.stop();
                    total_harvesting_compute_time_ms += elapsed_ms;
                    proofs_found += chains.size();
                    challenge_compute_time_ms += elapsed_ms;
                }
                if (challenge_compute_time_ms > max_compute_ms_per_challenge) {
                    max_compute_ms_per_challenge = challenge_compute_time_ms;
                }

            }

            total_plots_passed_filter += challenge_plots_passed_filter;

            // update progress bar
            if ((challenge_id + 1) % progress_bar_step_size == 0) {
                std::cout << "=" << std::flush;
            }
        }
        // finish progress bar
        std::cout << "]" << std::endl << std::endl;

        // now we can compute our disk stats
        // each plot passing filter requires 2 seeks + reading chaining set
        size_t total_seeks = total_plots_passed_filter * 2;
        size_t total_data_read_bytes = total_plots_passed_filter * num_plots_in_group * chaining_set_bytes * 2;
        double diskSeekTimeMs = total_seeks * diskSeekMs;
        double diskReadTimeMs = (static_cast<double>(total_data_read_bytes) / (diskReadMBs * 1000.0));
        double total_time_ms = diskSeekTimeMs + diskReadTimeMs;
        double disk_load_percentage = 100.0 * (total_time_ms / (numeric_cast<double>(num_challenges) * 9375.0));

        //std::cout << "---- Disk Read Simulation Results ----" << std::endl;
        double plots_passed_perc = (static_cast<double>(total_plots_passed_filter)) / static_cast<double>(num_grouped_plots * num_challenges);
        //std::cout << "Total plots passed filter: " << total_plots_passed_filter << " (1 out of " << (1/plots_passed_perc) << ")" << std::endl;
        //std::cout << "Total disk seeks: " << total_seeks << ", Total data read: " << (total_data_read_bytes / (1024.0 * 1024.0)) << " MB" << std::endl;
        //std::cout << "Total disk seek time: " << diskSeekTimeMs << " ms, Total disk read time: " << diskReadTimeMs << " ms" << std::endl;
        //std::cout << "Total time for " << num_challenges << " challenges: " << total_time_ms << " ms" << std::endl;
        //std::cout << "Estimated HDD load for 1 challenge every 9.375 seconds: " << disk_load_percentage << "%" << std::endl;
        // get max load experienced for a challenge
       // std::cout << "Max compute time for a single challenge: " << max_compute_ms_per_challenge << " ms" << std::endl;
        //std::cout << "Max plots passing filter for a single challenge: " << max_plots_passing_filter_per_challenge << std::endl;
        // and load calc for max
        double max_disk_load_percentage = 100.0 * ((static_cast<double>(max_plots_passing_filter_per_challenge) * 2 * diskSeekMs + (static_cast<double>(max_plots_passing_filter_per_challenge * num_plots_in_group * chaining_set_bytes * 2) / (diskReadMBs * 1000.0))) / 9375.0);
        //std::cout << "Estimated max HDD load for a single challenge: " << max_disk_load_percentage << "%" << std::endl;
        double max_compute_load_percentage = 100.0 * (max_compute_ms_per_challenge / 9375.0);
        //std::cout << "Estimated max CPU harvesting load for a single challenge: " << max_compute_load_percentage << "%" << std::endl;
                
        //std::cout << "---- Harvesting Compute Time ----" << std::endl;
        //std::cout << "Total harvesting compute time for " << num_challenges << " challenges: " << total_harvesting_compute_time_ms << " ms" << std::endl;
        //std::cout << "Total proofs found: " << proofs_found << std::endl;
        double avg_compute_time_per_challenge_ms = total_harvesting_compute_time_ms / static_cast<double>(total_challenges_before_compute_cap);
        //std::cout << "Average harvesting compute time per challenge: " << avg_compute_time_per_challenge_ms << " ms" << std::endl;
        double cpu_harvesting_load_percentage = 100.0 * (total_harvesting_compute_time_ms / (total_challenges_before_compute_cap * 9375.0));
        //std::cout << "Estimated CPU harvesting load for 1 challenge every 9.375 seconds: " << cpu_harvesting_load_percentage << "%" << std::endl;

        
    

        // --------------------------------------------------
        // OVERVIEW SECTION
        // --------------------------------------------------
        printSectionHeader("Overall Harvesting Overview");

        printRow("Challenges simulated", num(num_challenges, 0));
        printRow("Total proofs found", num(proofs_found, 0));
        printSeparator();
        printRow("HDD Capacity", tb(static_cast<double>(diskTB)));
        printRow("Avg HDD load (all challenges)", pct(disk_load_percentage));
        printRow("Max HDD load (single challenge)", pct(max_disk_load_percentage));
        size_t read_bytes_per_day = (total_data_read_bytes * 9216) / num_challenges;
        printRow("Estimated data read per day", bytes_sensible(static_cast<double>(read_bytes_per_day)));
        printSeparator();

        printRow("Avg CPU harvesting load", pct(cpu_harvesting_load_percentage));
        printRow("Max CPU harvesting load", pct(max_compute_load_percentage));
        printSeparator();

        printRow("Max plots passing filter (1 challenge)",
                num(max_plots_passing_filter_per_challenge, 0));
        printRow("Overall filter pass rate",
                num(plots_passed_perc * 100.0, 4) + std::string(" %"));
        //printRow("Approx. 1 out of", num(one_out_of, 2));
        printSeparator('=');
        std::cout << std::endl;

        // --------------------------------------------------
        // DISK I/O SECTION
        // --------------------------------------------------
        printSectionHeader("Disk I/O Details");

        printRow("Total plots passed filter",
                num(total_plots_passed_filter, 0));
        printRow("Total disk seeks", num(total_seeks, 0));
        printRow("Total data read", bytes_sensible(static_cast<double>(total_data_read_bytes)));
        printSeparator();

        printRow("Total disk seek time", ms(diskSeekTimeMs));
        printRow("Total disk read time", ms(diskReadTimeMs));
        printRow("Total disk time (all challenges)", ms(total_time_ms));
        printRow("HDD load @ 1 challenge / 9.375s",
                pct(disk_load_percentage));
        printSeparator('=');
        std::cout << std::endl;

        // --------------------------------------------------
        // HARVESTING COMPUTE SECTION
        // --------------------------------------------------
        printSectionHeader("Harvesting Compute Details");
        printRow("Total simulation runs before cap",
                num(total_challenges_before_compute_cap, 0));
        printSeparator();
        printRow("Farm size (plots)", num(num_plots, 0));
        printRow("Farm netspace", tb(static_cast<double>(diskTB)));
        printSeparator();
        printRow("Total harvesting compute time",
                ms(total_harvesting_compute_time_ms));
        printRow("Average compute time / challenge",
                ms(avg_compute_time_per_challenge_ms));
        printRow("Max compute time (single challenge)",
                ms(max_compute_ms_per_challenge));
        printSeparator();

        printRow("Avg CPU harvesting load @ 9.375s",
                pct(cpu_harvesting_load_percentage));
        printRow("Max CPU harvesting load @ 9.375s",
                pct(max_compute_load_percentage));
        printSeparator('=');
        std::cout << std::endl;
    }

private:
    ProofParams proof_params_;
};
