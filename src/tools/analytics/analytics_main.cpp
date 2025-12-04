#include "plot/PlotFile.hpp"
#include "prove/Prover.hpp"
#include "pos/ProofValidator.hpp"
#include "common/Utils.hpp"
#include "DiskBench.hpp"

void printUsage()
{
    std::cout << "Usage:\n"
              << "  analytics simdiskusage [plotIdFilter=256] [diskTB=20] [diskSeekMs=10] [diskReadMBs=70]\n";
}

int main(int argc, char *argv[])
try
{
    std::cout << "ChiaPOS2 Analytics" << std::endl;

    if (argc < 2)
    {
        printUsage();
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "simdiskusage")
    {
        size_t plotIdFilter = 8;
        size_t plotsInGroup = 32;
        size_t diskTB = 20;
        double diskSeekMs = 10.0;
        double diskReadMBs = 250.0;
        if (argc < 2 || argc > 7)
        {
            std::cerr << "Usage: " << argv[0] << " simdiskusage [plotIdFilterBits=8] [plotsInGroup=32] [diskTB=20] [diskSeekMs=10] [diskReadMBs=250]\n";
            return 1;
        }
        if (argc >= 3) {
            plotIdFilter = std::stoul(argv[2]);
        }
        if (argc >= 4) {
            plotsInGroup = std::stoul(argv[3]);
        }
        if (argc >= 5) {
            diskTB = std::stoul(argv[4]);
        }
        if (argc >= 6) {
            diskSeekMs = std::stod(argv[5]);
        }
        if (argc >= 7) {
            diskReadMBs = std::stod(argv[6]);
        }
        ProofParams proof_params(Utils::hexToBytes("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF").data(), 28, 2);
        DiskBench diskbench(proof_params);
        diskbench.simulateChallengeDiskReads(plotIdFilter, plotsInGroup, diskTB, diskSeekMs, diskReadMBs);

        return 0;
    }
    else if (mode == "simpreallocateplotgrouping")
    {
        if (argc < 2 || argc > 5)
        {
            std::cerr << "Usage: " << argv[0] << " simpreallocateplotgrouping [plotFile] [numPlotsInGroup=64] [numTrials=1000]\n";
            return 1;
        }
        std::string plotFile = argv[2];
        size_t numPlotsInGroup = 64;
        int num_trials = 1000;
        if (argc >= 4) {
            numPlotsInGroup = std::stoul(argv[3]);
        }
        if (argc >= 5) {
            num_trials = std::stoi(argv[4]);
        }
        std::cout << "Analyzing plot file: " << plotFile << " for groupings of " << numPlotsInGroup << " plots over " << num_trials << " trials.\n";
        PlotFile plot_file(plotFile);
        ProofParams params = plot_file.getProofParams();
        // get number of challenge ranges in plot
        uint32_t num_challenge_ranges = params.get_num_chaining_sets();

        // set random generator from 0 to num_challenge_ranges - 1
        std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<uint32_t> dist(0, num_challenge_ranges - 1);

        int min_challenge_range_count = 10000000;
        int max_challenge_range_count = 0;
        int total_fragments = 0;
        int min_total_fragments = 1000000000;
        int max_total_fragments = 0;
        long long sum_total_fragments = 0; // accumulate totals to compute average
        for (int trial = 0; trial < num_trials; ++trial) {
            total_fragments = 0;
            std::cout << "Trial " << trial << ":\n";
            for (size_t i = 0; i < numPlotsInGroup; ++i) {
                uint32_t challenge_range = dist(rng);
                Range range = params.get_chaining_set_range(challenge_range);
                std::vector<ProofFragment> fragments = plot_file.getProofFragmentsInRange(range);
                int num_fragments = static_cast<int>(fragments.size());
                total_fragments = total_fragments + num_fragments;
                if (num_fragments < min_challenge_range_count) {
                    min_challenge_range_count = num_fragments;
                }
                if (num_fragments > max_challenge_range_count) {
                    max_challenge_range_count = num_fragments;
                }
                //std::cout << "Plot " << i << ": Challenge range " << challenge_range
                //        << " (" << range.start << " - " << range.end << ") has "
                //        << num_fragments << " fragments.\n";
            }
            if (total_fragments < min_total_fragments) {
                min_total_fragments = total_fragments;
            }
            if (total_fragments > max_total_fragments) {
                max_total_fragments = total_fragments;
            }
            sum_total_fragments += total_fragments;
        }
        std::cout << "Over " << num_trials << " trials of " << numPlotsInGroup << " plots each:\n";
        std::cout << "Min challenge range fragment count: " << min_challenge_range_count << "\n";
        std::cout << "Max challenge range fragment count: " << max_challenge_range_count << "\n";
        std::cout << "Min total fragments in group: " << min_total_fragments << "\n";
        std::cout << "Max total fragments in group: " << max_total_fragments << "\n";
        // average total fragments per group across trials
        double avg_total_fragments = num_trials > 0 ? static_cast<double>(sum_total_fragments) / static_cast<double>(num_trials) : 0.0;
        std::cout << "Average total fragments in group: " << avg_total_fragments << "\n";

        // percentage difference between max and average:
        double percent_diff = (static_cast<double>(max_total_fragments) - avg_total_fragments) / avg_total_fragments * 100.0;
        std::cout << "Percentage difference between max and average: " << percent_diff << "%\n";

        std::cout << "Groupings of " << numPlotsInGroup << " plots may require preallocation with padding of at least "
                  << (percent_diff) << "% above average.\n";


        

        return 0;
    }
    else
    {
        std::cerr << "Unknown mode: " << mode << std::endl;
        printUsage();
        return 1;
    }
}
catch (const std::exception &ex)
{
    std::cerr << "Failed with exception: " << ex.what() << std::endl;
    return 1;
}
