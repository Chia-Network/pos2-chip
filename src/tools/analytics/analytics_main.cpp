#include "plot/PlotFile.hpp"
#include "prove/Prover.hpp"
#include "pos/ProofValidator.hpp"
#include "common/Utils.hpp"
#include "DiskBench.hpp"
#include "pos/aes/AesHash.hpp"
#include "pos/BlakeHash.hpp"
#include "pos/ChachaHash.hpp"
#include "common/thread.hpp"

void printUsage()
{
    std::cout << "Usage:\n"
              << "  analytics simdiskusage [plotIdFilter=256] [diskTB=20] [diskSeekMs=10] [diskReadMBs=70]\n"
              << "  analytics hashbench [N (for 2^N)] [rounds=16] [threads=max]\n";
}

int hashBench(int N, int rounds, int num_threads)
{
    uint64_t count = 1ULL << N;
    std::array<uint8_t, 32> plot_id = {0};
    // don't spawn more threads than items
    if (count < numeric_cast<uint64_t>(num_threads))
        num_threads = numeric_cast<int>(count);

    // compute hashes
    std::vector<uint32_t> out;
    out.resize(count);

    AesHash hasher(plot_id.data(), 28);
    ChachaHash chacha_hasher(plot_id.data());

    uint64_t chacha_count = count / 16; // chacha does groups of 16.

    int total_tests = 4;
    for (int test = 0; test < total_tests; test++)
    {
        std::cout << "Doing test " << test << "/" << total_tests << "...\n";
        // show our input parameters
        if (test == 0)
        {
            #if (HAVE_AES)
            std::cout << "AES Hardware Hash Benchmark\n";
            #else
            std::cout << "AES Hardware not supported on this platform.\n";
            std::cout << "Skipping hardware AES benchmark.\n";
            continue;
            #endif
        }
        else if (test == 1)
        {
            std::cout << "AES Software Hash Benchmark\n";
        }
        else if (test == 2)
        {
            std::cout << "Blake Hash Benchmark\n";
        }
        else if (test == 3)
        {
            std::cout << "Chacha Hash Benchmark\n";
        }
        std::cout << "------------------------------------\n";
        std::cout << "   Total hashes to compute : " << count << " (2^" << N << ")\n";
        std::cout << "   Threads                 : " << num_threads << "\n";
        if (test == 0 || test == 1) {
            std::cout << "   AES Rounds              : " << rounds << "\n";
        }
        std::cout << "------------------------------------\n";
        std::vector<thread> threads;
        threads.reserve(num_threads);
        uint64_t base = 0;
        uint64_t chunk = count / num_threads;
        if (test == 3) {
            // chacha does groups of 16, so change the count.
            chunk = chacha_count / num_threads;
        }
        auto t0 = std::chrono::high_resolution_clock::now();
        for (int ti = 0; ti < num_threads; ++ti)
        {
            uint64_t start = base + ti * chunk;
            uint64_t end = (ti + 1 == num_threads) ? count : (start + chunk);
            if (test == 0)
            {
                threads.emplace_back([start, end, &out, &hasher, rounds]()
                                     {
                                         for (uint64_t i = start; i < end; ++i)
                                         {
                                             out[i] = hasher.hash_x<false>(static_cast<uint32_t>(i), rounds);
                                         } });
            }
            else if (test == 1)
            {
                threads.emplace_back([start, end, &out, &hasher, rounds]()
                                     {
                                         for (uint64_t i = start; i < end; ++i)
                                         {
                                             out[i] = hasher.hash_x<true>(static_cast<uint32_t>(i), rounds);
                                         } });
            }
            else if (test == 2)
            {
                threads.emplace_back([start, end, &out]()
                                     {
                                        uint32_t block_words[16] = {0};
                                         for (uint64_t i = start; i < end; ++i)
                                         {
                                            block_words[0] = static_cast<uint32_t>(i);
                                            out[i] = BlakeHash::hash_block_64(block_words).r[0];
                                         } });
            }
            else if (test == 3)
            {
                end = (start + chunk);
                threads.emplace_back([start, end, &out, &chacha_hasher]()
                                     {
                                         for (uint64_t i = start; i < end; ++i)
                                         {
                                            chacha_hasher.do_chacha16_range(static_cast<uint32_t>(i), &out[i]);
                                         } });
            }
        }

        // join via destructor by clearing the vector
        threads.clear();

        auto t1 = std::chrono::high_resolution_clock::now();

        // timing / throughput
        std::chrono::duration<double> elapsed_s = t1 - t0;
        double ms = elapsed_s.count() * 1000.0;
        double hashes_per_ms = ms > 0.0 ? (double)count / ms : 0.0;
        double bytes_processed = (double)count * sizeof(uint32_t); // 4 bytes per hash output
        double gb_per_s = elapsed_s.count() > 0.0 ? (bytes_processed / elapsed_s.count()) / 1e9 : 0.0;

        // show our results nicely
        std::cout << std::fixed << std::setprecision(3);
        std::cout << "   Elapsed.   : " << ms << " ms (" << elapsed_s.count() << " s)\n";
        std::cout << "   Throughput : " << hashes_per_ms << " hashes/ms\n";
        std::cout << "   Bandwidth  : " << gb_per_s << " GB/s\n";
        std::cout << "------------------------------------\n";
    }
    return 0;
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
        if (argc >= 3)
        {
            plotIdFilter = std::stoul(argv[2]);
        }
        if (argc >= 4)
        {
            plotsInGroup = std::stoul(argv[3]);
        }
        if (argc >= 5)
        {
            diskTB = std::stoul(argv[4]);
        }
        if (argc >= 6)
        {
            diskSeekMs = std::stod(argv[5]);
        }
        if (argc >= 7)
        {
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
            std::cerr << "Usage: " << argv[0] << " simpreallocateplotgrouping [plotFile] [numPlotsInGroup=64] [numTrials=10000]\n";
            return 1;
        }
        std::string plotFile = argv[2];
        size_t numPlotsInGroup = 64;
        int num_trials = 10000;
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

        std::vector<int> challenge_range_counts(num_challenge_ranges, 0);
        // go through plot and get all counts
        std::cout << "Reading all challenge ranges from plot file...\n";
        for (uint32_t challenge_range = 0; challenge_range < num_challenge_ranges; ++challenge_range) {
            if (challenge_range % 1000 == 0) {
                std::cout << "  Reading challenge range " << challenge_range << " / " << num_challenge_ranges << "\n";
            }
            Range range = params.get_chaining_set_range(challenge_range);
            std::vector<ProofFragment> fragments = plot_file.getProofFragmentsInRange(range);
            challenge_range_counts[challenge_range] = static_cast<int>(fragments.size());
        }

        // set random generator from 0 to num_challenge_ranges - 1
        std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<uint32_t> dist(0, num_challenge_ranges - 1);

        int min_challenge_range_count = 10000000;
        int max_challenge_range_count = 0;
        int total_fragments = 0;
        int min_total_fragments = 1000000000;
        int max_total_fragments = 0;
        long long sum_total_fragments = 0; // accumulate totals to compute average
        std::cout << "Simulating " << num_trials << " trials...\n";
        for (int trial = 0; trial < num_trials; ++trial) {
            total_fragments = 0;
            if (trial % 1000 == 0) {
                std::cout << "  Trial " << trial << " / " << num_trials << "\n";
            }
            for (size_t i = 0; i < numPlotsInGroup; ++i) {
                uint32_t challenge_range = dist(rng);
                /*Range range = params.get_chaining_set_range(challenge_range);
                std::vector<ProofFragment> fragments = plot_file.getProofFragmentsInRange(range);
                int num_fragments = static_cast<int>(fragments.size());*/
                int num_fragments = challenge_range_counts[challenge_range];
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
    else if (mode == "hashbench")
    {
        if (argc < 3 || argc > 5)
        {
            std::cerr << "Usage: " << argv[0] << " hashbench [N (for 2^N)] [rounds=16] [threads=max]\n";
            return 1;
        }
        int N = std::stoi(argv[2]);
        int rounds = 16;
        if (argc >= 4)
        {
            rounds = std::stoi(argv[3]);
        }
        int num_threads = std::thread::hardware_concurrency();
        if (argc >= 5)
        {
            std::string threads_arg = argv[4];
            if (threads_arg != "max")
            {
                num_threads = std::stoi(threads_arg);
            }
        }
        return hashBench(N, rounds, num_threads);
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
