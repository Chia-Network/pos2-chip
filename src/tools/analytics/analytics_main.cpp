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
            if (HAVE_AES)
            {
                std::cout << "AES Hardware Hash Benchmark\n";
            }
            else
            {
                std::cout << "AES Hardware not supported on this platform.\n";
                std::cout << "Skipping hardware AES benchmark.\n";
                continue;
            }
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
