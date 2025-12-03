// Compile: g++ -O3 -march=native -maes -std=c++17 -pthread -o aes_bench main.cpp soft_aes.cpp
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <thread>
#include <algorithm>
#include "pos/aes/AesHash.hpp"

class HashBench {
public:
	static void run(uint64_t total_hashes, unsigned int num_threads) {
		std::vector<uint32_t> out;
		out.resize(total_hashes);

		// prepare 32-byte plot id (AES key material). zero by default.
		uint8_t plot_id[32];
		std::memset(plot_id, 0, sizeof(plot_id));

		AesHash hasher(plot_id);

		#ifdef HAVE_AES
		{
			std::cout << "Using hardware AES\n";
			std::vector<std::thread> threads;
			threads.reserve(num_threads);
			uint64_t base = 0;
			uint64_t chunk = total_hashes / num_threads;
			auto t0 = std::chrono::high_resolution_clock::now();
			for (unsigned int ti = 0; ti < num_threads; ++ti) {
				uint64_t start = base + ti * chunk;
				uint64_t end = (ti + 1 == num_threads) ? total_hashes : (start + chunk);
				threads.emplace_back([start, end, &out, &hasher]() {
					for (uint64_t i = start; i < end; ++i) {
						out[i] = hasher.hash_x<false>(static_cast<uint32_t>(i));
					}
				});
			}
			for (auto &th : threads) th.join();

			auto t1 = std::chrono::high_resolution_clock::now();

			// timing / throughput
			std::chrono::duration<double> elapsed_s = t1 - t0;
			double ms = elapsed_s.count() * 1000.0;
			double hashes_per_ms = ms > 0.0 ? (double)total_hashes / ms : 0.0;
			double bytes_processed = (double)total_hashes * sizeof(uint32_t); // 4 bytes per hash output
			double gb_per_s = elapsed_s.count() > 0.0 ? (bytes_processed / elapsed_s.count()) / 1e9 : 0.0;

			std::cout << std::fixed << std::setprecision(3);
			std::cout << "Threads: " << num_threads << '\n';
			std::cout << "Elapsed: " << ms << " ms (" << elapsed_s.count() << " s)\n";
			std::cout << "Throughput: " << hashes_per_ms << " hashes/ms\n";
			std::cout << "Bandwidth: " << gb_per_s << " GB/s\n";
		}
		#endif
		{
			std::cout << "Using software AES\n";
			std::vector<std::thread> threads;
			threads.reserve(num_threads);
			uint64_t base = 0;
			uint64_t chunk = total_hashes / num_threads;
			auto t0 = std::chrono::high_resolution_clock::now();
			for (unsigned int ti = 0; ti < num_threads; ++ti) {
				uint64_t start = base + ti * chunk;
				uint64_t end = (ti + 1 == num_threads) ? total_hashes : (start + chunk);
				threads.emplace_back([start, end, &out, &hasher]() {
					for (uint64_t i = start; i < end; ++i) {
						out[i] = hasher.hash_x<true>(static_cast<uint32_t>(i));
					}
				});
			}
			for (auto &th : threads) th.join();
			auto t1 = std::chrono::high_resolution_clock::now();
			// timing / throughput
			std::chrono::duration<double> elapsed_s = t1 - t0;
			double ms = elapsed_s.count() * 1000.0;
			double hashes_per_ms = ms > 0.0 ? (double)total_hashes / ms : 0.0;
			double bytes_processed = (double)total_hashes * sizeof(uint32_t); // 4 bytes per hash output
			double gb_per_s = elapsed_s.count() > 0.0 ? (bytes_processed / elapsed_s.count()) / 1e9 : 0.0;
			std::cout << std::fixed << std::setprecision(3);
			std::cout << "Threads: " << num_threads << '\n';
			std::cout << "Elapsed: " << ms << " ms (" << elapsed_s.count() << " s)\n";
			std::cout << "Throughput: " << hashes_per_ms << " hashes/ms\n";
			std::cout << "Bandwidth: " << gb_per_s << " GB/s\n";
		}
	}
};