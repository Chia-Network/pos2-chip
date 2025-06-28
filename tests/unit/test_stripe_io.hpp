// filepath: tests/unit/test_stripe_io.hpp
#include "plot/MemoryGrid.hpp"
#include <cstdio>
#include <vector>
#include <string>
#include <cstddef>

TEST_SUITE_BEGIN("stripe-io");

TEST_CASE("push and pull stripes") {
    const size_t N = 2;
    const size_t blockBytes = 16;
    const std::string filename = "stripe_io_test_h.bin";
    std::remove(filename.c_str());

    MemoryGrid mg(N, blockBytes);
    DiskGrid dg(N, blockBytes, filename);
    StripeIO sio(mg, dg);

    std::vector<std::byte> src;
    for (size_t i = 0; i < N * N * blockBytes * 2; ++i) {
        src.push_back(static_cast<std::byte>(i + 1));
    }

    // output each src row
    /*std::cout << "Source data: " << std::endl;
    for (size_t i = 0; i < N; ++i) {
        std::cout << "Row " << i << ": ";
        for (size_t j = 0; j < N * blockBytes * 2; ++j) {
            std::cout << std::to_integer<int>(src[i * N * blockBytes * 2 + j]) << " ";
        }
        std::cout << std::endl;
    }*/
    
    size_t endBytes[]   = {blockBytes*2, blockBytes*2};

    sio.pushStripe(true, 0, src.data(), endBytes, 0);
    {
        std::vector<std::byte> dst(endBytes[0] + endBytes[1]);
        sio.pullStripe(true, 0, dst.data(),  endBytes, 0);
        if (false) { // for debugging
            std::cout << "Stripe 0 pulled: " << std::endl;
            for (size_t i = 0; i < N * blockBytes * 2; ++i) {
                std::cout << std::to_integer<int>(dst[i]) << " ";
            }
            std::cout << std::endl;
        }

        std::vector<std::byte> expected(N * blockBytes * 2);
        for (size_t i = 0; i < N * blockBytes * 2; ++i) {
            expected[i] = static_cast<std::byte>(i + 1);
        }

        if (false) { // for debugging
            std::cout << "Expected: " << std::endl;
            for (size_t i = 0; i < N * blockBytes * 2; ++i) {
                std::cout << std::to_integer<int>(expected[i]) << " ";
            }
            std::cout << std::endl;
        }
        CHECK(dst == expected);
    }
    sio.pushStripe(false, N-1, src.data(), endBytes, 0);
    {
        std::vector<std::byte> dst(endBytes[0] + endBytes[1]);
        sio.pullStripe(false, N-1, dst.data(),  endBytes, 0);
        if (false) { // for debugging
            std::cout << "Stripe " << N-1 << " pulled: " << std::endl;
            for (size_t i = 0; i < N * blockBytes * 2; ++i) {
                std::cout << std::to_integer<int>(dst[i]) << " ";
            }
            std::cout << std::endl;
        }
        std::vector<std::byte> expected(N * blockBytes * 2);
        for (size_t i = 0; i < N * blockBytes * 2; ++i) {
            expected[i] = static_cast<std::byte>(i + 1);
        }
        if (false) { // for debugging
            std::cout << "Expected: " << std::endl;
            for (size_t i = 0; i < N * blockBytes * 2; ++i) {
                std::cout << std::to_integer<int>(expected[i]) << " ";
            }
            std::cout << std::endl;
        }
        CHECK(dst == expected);
    }
}

TEST_CASE("push and pull stripes vectors ram only") {
    std::vector<uint64_t> src = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    const int N = 4;
    MemoryGrid mg(N, sizeof(uint64_t) * src.size());
    const std::string filename = "stripe_io_test_h.bin";
    std::remove(filename.c_str());
    DiskGrid dg(N, 0, "n/a"); // no need for disk
    StripeIO sio(mg, dg);

    std::vector<int> src_splits = { 3, 6, 9, 12 };
    std::vector<size_t> src_bytes = { sizeof(uint64_t) * src_splits[0], 
                                         sizeof(uint64_t) * (src_splits[1] - src_splits[0]),
                                         sizeof(uint64_t) * (src_splits[2] - src_splits[1]),
                                         sizeof(uint64_t) * (src_splits[3] - src_splits[2]) };
    sio.pushStripe(true, 0, src.data(), src_bytes.data(), 0);
    {
        std::vector<uint64_t> dst(src.size());
        std::vector<size_t> dst_bytes = { sizeof(uint64_t) * src_splits[0], 
                                          sizeof(uint64_t) * (src_splits[1] - src_splits[0]),
                                          sizeof(uint64_t) * (src_splits[2] - src_splits[1]),
                                          sizeof(uint64_t) * (src_splits[3] - src_splits[2]) };
        sio.pullStripe(true, 0, dst.data(), dst_bytes.data(), 0);
        CHECK(dst == src);
    }
}

TEST_SUITE_END();
