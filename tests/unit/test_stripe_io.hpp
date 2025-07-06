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

    sio.pushStripe(StripeIO::Direction::HORIZONTAL, 0, src.data(), endBytes, 0);
    {
        std::vector<std::byte> dst(endBytes[0] + endBytes[1]);
        sio.pullStripe(StripeIO::Direction::HORIZONTAL, 0, dst.data(),  endBytes, 0);
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
    sio.pushStripe(StripeIO::Direction::VERTICAL, N-1, src.data(), endBytes, 0);
    {
        std::vector<std::byte> dst(endBytes[0] + endBytes[1]);
        sio.pullStripe(StripeIO::Direction::VERTICAL, N-1, dst.data(),  endBytes, 0);
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
    sio.pushStripe(StripeIO::Direction::HORIZONTAL, 0, src.data(), src_bytes.data(), 0);
    {
        std::vector<uint64_t> dst(src.size());
        std::vector<size_t> dst_bytes = { sizeof(uint64_t) * src_splits[0], 
                                          sizeof(uint64_t) * (src_splits[1] - src_splits[0]),
                                          sizeof(uint64_t) * (src_splits[2] - src_splits[1]),
                                          sizeof(uint64_t) * (src_splits[3] - src_splits[2]) };
        sio.pullStripe(StripeIO::Direction::HORIZONTAL, 0, dst.data(), dst_bytes.data(), 0);
        CHECK(dst == src);
    }
}

TEST_CASE("push stripe into sections, pull into section") {
    std::vector<uint64_t> src_0 = {0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3};
    std::vector<uint64_t> src_1 = {0, 0, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3};
    std::vector<uint64_t> src_2 = {0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 3};
    std::vector<uint64_t> src_3 = {0, 0, 0, 0, 1, 2, 2, 2, 2, 3, 3, 3};
    const int N = 4;
    MemoryGrid mg(N, sizeof(uint64_t) * src_0.size());
    const std::string filename = "stripe_io_test_h.bin";
    std::remove(filename.c_str());
    DiskGrid dg(N, 0, "n/a"); // no need for disk
    StripeIO sio(mg, dg);

    std::vector<int> src_0_counts = { 3, 3, 3, 3 };
    std::vector<int> src_1_counts = { 2, 4, 3, 3 };
    std::vector<int> src_2_counts = { 3, 4, 2, 3 };
    std::vector<int> src_3_counts = { 4, 1, 4, 3 };

    std::vector<size_t> src_bytes(4);
    for (size_t i = 0; i < 4; ++i) {
        src_bytes[i] = sizeof(uint64_t) * src_0_counts[i];
    }
    sio.pushStripe(StripeIO::Direction::HORIZONTAL, 0, src_0.data(), src_bytes.data(), 0);

    for (size_t i = 0; i < 4; ++i) {
        src_bytes[i] = sizeof(uint64_t) * src_1_counts[i];
    }
    sio.pushStripe(StripeIO::Direction::HORIZONTAL, 1, src_1.data(), src_bytes.data(), 0);

    for (size_t i = 0; i < 4; ++i) {
        src_bytes[i] = sizeof(uint64_t) * src_2_counts[i];
    }
    sio.pushStripe(StripeIO::Direction::HORIZONTAL, 2, src_2.data(), src_bytes.data(), 0);
    for (size_t i = 0; i < 4; ++i) {
        src_bytes[i] = sizeof(uint64_t) * src_3_counts[i];
    }
    sio.pushStripe(StripeIO::Direction::HORIZONTAL, 3, src_3.data(), src_bytes.data(), 0);


    for (int section = 0; section < 4; ++section) {
        
        std::vector<int> dst_counts = { src_0_counts[section], 
                                             src_1_counts[section],
                                             src_2_counts[section],
                                             src_3_counts[section] };
        size_t sum_counts = dst_counts[0] + dst_counts[1] + dst_counts[2] + dst_counts[3];
        std::vector<uint64_t> dst(sum_counts);
        std::vector<size_t> dst_bytes(4);
        for (size_t i = 0; i < 4; ++i) {
            dst_bytes[i] = sizeof(uint64_t) * dst_counts[i];
        }
        sio.pullStripe(StripeIO::Direction::VERTICAL, section, dst.data(), dst_bytes.data(), 0);
        // all dst data should be value 0
        for (size_t i = 0; i < sum_counts; ++i) {
            CHECK(dst[i] == section);
        }
    }
}

TEST_SUITE_END();
