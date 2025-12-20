#include "pos/aes/AesHash.hpp"
#include "test_util.h"
#include <array>
#include <iostream>
#include <vector>

// initial tests compare soft/hard AES results for equality.
// regression test emits known-good results from software AES, that systems that are then tested for
// equality across all platforms.

#if HAVE_AES
TEST_CASE("AesHash g_x soft vs hardware")
{
    std::array<uint8_t, 32> plot_id {};
    for (size_t i = 0; i < plot_id.size(); ++i)
        plot_id[i] = static_cast<uint8_t>(i * 7 + 3);
    int k = 20;
    AesHash hasher(plot_id.data(), k);

    for (uint32_t x: { 0u, 1u, 0x12345678u, 0xFFFFFFFFu, 0xABCDEF12u }) {
        REQUIRE(hasher.g_x<false>(x) == hasher.g_x<true>(x));
    }
}
#endif

#if HAVE_AES
TEST_CASE("AesHash matching_target soft vs hardware")
{
    std::array<uint8_t, 32> plot_id {};
    for (size_t i = 0; i < plot_id.size(); ++i)
        plot_id[i] = static_cast<uint8_t>(i);
    int k = 28;
    AesHash hasher(plot_id.data(), k);

    for (int extra_bits: { 0, 1 }) {
        for (uint64_t meta: { 0ULL, 0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL }) {
            REQUIRE(hasher.matching_target<false>(1, 0xDEADBEEF, meta, extra_bits)
                == hasher.matching_target<true>(1, 0xDEADBEEF, meta, extra_bits));
            REQUIRE(hasher.matching_target<false>(3, 0x0123ABCD, meta, extra_bits)
                == hasher.matching_target<true>(3, 0x0123ABCD, meta, extra_bits));
        }
    }
}
#endif

#if HAVE_AES
TEST_CASE("AesHash pairing soft vs hardware")
{
    std::array<uint8_t, 32> plot_id {};
    for (size_t i = 0; i < plot_id.size(); ++i)
        plot_id[i] = static_cast<uint8_t>(255 - i);
    int k = 16;
    AesHash hasher(plot_id.data(), k);

    auto check_equal = [](AesHash::Result128 a, AesHash::Result128 b) {
        REQUIRE(a.r[0] == b.r[0]);
        REQUIRE(a.r[1] == b.r[1]);
        REQUIRE(a.r[2] == b.r[2]);
        REQUIRE(a.r[3] == b.r[3]);
    };

    for (int extra_bits: { 0, 1 }) {
        auto r1 = hasher.pairing<false>(0x0123456789ABCDEFULL, 0x0FEDCBA987654321ULL, extra_bits);
        auto r2 = hasher.pairing<true>(0x0123456789ABCDEFULL, 0x0FEDCBA987654321ULL, extra_bits);
        check_equal(r1, r2);

        r1 = hasher.pairing<false>(0ULL, 0ULL, extra_bits);
        r2 = hasher.pairing<true>(0ULL, 0ULL, extra_bits);
        check_equal(r1, r2);

        r1 = hasher.pairing<false>(0xFFFFFFFFFFFFFFFFULL, 0xAAAAAAAAAAAAAAAAULL, extra_bits);
        r2 = hasher.pairing<true>(0xFFFFFFFFFFFFFFFFULL, 0xAAAAAAAAAAAAAAAAULL, extra_bits);
        check_equal(r1, r2);
    }
}
#endif

#if HAVE_AES
TEST_CASE("AesHash regression list soft")
{
    std::array<uint8_t, 32> plot_id {};
    for (size_t i = 0; i < plot_id.size(); ++i)
        plot_id[i] = static_cast<uint8_t>(i * 11 + 5);
    int k = 24;
    AesHash hasher(plot_id.data(), k);
    auto hw = hasher.regression_results<false>();
    auto sw = hasher.regression_results<true>();

    REQUIRE(hw.size() == sw.size());
    for (size_t i = 0; i < hw.size(); ++i) {
        REQUIRE(hw[i] == sw[i]);
    }
}
#endif

// Emits regression list in software, checks if matches HW if available.
// We use one platform to emit the list, then paste it into the test below
// This way we can ensure the regression list is stable across changes and platforms in soft/hw AES.
TEST_CASE("AesHash emit regression list to CLI")
{
    std::array<uint8_t, 32> plot_id {};
    for (size_t i = 0; i < plot_id.size(); ++i)
        plot_id[i] = static_cast<uint8_t>(i * 11 + 5);
    int k = 24;
    AesHash hasher(plot_id.data(), k);

    auto sw = hasher.regression_results<true>();

#if HAVE_AES
    auto hw = hasher.regression_results<false>();
    REQUIRE(hw == sw);
#endif

    std::cout << "#define K_AES_REGRESSION_DEFINED 1\n";
    std::cout << "/* AesHash regression list: k=" << k << ", plot_id[i] = i*11+5 */\n";
    std::cout << "constexpr uint32_t kAesRegression[" << hw.size() << "] = {";
    for (size_t i = 0; i < hw.size(); ++i) {
        std::cout << hw[i];
        if (i + 1 < hw.size())
            std::cout << ", ";
        if ((i + 1) % 8 == 0)
            std::cout << "\n";
    }
    std::cout << "};\n";
}

// Paste the emitted list here from the emit regression test:
constexpr uint32_t kAesRegression[41] = { 10343082,
    7326751,
    6927852,
    6968908,
    11512430,
    409340410,
    505582378,
    1721018924,
    1480140290,
    1396524303,
    3587190239,
    707841484,
    1331347346,
    1241879891,
    2167726916,
    3067597756,
    4168169983,
    1091708360,
    2175255815,
    2816383768,
    1674980125,
    2543702698,
    4091426003,
    533075521,
    3859141200,
    31044209,
    4179457918,
    1030061401,
    3699883668,
    210961197,
    1476679550,
    3006735961,
    939518466,
    1218571309,
    716491999,
    1747602127,
    1064749683,
    1584340891,
    3071410499,
    4118871486,
    1400922689 };
TEST_CASE("AesHash fixed regression list matches")
{
    std::array<uint8_t, 32> plot_id {};
    for (size_t i = 0; i < plot_id.size(); ++i)
        plot_id[i] = static_cast<uint8_t>(i * 11 + 5);
    int k = 24;
    AesHash hasher(plot_id.data(), k);

    auto sw = hasher.regression_results<true>();

    size_t n = sizeof(kAesRegression) / sizeof(kAesRegression[0]);
    REQUIRE(sw.size() == n);
    for (size_t i = 0; i < n; ++i) {
        REQUIRE(sw[i] == kAesRegression[i]);
    }
}
