#include "common/Utils.hpp"
#include "pos/FeistelCipher.hpp"
#include "pos/sha/sha256.hpp"
#include "test_util.h"

#include "feistel_test_cases.hpp"

TEST_CASE("FeistelCipher fixed encryption and decryption vectors")
{
    std::array<std::array<uint8_t, 32>, kFeistelPlotIdHex.size()> plot_ids;
    for (size_t i = 0; i < plot_ids.size(); ++i) {
        plot_ids[i] = Utils::hexToBytes(kFeistelPlotIdHex[i]);
    }

    for (size_t i = 0; i < kFeistelVectors.size(); ++i) {
        auto const& vector = kFeistelVectors[i];
        CAPTURE(i);
        CAPTURE(vector.plot_id);
        CAPTURE(vector.k);
        CAPTURE(vector.plaintext);

        FeistelCipher cipher(plot_ids[vector.plot_id].data(), vector.k);
        uint64_t const ciphertext = cipher.encrypt(vector.plaintext);
        CHECK(ciphertext == vector.ciphertext);
        CHECK(cipher.decrypt(vector.ciphertext) == vector.plaintext);
        CHECK(cipher.decrypt(ciphertext) == vector.plaintext);
    }
}
