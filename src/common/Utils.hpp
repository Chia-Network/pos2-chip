#pragma once

#include <array>
#include <cassert>
#include <cstdint>
#include <iomanip>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// This function acts like static_cast but asserts that the value is unchanged
// it only affects debug builds
template <typename To, typename From>
To numeric_cast(From f)
{
    if constexpr (std::is_signed_v<From> && !std::is_signed_v<To>) {
        assert(f >= 0);
        assert(f <= std::numeric_limits<From>::max());
    }
    To const ret = static_cast<To>(f);
    if constexpr (!std::is_signed_v<From> && std::is_signed_v<To>) {
        assert(ret >= 0);
        assert(ret <= std::numeric_limits<To>::max());
    }
    assert(static_cast<From>(ret) == f);
    return ret;
}

class Utils {
public:
    static std::array<uint8_t, 32> hexToBytes(std::string const& hex)
    {
        std::array<uint8_t, 32> bytes {};
        for (size_t i = 0; i < bytes.size(); ++i) {
            auto byte_str = hex.substr(2 * i, 2);
            bytes[i] = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
        }
        return bytes;
    }

    static std::string bytesToHex(std::span<uint8_t const> const bytes)
    {
        std::ostringstream oss;
        for (auto const& byte: bytes) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return oss.str();
    }

    static std::string toHex(uint32_t value, int width = 8)
    {
        std::ostringstream oss;
        oss << std::hex << std::setw(width) << std::setfill('0') << value;
        return oss.str();
    }

    static uint32_t fromHex(std::string const& hex)
    {
        return static_cast<uint32_t>(std::strtoul(hex.c_str(), nullptr, 16));
    }

    static std::string kValuesToCompressedHex(int const k, std::span<uint32_t const> const proof)
    {
        // pack k-bit values into a bitstream
        size_t const total_bits = proof.size() * static_cast<size_t>(k);
        std::vector<bool> bits;
        bits.reserve(total_bits);
        for (auto v: proof) {
            for (int i = k - 1; i >= 0; --i) {
                bits.push_back((v >> i) & 1);
            }
        }
        // pad to full nibble
        while (bits.size() % 4)
            bits.push_back(0);

        static char const hex_chars[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(bits.size() / 4);
        for (size_t i = 0; i < bits.size(); i += 4) {
            uint8_t nibble = numeric_cast<uint8_t>(
                (bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3]);
            hex.push_back(hex_chars[nibble]);
        }
        return hex;
    }

    static std::vector<uint32_t> compressedHexToKValues(int const k, std::string const& hex)
    {
        // convert hex back to bitstream
        size_t total_bits = hex.size() * 4;
        if (total_bits < static_cast<size_t>(k) || (total_bits % k) != 0) {
            throw std::invalid_argument("Hex length not compatible with k");
        }
        std::vector<bool> bits;
        bits.reserve(total_bits);
        for (char c: hex) {
            int val = 0;
            if (c >= '0' && c <= '9')
                val = c - '0';
            else if (c >= 'a' && c <= 'f')
                val = 10 + (c - 'a');
            else if (c >= 'A' && c <= 'F')
                val = 10 + (c - 'A');
            else
                throw std::invalid_argument("Invalid hex character");
            for (int b = 3; b >= 0; --b) {
                bits.push_back((val >> b) & 1);
            }
        }
        // reconstruct proof
        size_t count = total_bits / k;
        std::vector<uint32_t> proof;
        proof.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            uint32_t v = 0;
            for (int j = 0; j < k; ++j) {
                v = (v << 1) | bits[i * k + j];
            }
            proof.push_back(v);
        }
        return proof;
    }
};
