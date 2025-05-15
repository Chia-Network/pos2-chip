#pragma once

#include <cstdint>
#include <array>
#include <string>

class Utils
{
    public:
    static std::array<uint8_t, 32> hexToBytes(const std::string& hex) {
        std::array<uint8_t, 32> bytes{};
        for (size_t i = 0; i < bytes.size(); ++i) {
            auto byte_str = hex.substr(2 * i, 2);
            bytes[i] = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
        }
        return bytes;
    }
};