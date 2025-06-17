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

    static std::string bytesToHex(const std::array<uint8_t, 32>& bytes) {
        std::ostringstream oss;
        for (const auto& byte : bytes) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return oss.str();
    }

    static std::string toHex(uint32_t value, size_t width = 8) {
        std::ostringstream oss;
        oss << std::hex << std::setw(width) << std::setfill('0') << value;
        return oss.str();
    }

    static uint32_t fromHex(const std::string& hex) {
        return static_cast<uint32_t>(std::strtoul(hex.c_str(), nullptr, 16));
    }
};