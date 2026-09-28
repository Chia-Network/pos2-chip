#include "test_util.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

extern "C" {
#include "pos/sha/sha256.h"
}

namespace {

using Digest = std::array<uint8_t, SHA256_DIGEST_LENGTH>;

struct HashVector {
    std::vector<uint8_t> message;
    Digest digest;
};

struct MonteVectors {
    Digest seed;
    std::vector<Digest> checkpoints;
};

std::filesystem::path vector_path(char const* name)
{
    return std::filesystem::path(SHA256_TEST_DATA_DIR) / name;
}

inline int hex_digit(char digit)
{
    if (digit >= '0' && digit <= '9') {
        return digit - '0';
    }
    if (digit >= 'a' && digit <= 'f') {
        return digit - 'a' + 10;
    }
    if (digit >= 'A' && digit <= 'F') {
        return digit - 'A' + 10;
    }
    throw std::runtime_error("Invalid hex digit in SHA-256 test vectors");
}

std::vector<uint8_t> from_hex(std::string_view hex)
{
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Odd number of hex digits in SHA-256 test vectors");
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(uint8_t((hex_digit(hex[i]) << 4) | hex_digit(hex[i + 1])));
    }
    return bytes;
}

Digest digest_from_hex(std::string_view hex)
{
    auto const bytes = from_hex(hex);
    if (bytes.size() != SHA256_DIGEST_LENGTH) {
        throw std::runtime_error("Invalid digest length in SHA-256 test vectors");
    }
    Digest digest;
    std::copy(bytes.begin(), bytes.end(), digest.begin());
    return digest;
}

size_t bit_count_from_text(std::string_view text)
{
    size_t parsed = 0;
    size_t const bits = std::stoull(std::string(text), &parsed);
    if (parsed != text.size() || bits % 8 != 0) {
        throw std::runtime_error("Invalid bit length in SHA-256 test vectors");
    }
    return bits;
}

template<typename HandleField>
void read_fields(std::filesystem::path const& path, HandleField handle_field)
{
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("Could not open " + path.string());
    }

    bool saw_header = false;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty() || line[0] == '#') {
            continue;
        }
        if (line == "[L = 32]") {
            saw_header = true;
            continue;
        }
        size_t const equals = line.find(" = ");
        if (equals == std::string::npos) {
            throw std::runtime_error("Invalid line in " + path.string());
        }
        handle_field(std::string_view(line).substr(0, equals),
            std::string_view(line).substr(equals + 3));
    }
    if (!input.eof() || !saw_header) {
        throw std::runtime_error("Could not read SHA-256 vectors from " + path.string());
    }
}

std::vector<HashVector> read_hash_vectors(char const* name)
{
    std::vector<HashVector> vectors;
    std::optional<size_t> bits;
    std::optional<std::vector<uint8_t>> message;

    read_fields(vector_path(name), [&](std::string_view field, std::string_view value) {
        if (field == "Len") {
            if (bits || message) {
                throw std::runtime_error("Incomplete SHA-256 vector");
            }
            bits = bit_count_from_text(value);
        }
        else if (field == "Msg") {
            if (!bits || message) {
                throw std::runtime_error("Unexpected SHA-256 message");
            }
            message = from_hex(value);
            // NIST writes Msg = 00 for a zero-length message.
            if (*bits == 0 && *message == std::vector<uint8_t> { 0 }) {
                message->clear();
            }
            if (message->size() != *bits / 8) {
                throw std::runtime_error("SHA-256 message length does not match Len");
            }
        }
        else if (field == "MD") {
            if (!bits || !message) {
                throw std::runtime_error("Unexpected SHA-256 digest");
            }
            vectors.push_back({ std::move(*message), digest_from_hex(value) });
            bits.reset();
            message.reset();
        }
        else {
            throw std::runtime_error("Unexpected field in SHA-256 vectors");
        }
    });
    if (bits || message || vectors.empty()) {
        throw std::runtime_error("Incomplete SHA-256 vector file");
    }
    return vectors;
}

MonteVectors read_monte_vectors()
{
    MonteVectors vectors {};
    bool has_seed = false;
    std::optional<size_t> count;

    read_fields(vector_path("SHA256Monte.rsp"),
        [&](std::string_view field, std::string_view value) {
            if (field == "Seed") {
                if (has_seed) {
                    throw std::runtime_error("Duplicate SHA-256 Monte Carlo seed");
                }
                vectors.seed = digest_from_hex(value);
                has_seed = true;
            }
            else if (field == "COUNT") {
                if (!has_seed || count) {
                    throw std::runtime_error("Unexpected SHA-256 Monte Carlo count");
                }
                size_t parsed = 0;
                size_t const index = std::stoull(std::string(value), &parsed);
                if (parsed != value.size() || index != vectors.checkpoints.size()) {
                    throw std::runtime_error("Invalid SHA-256 Monte Carlo count");
                }
                count = index;
            }
            else if (field == "MD") {
                if (!count) {
                    throw std::runtime_error("Unexpected SHA-256 Monte Carlo digest");
                }
                vectors.checkpoints.push_back(digest_from_hex(value));
                count.reset();
            }
            else {
                throw std::runtime_error("Unexpected SHA-256 Monte Carlo field");
            }
        });
    if (!has_seed || count || vectors.checkpoints.size() != 100) {
        throw std::runtime_error("Incomplete SHA-256 Monte Carlo vectors");
    }
    return vectors;
}

Digest hash_bytes(std::span<uint8_t const> message)
{
    sha256 state {};
    sha256_init(&state);
    uint8_t const empty = 0;
    void const* data = message.empty() ? &empty : message.data();
    sha256_update(&state, data, static_cast<unsigned long>(message.size()));
    Digest digest;
    sha256_sum(&state, digest.data());
    return digest;
}

Digest hash_in_chunks(std::span<uint8_t const> message, size_t chunk_size)
{
    sha256 state {};
    sha256_init(&state);
    uint8_t const empty = 0;
    sha256_update(&state, &empty, 0);
    for (size_t offset = 0; offset < message.size(); offset += chunk_size) {
        size_t const size = std::min(chunk_size, message.size() - offset);
        sha256_update(&state, message.data() + offset, static_cast<unsigned long>(size));
    }
    Digest digest;
    sha256_sum(&state, digest.data());
    return digest;
}

void check_hash_vectors(char const* name, size_t expected_count)
{
    auto const vectors = read_hash_vectors(name);
    REQUIRE(vectors.size() == expected_count);
    std::string const filename(name);
    for (size_t i = 0; i < vectors.size(); ++i) {
        CAPTURE(filename);
        CAPTURE(i);
        auto const& vector = vectors[i];
        CHECK(hash_bytes(vector.message) == vector.digest);
        for (size_t chunk_size: { 1u, 7u, 55u, 56u, 63u, 64u, 65u, 127u }) {
            CAPTURE(chunk_size);
            CHECK(hash_in_chunks(vector.message, chunk_size) == vector.digest);
        }
    }
}

} // namespace

TEST_SUITE_BEGIN("sha256");

TEST_CASE("sha256-short-messages")
{
    // Check all NIST short messages, including the empty message and SHA-256 block boundaries.
    check_hash_vectors("SHA256ShortMsg.rsp", 65);
}

TEST_CASE("sha256-long-messages")
{
    // Check NIST long messages both at once and across many update boundaries.
    check_hash_vectors("SHA256LongMsg.rsp", 64);
}

TEST_CASE("sha256-monte-carlo")
{
    // Recreate NIST's 100,000-hash chain and check each of its 100 saved digests.
    MonteVectors const vectors = read_monte_vectors();
    Digest seed = vectors.seed;

    for (size_t count = 0; count < vectors.checkpoints.size(); ++count) {
        CAPTURE(count);
        std::array<uint8_t, SHA256_DIGEST_LENGTH * 3> message;
        for (size_t i = 0; i < 3; ++i) {
            std::copy(seed.begin(), seed.end(), message.begin() + i * seed.size());
        }
        Digest digest {};
        for (size_t i = 0; i < 1000; ++i) {
            digest = hash_bytes(message);
            std::copy(message.begin() + SHA256_DIGEST_LENGTH, message.end(), message.begin());
            std::copy(digest.begin(), digest.end(), message.begin() + SHA256_DIGEST_LENGTH * 2);
        }
        CHECK(digest == vectors.checkpoints[count]);
        seed = digest;
    }
}

TEST_SUITE_END();
