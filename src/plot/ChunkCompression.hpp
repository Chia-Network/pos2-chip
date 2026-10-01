#pragma once

#include "fse.h" // adjust include path as needed
#include "common/Utils.hpp"
#include "pos/ProofCore.hpp"
#include "common/BitReader.hpp"
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

// #define DEBUG_CHUNK_COMPRESSOR false

class ChunkCompressor {
public:
    static std::vector<uint8_t> compressProofFragments(
        std::span<ProofFragment const> const proof_fragments,
        uint64_t const start_proof_fragment_range,
        int const stub_bits)
    {
#ifdef DEBUG_CHUNK_COMPRESSOR
        {
            std::cout << "ChunkCompressor::compressProofFragments: start_proof_fragment_range = "
                      << start_proof_fragment_range
                      << ", number of proof fragments = " << proof_fragments.size()
                      << ", stub_bits = " << stub_bits << std::endl;
            if (proof_fragments.size() < 100) {
                // output all proof fragments
                std::cout << "Proof fragments: ";
                for (auto const& fragment: proof_fragments) {
                    std::cout << fragment << " ";
                }
                std::cout << std::endl;
            }
        }
#endif
        auto [deltas, stubs]
            = deltifyAndStubProofFragments(start_proof_fragment_range, proof_fragments, stub_bits);
#ifdef DEBUG_CHUNK_COMPRESSOR
        if (proof_fragments.size() < 100) {
            std::cout << "Deltas:\n";
            for (auto const& value: deltas) {
                std::cout << static_cast<int>(value) << " ";
            }
            std::cout << "\nStubs:\n";
            for (auto const& value: stubs) {
                std::cout << value << " ";
            }
            std::cout << "\n";
        }
#endif
        return compress(deltas, stubs, static_cast<uint8_t>(stub_bits));
    }

    static std::vector<ProofFragment> decompressProofFragments(
        std::span<uint8_t const> const compressed_data,
        uint64_t const start_proof_fragment_range,
        int const stub_bits)
    {
        std::vector<uint8_t> deltas;
        std::vector<uint64_t> stubs;
        decompress(compressed_data, static_cast<uint8_t>(stub_bits), deltas, stubs);

#ifdef DEBUG_CHUNK_COMPRESSOR
        if (deltas.size() < 100) {
            std::cout << "Decompressed Deltas:\n";
            for (auto const& value: deltas) {
                std::cout << static_cast<int>(value) << " ";
            }
            std::cout << "\nDecompressed Stubs:\n";
            for (auto const& value: stubs) {
                std::cout << value << " ";
            }
            std::cout << "\n";
        }
#endif

        if (deltas.size() != stubs.size()) {
            throw std::runtime_error("ChunkCompressor::decompressProofFragments: size mismatch "
                                     "between deltas and stubs");
        }

        std::vector<ProofFragment> proof_fragments;
        proof_fragments.reserve(deltas.size());

        ProofFragment previous = start_proof_fragment_range;
        for (size_t i = 0; i < deltas.size(); ++i) {
            uint64_t delta = (static_cast<uint64_t>(deltas[i]) << stub_bits) | stubs[i];
            ProofFragment fragment = previous + delta;
            proof_fragments.push_back(fragment);
            previous = fragment;
        }

#ifdef DEBUG_CHUNK_COMPRESSOR
        if (proof_fragments.size() < 100) {
            std::cout << "Reconstructed Proof Fragments:\n";
            for (auto const& fragment: proof_fragments) {
                std::cout << fragment << " ";
            }
            std::cout << "\n";
        }
#endif

        return proof_fragments;
    }

    static std::pair<std::vector<uint8_t>, std::vector<uint64_t>> deltifyAndStubProofFragments(
        uint64_t const start_proof_fragment_range,
        std::span<ProofFragment const> const proof_fragments,
        int const stub_bits)
    {
        if (stub_bits == 0 || stub_bits >= 64) {
            throw std::invalid_argument(
                "ChunkCompressor::deltifyAndStubProofFragments: stub_bits must be in [1, 63]");
        }

        std::vector<uint8_t> deltas;
        std::vector<uint64_t> stubs;

        deltas.reserve(proof_fragments.size());
        stubs.reserve(proof_fragments.size());

        ProofFragment previous = start_proof_fragment_range;
        for (ProofFragment fragment: proof_fragments) {
            if (fragment < previous) {
                throw std::invalid_argument("ChunkCompressor::deltifyAndStubProofFragments: proof "
                                            "fragments must be non-decreasing");
            }
            uint64_t delta = fragment - previous;
            uint64_t stub = delta & ((1ULL << stub_bits) - 1);
            int delta_byte = static_cast<int>(delta >> stub_bits);
            if (delta_byte > std::numeric_limits<uint8_t>::max()) {
                std::cerr << "Delta too large: fragment=" << fragment << ", previous=" << previous
                          << ", delta=" << delta << ", stub_bits=" << stub_bits
                          << ", delta_byte=" << delta_byte << std::endl;
                throw std::invalid_argument("ChunkCompressor::deltifyAndStubProofFragments: delta "
                                            "too large to fit in one byte");
            }

            deltas.push_back(static_cast<uint8_t>(delta_byte));
            stubs.push_back(stub);

            previous = fragment;
        }

        return { deltas, stubs };
    }

    // Compress a single chunk (block)
    // - deltas: 1-byte per value (already computed)
    // - stubs: low bits for each value (uint64_t, but only stub_bits used)
    // - stub_bits: number of LSBs in each stub (1..56 typically)
    //
    // Returns: encoded chunk bytes
    static std::vector<uint8_t> compress(std::span<uint8_t const> const deltas,
        std::span<uint64_t const> const stubs,
        uint8_t const stub_bits)
    {
        // deltas and stubs must have the same size
        assert(deltas.size() == stubs.size());
        // stub bits must make sense
        assert(stub_bits >= 0 && stub_bits < 56);

        uint32_t const num_values = static_cast<uint32_t>(deltas.size());
        if (num_values == 0) {
            // Encode an empty chunk with zero sizes.
            std::vector<uint8_t> chunk;
            chunk.reserve(12);
            append_u32(chunk, 0); // num_values
            append_u32(chunk, 0); // fse_size
            append_u32(chunk, 0); // stub_bytes_size
            return chunk;
        }

        // 1) FSE-compress the deltas
        size_t srcSize = deltas.size();
        size_t maxDst = POS2_FSE_compressBound(srcSize);
        std::vector<uint8_t> fse_data(maxDst);

        size_t cSize = POS2_FSE_compress(fse_data.data(), maxDst, deltas.data(), srcSize);
        if (POS2_FSE_isError(cSize)) {
            throw std::runtime_error("ChunkCompressor::compress: FSE_compress failed");
        }
        fse_data.resize(cSize);
        uint32_t const fse_size = static_cast<uint32_t>(cSize);

        // 2) Bit-pack stubs into bytes
        std::vector<uint8_t> stub_bytes = packStubs(stubs, stub_bits);
        uint32_t const stub_bytes_size = static_cast<uint32_t>(stub_bytes.size());

        // 3) Build chunk blob
        std::vector<uint8_t> chunk;
        chunk.reserve(12 + fse_size + stub_bytes_size);

        append_u32(chunk, num_values);
        append_u32(chunk, fse_size);
        append_u32(chunk, stub_bytes_size);

        // fse data
        chunk.insert(chunk.end(), fse_data.begin(), fse_data.end());
        // stub data
        chunk.insert(chunk.end(), stub_bytes.begin(), stub_bytes.end());

        return chunk;
    }

    // Decompress a single chunk
    // - chunk: bytes produced by compress()
    // - stub_bits: same as used during compression
    // Output:
    // - out_deltas: resized to num_values, filled with deltas
    // - out_stubs:  resized to num_values, filled with stub values
    static void decompress(std::span<uint8_t const> const chunk,
        uint8_t const stub_bits,
        std::vector<uint8_t>& out_deltas,
        std::vector<uint64_t>& out_stubs)
    {
        assert(chunk.size() > 12); // don't use tiny chunks
        assert(stub_bits >= 0 && stub_bits < 56);

        uint8_t const* p = chunk.data();
        uint8_t const* const end = chunk.data() + chunk.size();

        uint32_t num_values = read_u32(p, end);
        uint32_t fse_size = read_u32(p, end);
        uint32_t stub_bytes_size = read_u32(p, end);

        // Handle empty chunk
        if (num_values == 0) {
            out_deltas.clear();
            out_stubs.clear();
            return;
        }

        if (chunk.data() + chunk.size() < p + fse_size + stub_bytes_size) {
            throw std::runtime_error("ChunkCompressor::decompress: chunk truncated");
        }

        uint8_t const* fse_data = p;
        uint8_t const* stub_bytes = p + fse_size;

        // 1) FSE-decompress deltas
        out_deltas.resize(num_values);
        size_t dSize = POS2_FSE_decompress(out_deltas.data(), num_values, fse_data, fse_size);
        if (POS2_FSE_isError(dSize) || dSize != num_values) {
            throw std::runtime_error(
                "ChunkCompressor::decompress: FSE_decompress failed or size mismatch");
        }

        // 2) Unpack stubs
        out_stubs.resize(num_values);
        unpackStubs(stub_bytes, stub_bytes_size, stub_bits, out_stubs);
    }

private:
    // ---- Helpers for (de)serialization ----

    static void append_u32(std::vector<uint8_t>& buf, uint32_t v)
    {
        buf.push_back(static_cast<uint8_t>(v & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    }

    static uint32_t read_u32(uint8_t const*& p, uint8_t const* end)
    {
        if (p + 4 > end) {
            throw std::runtime_error("ChunkCompressor::read_u32: out of bounds");
        }
        uint32_t v = 0;
        v |= static_cast<uint32_t>(p[0]);
        v |= static_cast<uint32_t>(p[1]) << 8;
        v |= static_cast<uint32_t>(p[2]) << 16;
        v |= static_cast<uint32_t>(p[3]) << 24;
        p += 4;
        return v;
    }

    // ---- Stub bitpacking ----

    // Pack stubs (each using stub_bits LSBs) into a byte array (little-endian bit order).
    static std::vector<uint8_t> packStubs(std::span<uint64_t const> const stubs, uint8_t stub_bits)
    {
        std::vector<uint8_t> out;
        if (stubs.empty())
            return out;

        uint64_t bitbuf = 0;
        int bitcount = 0;

        uint64_t mask = (stub_bits == 64) ? std::numeric_limits<uint64_t>::max()
                                          : ((1ULL << stub_bits) - 1ULL);

        for (uint64_t stub: stubs) {
            uint64_t v = stub & mask;
            bitbuf |= (v << bitcount);
            bitcount += stub_bits;

            while (bitcount >= 8) {
                out.push_back(static_cast<uint8_t>(bitbuf & 0xFF));
                bitbuf >>= 8;
                bitcount -= 8;
            }
        }

        if (bitcount > 0) {
            out.push_back(static_cast<uint8_t>(bitbuf & 0xFF));
        }

        return out;
    }

    // Unpack stubs from a bit-packed byte array
    static void unpackStubs(uint8_t const* stub_bytes,
        size_t stub_bytes_size,
        uint8_t stub_bits,
        std::vector<uint64_t>& out_stubs)
    {
        uint8_t const* p = stub_bytes;
        uint8_t const* const end = stub_bytes + stub_bytes_size;

        uint64_t bitbuf = 0;
        int bitcount = 0;

        uint64_t mask = (stub_bits == 64) ? std::numeric_limits<uint64_t>::max()
                                          : ((1ULL << stub_bits) - 1ULL);

        for (size_t i = 0; i < out_stubs.size(); ++i) {
            // Ensure we have enough bits in buffer
            while (bitcount < stub_bits) {
                if (p >= end) {
                    throw std::runtime_error("ChunkCompressor::unpackStubs: not enough stub data");
                }
                bitbuf |= (static_cast<uint64_t>(*p) << bitcount);
                ++p;
                bitcount += 8;
            }

            uint64_t v = bitbuf & mask;
            bitbuf >>= stub_bits;
            bitcount -= stub_bits;

            out_stubs[i] = v;
        }
    }
};


///
/// This is the format in which the chunk index table is encoded.
/// (Which determines the offsets of the chunks in the plot file.)
///

// Floor integer square root of n. Bit-exact; do not use floating sqrt.
inline uint64_t gsz_isqrt_u64(uint64_t n) {
    if (n < 2) {
        return n;
    }

    // Highest bit set in the root is at most half of that in n.
    uint64_t op  = n;
    uint64_t res = 0;

    // Highest even-numbered bit <= highest set bit in n.
    uint64_t msb = 63 - Bits::count_leading_zeros(n);
    uint64_t one = 1ull << (msb & (~(1ull)));

    while (one != 0) {
        if (op >= res + one) {
            op -= res + one;
            res = (res >> 1) + one;
        } 
        else {
            res >>= 1;
        }

        one >>= 2;
    };

    return res;
}

// floor(log2(n)) for n >= 1 
inline int gsz_floor_log2_u64(uint64_t n) {
    return int(63ull - Bits::count_leading_zeros(n));
}

/*
 * round(log2(n)) for n >= 1, in integers:
 *   f = floor(log2(n));  round up iff n >= 2^f * sqrt(2)
 *   i.e. n*n >= 2^(2f+1)
 */
inline int gsz_round_log2_u64( uint64_t n ) {
    if (n <= 1) {
        return 0;
    }
    int f = gsz_floor_log2_u64(n);
    if (f >= 32) {
        // G should never be >= 65,536, therefore we should never hit this
        // or need 128 bit values.
        throw std::runtime_error("gsz_round_log2_u64 N would overflow");
    }
    // if (f >= 63) {        // n >= 2^63; n*n would overflow — only compare top half
    //     return f;         // 2^f * sqrt(2) > 2^63 for f>=63 in our use, keep f
    // }

    //  Widening compare: n*n < (1 << (2f+1)) ? f : f+1
    uint64_t nn       = n * n;
    uint64_t boundary = 1ull << (2 * uint64_t(f) + 1);

    return (nn < boundary) ? f : f + 1;
}

inline int gsz_rice_k_for_g(uint64_t g) {
    // 357 * g fits in uint64 for all uint32 g (357 * (2^32-1) < 2^64).
    uint64_t med_est = gsz_isqrt_u64(357 * g);
    if (med_est == 0) {
        med_est = 1;
    }

    return gsz_round_log2_u64(med_est);
}

inline uint64_t gsz_expected_for_g(uint64_t g) {
    return (g * 60301) >> 8;
}

template<bool K_NOT_ZERO>
inline int64_t gsz_decode_delta(uint32_t const k, BitReader& reader) {

    uint64_t const sign_bit = reader.read_one();

    uint64_t r = 0;
    if constexpr (K_NOT_ZERO) {
        r = reader.read_u64(k);   // remainder
    }

    uint64_t const q = reader.read_unary_64(); // quotient

    uint64_t const mag       = (q << k) | r;
    uint64_t const sign_mask = 0ull - sign_bit;
    int64_t  const delta     = int64_t((mag ^ sign_mask) + sign_bit);

    return delta;
}

template<bool K_NOT_ZERO>
void _gsz_decode_internal(std::span<uint64_t> out_sizes, uint32_t k, uint64_t group_size, BitReader& reader) {
    auto expected = (int64_t)gsz_expected_for_g(group_size);

    int64_t i = 0;
    for (auto &v : out_sizes) {
        int64_t delta = gsz_decode_delta<K_NOT_ZERO>(k, reader);
        delta += expected;

        if (delta < 1) {
            throw std::runtime_error("Invalid delta " + std::to_string(delta) + " at index " + std::to_string(i));
        }

        v = (uint64_t)delta;
        i++;
    }
}

void gsz_decode(std::span<uint64_t> out_sizes, uint64_t group_size, BitReader& reader) {

    auto k = (uint32_t)gsz_rice_k_for_g(group_size);

    if (k != 0) {
        _gsz_decode_internal<true>(out_sizes, k, group_size, reader);
    }
    else {
        _gsz_decode_internal<false>(out_sizes, k, group_size, reader);
    }
}


template<bool K_NOT_ZERO>
inline void gsz_encode_delta(int64_t const delta, uint32_t const k, uint64_t const k_mask, BitWriter& writer)
{
    uint64_t const value     = uint64_t(delta);
    uint64_t const sign_bit  = value >> 63;
    uint64_t const sign_mask = 0ull - sign_bit;
    uint64_t const mag       = (value ^ sign_mask) + sign_bit;
    uint64_t const q         = mag >> k; // quotient

    // Written into a u64-based bit field:
    // MSbit                                                                LSbit
    // --------------------------------------------------------------------------
    // <zero_bit_separator><unary_quotient_bits>[remainder_binary_bits]<sign_bit>
    //                                          ^
    //                         variable-size <- | -> fixed-size with optional field

    uint64_t const field_size = q + k + 2;
    assert(field_size <= 64);

    uint64_t const unary_value = (1ull << q) - 1;

    if constexpr (K_NOT_ZERO) {
        uint64_t const r = mag & k_mask; // remainder binary bits

        uint64_t const field = (unary_value << (k + 1)) | (r << 1) | sign_bit;
        writer.append(field, uint32_t(field_size));
    }
    else {
        uint64_t const field = (unary_value << 1) | sign_bit;
        writer.append(field, uint32_t(field_size));
    }
}

template<bool K_NOT_ZERO>
void _gsz_encode_internal(std::span<uint64_t const> const sizes, uint32_t const k,
    uint64_t const group_size, BitWriter& writer)
{
    int64_t const expected = int64_t(gsz_expected_for_g(group_size));
    uint64_t const k_mask  = (1ull << k) - 1;

    for (uint64_t const v : sizes) {
        int64_t const delta = int64_t(v) - expected;
        gsz_encode_delta<K_NOT_ZERO>(delta, k, k_mask, writer);
    }
}

void gsz_encode(std::span<uint64_t const> const sizes, uint64_t const group_size, BitWriter& writer)
{
    uint32_t const k = uint32_t(gsz_rice_k_for_g(group_size));

    if (k != 0) {
        _gsz_encode_internal<true>(sizes, k, group_size, writer);
    }
    else {
        _gsz_encode_internal<false>(sizes, k, group_size, writer);
    }
}
