#pragma once

constexpr int TOTAL_XS_IN_PROOF = 128;
constexpr int TOTAL_T1_PAIRS_IN_PROOF = 64;
constexpr int TOTAL_T2_PAIRS_IN_PROOF = 32;
constexpr int TOTAL_T3_PAIRS_IN_PROOF = 16;
constexpr int TOTAL_PROOF_FRAGMENTS_IN_PROOF = 16;

constexpr int NUM_CHAIN_LINKS = 16;
constexpr int CHAIN_SET_BITS
    = 6; // number of bits to determine chaining set size (64 entries per set)
constexpr int CHAIN_FACTOR_FRONT_LOAD_BITS = CHAIN_SET_BITS;

constexpr uint32_t TESTNET_G_XOR_CONST = 0xA3B1C4D7;
