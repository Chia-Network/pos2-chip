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

// Number of distinct challenge fragment sets selected per challenge. Each set has
// a chaining_set index that is exclusive modulo NUM_CHALLENGE_SETS, and the chain
// cycles through the sets in order: 0, 1, ..., NUM_CHALLENGE_SETS - 1, 0, 1, ...
// NUM_CHAIN_LINKS must be a multiple of NUM_CHALLENGE_SETS.
constexpr int NUM_CHALLENGE_SETS = 4;
static_assert(NUM_CHAIN_LINKS % NUM_CHALLENGE_SETS == 0,
    "NUM_CHAIN_LINKS must be a multiple of NUM_CHALLENGE_SETS");

constexpr uint32_t TESTNET_G_XOR_CONST = 0xA3B1C4D7;
