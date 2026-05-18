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

// Number of distinct challenge fragment sets selected per challenge. Each set
// has a chaining_set index that is exclusive modulo NUM_CHALLENGE_SETS. A chain
// can start in *any* of the selected sets; once started in set s the chain
// cycles through sets s, s+1, s+2, ..., s+NUM_CHAIN_LINKS-1 (mod
// NUM_CHALLENGE_SETS). NUM_CHAIN_LINKS must be a multiple of
// NUM_CHALLENGE_SETS so every set is hit exactly L/N times regardless of the
// starting set.
constexpr int NUM_CHALLENGE_SETS = 4;
static_assert(NUM_CHAIN_LINKS % NUM_CHALLENGE_SETS == 0,
    "NUM_CHAIN_LINKS must be a multiple of NUM_CHALLENGE_SETS");

// Number of zero low-bits required of the iter-0 chain hash for a fragment to
// qualify as a chain "starter". With NUM_CHALLENGE_SETS candidate sets each
// contributing ~chaining_set_size starter candidates, this filter probabilistically
// reduces the surviving starters back down to ~chaining_set_size on average,
// preserving the original branching shape of the search tree (and hence the
// design target of ~1 chain per challenge).
//
// Setting this to log2(NUM_CHALLENGE_SETS) makes the expected starter count
// independent of NUM_CHALLENGE_SETS.
constexpr int CHAIN_STARTER_FILTER_BITS = 2;
static_assert((1 << CHAIN_STARTER_FILTER_BITS) == NUM_CHALLENGE_SETS,
    "CHAIN_STARTER_FILTER_BITS should be log2(NUM_CHALLENGE_SETS)");

constexpr uint32_t TESTNET_G_XOR_CONST = 0xA3B1C4D7;
