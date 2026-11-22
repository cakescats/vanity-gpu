// Plain structs shared between host code and CUDA kernels.
#pragma once
#include <cstdint>

#define MAX_PATTERNS 16
#define MAX_DIG 48
#define MAX_HITS 65536

// One compiled search pattern. Which fields are used depends on the chain:
//  EVM : hmask/hval over the 40-nibble address (5 big-endian words)
//  TRON: nrange<=1 over the 20-byte payload (rlo/rhi words 0..4), plus digits
//  SOL : nrange<=2 over the 32-byte public key (rlo/rhi words 0..7), plus digits
//  TON : bmask/bval over the 36-byte user-friendly address (9 big-endian words)
struct DevPattern {
  uint32_t hmask[5], hval[5];
  uint32_t bmask[9], bval[9];
  uint32_t nrange;
  uint32_t rlo[2][8], rhi[2][8];  // inclusive bounds, big-endian words
  uint32_t ndig;                  // base58 character constraints
  uint32_t npass;                 // base58 passes (5 digits each) the digits need; 0 = all
  uint8_t dpos[MAX_DIG];          // position from start (dstart=1) or from end
  uint8_t dval[MAX_DIG];          // base58 digit value
  uint8_t dstart[MAX_DIG];
};

// Index for large pattern lists (more than MAX_PATTERNS after expansion).
// Every pattern gets a range of a 64-bit key taken from the address (index 0: the
// leading characters, index 1: the trailing characters, see index_key_* in the
// engines). The key space is cut into disjoint segments, each listing the patterns
// that cover it. A bitmap over the top bits of the key rejects almost every address
// with one load; the rest do a binary search and test the listed patterns exactly.
struct DevIndex {
  const uint32_t* bitmap;
  const unsigned long long* lo;  // segment bounds, sorted, inclusive
  const unsigned long long* hi;
  const uint32_t* off;           // nseg + 1 offsets into pid
  const uint32_t* pid;           // pattern ids, most specific first
  uint32_t nseg;
  uint32_t shift;                // bitmap bucket = key >> shift
};

struct DevConfig {
  uint32_t npat;
  uint32_t ndev;         // patterns >= ndev are matched by their index key range alone
  uint32_t need_digits;  // base58 digits, the TON crc16 or the bech32 checksum are needed
  uint32_t score;        // 0 off, 1 runs of one character (--beauty), 2 character class (--only)
  uint32_t min_score;
  uint32_t b_start;      // first address char that counts for the score
  uint32_t cls_lo, cls_hi;  // class: bit v = alphabet index v allowed (EVM: 0-15 = 0-9 a-f, 16-21 = A-F)
  uint32_t cls_case;     // EVM: the class depends on the EIP-55 letter case
  uint32_t bech_init;    // BTC: bech32 checksum state after "bc" + witness version 0
  // TRON / BTC P2SH --beauty prefilter (lead_k = 0: off). The leading run must be >= lead_k
  // when the trailing run is < 5, so before all 34 base58 digits are computed: the top
  // digits q = floor(n / 58^(33-k)) ~ umulhi(n >> 135, lead_mul) (error < 2), and
  // q - lead_base must be c * lead_rep (k equal digits c) up to that error.
  uint32_t lead_k;
  float lead_inv;  // 1 / lead_rep
  unsigned long long lead_mul, lead_base, lead_rep;
};

struct Hit {
  uint32_t tid;
  uint32_t pat;     // pattern index, or BEAUTY_HIT
  uint64_t m;       // secp: group counter of the thread
  int32_t idx;      // secp: point index inside the group
  uint32_t flags;   // secp: bit0 = negated, bits1-2 = endomorphism power
  uint32_t score;
  uint32_t pad;
  uint32_t seed[8]; // ed25519: the 32-byte seed
};

#define BEAUTY_HIT 0xFFFFFFFFu
