#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "devtypes.h"

// BTC = native SegWit P2WPKH (bc1q...), BTC_LEGACY = P2PKH (1...),
// BTC_P2SH = P2SH-wrapped P2WPKH (3...). All Bitcoin types use compressed keys.
enum class Chain { EVM, TRON, SOL, TON, BTC, BTC_LEGACY, BTC_P2SH };
const char* chain_name(Chain c);
inline bool is_btc(Chain c) { return c == Chain::BTC || c == Chain::BTC_LEGACY || c == Chain::BTC_P2SH; }
inline bool is_ed25519(Chain c) { return c == Chain::SOL || c == Chain::TON; }

// A pattern is "PREFIX", "PREFIX..SUFFIX" or "..SUFFIX"; '?' matches any char and
// [abc] any of a, b, c. With -i / -l / -c one written pattern expands to many concrete ones.
// prefix/suffix here are relative to the full address string
// (EVM: 40 lowercase hex chars without 0x; TRON: 34 chars starting with T;
// TON: 48 base64url chars of the non-bounceable form, starting with UQ;
// BTC: 42 lowercase chars starting with bc1q; BTC_LEGACY: 1...; BTC_P2SH: 3...).
struct Pattern {
  std::string prefix, suffix;
  uint32_t src = 0;  // index into PatternSet::src: what the user wrote
  double p = 0;      // probability that a random address matches
  std::string text() const { return suffix.empty() ? prefix : prefix + ".." + suffix; }
};

struct HostIndex {
  std::vector<uint32_t> bitmap;
  std::vector<uint64_t> lo, hi;
  std::vector<uint32_t> off, pid;
  uint32_t shift = 0;
  size_t npat = 0;
  bool empty() const { return lo.empty(); }
};

struct MatchOptions {
  bool ignore_case = false;  // -i: letters match both cases
  bool similar = false;      // -l: look-alike characters (o=0, i=l=1, e=3, a=4, s=5, ...)
  bool caps = false;         // -c: word, Word and WORD
  int max_subs = -1;         // --subs: at most this many changed characters (-1: no limit)
};

enum class Score { NONE, REPEAT, CLASS };

struct CompileOptions {
  MatchOptions match;
  Score score = Score::NONE;  // REPEAT: --beauty, CLASS: --only
  int min_score = 0;         // 0 = default for the chain
  std::string only;          // --only: digits, lower, upper, letters (joined with +) or literal chars
  size_t skip_from = (size_t)-1;  // patterns at index >= skip_from are skipped if invalid
  size_t list_from = (size_t)-1;  // patterns at index >= list_from are list lines (list_subs);
                                  // unset: the same as skip_from
  int list_subs = 3;              // --subs default for list lines (patterns given as arguments: no limit)
  double rarity = 0;              // --rarity: pick min_score (when 0) so a hit is ~1 in 2^rarity
  size_t max_patterns = 0;        // 0 = default (20M)
};

struct PatternSet {
  Chain chain = Chain::EVM;
  // [0, cfg.npat) are tested one by one, the rest via idx. Patterns [0, dev.size()) have a
  // DevPattern; later ones are "key-only": their index key range is the whole test.
  std::vector<Pattern> pats;
  std::vector<std::string> src;  // patterns as written
  Score score = Score::NONE;
  int min_score = 0;
  std::string cls;       // CLASS: the allowed characters (as the address shows them)
  std::string cls_name;  // CLASS: as the user wrote it
  std::vector<DevPattern> dev;
  DevConfig cfg{};
  HostIndex idx[2];  // 0: leading characters, 1: trailing characters
  size_t lines = 0;  // patterns as written, before expansion
  std::vector<std::string> skipped;  // why lines of a list file were skipped
  double p_match = 0;  // probability that a random key is reported
  double p_score = 0;  // the part of p_match that comes from --beauty / --only
};

// Throws std::runtime_error with a user-facing message on invalid input.
PatternSet compile_patterns(Chain chain, const std::vector<std::string>& args, const CompileOptions& o);
// Short form used by tests: beauty = --beauty.
PatternSet compile_patterns(Chain chain, const std::vector<std::string>& args, bool beauty, int min_score,
                            const MatchOptions& mo = {}, size_t skip_from = (size_t)-1);

// Concrete patterns a written pattern stands for (exposed for tests).
std::vector<std::string> expand_pattern(Chain chain, const std::string& arg, const MatchOptions& mo);
// Characters of a written pattern that will be fixed (for --min-len): '?', '..' and the fixed
// start of the address do not count, [abc] counts as one.
size_t pattern_body_len(Chain chain, const std::string& arg);

int default_min_score(Chain c);
std::string describe(const PatternSet& ps, uint32_t pid);  // "pattern TEXT (from SRC)" for reports
bool match_one(const Pattern& p, const std::string& addr);
int beauty_score(Chain c, const std::string& addr);
// --beauty or --only score of an address in its matching form (EVM: 40 lowercase hex chars).
int score_address(const PatternSet& ps, const std::string& addr);
std::string score_what(const PatternSet& ps, int score);  // "beauty score 12 (1 in 2^36.5)"
// P(score >= s) for a random address, and the same as -log2: the "rarity" that makes
// scores of different chains comparable (EVM 13, BTC 11 and TRON 9 are all ~2^40).
double score_probability(const PatternSet& ps, int s);
double score_bits(const PatternSet& ps, int s);
int score_positions(Chain c, Score s);  // characters that count for the score
// Hits for a key-only pattern may lie outside the pattern (range edges, characters beyond
// the index key); the CPU check drops those quietly. Same for base58check prefix ranges,
// which ignore the checksum.
bool may_overmatch(const PatternSet& ps, uint32_t pid);
