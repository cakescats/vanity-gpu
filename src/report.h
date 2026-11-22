#pragma once
#include <csignal>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "pattern.h"

extern volatile std::sig_atomic_t g_stop;

using KV = std::vector<std::pair<std::string, std::string>>;

// Collects verified results: prints them and appends them to the results file (mode 0600).
class Reporter {
 public:
  Reporter(const PatternSet& ps, std::string path, bool show_keys, uint64_t want, bool quiet);
  // multi mode: one pattern set per chain, searched with the same keys
  Reporter(std::vector<const PatternSet*> sets, std::string path, bool show_keys, uint64_t want, bool quiet);

  // `info` is printed always, `secret` only with --show-keys (both go to the file).
  void found(Chain chain, const std::string& address, const std::string& what, const KV& info, const KV& secret);
  void reject(const std::string& why);
  void dropped(uint64_t n);
  bool done() const { return want_ && found_ >= want_; }
  void progress(double keys, double secs, bool final_line, const std::string& note = "");

  uint64_t found_count() const { return found_; }
  uint64_t found_count(Chain c) const;
  std::string label() const;  // "EVM" or "EVM+TRON+BTC"
  const std::vector<std::string>& addresses() const { return addresses_; }
  uint64_t rejected() const { return rejected_; }

 private:
  std::vector<const PatternSet*> sets_;
  double p_match_ = 0;  // any set reports a random key
  std::vector<std::pair<Chain, uint64_t>> per_chain_;
  std::string path_;
  bool show_keys_, quiet_;
  uint64_t want_, found_ = 0, rejected_ = 0;
  std::vector<std::string> addresses_;
  bool dropped_warned_ = false;
};

struct EngineOptions {
  int device = 0;
  int blocks = 0;
  int threads = 0;
  double bench = 0;     // seconds; 0 = run until done
  std::string pubkey;   // secp256k1 split-key mode
  int cpu = 0;          // evm/tron: CPU worker threads next to the GPU
  bool no_gpu = false;  // CPU workers only (tests)
};

// Both return the number of keys checked. With several sets (multi mode, one per chain,
// all secp256k1 or all ed25519) every key is checked against each of them.
double run_secp(const PatternSet& ps, const EngineOptions& eo, Reporter& rep);
double run_secp(const std::vector<const PatternSet*>& sets, const EngineOptions& eo, Reporter& rep);
double run_ed(const PatternSet& ps, const EngineOptions& eo, Reporter& rep);
double run_ed(const std::vector<const PatternSet*>& sets, const EngineOptions& eo, Reporter& rep);
