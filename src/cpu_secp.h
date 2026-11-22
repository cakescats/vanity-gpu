// EVM / TRON / Bitcoin search on CPU threads, alongside the GPU (--cpu N).
//
// Each worker walks its own window of the same split-key walk as the GPU kernel:
// points P0 + d*G with d = tid*2^64 + HALF + m*GRP + idx, tid = CPU_TID0 + worker.
// Hits use the GPU hit format and go through the same CPU re-verification
// (hostcrypto.cpp) before they are reported, so this code is checked like the GPU's.
#pragma once
#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

#include "hostcrypto.h"
#include "pattern.h"

constexpr int SECP_HALF = 256;              // must match engine_secp.cu
constexpr int SECP_GRP = 2 * SECP_HALF;
constexpr uint32_t CPU_TID0 = 0xC0000000u;  // GPU thread ids are far below this

class CpuSecp {
 public:
  CpuSecp(const PatternSet& ps, const hc::SPt& P0, int nthreads);
  // multi mode: every key is checked against each set (distinct secp256k1 chains)
  CpuSecp(std::vector<const PatternSet*> sets, const hc::SPt& P0, int nthreads);
  ~CpuSecp();
  CpuSecp(const CpuSecp&) = delete;
  CpuSecp& operator=(const CpuSecp&) = delete;

  void take_hits(std::vector<Hit>& out);  // appends the hits found so far
  double keys() const { return (double)keys_.load(std::memory_order_relaxed); }
  int threads() const { return (int)pool_.size(); }

 private:
  void worker(uint32_t tid);
  std::vector<const PatternSet*> sets_;
  hc::SPt P0_;
  std::atomic<bool> stop_{false};
  std::atomic<uint64_t> keys_{0};
  std::mutex mu_;
  std::vector<Hit> hits_;
  std::vector<std::thread> pool_;
};

// Default worker count for --cpu max: all hardware threads but one for the GPU loop.
int cpu_default_threads();
