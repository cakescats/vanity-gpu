// Host side: copy a compiled PatternSet (small list, all patterns, list index) to the GPU.
// Include after common.cuh in each engine (the __constant__ symbols are per file).
#pragma once
#include <stdexcept>
#include <string>
#include <vector>

#include "common.cuh"
#include "pattern.h"

// Internal linkage: each engine has its own __constant__ symbols, so the two copies
// of this class must not be merged by the linker.
namespace {

class DevPatterns {
 public:
  DevPatterns(const PatternSet& ps, int slot) {
    if (slot < 0 || slot >= NSLOT) throw std::logic_error("pattern slot");
    if (ps.cfg.npat)
      put(cudaMemcpyToSymbol(c_pat, ps.dev.data(), ps.cfg.npat * sizeof(DevPattern),
                             (size_t)slot * MAX_PATTERNS * sizeof(DevPattern)));
    put(cudaMemcpyToSymbol(c_cfg, &ps.cfg, sizeof(DevConfig), (size_t)slot * sizeof(DevConfig)));
    const DevPattern* g = nullptr;
    if (!ps.idx[0].empty() || !ps.idx[1].empty()) g = (const DevPattern*)upload(ps.dev);
    put(cudaMemcpyToSymbol(c_gpat, &g, sizeof g, (size_t)slot * sizeof g));
    DevIndex di[2] = {};
    for (int k = 0; k < 2; k++) {
      const HostIndex& I = ps.idx[k];
      if (I.empty()) continue;
      di[k].bitmap = (const uint32_t*)upload(I.bitmap);
      di[k].lo = (const unsigned long long*)upload(I.lo);
      di[k].hi = (const unsigned long long*)upload(I.hi);
      di[k].off = (const uint32_t*)upload(I.off);
      di[k].pid = (const uint32_t*)upload(I.pid);
      di[k].nseg = (uint32_t)I.lo.size();
      di[k].shift = I.shift;
    }
    put(cudaMemcpyToSymbol(c_idx, di, sizeof di, (size_t)slot * sizeof di));
  }
  ~DevPatterns() {
    for (void* p : bufs_) cudaFree(p);
  }
  DevPatterns(const DevPatterns&) = delete;
  DevPatterns& operator=(const DevPatterns&) = delete;
  size_t bytes() const { return bytes_; }

 private:
  std::vector<void*> bufs_;
  size_t bytes_ = 0;

  static void put(cudaError_t e) {
    if (e != cudaSuccess) throw std::runtime_error(std::string("CUDA (patterns): ") + cudaGetErrorString(e));
  }
  template <class T>
  void* upload(const std::vector<T>& v) {
    void* p = nullptr;
    size_t n = v.size() * sizeof(T);
    put(cudaMalloc(&p, n ? n : 16));
    bufs_.push_back(p);
    if (n) put(cudaMemcpy(p, v.data(), n, cudaMemcpyHostToDevice));
    bytes_ += n;
    return p;
  }
};

}  // namespace
