// PTX helpers and generic 256-bit arithmetic shared by both curves.
#pragma once
#include <cstdint>

#include "devtypes.h"

#define DI __device__ __forceinline__

#define ADD_CC(r, a, b) asm volatile("add.cc.u32 %0, %1, %2;" : "=r"(r) : "r"(a), "r"(b))
#define ADDC_CC(r, a, b) asm volatile("addc.cc.u32 %0, %1, %2;" : "=r"(r) : "r"(a), "r"(b))
#define ADDC(r, a, b) asm volatile("addc.u32 %0, %1, %2;" : "=r"(r) : "r"(a), "r"(b))
#define SUB_CC(r, a, b) asm volatile("sub.cc.u32 %0, %1, %2;" : "=r"(r) : "r"(a), "r"(b))
#define SUBC_CC(r, a, b) asm volatile("subc.cc.u32 %0, %1, %2;" : "=r"(r) : "r"(a), "r"(b))
#define SUBC(r, a, b) asm volatile("subc.u32 %0, %1, %2;" : "=r"(r) : "r"(a), "r"(b))
#define MADLO_CC(r, a, b, c) asm volatile("mad.lo.cc.u32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(b), "r"(c))
#define MADLOC_CC(r, a, b, c) asm volatile("madc.lo.cc.u32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(b), "r"(c))
#define MADHI_CC(r, a, b, c) asm volatile("mad.hi.cc.u32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(b), "r"(c))
#define MADHIC_CC(r, a, b, c) asm volatile("madc.hi.cc.u32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(b), "r"(c))
#define MADHIC(r, a, b, c) asm volatile("madc.hi.u32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(b), "r"(c))

DI uint32_t bswap32(uint32_t x) { return __byte_perm(x, 0, 0x0123); }

DI void copy8(uint32_t r[8], const uint32_t a[8]) {
#pragma unroll
  for (int i = 0; i < 8; i++) r[i] = a[i];
}

DI void load8(uint32_t r[8], const uint32_t* p) {
  uint4 a = __ldg(reinterpret_cast<const uint4*>(p));
  uint4 b = __ldg(reinterpret_cast<const uint4*>(p) + 1);
  r[0] = a.x; r[1] = a.y; r[2] = a.z; r[3] = a.w;
  r[4] = b.x; r[5] = b.y; r[6] = b.z; r[7] = b.w;
}

// r[0..15] = a * b (little-endian 32-bit limbs), operand scanning.
DI void mul_wide(uint32_t r[16], const uint32_t a[8], const uint32_t b[8]) {
#pragma unroll
  for (int k = 0; k < 16; k++) r[k] = 0;
#pragma unroll
  for (int i = 0; i < 8; i++) {
    MADLO_CC(r[i], a[0], b[i], r[i]);
#pragma unroll
    for (int j = 1; j < 8; j++) MADLOC_CC(r[i + j], a[j], b[i], r[i + j]);
    ADDC(r[i + 8], r[i + 8], 0);
    MADHI_CC(r[i + 1], a[0], b[i], r[i + 1]);
#pragma unroll
    for (int j = 1; j < 7; j++) MADHIC_CC(r[i + j + 1], a[j], b[i], r[i + j + 1]);
    MADHIC(r[i + 8], a[7], b[i], r[i + 8]);
  }
}

// ------------------------------------------------------------- hits / patterns

// One pattern set per slot, so one kernel can search several chains at once (multi
// mode). Slot = the chain's kernel variant (secp: EVM 0 .. BTC-p2sh 4; ed: SOL 0, TON 1);
// each engine defines NSLOT before including this file.
#ifndef NSLOT
#error "define NSLOT before including common.cuh"
#endif
static __constant__ DevPattern c_pat[NSLOT][MAX_PATTERNS];
static __constant__ DevConfig c_cfg[NSLOT];
static __constant__ DevIndex c_idx[NSLOT][2];         // pattern-list index: leading / trailing key
static __constant__ const DevPattern* c_gpat[NSLOT];  // all patterns (global memory)

DI uint64_t nibrev64(uint64_t x) {
  uint32_t hi = bswap32((uint32_t)x), lo = bswap32((uint32_t)(x >> 32));
  x = (uint64_t)hi << 32 | lo;
  return ((x & 0x0F0F0F0F0F0F0F0Full) << 4) | ((x >> 4) & 0x0F0F0F0F0F0F0F0Full);
}

// Cheap first test: is any pattern possible for this key?
DI bool idx_maybe(const DevIndex& I, uint64_t key) {
  const uint64_t b = key >> I.shift;
  return (__ldg(I.bitmap + (b >> 5)) >> (b & 31)) & 1u;
}

// Exact test: the first listed pattern of the key's segment that `test` accepts, or -1.
template <int S, class F>
DI int idx_find(const DevIndex& I, uint64_t key, F&& test) {
  uint32_t lo = 0, hi = I.nseg;
  while (lo < hi) {
    uint32_t mid = (lo + hi) >> 1;
    if (__ldg(I.lo + mid) <= key) lo = mid + 1;
    else hi = mid;
  }
  if (lo == 0) return -1;
  const uint32_t s = lo - 1;
  if (key > __ldg(I.hi + s)) return -1;
  for (uint32_t j = __ldg(I.off + s), e = __ldg(I.off + s + 1); j < e; j++) {
    const uint32_t p = __ldg(I.pid + j);
    if (p >= c_cfg[S].ndev || test(c_gpat[S][p])) return (int)p;  // key-only patterns: the range is the test
  }
  return -1;
}

template <int S>
DI uint64_t cls_mask() { return (uint64_t)c_cfg[S].cls_hi << 32 | c_cfg[S].cls_lo; }

// --beauty / --only score of the n characters after the fixed start of the address;
// val(i) is the alphabet index of character i. Same definitions as score_address().
//  score 1: leading run of one character + trailing run
//  score 2: leading run of class characters + trailing run (whole address: n)
template <int S, class V>
DI uint32_t run_score(V&& val, int n, uint64_t mask) {
  if (c_cfg[S].score == 1) {
    const uint32_t c0 = val(0), cl = val(n - 1);
    int L = 1, R = 1;
    while (L < n && val(L) == c0) L++;
    while (R < n && val(n - 1 - R) == cl) R++;
    return (uint32_t)(L + R);
  }
  int L = 0;
  while (L < n && ((mask >> val(L)) & 1u)) L++;
  if (L == n) return (uint32_t)n;
  int R = 0;
  while (R < n && ((mask >> val(n - 1 - R)) & 1u)) R++;
  return (uint32_t)(L + R);
}

// Small list first, then both indexes; match(P) tests one pattern exactly.
// key(k) computes index key k (only called when that index is in use). Kernels are
// compiled with and without the index (IDX) so short pattern lists pay nothing for it.
template <bool IDX, int S, class M, class K>
DI int find_pattern(M&& match, K&& key) {
  for (uint32_t p = 0; p < c_cfg[S].npat; p++)
    if (match(c_pat[S][p])) return (int)p;
  if constexpr (IDX) {
#pragma unroll
    for (int k = 0; k < 2; k++) {
      if (!c_idx[S][k].nseg) continue;
      const uint64_t x = key(k);
      if (!idx_maybe(c_idx[S][k], x)) continue;
      int p = idx_find<S>(c_idx[S][k], x, match);
      if (p >= 0) return p;
    }
  }
  return -1;
}

DI void emit_hit(Hit* hits, uint32_t* nhits, const Hit& h) {
  uint32_t k = atomicAdd(nhits, 1u);
  if (k < MAX_HITS) hits[k] = h;
}

// Inclusive range check on big-endian word arrays.
template <int NW>
DI bool in_range(const uint32_t* a, const uint32_t* lo, const uint32_t* hi) {
#pragma unroll
  for (int k = 0; k < NW; k++) {
    if (a[k] != lo[k]) {
      if (a[k] < lo[k]) return false;
      break;
    }
  }
#pragma unroll
  for (int k = 0; k < NW; k++) {
    if (a[k] != hi[k]) return a[k] < hi[k];
  }
  return true;
}

// Base58 digits of a big-endian number, least significant digit first.
template <int NW, int NPASS>
DI void b58_digits(const uint32_t in[NW], uint8_t dig[NPASS * 5]) {
  uint32_t w[NW];
#pragma unroll
  for (int k = 0; k < NW; k++) w[k] = in[k];
#pragma unroll
  for (int p = 0; p < NPASS; p++) {
    uint64_t rem = 0;
#pragma unroll
    for (int k = 0; k < NW; k++) {
      uint64_t cur = (rem << 32) | w[k];
      uint64_t q = cur / 656356768ull;  // 58^5
      rem = cur - q * 656356768ull;
      w[k] = (uint32_t)q;
    }
    uint32_t r = (uint32_t)rem;
#pragma unroll
    for (int d = 0; d < 5; d++) {
      dig[p * 5 + d] = (uint8_t)(r % 58);
      r /= 58;
    }
  }
}

// Only the `npass` least significant passes of b58_digits (digits 0 .. 5*npass-1).
template <int NW>
DI void b58_low_digits(const uint32_t in[NW], uint8_t* dig, int npass) {
  uint32_t w[NW];
#pragma unroll
  for (int k = 0; k < NW; k++) w[k] = in[k];
#pragma unroll 1
  for (int p = 0; p < npass; p++) {
    uint64_t rem = 0;
#pragma unroll
    for (int k = 0; k < NW; k++) {
      uint64_t cur = (rem << 32) | w[k];
      uint64_t q = cur / 656356768ull;
      rem = cur - q * 656356768ull;
      w[k] = (uint32_t)q;
    }
    uint32_t r = (uint32_t)rem;
#pragma unroll
    for (int d = 0; d < 5; d++) {
      dig[p * 5 + d] = (uint8_t)(r % 58);
      r /= 58;
    }
  }
}

DI bool digits_ok(const DevPattern& P, const uint8_t* dig, int len) {
  for (uint32_t k = 0; k < P.ndig; k++) {
    int pos = P.dpos[k];
    int idx = P.dstart[k] ? len - 1 - pos : pos;
    if (idx < 0 || dig[idx] != P.dval[k]) return false;
  }
  return true;
}

// Leading run (from string index s0) + trailing run; same definition as beauty_score().
DI uint32_t beauty_digits(const uint8_t* dig, int len, int s0) {
  int c0 = dig[len - 1 - s0];
  int L = 1;
  while (s0 + L < len && dig[len - 1 - s0 - L] == c0) L++;
  int cl = dig[0];
  int R = 1;
  while (R < len - s0 && dig[R] == cl) R++;
  return (uint32_t)(L + R);
}
