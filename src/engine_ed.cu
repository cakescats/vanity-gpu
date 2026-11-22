// Solana and TON (wallet v5r1) search on ed25519.
//
// A Solana keypair is a 32-byte seed; the curve scalar is SHA-512(seed), so keys cannot
// be walked incrementally. Each candidate seed is a ChaCha20 block keyed with 256 bits
// from the OS CSPRNG (never a small seed as in profanity), followed by SHA-512 and a
// fixed-base scalar multiplication with a large precomputed table (see Tab below).
#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <thread>
#include <memory>
#include <vector>

#define NSLOT 2  // pattern slots: SOL 0, TON 1 (multi mode searches both with each key)
#include "common.cuh"
#include "hashes.cuh"
#include "hostcrypto.h"
#include "report.h"
#include "rng.h"
#include "upload.cuh"

namespace {

#define CUDA_CHECK(x)                                                                   \
  do {                                                                                  \
    cudaError_t e_ = (x);                                                               \
    if (e_ != cudaSuccess)                                                              \
      throw std::runtime_error(std::string("CUDA: ") + cudaGetErrorString(e_) + " at " + \
                               __FILE__ + ":" + std::to_string(__LINE__));              \
  } while (0)

constexpr int KPT = 64;                          // keys per thread per step (batched inversion)
// Fixed-base table: signed radix-2^W digits, NWIN mixed additions per key.
//  W = 22: 12 additions, 2.4 GB table (used when the card has the memory)
//  W = 16: 16 additions, 50 MB table
// Clamped scalars are < 2^255; NWIN has one extra window when needed so the top digit
// (plus carry) stays <= 2^(W-1).
template <int W>
struct Tab {
  static constexpr int NWIN = (255 + W) / W;
  static constexpr int ENTRIES = (1 << (W - 1)) + 1;  // |digit| = 0 .. 2^(W-1)
  static constexpr size_t WORDS = (size_t)NWIN * ENTRIES * 24;  // [window][|digit|][ypx, ymx, xy2d][8]
};

// ------------------------------------------------------------- GF(2^255-19)
// Values are kept < 2^256 ("weakly reduced") and made canonical only for encoding.

DI void f_reduce(uint32_t r[8], const uint32_t t[16]) {
  uint32_t u[8];
  uint64_t acc = 0;
#pragma unroll
  for (int j = 0; j < 8; j++) {
    acc += (uint64_t)t[j] + (uint64_t)t[8 + j] * 38u;
    u[j] = (uint32_t)acc;
    acc >>= 32;
  }
  uint32_t c = (uint32_t)acc * 38u, c2;
  ADD_CC(u[0], u[0], c);
#pragma unroll
  for (int j = 1; j < 8; j++) ADDC_CC(u[j], u[j], 0);
  ADDC(c2, 0, 0);
  r[0] = u[0] + 38u * c2;
#pragma unroll
  for (int j = 1; j < 8; j++) r[j] = u[j];
}

DI void f_mul(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
  uint32_t t[16];
  mul_wide(t, a, b);
  f_reduce(r, t);
}
DI void f_sqr(uint32_t r[8], const uint32_t a[8]) { f_mul(r, a, a); }

DI void f_add(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
  uint32_t c;
  ADD_CC(r[0], a[0], b[0]);
#pragma unroll
  for (int j = 1; j < 8; j++) ADDC_CC(r[j], a[j], b[j]);
  ADDC(c, 0, 0);
  ADD_CC(r[0], r[0], 38u * c);
#pragma unroll
  for (int j = 1; j < 8; j++) ADDC_CC(r[j], r[j], 0);
  ADDC(c, 0, 0);
  r[0] += 38u * c;
}

DI void f_sub(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
  uint32_t bw;
  SUB_CC(r[0], a[0], b[0]);
#pragma unroll
  for (int j = 1; j < 8; j++) SUBC_CC(r[j], a[j], b[j]);
  SUBC(bw, 0, 0);
  SUB_CC(r[0], r[0], 38u & bw);
#pragma unroll
  for (int j = 1; j < 8; j++) SUBC_CC(r[j], r[j], 0);
  SUBC(bw, 0, 0);
  r[0] -= 38u & bw;
}

DI void f_canon(uint32_t r[8]) {
  uint32_t top = r[7] >> 31;
  r[7] &= 0x7FFFFFFFu;
  ADD_CC(r[0], r[0], 19u * top);
#pragma unroll
  for (int j = 1; j < 7; j++) ADDC_CC(r[j], r[j], 0);
  ADDC(r[7], r[7], 0);
  uint32_t t[8];
  ADD_CC(t[0], r[0], 19u);
#pragma unroll
  for (int j = 1; j < 7; j++) ADDC_CC(t[j], r[j], 0);
  ADDC(t[7], r[7], 0);
  bool ge = (t[7] >> 31) != 0;  // r >= p
  t[7] &= 0x7FFFFFFFu;
#pragma unroll
  for (int j = 0; j < 8; j++) r[j] = ge ? t[j] : r[j];
}

DI void f_sqr_n(uint32_t r[8], int n) {
#pragma unroll 1
  for (int i = 0; i < n; i++) f_sqr(r, r);
}

// z^(p-2), ref10 addition chain
DI void f_inv(uint32_t out[8], const uint32_t z[8]) {
  uint32_t t0[8], t1[8], t2[8], t3[8];
  f_sqr(t0, z);
  f_sqr(t1, t0); f_sqr(t1, t1);
  f_mul(t1, z, t1);
  f_mul(t0, t0, t1);
  f_sqr(t2, t0);
  f_mul(t1, t1, t2);
  copy8(t2, t1); f_sqr_n(t2, 5); f_mul(t1, t2, t1);
  copy8(t2, t1); f_sqr_n(t2, 10); f_mul(t2, t2, t1);
  copy8(t3, t2); f_sqr_n(t3, 20); f_mul(t2, t3, t2);
  f_sqr_n(t2, 10); f_mul(t1, t2, t1);
  copy8(t2, t1); f_sqr_n(t2, 50); f_mul(t2, t2, t1);
  copy8(t3, t2); f_sqr_n(t3, 100); f_mul(t2, t3, t2);
  f_sqr_n(t2, 50); f_mul(t1, t2, t1);
  f_sqr_n(t1, 5); f_mul(out, t1, t0);
}

// ------------------------------------------------------------- group (extended coords, a = -1)

struct P3 {
  uint32_t X[8], Y[8], Z[8], T[8];
};

// p += q, q in Niels form (y+x, y-x, 2dxy). need_t = false skips T (the last add: only X, Y, Z
// are used afterwards).
DI void p3_madd(P3& p, const uint32_t ypx[8], const uint32_t ymx[8], const uint32_t xy2d[8], bool need_t = true) {
  uint32_t A[8], B[8], C[8], D[8], E[8], F[8], G[8], H[8];
  f_sub(A, p.Y, p.X);
  f_mul(A, A, ymx);
  f_add(B, p.Y, p.X);
  f_mul(B, B, ypx);
  f_mul(C, p.T, xy2d);
  f_add(D, p.Z, p.Z);
  f_sub(E, B, A);
  f_sub(F, D, C);
  f_add(G, D, C);
  f_add(H, B, A);
  f_mul(p.X, E, F);
  f_mul(p.Y, G, H);
  if (need_t) f_mul(p.T, E, H);
  f_mul(p.Z, F, G);
}

// p = q (Niels form): what p3_madd gives for p = identity, with 1 multiplication instead of 7.
// E = 2x, H = 2y; (X:Y:Z:T) = (2E : 2H : 4 : EH) = (x : y : 1 : xy) scaled by 4.
DI void p3_set(P3& p, const uint32_t ypx[8], const uint32_t ymx[8]) {
  uint32_t E[8], H[8];
  f_sub(E, ypx, ymx);
  f_add(H, ypx, ymx);
  f_mul(p.T, E, H);
  f_add(p.X, E, E);
  f_add(p.Y, H, H);
#pragma unroll
  for (int k = 0; k < 8; k++) p.Z[k] = k == 0 ? 4 : 0;
}

// p += d * 256^w * B, branch-free (warps never diverge on the digit's sign or zero):
// tab[w][|d|] holds |d| * 256^w * B in Niels form, entry 0 is the identity.
// MODE 0: p += q, 1: p = q (first digit, p not read). need_t = false: the last digit, T is not needed.
// (A runtime flag, not a template: a second copy of p3_madd made the kernels slower.)
template <int W, int MODE = 0>
DI void madd_digit(P3& p, const uint32_t* tab, int w, int d, bool need_t = true) {
  const int a = d < 0 ? -d : d;
  const uint4* e = reinterpret_cast<const uint4*>(tab + ((size_t)w * Tab<W>::ENTRIES + a) * 24);
  uint32_t t[24];
#pragma unroll
  for (int k = 0; k < 6; k++) {
    uint4 v = __ldg(e + k);
    t[4 * k] = v.x; t[4 * k + 1] = v.y; t[4 * k + 2] = v.z; t[4 * k + 3] = v.w;
  }
  // -(x, y) = (-x, y): swap y+x with y-x and negate 2dxy
  const bool neg = d < 0;
  uint32_t ypx[8], ymx[8], xy2d[8], nxy[8];
  const uint32_t z[8] = {0, 0, 0, 0, 0, 0, 0, 0};
#pragma unroll
  for (int k = 0; k < 8; k++) xy2d[k] = t[16 + k];
  f_sub(nxy, z, xy2d);
#pragma unroll
  for (int k = 0; k < 8; k++) {
    ypx[k] = neg ? t[8 + k] : t[k];
    ymx[k] = neg ? t[k] : t[8 + k];
    xy2d[k] = neg ? nxy[k] : xy2d[k];
  }
  if (MODE == 1)
    p3_set(p, ypx, ymx);
  else
    p3_madd(p, ypx, ymx, xy2d, need_t);
}

// A = a*B with a = clamp(sha512(seed)[0..32]), as NWIN signed radix-2^W digits.
template <int W>
DI void scalarmult_base(P3& p, const uint64_t h[4], const uint32_t* tab) {
  constexpr int NWIN = Tab<W>::NWIN;
  // scalar as little-endian 32-bit words (sha512 output bytes are little-endian scalar bytes)
  uint32_t s[12];
#pragma unroll
  for (int k = 0; k < 4; k++) {
    uint64_t v = h[k];
    s[2 * k] = bswap32((uint32_t)(v >> 32));
    s[2 * k + 1] = bswap32((uint32_t)v);
  }
  s[0] &= ~7u;
  s[7] = (s[7] & 0x7FFFFFFFu) | 0x40000000u;
  s[8] = s[9] = s[10] = s[11] = 0;
  // digits in [-2^(W-1), 2^(W-1)); the top one stays non-negative and small
  int32_t e[NWIN];
  int carry = 0;
#pragma unroll
  for (int i = 0; i < NWIN; i++) {
    const int bit = i * W, w = bit >> 5, off = bit & 31;
    uint32_t raw = s[w] >> off;
    if (off + W > 32) raw |= s[w + 1] << (32 - off);
    int v = (int)(raw & ((1u << W) - 1)) + carry;
    carry = i < NWIN - 1 && v >= (1 << (W - 1));
    e[i] = v - (carry << W);
  }
  madd_digit<W, 1>(p, tab, 0, e[0]);
#pragma unroll 1
  for (int w = 1; w < NWIN; w++) madd_digit<W>(p, tab, w, e[w], w < NWIN - 1);
}

// ------------------------------------------------------------- kernel

__constant__ uint32_t c_key[8];
__constant__ uint32_t c_ton_code[8];  // wallet v5r1 code cell hash, big-endian words
__constant__ uint32_t c_ton_wid;

struct EdArgs {
  const uint32_t* table;
  Hit* hits;
  uint32_t* nhits;
  uint32_t T;
  int nsteps;
  unsigned long long ctr;
};

DI void emit_seed(uint32_t slot, uint32_t tid, uint32_t pat, uint32_t score, const uint32_t seed[8], const EdArgs& A) {
  Hit h{tid, pat, 0, 0, 0, score, slot, {0}};
#pragma unroll
  for (int k = 0; k < 8; k++) h.seed[k] = seed[k];
  emit_hit(A.hits, A.nhits, h);
}

// Solana: the address is base58 of the public key.
template <bool IDX>
DI void check_sol(const uint32_t n[8], const uint32_t seed[8], uint32_t tid, const EdArgs& A) {
  // the address is one '1' per leading zero byte (z of them), then base58(n)
  int lz = 0;
#pragma unroll
  for (int k = 0; k < 8; k++) {
    if (lz != 32 * k) break;
    lz += n[k] ? __clz(n[k]) : 32;
  }
  const int z = lz >> 3;
  uint8_t dig[45];
  int len = 45, have = 0;  // base58 passes computed so far (9 = all, then len is known)
  auto digits = [&](int need) {
    if (have >= need) return;
    if (need >= 9) {
      b58_digits<8, 9>(n, dig);
      len = 45;
      while (len > 1 && dig[len - 1] == 0) len--;
      have = 9;
    } else {
      b58_low_digits<8>(n, dig, need);
      have = need;
    }
  };
  auto match = [&](const DevPattern& P) {
    if (P.nrange) {
      bool in = in_range<8>(n, P.rlo[0], P.rhi[0]);
      if (!in && P.nrange > 1) in = in_range<8>(n, P.rlo[1], P.rhi[1]);
      if (!in) return false;
    }
    if (P.ndig) {
      digits(P.npass ? (int)P.npass : 9);
      for (uint32_t k = 0; k < P.ndig; k++) {
        const int pos = P.dpos[k];
        const int i = P.dstart[k] ? len - 1 - (pos - z) : pos;  // digit index, 0 = last char
        const int v = i < len ? dig[i] : i < len + z ? 0 : -1;    // past the digits: the '1's
        if (v != P.dval[k]) return false;
      }
    }
    return true;
  };
  auto key = [&](int k) -> uint64_t {
    if (k == 0) return (uint64_t)n[0] << 32 | n[1];
    digits(2);
    uint64_t v = 0;
#pragma unroll
    for (int i = 0; i < 10; i++) v = v * 58 + dig[i];
    return v << 5;
  };
  const int hitp = find_pattern<IDX, 0>(match, key);
  uint32_t score = 0;
  if (c_cfg[0].score) {
    digits(9);
    score = run_score<0>([&](int i) { return i < z ? 0u : (uint32_t)dig[len - 1 - (i - z)]; }, z + len, cls_mask<0>());
  }
  if (hitp >= 0 || (c_cfg[0].score && score >= c_cfg[0].min_score))
    emit_seed(0, tid, hitp >= 0 ? (uint32_t)hitp : BEAUTY_HIT, score, seed, A);
}

// OR a 32-bit value into a big-endian bit stream at a (compile-time) bit position.
DI void put32(uint32_t* w, int bitpos, uint32_t v) {
  int i = bitpos >> 5, sh = bitpos & 31;
  w[i] |= v >> sh;
  if (sh) w[i + 1] |= v << (32 - sh);
}

// TON wallet v5r1 address of public key `pub` (big-endian words) as the 36-byte
// user-friendly form [0x51, 0x00, hash(32), crc16(2)] in 9 big-endian words; crc left 0.
DI void ton_address_words(const uint32_t pub[8], uint32_t S[9]) {
  // data cell repr: d1=0, d2=81, then bits 1 | seqno:32 | wallet_id:32 | pubkey:256 | 0 | tag
  uint32_t w[16];
#pragma unroll
  for (int i = 0; i < 16; i++) w[i] = 0;
  w[0] = 0x00518000u;
  put32(w, 49, c_ton_wid);
#pragma unroll
  for (int k = 0; k < 8; k++) put32(w, 81 + 32 * k, pub[k]);
  w[10] |= 1u << 13;  // completion tag at bit 338
  w[10] |= 0x80u;     // sha256 padding at bit 344
  w[15] = 344;
  uint32_t hd[8] = {SHA256_IV_LIST};
  sha256_compress(hd, w);

  // StateInit repr: 02 01 34 | depth(code)=6 | depth(data)=0 | code hash | data hash  (71 bytes)
  uint32_t W[32];
#pragma unroll
  for (int i = 0; i < 32; i++) W[i] = 0;
  W[0] = 0x02013400u;
  W[1] = 0x06000000u;
#pragma unroll
  for (int k = 0; k < 8; k++) put32(W, 56 + 32 * k, c_ton_code[k]);
#pragma unroll
  for (int k = 0; k < 8; k++) put32(W, 312 + 32 * k, hd[k]);
  W[17] |= 0x80u;  // padding at bit 568
  W[31] = 568;
  uint32_t h[8] = {SHA256_IV_LIST};
  sha256_compress(h, W);
  sha256_compress(h, W + 16);

  S[0] = 0x51000000u | (h[0] >> 16);
#pragma unroll
  for (int k = 1; k < 8; k++) S[k] = (h[k - 1] << 16) | (h[k] >> 16);
  S[8] = h[7] << 16;
}

DI uint32_t crc16_xmodem34(const uint32_t S[9]) {
  uint32_t crc = 0;
#pragma unroll
  for (int i = 0; i < 34; i++) {
    crc ^= ((S[i >> 2] >> (24 - 8 * (i & 3))) & 0xFFu) << 8;
#pragma unroll
    for (int k = 0; k < 8; k++) crc = (crc & 0x8000u) ? ((crc << 1) ^ 0x1021u) : (crc << 1);
    crc &= 0xFFFFu;
  }
  return crc;
}

DI uint32_t b64_char(const uint32_t S[9], int i) {
  int b = 6 * i, w = b >> 5, off = b & 31;
  uint32_t v = S[w] << off;
  if (off > 26) v |= S[w + 1] >> (32 - off);
  return v >> 26;
}

template <bool IDX>
DI void check_ton(const uint32_t n[8], const uint32_t seed[8], uint32_t tid, const EdArgs& A) {
  uint32_t S[9];
  ton_address_words(n, S);
  if (c_cfg[1].need_digits) S[8] |= crc16_xmodem34(S);
  auto match = [&](const DevPattern& P) {
    uint32_t diff = 0;
#pragma unroll
    for (int k = 0; k < 9; k++) diff |= (S[k] ^ P.bval[k]) & P.bmask[k];
    return diff == 0;
  };
  auto key = [&](int k) -> uint64_t {
    if (k == 0) return (((uint64_t)S[0] << 32 | S[1]) << 18) | (S[2] >> 14);  // chars 3..13
    uint64_t v = 0;  // chars 47, 46, .. 38
#pragma unroll
    for (int i = 0; i < 10; i++) v = v << 6 | b64_char(S, 47 - i);
    return v << 4;
  };
  const int hitp = find_pattern<IDX, 1>(match, key);
  uint32_t score = 0;
  if (c_cfg[1].score) {
    const int s0 = (int)c_cfg[1].b_start;
    score = run_score<1>([&](int i) { return b64_char(S, s0 + i); }, 48 - s0, cls_mask<1>());
  }
  if (hitp >= 0 || (c_cfg[1].score && score >= c_cfg[1].min_score))
    emit_seed(1, tid, hitp >= 0 ? (uint32_t)hitp : BEAUTY_HIT, score, seed, A);
}

// MODE: 0 Solana, 1 TON, 2 both (multi: the TON hashes come on top of the shared key)
template <int MODE, int W, bool IDX>
__global__ void __launch_bounds__(256) ed_kernel(EdArgs A) {
  const uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid >= A.T) return;

#pragma unroll 1
  for (int step = 0; step < A.nsteps; step++) {
    uint32_t seeds[KPT][8], X[KPT][8], Y[KPT][8], Z[KPT][8];
#pragma unroll 1
    for (int j = 0; j < KPT; j += 2) {
      uint64_t blk = A.ctr + ((uint64_t)step * A.T + tid) * (KPT / 2) + j / 2;
      uint32_t out[16];
      chacha20_block(c_key, blk, out);
#pragma unroll
      for (int k = 0; k < 8; k++) {
        seeds[j][k] = out[k];
        seeds[j + 1][k] = out[8 + k];
      }
    }
#pragma unroll 1
    for (int j = 0; j < KPT; j++) {
      uint64_t h[4];
      sha512_32(seeds[j], h);
      P3 p;
      scalarmult_base<W>(p, h, A.table);
      copy8(X[j], p.X);
      copy8(Y[j], p.Y);
      copy8(Z[j], p.Z);
    }
    // batched inversion of Z
    uint32_t pre[KPT][8], inv[8], zi[8], x[8], y[8];
    copy8(pre[0], Z[0]);
#pragma unroll 1
    for (int j = 1; j < KPT; j++) f_mul(pre[j], pre[j - 1], Z[j]);
    f_inv(inv, pre[KPT - 1]);
#pragma unroll 1
    for (int j = KPT - 1; j >= 0; j--) {
      if (j > 0) {
        f_mul(zi, inv, pre[j - 1]);
        f_mul(inv, inv, Z[j]);
      } else {
        copy8(zi, inv);
      }
      f_mul(x, X[j], zi);
      f_mul(y, Y[j], zi);
      f_canon(x);
      f_canon(y);
      // public key bytes = y (LE) with the sign of x in the top bit, as big-endian words
      uint32_t n[8];
#pragma unroll
      for (int k = 0; k < 8; k++) n[k] = bswap32(k == 7 ? (y[7] | (x[0] << 31)) : y[k]);
      if (MODE != 1) check_sol<IDX>(n, seeds[j], tid, A);
      if (MODE != 0) check_ton<IDX>(n, seeds[j], tid, A);
    }
  }
}

double now_s() {
  using namespace std::chrono;
  return duration<double>(steady_clock::now().time_since_epoch()).count();
}

}  // namespace

// Fixed-base table on the CPU. Each window is a chain P += B_w in extended coordinates,
// normalised with one batched inversion, so building ~0.5M entries takes well under a second.
template <int W>
static void build_table(std::vector<uint32_t>& tab) {
  using namespace hc;
  constexpr int NWIN = Tab<W>::NWIN, ENTRIES = Tab<W>::ENTRIES;
  tab.assign(Tab<W>::WORDS, 0);
  std::vector<EPt> bases(NWIN);
  bases[0] = e_base();
  for (int w = 1; w < NWIN; w++) {
    bases[w] = bases[w - 1];
    for (int i = 0; i < W; i++) bases[w] = e_add(bases[w], bases[w]);
  }
  auto window = [&](int w) {
    const Field& F = F25519;
    const U256 d2 = F.add(ED_D, ED_D), one = U256::from_u64(1);
    const U256 qx = bases[w].x, qy = bases[w].y, qt2d = F.mul(d2, F.mul(qx, qy));
    const U256 qypx = F.add(qy, qx), qymx = F.sub(qy, qx);
    // walk the chain in blocks; each block is normalised with one batched inversion
    constexpr int BLK = 4096;
    std::vector<U256> X(BLK), Y(BLK), Z(BLK), pre(BLK);
    U256 x = U256(), y = one, z = one, t = U256();  // identity
    for (int j0 = 0; j0 < ENTRIES; j0 += BLK) {
      const int n = std::min(BLK, ENTRIES - j0);
      for (int j = 0; j < n; j++) {
        X[j] = x; Y[j] = y; Z[j] = z;
        // (x:y:z:t) += (qx, qy) with the same formulas as the GPU's p3_madd
        U256 A = F.mul(F.sub(y, x), qymx), B = F.mul(F.add(y, x), qypx);
        U256 C = F.mul(t, qt2d), D = F.add(z, z);
        U256 E = F.sub(B, A), Fv = F.sub(D, C), G = F.add(D, C), H = F.add(B, A);
        x = F.mul(E, Fv); y = F.mul(G, H); t = F.mul(E, H); z = F.mul(Fv, G);
      }
      pre[0] = Z[0];
      for (int j = 1; j < n; j++) pre[j] = F.mul(pre[j - 1], Z[j]);
      U256 inv = F.inv(pre[n - 1]);
      for (int j = n - 1; j >= 0; j--) {
        U256 zi = j ? F.mul(inv, pre[j - 1]) : inv;
        if (j) inv = F.mul(inv, Z[j]);
        U256 ax = F.mul(X[j], zi), ay = F.mul(Y[j], zi);
        uint32_t* e = &tab[((size_t)w * ENTRIES + j0 + j) * 24];
        F.add(ay, ax).to_u32(e);
        F.sub(ay, ax).to_u32(e + 8);
        F.mul(d2, F.mul(ax, ay)).to_u32(e + 16);
      }
    }
  };
  std::vector<std::thread> pool;
  for (int w = 0; w < NWIN; w++) pool.emplace_back(window, w);
  for (auto& th : pool) th.join();
}

template <int W, bool IDX>
static void (*pick_ed(int mode))(EdArgs) {
  return mode == 0 ? ed_kernel<0, W, IDX> : mode == 1 ? ed_kernel<1, W, IDX> : ed_kernel<2, W, IDX>;
}

double run_ed(const PatternSet& ps, const EngineOptions& eo, Reporter& rep) {
  return run_ed(std::vector<const PatternSet*>{&ps}, eo, rep);
}

double run_ed(const std::vector<const PatternSet*>& sets, const EngineOptions& eo, Reporter& rep) {
  using namespace hc;
  const PatternSet* by_slot[NSLOT] = {};
  bool idx = false;
  for (const PatternSet* p : sets) {
    if (!is_ed25519(p->chain)) throw std::logic_error("run_ed: not an ed25519 chain");
    const int sl = p->chain == Chain::TON ? 1 : 0;
    if (by_slot[sl]) throw std::runtime_error(std::string("chain ") + chain_name(p->chain) + " given twice");
    by_slot[sl] = p;
    idx |= !p->idx[0].empty() || !p->idx[1].empty();
  }
  const int mode = by_slot[0] && by_slot[1] ? 2 : by_slot[1] ? 1 : 0;
  CUDA_CHECK(cudaSetDevice(eo.device));
  cudaDeviceProp prop;
  CUDA_CHECK(cudaGetDeviceProperties(&prop, eo.device));

  // ---- base-point table in Niels form: tab[w][j] = j * 2^(W*w) * B.
  // The big table needs 2.4 GB of VRAM (+ the same in RAM while it is built).
  size_t free_mem = 0, total_mem = 0;
  CUDA_CHECK(cudaMemGetInfo(&free_mem, &total_mem));
  const bool big = free_mem > Tab<22>::WORDS * 4 + (size_t(3) << 30);
  std::vector<uint32_t> tab;
  if (big) build_table<22>(tab);
  else build_table<16>(tab);

  void (*kern)(EdArgs) = idx ? (big ? pick_ed<22, true>(mode) : pick_ed<16, true>(mode))
                             : (big ? pick_ed<22, false>(mode) : pick_ed<16, false>(mode));
  const size_t tab_bytes = tab.size() * 4;
  int threads = eo.threads ? eo.threads : 128;
  int per_sm = 0;
  CUDA_CHECK(cudaOccupancyMaxActiveBlocksPerMultiprocessor(&per_sm, kern, threads, 0));
  int blocks = eo.blocks ? eo.blocks : prop.multiProcessorCount * std::max(1, per_sm);
  const uint32_t T = (uint32_t)blocks * threads;

  uint32_t key[8];
  os_random(key, sizeof key);
  CUDA_CHECK(cudaMemcpyToSymbol(c_key, key, sizeof key));
  secure_zero(key, sizeof key);

  EdArgs A{};
  A.T = T;
  uint32_t* d_tab;
  CUDA_CHECK(cudaMalloc(&d_tab, tab_bytes));
  CUDA_CHECK(cudaMemcpy(d_tab, tab.data(), tab_bytes, cudaMemcpyHostToDevice));
  std::vector<uint32_t>().swap(tab);  // release the host copy
  A.table = d_tab;
  CUDA_CHECK(cudaMalloc(&A.hits, MAX_HITS * sizeof(Hit)));
  CUDA_CHECK(cudaMalloc(&A.nhits, 4));
  CUDA_CHECK(cudaMemset(A.nhits, 0, 4));
  std::vector<std::unique_ptr<DevPatterns>> dev_pats;
  for (const PatternSet* p : sets) dev_pats.emplace_back(new DevPatterns(*p, p->chain == Chain::TON ? 1 : 0));
  uint32_t code[8];
  for (int k = 0; k < 8; k++)
    code[k] = (uint32_t)TON_W5_CODE_HASH[4 * k] << 24 | (uint32_t)TON_W5_CODE_HASH[4 * k + 1] << 16 |
              (uint32_t)TON_W5_CODE_HASH[4 * k + 2] << 8 | TON_W5_CODE_HASH[4 * k + 3];
  CUDA_CHECK(cudaMemcpyToSymbol(c_ton_code, code, sizeof code));
  const uint32_t wid = TON_WALLET_ID_MAINNET;
  CUDA_CHECK(cudaMemcpyToSymbol(c_ton_wid, &wid, sizeof wid));

  unsigned long long ctr = 0;  // ChaCha20 block counter, never reused within a run
  std::vector<Hit> hits(MAX_HITS);
  int nsteps = 1, run_steps = 1;
  double keys = 0, t_start = now_s(), t_print = 0;
  cudaEvent_t ev0, ev1;
  CUDA_CHECK(cudaEventCreate(&ev0));
  CUDA_CHECK(cudaEventCreate(&ev1));
  auto launch = [&]() {
    A.nsteps = run_steps = nsteps;
    A.ctr = ctr;
    ctr += (unsigned long long)T * nsteps * (KPT / 2);
    CUDA_CHECK(cudaEventRecord(ev0));
    kern<<<blocks, threads>>>(A);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaEventRecord(ev1));
  };
  launch();
  bool running = true;
  while (running) {
    CUDA_CHECK(cudaEventSynchronize(ev1));
    float ms = 0;
    CUDA_CHECK(cudaEventElapsedTime(&ms, ev0, ev1));
    keys += (double)T * run_steps * KPT;

    uint32_t nh = 0, n = 0;
    CUDA_CHECK(cudaMemcpy(&nh, A.nhits, 4, cudaMemcpyDeviceToHost));
    if (nh) {
      n = std::min<uint32_t>(nh, MAX_HITS);
      CUDA_CHECK(cudaMemcpy(hits.data(), A.hits, n * sizeof(Hit), cudaMemcpyDeviceToHost));
      CUDA_CHECK(cudaMemset(A.nhits, 0, 4));
      if (nh > MAX_HITS) rep.dropped(nh - MAX_HITS);
    }

    // keep each launch around 150 ms, then start the next one so the GPU keeps
    // working while the CPU re-verifies this batch
    if (ms < 75 && nsteps < 4096) nsteps *= 2;
    else if (ms > 300 && nsteps > 1) nsteps /= 2;
    double el = now_s() - t_start;
    running = !g_stop && !rep.done() && !(eo.bench > 0 && el >= eo.bench);
    if (running) launch();

    {  // re-verify every GPU hit on the CPU before reporting it
      for (uint32_t i = 0; i < n && !rep.done(); i++) {
        Hit& h = hits[i];
        const PatternSet* pp = h.pad < NSLOT ? by_slot[h.pad] : nullptr;
        if (!pp) {
          rep.reject("hit for an unknown chain slot");
          continue;
        }
        const PatternSet& ps = *pp;
        const bool ton = ps.chain == Chain::TON;
        uint8_t kp[64];
        memcpy(kp, h.seed, 32);
        ed_pubkey(kp, kp + 32);
        uint8_t acct[32];
        if (ton) ton_account_hash(kp + 32, wid, acct);
        std::string addr = ton ? ton_address(acct, false) : sol_address(kp + 32);
        std::string what;
        bool ok;
        if (h.pat == BEAUTY_HIT) {
          int sc = score_address(ps, addr);
          ok = sc >= ps.min_score;
          what = score_what(ps, sc);
        } else {
          ok = h.pat < ps.pats.size() && match_one(ps.pats[h.pat], addr);
          what = ok ? describe(ps, h.pat) : "";
        }
        if (!ok) {
          if (h.pat == BEAUTY_HIT || h.pat >= ps.pats.size() || !may_overmatch(ps, h.pat)) rep.reject(addr);
        } else {
          if (ton) {
            KV info = {{"wallet", "W5 (v5r1), mainnet, workchain 0"},
                       {"bounceable", ton_address(acct, true)},
                       {"raw", "0:" + hex(acct, 32)},
                       {"public_key", hex(kp + 32, 32)}};
            KV secret = {{"private_key", hex(kp, 32)}};
            rep.found(ps.chain, addr, what, info, secret);
          } else {
            std::string json = "[";
            for (int k = 0; k < 64; k++) json += std::to_string(kp[k]) + (k < 63 ? "," : "]");
            KV secret = {{"private_key_base58", base58(kp, 64)}, {"keypair_json", json}};
            rep.found(ps.chain, addr, what, {}, secret);
          }
        }
        secure_zero(kp, sizeof kp);
        secure_zero(&h, sizeof h);
      }
    }

    if (rep.done()) running = false;
    el = now_s() - t_start;
    if (el - t_print > 1.0) {
      rep.progress(keys, el, false);
      t_print = el;
    }
  }
  CUDA_CHECK(cudaDeviceSynchronize());  // a launch issued before the last results may still run
  rep.progress(keys, now_s() - t_start, true);
  cudaEventDestroy(ev0);
  cudaEventDestroy(ev1);
  // the hit buffer holds seeds of found wallets and c_key derives every seed of this run
  const uint32_t zero[8] = {0};
  cudaMemcpyToSymbol(c_key, zero, sizeof zero);
  cudaMemset(A.hits, 0, MAX_HITS * sizeof(Hit));
  secure_zero(hits.data(), hits.size() * sizeof(Hit));
  cudaFree(d_tab);
  cudaFree(A.hits);
  cudaFree(A.nhits);
  return keys;
}
