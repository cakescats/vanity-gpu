// EVM / TRON search on secp256k1.
//
// Split-key design: the host draws k0 from the OS CSPRNG and gives the GPU only the
// public point P0 = k0*G. Each GPU thread walks its own window of points
// P0 + d*G, so a hit only reveals an offset d (plus sign / endomorphism). The final
// private key  k = ±λ^e (k0 + d) mod n  is assembled and verified on the CPU.
#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <thread>
#include <vector>

#include <memory>

#define NSLOT 5  // one pattern set per chain kernel variant (K_EVM .. K_BTC_P2SH)
#include "common.cuh"
#include "cpu_secp.h"
#include "hashes.cuh"
#include "hostcrypto.h"
#include "report.h"
#include "rng.h"
#include "secp_field.cuh"
#include "upload.cuh"

using namespace secp;

namespace {

constexpr int HALF = 256;       // points on each side of the group centre
constexpr int GRP = 2 * HALF;   // points per batched inversion
constexpr int VARIANTS = 6;     // ±y × {1, β, β²}
static_assert(HALF == SECP_HALF, "CPU workers walk the same groups");

#define CUDA_CHECK(x)                                                                   \
  do {                                                                                  \
    cudaError_t e_ = (x);                                                               \
    if (e_ != cudaSuccess)                                                              \
      throw std::runtime_error(std::string("CUDA: ") + cudaGetErrorString(e_) + " at " + \
                               __FILE__ + ":" + std::to_string(__LINE__));              \
  } while (0)

__constant__ uint32_t c_beta[8];
__constant__ uint32_t c_g2x[8], c_g2y[8];  // GRP * G

struct SecpArgs {
  uint32_t* stx;  // thread centres, SoA [8][T]
  uint32_t* sty;
  unsigned long long* stm;  // group counter per thread
  const uint32_t* tgx;      // (i+1)*G, i < HALF, AoS [HALF][8]
  const uint32_t* tgy;
  Hit* hits;
  uint32_t* nhits;
  uint32_t T;
  int nsteps;
};

// Kernel variants (CHAIN template argument); each single chain is also its pattern slot.
// K_MULTI checks every chain enabled in c_on with one EC walk: EVM and TRON share the
// Keccak hash, the three Bitcoin types share hash160.
constexpr int K_EVM = 0, K_TRON = 1, K_BTC = 2, K_BTC_LEGACY = 3, K_BTC_P2SH = 4, K_MULTI = 5;
__constant__ uint32_t c_on;  // K_MULTI: bit k = slot k is searched

// Test one address: a = the 20-byte hash (EVM/TRON: keccak, Bitcoin: hash160 or the
// P2SH script hash) as 5 big-endian words.
// LEAD: compile the --beauty lead-run prefilter of TRON / P2SH in. A separate kernel variant:
// its code alone (never run) made the plain P2SH prefix search 16% slower (2.19 -> 1.84 Gkey/s).
template <int CHAIN, bool IDX, bool LEAD = false>
DI void check_addr(const uint32_t a[5], uint32_t tid, uint64_t m, int idx, uint32_t flags, const SecpArgs& A) {
  int hp = -1;
  uint32_t score = 0;
  if constexpr (CHAIN == K_EVM) {  // nibble masks
    auto match = [&](const DevPattern& P) {
      return !(((a[0] ^ P.hval[0]) & P.hmask[0]) | ((a[1] ^ P.hval[1]) & P.hmask[1]) |
               ((a[2] ^ P.hval[2]) & P.hmask[2]) | ((a[3] ^ P.hval[3]) & P.hmask[3]) |
               ((a[4] ^ P.hval[4]) & P.hmask[4]));
    };
    auto key = [&](int k) -> uint64_t {
      return k == 0 ? ((uint64_t)a[0] << 32 | a[1]) : nibrev64((uint64_t)a[3] << 32 | a[4]);
    };
    hp = find_pattern<IDX, CHAIN>(match, key);
    if (c_cfg[CHAIN].score) {
      auto nib = [&](int i) { return (a[i >> 3] >> (28 - 4 * (i & 7))) & 15u; };
      if (c_cfg[CHAIN].score == 2 && c_cfg[CHAIN].cls_case) {
        // first with letters of either case, then with the EIP-55 case of the survivors
        const uint64_t m22 = cls_mask<CHAIN>();
        const uint64_t ci = (m22 & 0xFFFFu) | (((m22 >> 16) & 0x3Fu) << 10);
        score = run_score<CHAIN>(nib, 40, ci);
        if (score >= c_cfg[CHAIN].min_score) {
          uint32_t hn[5];
          eip55_hash(a, hn);
          auto cnib = [&](int i) {
            uint32_t v = nib(i);
            if (v >= 10 && ((hn[i >> 3] >> (28 - 4 * (i & 7))) & 15u) >= 8) v += 6;  // A-F
            return v;
          };
          score = run_score<CHAIN>(cnib, 40, m22);
        }
      } else {
        score = run_score<CHAIN>(nib, 40, cls_mask<CHAIN>());
      }
    }
  } else if constexpr (CHAIN == K_BTC) {  // bech32: 5-bit masks over hash160 + checksum
    uint32_t S[6] = {a[0], a[1], a[2], a[3], a[4], 0};
    if (c_cfg[CHAIN].need_digits) S[5] = bech32_checksum(a, c_cfg[CHAIN].bech_init) << 2;
    auto match = [&](const DevPattern& P) {
      uint32_t diff = 0;
#pragma unroll
      for (int k = 0; k < 6; k++) diff |= (S[k] ^ P.bval[k]) & P.bmask[k];
      return diff == 0;
    };
    auto key = [&](int k) -> uint64_t {
      if (k == 0) return (uint64_t)S[0] << 32 | S[1];
      uint64_t v = 0;  // chars 37, 36, .. 26
#pragma unroll
      for (int i = 0; i < 12; i++) v = v << 5 | b5_at(S, 37 - i);
      return v << 4;
    };
    hp = find_pattern<IDX, CHAIN>(match, key);
    if (c_cfg[CHAIN].score) score = run_score<CHAIN>([&](int i) { return b5_at(S, i); }, 38, cls_mask<CHAIN>());
  } else if constexpr (CHAIN == K_BTC_LEGACY) {
    // address = '1' + one '1' per leading zero byte of the hash (z) + base58(hash || checksum)
    int lz = 0;
#pragma unroll
    for (int k = 0; k < 5; k++) {
      if (lz != 32 * k) break;
      lz += a[k] ? __clz(a[k]) : 32;
    }
    const int z = lz >> 3;
    uint8_t dig[35];
    uint32_t n[6];
    int D = 35, have = 0;  // base58 passes computed so far (7 = all, then D is known)
    auto digits = [&](int need) {
      if (have == 0) {
#pragma unroll
        for (int k = 0; k < 5; k++) n[k] = a[k];
        n[5] = b58check_checksum<0x00>(a);
      }
      if (have >= need) return;
      if (need >= 7) {
        b58_digits<6, 7>(n, dig);
        D = 35;
        while (D > 1 && dig[D - 1] == 0) D--;
        have = 7;
      } else {
        b58_low_digits<6>(n, dig, need);
        have = need;
      }
    };
    auto match = [&](const DevPattern& P) {
      if (P.nrange) {
        bool in = in_range<5>(a, P.rlo[0], P.rhi[0]);
        if (!in && P.nrange > 1) in = in_range<5>(a, P.rlo[1], P.rhi[1]);
        if (!in) return false;
      }
      if (P.ndig) {
        digits(P.npass ? (int)P.npass : 7);
        const int zz = 1 + z;  // leading '1' characters
        for (uint32_t k = 0; k < P.ndig; k++) {
          const int pos = P.dpos[k];
          const int i = P.dstart[k] ? D - 1 - (pos - zz) : pos;  // digit index, 0 = last char
          const int v = i < D ? dig[i] : i < D + zz ? 0 : -1;
          if (v != P.dval[k]) return false;
        }
      }
      return true;
    };
    auto key = [&](int k) -> uint64_t {
      if (k == 0) return (uint64_t)a[0] << 32 | a[1];
      digits(2);
      uint64_t v = 0;
#pragma unroll
      for (int i = 0; i < 10; i++) v = v * 58 + dig[i];
      return v << 5;
    };
    hp = find_pattern<IDX, CHAIN>(match, key);
    if (c_cfg[CHAIN].score) {
      digits(7);
      score = run_score<CHAIN>([&](int i) { return i < z ? 0u : (uint32_t)dig[D - 1 - (i - z)]; }, z + D, cls_mask<CHAIN>());
    }
  } else {  // TRON, BTC P2SH: 34-char base58check, range on the payload, digits only when needed
    constexpr uint32_t VER = CHAIN == K_TRON ? 0x41u : 0x05u;
    uint8_t dig[35];
    uint32_t n[7];
    int have = 0;  // base58 passes computed so far (7 = all 34 digits)
    auto digits = [&](int need) {
      if (have == 0) {
        n[0] = VER;
#pragma unroll
        for (int k = 0; k < 5; k++) n[k + 1] = a[k];
        n[6] = b58check_checksum<VER>(a);
      }
      if (have < need) {
        if (need >= 7) b58_digits<7, 7>(n, dig);
        else b58_low_digits<7>(n, dig, need);
        have = need >= 7 ? 7 : need;
      }
    };
    auto match = [&](const DevPattern& P) {
      if (P.nrange && !in_range<5>(a, P.rlo[0], P.rhi[0])) return false;
      if (P.ndig) {
        digits(P.npass ? (int)P.npass : 7);
        if (!digits_ok(P, dig, 34)) return false;
      }
      return true;
    };
    auto key = [&](int k) -> uint64_t {
      if (k == 0) return (uint64_t)a[0] << 32 | a[1];
      digits(2);  // last 10 characters, last one most significant
      uint64_t v = 0;
#pragma unroll
      for (int i = 0; i < 10; i++) v = v * 58 + dig[i];
      return v << 5;
    };
    hp = find_pattern<IDX, CHAIN>(match, key);
    if (c_cfg[CHAIN].score) {
      bool full = true;
      if (LEAD && c_cfg[CHAIN].lead_k) {  // --beauty: skip the full digits unless the score can reach min_score
        digits(1);
        int R = 1;
        while (R < 5 && dig[R] == dig[0]) R++;
        if (R < 5) {
          const uint64_t T = (uint64_t)n[0] << 57 | (uint64_t)n[1] << 25 | (n[2] >> 7);
          const int64_t W = (int64_t)(__umul64hi(T, c_cfg[CHAIN].lead_mul) - c_cfg[CHAIN].lead_base);
          const int64_t c = __float2ll_rn((float)W * c_cfg[CHAIN].lead_inv);
          const int64_t d = W - c * (int64_t)c_cfg[CHAIN].lead_rep;
          full = d >= -2 && d <= 2;
        }
      }
      if (full) {
        digits(7);
        score = run_score<CHAIN>([&](int i) { return (uint32_t)dig[32 - i]; }, 33, cls_mask<CHAIN>());
      }
    }
  }
  if (hp >= 0) {
    Hit h{tid, (uint32_t)hp, m, idx, flags, 0, (uint32_t)CHAIN, {0}};
    emit_hit(A.hits, A.nhits, h);
  }
  if (c_cfg[CHAIN].score && score >= c_cfg[CHAIN].min_score) {
    Hit h{tid, BEAUTY_HIT, m, idx, flags, score, (uint32_t)CHAIN, {0}};
    emit_hit(A.hits, A.nhits, h);
  }
}

// Check the 6 keys that share the work of one point: (x,±y), (βx,±y), (β²x,±y).
template <int CHAIN, bool IDX, bool LEAD>
DI void check_point(const uint32_t x[8], const uint32_t y[8], uint32_t tid, uint64_t m, int idx,
                    const SecpArgs& A) {
  uint32_t xs[8];
  copy8(xs, x);
  if constexpr (CHAIN <= K_TRON) {
    uint32_t ny[8];
    fe_neg(ny, y);
#pragma unroll 1
    for (int e = 0; e < 3; e++) {
      if (e) fe_mul(xs, xs, c_beta);
#pragma unroll 1
      for (int n = 0; n < 2; n++) {
        uint32_t ys[8], a[5];
#pragma unroll
        for (int k = 0; k < 8; k++) ys[k] = n ? ny[k] : y[k];
        keccak_addr(xs, ys, a);
        check_addr<CHAIN, IDX, LEAD>(a, tid, m, idx, (uint32_t)(n | (e << 1)), A);
      }
    }
  } else if constexpr (CHAIN == K_MULTI) {
    const uint32_t on = c_on;
    const uint32_t odd = y[0] & 1u;
    uint32_t ny[8];
    if (on & 3u) fe_neg(ny, y);
#pragma unroll 1
    for (int e = 0; e < 3; e++) {
      if (e) fe_mul(xs, xs, c_beta);
#pragma unroll 1
      for (int n = 0; n < 2; n++) {
        const uint32_t fl = (uint32_t)(n | (e << 1));
        uint32_t a[5];
        if (on & 3u) {
          uint32_t ys[8];
#pragma unroll
          for (int k = 0; k < 8; k++) ys[k] = n ? ny[k] : y[k];
          keccak_addr(xs, ys, a);
          if (on & 1u) check_addr<K_EVM, IDX, LEAD>(a, tid, m, idx, fl, A);
          if (on & 2u) check_addr<K_TRON, IDX, LEAD>(a, tid, m, idx, fl, A);
        }
        if (on & 28u) {
          hash160_comp(xs, odd ^ (uint32_t)n, a);
          if (on & 4u) check_addr<K_BTC, IDX, LEAD>(a, tid, m, idx, fl, A);
          if (on & 8u) check_addr<K_BTC_LEGACY, IDX, LEAD>(a, tid, m, idx, fl, A);
          if (on & 16u) {
            uint32_t s[5];
            hash160_p2sh(a, s);
            check_addr<K_BTC_P2SH, IDX, LEAD>(s, tid, m, idx, fl, A);
          }
        }
      }
    }
  } else {  // Bitcoin: the compressed key needs only the parity of y (flipped by -y)
    const uint32_t odd = y[0] & 1u;
#pragma unroll 1
    for (int e = 0; e < 3; e++) {
      if (e) fe_mul(xs, xs, c_beta);
#pragma unroll 1
      for (int n = 0; n < 2; n++) {
        uint32_t a[5];
        hash160_comp(xs, odd ^ (uint32_t)n, a);
        if constexpr (CHAIN == K_BTC_P2SH) {
          uint32_t s[5];
          hash160_p2sh(a, s);
          check_addr<CHAIN, IDX, LEAD>(s, tid, m, idx, (uint32_t)(n | (e << 1)), A);
        } else {
          check_addr<CHAIN, IDX, LEAD>(a, tid, m, idx, (uint32_t)(n | (e << 1)), A);
        }
      }
    }
  }
}

// r = (x1,y1) + (x2,y2) given dxinv = 1 / (x2 - x1).
DI void affine_add(uint32_t rx[8], uint32_t ry[8], const uint32_t x1[8], const uint32_t y1[8],
                   const uint32_t x2[8], const uint32_t y2[8], const uint32_t dxinv[8]) {
  uint32_t lam[8], t[8];
  fe_sub(t, y2, y1);
  fe_mul(lam, t, dxinv);
  fe_sqr(t, lam);
  fe_sub(t, t, x1);
  fe_sub(rx, t, x2);
  fe_sub(t, x1, rx);
  fe_mul(t, lam, t);
  fe_sub(ry, t, y1);
}

template <int CHAIN, bool IDX, bool LEAD>
__global__ void __launch_bounds__(256) secp_kernel(SecpArgs A) {
  const uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid >= A.T) return;

  uint32_t cx[8], cy[8];
#pragma unroll
  for (int k = 0; k < 8; k++) {
    cx[k] = A.stx[k * A.T + tid];
    cy[k] = A.sty[k * A.T + tid];
  }
  uint64_t m = A.stm[tid];
  uint32_t subp[HALF][8];  // prefix products of dx (local memory)

#pragma unroll 1
  for (int step = 0; step < A.nsteps; step++) {
    check_point<CHAIN, IDX, LEAD>(cx, cy, tid, m, 0, A);

    // forward pass: subp[i] = prod_{j<=i} (G_j.x - cx), then the centre-advance term
    uint32_t acc[8], dx[8], gx[8], gy[8];
    load8(gx, A.tgx);
    fe_sub(acc, gx, cx);
    copy8(subp[0], acc);
#pragma unroll 1
    for (int i = 1; i < HALF; i++) {
      load8(gx, A.tgx + 8 * i);
      fe_sub(dx, gx, cx);
      fe_mul(acc, acc, dx);
      copy8(subp[i], acc);
    }
    uint32_t dx2[8];
    fe_sub(dx2, c_g2x, cx);
    fe_mul(acc, acc, dx2);

    uint32_t inv[8], dxinv[8];
    fe_inv(inv, acc);

    // next centre = C + GRP*G
    uint32_t nx[8], ny[8];
    fe_mul(dxinv, inv, subp[HALF - 1]);
    fe_mul(inv, inv, dx2);
    affine_add(nx, ny, cx, cy, c_g2x, c_g2y, dxinv);

    // backward pass: C ± (i+1)*G
#pragma unroll 1
    for (int i = HALF - 1; i >= 0; i--) {
      load8(gx, A.tgx + 8 * i);
      load8(gy, A.tgy + 8 * i);
      fe_sub(dx, gx, cx);
      if (i > 0) {
        fe_mul(dxinv, inv, subp[i - 1]);
        fe_mul(inv, inv, dx);
      } else {
        copy8(dxinv, inv);
      }
#pragma unroll 1
      for (int s = 0; s < 2; s++) {
        if (s == 1) {
          if (i == HALF - 1) break;  // -HALF belongs to the previous group
          fe_neg(gy, gy);
        }
        uint32_t px[8], py[8];
        affine_add(px, py, cx, cy, gx, gy, dxinv);
        check_point<CHAIN, IDX, LEAD>(px, py, tid, m, s ? -(i + 1) : (i + 1), A);
      }
    }
    copy8(cx, nx);
    copy8(cy, ny);
    m++;
  }

#pragma unroll
  for (int k = 0; k < 8; k++) {
    A.stx[k * A.T + tid] = cx[k];
    A.sty[k * A.T + tid] = cy[k];
  }
  A.stm[tid] = m;
}

int slot_of(Chain ch) {
  switch (ch) {
    case Chain::EVM: return K_EVM;
    case Chain::TRON: return K_TRON;
    case Chain::BTC: return K_BTC;
    case Chain::BTC_LEGACY: return K_BTC_LEGACY;
    case Chain::BTC_P2SH: return K_BTC_P2SH;
    default: throw std::logic_error("not a secp256k1 chain");
  }
}

using KernelFn = void (*)(SecpArgs);
template <int C>
KernelFn pick_kernel(bool idx, bool lead) {
  if constexpr (C == K_TRON || C == K_BTC_P2SH || C == K_MULTI)
    if (lead) return idx ? secp_kernel<C, true, true> : secp_kernel<C, false, true>;
  return idx ? secp_kernel<C, true, false> : secp_kernel<C, false, false>;
}

// The address in the form patterns are matched against (EVM: 40 lowercase hex chars).
std::string match_address(Chain ch, const hc::SPt& P) {
  using namespace hc;
  if (ch == Chain::EVM) return evm_address(P);
  if (ch == Chain::TRON) return tron_address(P);
  uint8_t h[20];
  btc_hash160(P, h);
  if (ch == Chain::BTC) return btc_p2wpkh(h);
  if (ch == Chain::BTC_LEGACY) return btc_p2pkh(h);
  return btc_p2sh_p2wpkh(h);
}

const char* cli_name(Chain ch) {
  switch (ch) {
    case Chain::EVM: return "evm";
    case Chain::TRON: return "tron";
    case Chain::BTC: return "btc";
    case Chain::BTC_LEGACY: return "btc-legacy";
    default: return "btc-p2sh";
  }
}

std::string cpu_note(double keys, double secs) {
  char b[64];
  snprintf(b, sizeof b, "CPU %.0f Mkey/s", secs > 0 ? keys / secs / 1e6 : 0.0);
  return b;
}

double now_s() {
  using namespace std::chrono;
  return duration<double>(steady_clock::now().time_since_epoch()).count();
}

}  // namespace

double run_secp(const PatternSet& ps, const EngineOptions& eo, Reporter& rep) {
  return run_secp(std::vector<const PatternSet*>{&ps}, eo, rep);
}

double run_secp(const std::vector<const PatternSet*>& sets, const EngineOptions& eo, Reporter& rep) {
  using namespace hc;
  const bool external = !eo.pubkey.empty();
  if (sets.empty()) throw std::logic_error("run_secp: no pattern sets");
  const PatternSet* by_slot[NSLOT] = {};
  uint32_t on = 0;
  bool idx = false;
  for (const PatternSet* p : sets) {
    const int sl = slot_of(p->chain);
    if (by_slot[sl]) throw std::runtime_error(std::string("chain ") + chain_name(p->chain) + " given twice");
    by_slot[sl] = p;
    on |= 1u << sl;
    idx |= !p->idx[0].empty() || !p->idx[1].empty();
  }
  const bool multi = sets.size() > 1;
  const std::string label = rep.label();

  CUDA_CHECK(cudaSetDevice(eo.device));
  cudaDeviceProp prop;
  CUDA_CHECK(cudaGetDeviceProperties(&prop, eo.device));

  // ---- base key
  U256 k0;
  SPt P0;
  if (external) {
    if (!s_parse_pubkey(eo.pubkey, P0)) throw std::runtime_error("--pubkey: not a valid secp256k1 public key");
  } else {
    uint8_t b[32];
    do {
      os_random(b, 32);
      k0 = U256::from_be(b);
    } while (k0.is_zero() || cmp(k0, SECP_N) >= 0);
    secure_zero(b, sizeof b);
    P0 = s_mul(k0, s_gen());
  }

  // ---- launch geometry
  const Chain ch = sets[0]->chain;
  bool lead = false;  // some set uses the --beauty prefilter
  for (const PatternSet* ps : sets) lead |= ps->cfg.lead_k != 0;
  KernelFn kern = multi                     ? pick_kernel<K_MULTI>(idx, lead)
                  : ch == Chain::EVM        ? pick_kernel<K_EVM>(idx, lead)
                  : ch == Chain::TRON       ? pick_kernel<K_TRON>(idx, lead)
                  : ch == Chain::BTC        ? pick_kernel<K_BTC>(idx, lead)
                  : ch == Chain::BTC_LEGACY ? pick_kernel<K_BTC_LEGACY>(idx, lead)
                                            : pick_kernel<K_BTC_P2SH>(idx, lead);
  int threads = eo.threads ? eo.threads : 256;
  int per_sm = 0;
  CUDA_CHECK(cudaOccupancyMaxActiveBlocksPerMultiprocessor(&per_sm, kern, threads, 0));
  int blocks = eo.blocks ? eo.blocks : prop.multiProcessorCount * std::max(1, per_sm);
  const uint32_t T = (uint32_t)blocks * threads;

  // ---- tables: (i+1)*G and GRP*G
  const SPt G = s_gen();
  std::vector<uint32_t> tgx(HALF * 8), tgy(HALF * 8);
  SPt acc = G;
  for (int i = 0; i < HALF; i++) {
    acc.x.to_u32(&tgx[8 * i]);
    acc.y.to_u32(&tgy[8 * i]);
    acc = s_add(acc, G);
  }
  SPt G2 = s_mul(U256::from_u64(GRP), G);

  // ---- thread start points: P0 + (t*2^64 + HALF)*G
  std::vector<uint32_t> stx(8 * (size_t)T), sty(8 * (size_t)T);
  {
    U256 two64;
    two64.w[1] = 1;
    const SPt Q = s_mul(two64, G);
    const SPt S = s_add(P0, s_mul(U256::from_u64(HALF), G));
    unsigned nth = std::max(1u, std::thread::hardware_concurrency());
    std::vector<std::thread> pool;
    uint32_t chunk = (T + nth - 1) / nth;
    for (unsigned c = 0; c < nth; c++) {
      pool.emplace_back([&, c]() {
        uint32_t t0 = c * chunk, t1 = std::min(T, t0 + chunk);
        if (t0 >= t1) return;
        U256 off;
        off.w[1] = t0;
        SPt P = s_add(S, s_mul(off, G));
        uint32_t w[8];
        for (uint32_t t = t0; t < t1; t++) {
          P.x.to_u32(w);
          for (int k = 0; k < 8; k++) stx[(size_t)k * T + t] = w[k];
          P.y.to_u32(w);
          for (int k = 0; k < 8; k++) sty[(size_t)k * T + t] = w[k];
          P = s_add(P, Q);
        }
      });
    }
    for (auto& th : pool) th.join();
  }

  // ---- device buffers
  SecpArgs A{};
  A.T = T;
  CUDA_CHECK(cudaMalloc(&A.stx, stx.size() * 4));
  CUDA_CHECK(cudaMalloc(&A.sty, sty.size() * 4));
  CUDA_CHECK(cudaMalloc(&A.stm, T * sizeof(unsigned long long)));
  uint32_t *d_tgx, *d_tgy;
  CUDA_CHECK(cudaMalloc(&d_tgx, tgx.size() * 4));
  CUDA_CHECK(cudaMalloc(&d_tgy, tgy.size() * 4));
  A.tgx = d_tgx;
  A.tgy = d_tgy;
  CUDA_CHECK(cudaMalloc(&A.hits, MAX_HITS * sizeof(Hit)));
  CUDA_CHECK(cudaMalloc(&A.nhits, 4));
  CUDA_CHECK(cudaMemcpy(A.stx, stx.data(), stx.size() * 4, cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(A.sty, sty.data(), sty.size() * 4, cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemset(A.stm, 0, T * sizeof(unsigned long long)));
  CUDA_CHECK(cudaMemcpy(d_tgx, tgx.data(), tgx.size() * 4, cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemcpy(d_tgy, tgy.data(), tgy.size() * 4, cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMemset(A.nhits, 0, 4));
  uint32_t w[8];
  SECP_BETA.to_u32(w);
  CUDA_CHECK(cudaMemcpyToSymbol(c_beta, w, 32));
  G2.x.to_u32(w);
  CUDA_CHECK(cudaMemcpyToSymbol(c_g2x, w, 32));
  G2.y.to_u32(w);
  CUDA_CHECK(cudaMemcpyToSymbol(c_g2y, w, 32));
  std::vector<std::unique_ptr<DevPatterns>> dev_pats;
  for (const PatternSet* p : sets) dev_pats.emplace_back(new DevPatterns(*p, slot_of(p->chain)));
  CUDA_CHECK(cudaMemcpyToSymbol(c_on, &on, sizeof on));

  // λ^e for e = 0, 1, 2
  U256 lam[3] = {U256::from_u64(1), SECP_LAMBDA, n_mul(SECP_LAMBDA, SECP_LAMBDA)};

  // ---- main loop
  std::unique_ptr<CpuSecp> cpu;
  if (eo.cpu > 0) cpu.reset(new CpuSecp(sets, P0, eo.cpu));
  const bool gpu = !eo.no_gpu;
  std::vector<Hit> hits(MAX_HITS), batch;
  int nsteps = 1, run_steps = 1;
  double gpu_keys = 0, keys = 0, t_start = now_s(), t_print = 0;
  cudaEvent_t ev0, ev1;
  CUDA_CHECK(cudaEventCreate(&ev0));
  CUDA_CHECK(cudaEventCreate(&ev1));
  auto launch = [&]() {
    A.nsteps = run_steps = nsteps;
    CUDA_CHECK(cudaEventRecord(ev0));
    kern<<<blocks, threads>>>(A);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaEventRecord(ev1));
  };
  if (gpu) launch();
  bool running = true;
  while (running) {
    batch.clear();
    if (gpu) {
      CUDA_CHECK(cudaEventSynchronize(ev1));
      float ms = 0;
      CUDA_CHECK(cudaEventElapsedTime(&ms, ev0, ev1));
      gpu_keys += (double)T * run_steps * GRP * VARIANTS;

      uint32_t nh = 0;
      CUDA_CHECK(cudaMemcpy(&nh, A.nhits, 4, cudaMemcpyDeviceToHost));
      if (nh) {
        uint32_t n = std::min<uint32_t>(nh, MAX_HITS);
        CUDA_CHECK(cudaMemcpy(hits.data(), A.hits, n * sizeof(Hit), cudaMemcpyDeviceToHost));
        CUDA_CHECK(cudaMemset(A.nhits, 0, 4));
        if (nh > MAX_HITS) rep.dropped(nh - MAX_HITS);
        batch.assign(hits.begin(), hits.begin() + n);
      }
      // keep each launch around 150 ms
      if (ms < 75 && nsteps < 4096) nsteps *= 2;
      else if (ms > 300 && nsteps > 1) nsteps /= 2;
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }
    if (cpu) cpu->take_hits(batch);
    keys = gpu_keys + (cpu ? cpu->keys() : 0);
    double el = now_s() - t_start;
    running = !g_stop && !rep.done() && !(eo.bench > 0 && el >= eo.bench);
    // start the next launch so the GPU keeps working while the CPU re-verifies this batch
    if (running && gpu) launch();

    {  // re-verify every hit on the CPU (hostcrypto.cpp) before reporting it
      for (size_t i = 0; i < batch.size() && !rep.done(); i++) {
        const Hit& h = batch[i];
        // d = tid*2^64 + HALF + m*GRP + idx
        U256 d;
        u128 low = (u128)h.m * GRP + (u128)(HALF + h.idx);
        d.w[0] = (uint64_t)low;
        d.w[1] = (uint64_t)h.tid + (uint64_t)(low >> 64);
        U256 a = lam[(h.flags >> 1) & 3];
        if (h.flags & 1) a = n_neg(a);
        U256 b = n_mul(a, d);
        U256 key;
        SPt P;
        if (external) {
          P = s_add(s_mul(a, P0), s_mul(b, G));
        } else {
          key = n_add(n_mul(a, k0), b);
          P = s_mul(key, G);
        }
        const PatternSet* pp = h.pad < NSLOT ? by_slot[h.pad] : nullptr;
        if (!pp) {
          rep.reject("hit for an unknown chain slot");
          continue;
        }
        const PatternSet& ps = *pp;
        const Chain ch = ps.chain;
        const bool evm = ch == Chain::EVM;
        std::string addr = match_address(ch, P);
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
          // base58check prefix ranges ignore the checksum and key-only list patterns are
          // tested by a 64-bit key, so hits right at a range edge may miss; those are
          // expected and silently dropped.
          if (h.pat == BEAUTY_HIT || h.pat >= ps.pats.size() || !may_overmatch(ps, h.pat)) rep.reject(addr);
          continue;
        }
        if (h.tid >= CPU_TID0) what += ", found by CPU";
        std::string shown = evm ? eip55(addr) : addr;
        KV info, secret;
        if (is_btc(ch))
          info.push_back({"type", ch == Chain::BTC          ? "native SegWit P2WPKH, compressed key"
                                  : ch == Chain::BTC_LEGACY ? "legacy P2PKH, compressed key"
                                                            : "P2SH-P2WPKH (nested SegWit), compressed key"});
        if (external) {
          info.push_back({"split_key_a", a.hex()});
          info.push_back({"split_key_b", b.hex()});
          info.push_back({"combine", "private_key = (a * your_key + b) mod n  ->  vanity-gpu combine " +
                                         std::string(cli_name(ch)) + " <your_key> " + a.hex() + " " + b.hex()});
        } else if (is_btc(ch)) {
          std::string wif = btc_wif(key);
          secret.push_back({"private_key_wif", wif});
          secret.push_back({"electrum_import", std::string(ch == Chain::BTC          ? "p2wpkh:"
                                                           : ch == Chain::BTC_LEGACY ? "p2pkh:"
                                                                                     : "p2wpkh-p2sh:") +
                                                   wif});
          secret.push_back({"private_key_hex", key.hex()});
          secure_zero(&wif[0], wif.size());
        } else {
          secret.push_back({"private_key", evm ? "0x" + key.hex() : key.hex()});
        }
        rep.found(ch, shown, what, info, secret);
        secure_zero(&key, sizeof key);
      }
    }

    if (rep.done()) running = false;
    el = now_s() - t_start;
    if (el - t_print > 1.0) {
      rep.progress(keys, el, false, cpu ? cpu_note(cpu->keys(), el) : "");
      t_print = el;
    }
  }
  if (cpu) {
    cpu.reset();  // stop and join the workers
    double el = now_s() - t_start;
    fprintf(stderr, "\r\033[K[%s] CPU share: %s\n", label.c_str(), cpu_note(keys - gpu_keys, el).c_str());
  }
  CUDA_CHECK(cudaDeviceSynchronize());  // a launch issued before the last results may still run
  rep.progress(keys, now_s() - t_start, true);
  cudaEventDestroy(ev0);
  cudaEventDestroy(ev1);

  secure_zero(&k0, sizeof k0);
  cudaFree(A.stx);
  cudaFree(A.sty);
  cudaFree(A.stm);
  cudaFree(d_tgx);
  cudaFree(d_tgy);
  cudaFree(A.hits);
  cudaFree(A.nhits);
  return keys;
}
