#include "cpu_secp.h"

#include "constants.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

using namespace hc;

namespace {

using u128 = unsigned __int128;

// ---------------------------------------------------------------- GF(p), p = 2^256 - C
// 4 x 64-bit limbs, little-endian; values are kept < 2^256 and made canonical for hashing.

constexpr uint64_t C = 0x1000003D1ull;

struct Fe {
  uint64_t v[4];
};

inline Fe fe_of(const U256& a) { return Fe{{a.w[0], a.w[1], a.w[2], a.w[3]}}; }

inline void add_small(uint64_t r[4], uint64_t c, uint64_t& carry) {
  u128 acc = (u128)r[0] + c;
  r[0] = (uint64_t)acc;
  acc >>= 64;
  for (int k = 1; k < 4; k++) {
    acc += r[k];
    r[k] = (uint64_t)acc;
    acc >>= 64;
  }
  carry = (uint64_t)acc;
}

inline void fe_mul(Fe& r, const Fe& a, const Fe& b) {
  uint64_t t[8];
  u128 acc = 0;
  for (int j = 0; j < 4; j++) {
    acc += (u128)a.v[0] * b.v[j];
    t[j] = (uint64_t)acc;
    acc >>= 64;
  }
  t[4] = (uint64_t)acc;
  for (int i = 1; i < 4; i++) {
    acc = 0;
    for (int j = 0; j < 4; j++) {
      acc += (u128)a.v[i] * b.v[j] + t[i + j];
      t[i + j] = (uint64_t)acc;
      acc >>= 64;
    }
    t[i + 4] = (uint64_t)acc;
  }
  // t_hi * 2^256 = t_hi * C (mod p)
  uint64_t o[4];
  acc = 0;
  for (int k = 0; k < 4; k++) {
    acc += (u128)t[4 + k] * C + t[k];
    o[k] = (uint64_t)acc;
    acc >>= 64;
  }
  // fold the top (< 2^34): top * C < 2^67
  const u128 f = (u128)(uint64_t)acc * C;
  acc = (u128)o[0] + (uint64_t)f;
  o[0] = (uint64_t)acc;
  acc >>= 64;
  acc += (u128)o[1] + (uint64_t)(f >> 64);
  o[1] = (uint64_t)acc;
  acc >>= 64;
  acc += o[2];
  o[2] = (uint64_t)acc;
  acc >>= 64;
  acc += o[3];
  o[3] = (uint64_t)acc;
  uint64_t carry = (uint64_t)(acc >> 64);
  if (carry) add_small(o, C, carry);  // the value wrapped past 2^256, so it is now tiny
  r = Fe{{o[0], o[1], o[2], o[3]}};
}

inline void fe_sqr(Fe& r, const Fe& a) { fe_mul(r, a, a); }

inline void fe_add(Fe& r, const Fe& a, const Fe& b) {
  u128 acc = 0;
  for (int k = 0; k < 4; k++) {
    acc += (u128)a.v[k] + b.v[k];
    r.v[k] = (uint64_t)acc;
    acc >>= 64;
  }
  uint64_t carry = (uint64_t)acc;
  while (carry) add_small(r.v, C, carry);
}

inline void fe_sub(Fe& r, const Fe& a, const Fe& b) {
  uint64_t borrow = 0;
  for (int k = 0; k < 4; k++) {
    u128 d = (u128)a.v[k] - b.v[k] - borrow;
    r.v[k] = (uint64_t)d;
    borrow = (uint64_t)(d >> 64) & 1;
  }
  while (borrow) {  // add p = subtract C modulo 2^256
    u128 d = (u128)r.v[0] - C;
    r.v[0] = (uint64_t)d;
    borrow = (uint64_t)(d >> 64) & 1;
    for (int k = 1; k < 4; k++) {
      d = (u128)r.v[k] - borrow;
      r.v[k] = (uint64_t)d;
      borrow = (uint64_t)(d >> 64) & 1;
    }
  }
}

inline void fe_canon(Fe& a) {
  uint64_t t[4] = {a.v[0], a.v[1], a.v[2], a.v[3]}, carry;
  add_small(t, C, carry);
  if (carry) memcpy(a.v, t, sizeof t);  // a >= p
}

inline void fe_sqr_n(Fe& r, int n) {
  for (int i = 0; i < n; i++) fe_sqr(r, r);
}

// a^(p-2), same addition chain as the GPU (libsecp256k1)
Fe fe_inv(const Fe& a) {
  Fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t;
  fe_sqr(x2, a); fe_mul(x2, x2, a);
  fe_sqr(x3, x2); fe_mul(x3, x3, a);
  x6 = x3; fe_sqr_n(x6, 3); fe_mul(x6, x6, x3);
  x9 = x6; fe_sqr_n(x9, 3); fe_mul(x9, x9, x3);
  x11 = x9; fe_sqr_n(x11, 2); fe_mul(x11, x11, x2);
  x22 = x11; fe_sqr_n(x22, 11); fe_mul(x22, x22, x11);
  x44 = x22; fe_sqr_n(x44, 22); fe_mul(x44, x44, x22);
  x88 = x44; fe_sqr_n(x88, 44); fe_mul(x88, x88, x44);
  x176 = x88; fe_sqr_n(x176, 88); fe_mul(x176, x176, x88);
  x220 = x176; fe_sqr_n(x220, 44); fe_mul(x220, x220, x44);
  x223 = x220; fe_sqr_n(x223, 3); fe_mul(x223, x223, x3);
  t = x223; fe_sqr_n(t, 23); fe_mul(t, t, x22);
  fe_sqr_n(t, 5); fe_mul(t, t, a);
  fe_sqr_n(t, 3); fe_mul(t, t, x2);
  fe_sqr_n(t, 2);
  Fe r;
  fe_mul(r, t, a);
  return r;
}

// r = p1 + p2 given dxinv = 1 / (x2 - x1)
inline void affine_add(Fe& rx, Fe& ry, const Fe& x1, const Fe& y1, const Fe& x2, const Fe& y2, const Fe& dxinv) {
  Fe lam, t;
  fe_sub(t, y2, y1);
  fe_mul(lam, t, dxinv);
  fe_sqr(t, lam);
  fe_sub(t, t, x1);
  fe_sub(rx, t, x2);
  fe_sub(t, x1, rx);
  fe_mul(t, lam, t);
  fe_sub(ry, t, y1);
}

// ---------------------------------------------------------------- 8-way Keccak-f[1600]
// GCC vector extensions: AVX-512 (vprolq / vpternlogq) with -march=native on this
// machine, plain AVX2 or scalar code elsewhere.

typedef uint64_t v8 __attribute__((vector_size(64)));

template <int N>
inline v8 rol(v8 x) {
  return (x << N) | (x >> (64 - N));
}

const uint64_t RC[24] = {0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808Aull, 0x8000000080008000ull,
                         0x000000000000808Bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull,
                         0x000000000000008Aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000Aull,
                         0x000000008000808Bull, 0x800000000000008Bull, 0x8000000000008089ull, 0x8000000000008003ull,
                         0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800Aull, 0x800000008000000Aull,
                         0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull};

// rho offsets and pi destinations for lane i = x + 5y: B[y + 5*((2x+3y)%5)] = rol(A[i], R[i])
#define KECCAK_RHO_PI(X)                                                                                    \
  X(0, 0, 0) X(1, 10, 1) X(2, 20, 62) X(3, 5, 28) X(4, 15, 27) X(5, 16, 36) X(6, 1, 44) X(7, 11, 6)     \
  X(8, 21, 55) X(9, 6, 20) X(10, 7, 3) X(11, 17, 10) X(12, 2, 43) X(13, 12, 25) X(14, 22, 39)            \
  X(15, 23, 41) X(16, 8, 45) X(17, 18, 15) X(18, 3, 21) X(19, 13, 8) X(20, 14, 18) X(21, 24, 2)          \
  X(22, 9, 61) X(23, 19, 56) X(24, 4, 14)

inline void keccakf8(v8 A[25]) {
  for (int r = 0; r < 24; r++) {
    v8 Cc[5], D[5], B[25];
    for (int x = 0; x < 5; x++) Cc[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    for (int x = 0; x < 5; x++) D[x] = Cc[(x + 4) % 5] ^ rol<1>(Cc[(x + 1) % 5]);
#define RHOPI(i, dst, rot) B[dst] = rot ? rol<(rot ? rot : 1)>(A[i] ^ D[(i) % 5]) : (A[i] ^ D[(i) % 5]);
    KECCAK_RHO_PI(RHOPI)
#undef RHOPI
    for (int y = 0; y < 25; y += 5)
      for (int x = 0; x < 5; x++) A[y + x] = B[y + x] ^ (~B[y + (x + 1) % 5] & B[y + (x + 2) % 5]);
    A[0] ^= RC[r];
  }
}

// Sanity check of the rho/pi table against the definition (run once at start-up).
bool rho_pi_table_ok() {
  static const int R[5][5] = {{0, 36, 3, 41, 18}, {1, 44, 10, 45, 2}, {62, 6, 43, 15, 61},
                              {28, 55, 25, 21, 56}, {27, 20, 39, 8, 14}};  // R[x][y]
  int dst[25], rot[25];
#define REC(i, d, r) dst[i] = d; rot[i] = r;
  KECCAK_RHO_PI(REC)
#undef REC
  for (int x = 0; x < 5; x++)
    for (int y = 0; y < 5; y++) {
      int i = x + 5 * y;
      if (dst[i] != y + 5 * ((2 * x + 3 * y) % 5) || rot[i] != R[x][y]) return false;
    }
  return true;
}

// ---------------------------------------------------------------- 16-way SHA-256 + RIPEMD-160
// hash160 of compressed public keys for the Bitcoin address types.

typedef uint32_t v16 __attribute__((vector_size(64)));

inline v16 ror(v16 x, int n) { return (x >> n) | (x << (32 - n)); }
inline v16 rol(v16 x, int n) { return (x << n) | (x >> (32 - n)); }
inline v16 bswap16(v16 x) {
  return ((x & 0xffu) << 24) | ((x & 0xff00u) << 8) | ((x >> 8) & 0xff00u) | (x >> 24);
}
inline v16 splat(uint32_t v) { return v16{v, v, v, v, v, v, v, v, v, v, v, v, v, v, v, v}; }

const uint32_t SHA_K[64] = {SHA256_K_LIST};
const uint32_t SHA_IV[8] = {SHA256_IV_LIST};

inline void sha256_16(v16 h[8], v16 w[16]) {
  v16 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (int i = 0; i < 64; i++) {
    if (i >= 16) {
      const v16 w15 = w[(i - 15) & 15], w2 = w[(i - 2) & 15];
      w[i & 15] += (ror(w15, 7) ^ ror(w15, 18) ^ (w15 >> 3)) + w[(i - 7) & 15] +
                   (ror(w2, 17) ^ ror(w2, 19) ^ (w2 >> 10));
    }
    const v16 t1 = hh + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + SHA_K[i] + w[i & 15];
    const v16 t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

// RIPEMD-160 of the 32-byte digests in h (big-endian words); out = 5 big-endian words.
inline void ripemd160_16(const v16 h[8], v16 out[5]) {
  static const int R1[80] = {0, 1, 2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 7,  4,  13, 1,
                             10, 6, 15, 3,  12, 0,  9,  5,  2,  14, 11, 8,  3,  10, 14, 4,  9,  15, 8,  1,
                             2,  7, 0,  6,  13, 11, 5,  12, 1,  9,  11, 10, 0,  8,  12, 4,  13, 3,  7,  15,
                             14, 5, 6,  2,  4,  0,  5,  9,  7,  12, 2,  10, 14, 1,  3,  8,  11, 6,  15, 13};
  static const int R2[80] = {5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12, 6,  11, 3,  7,
                             0,  13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,  15, 5,  1,  3,  7,  14, 6,  9,
                             11, 8,  12, 2,  10, 0,  4,  13, 8,  6,  4,  1,  3,  11, 15, 0,  5,  12, 2,  13,
                             9,  7,  10, 14, 12, 15, 10, 4,  1,  5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11};
  static const int S1[80] = {11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,  7,  6,  8,  13,
                             11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12, 11, 13, 6,  7,  14, 9,  13, 15,
                             14, 8,  13, 6,  5,  12, 7,  5,  11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,
                             8,  6,  5,  12, 9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6};
  static const int S2[80] = {8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,  9,  13, 15, 7,
                             12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11, 9,  7,  15, 11, 8,  6,  6,  14,
                             12, 13, 5,  14, 13, 13, 7,  5,  15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,
                             12, 5,  15, 8,  8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11};
  static const uint32_t K1[5] = {0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xA953FD4Eu};
  static const uint32_t K2[5] = {0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x7A6D76E9u, 0x00000000u};
  v16 X[16];
  for (int i = 0; i < 8; i++) X[i] = bswap16(h[i]);
  X[8] = splat(0x80u);
  for (int i = 9; i < 16; i++) X[i] = splat(0);
  X[14] = splat(256);
  const v16 h0 = splat(0x67452301u), h1 = splat(0xEFCDAB89u), h2 = splat(0x98BADCFEu), h3 = splat(0x10325476u),
            h4 = splat(0xC3D2E1F0u);
  v16 a1 = h0, b1 = h1, c1 = h2, d1 = h3, e1 = h4, a2 = h0, b2 = h1, c2 = h2, d2 = h3, e2 = h4;
  auto f = [](int r, v16 x, v16 y, v16 z) -> v16 {
    switch (r) {
      case 0: return x ^ y ^ z;
      case 1: return (x & y) | (~x & z);
      case 2: return (x | ~y) ^ z;
      case 3: return (x & z) | (y & ~z);
      default: return x ^ (y | ~z);
    }
  };
  for (int j = 0; j < 80; j++) {
    const int r = j >> 4;
    v16 t = rol(a1 + f(r, b1, c1, d1) + X[R1[j]] + K1[r], S1[j]) + e1;
    a1 = e1; e1 = d1; d1 = rol(c1, 10); c1 = b1; b1 = t;
    t = rol(a2 + f(4 - r, b2, c2, d2) + X[R2[j]] + K2[r], S2[j]) + e2;
    a2 = e2; e2 = d2; d2 = rol(c2, 10); c2 = b2; b2 = t;
  }
  out[0] = bswap16(h1 + c1 + d2);
  out[1] = bswap16(h2 + d1 + e2);
  out[2] = bswap16(h3 + e1 + a2);
  out[3] = bswap16(h4 + a1 + b2);
  out[4] = bswap16(h0 + b1 + c2);
}

inline uint32_t bswap32(uint32_t x) { return __builtin_bswap32(x); }

uint64_t nibrev64(uint64_t x) {
  x = __builtin_bswap64(x);
  return ((x & 0x0F0F0F0F0F0F0F0Full) << 4) | ((x >> 4) & 0x0F0F0F0F0F0F0F0Full);
}

bool in_range5(const uint32_t a[5], const uint32_t* lo, const uint32_t* hi) {
  for (int k = 0; k < 5; k++)
    if (a[k] != lo[k]) {
      if (a[k] < lo[k]) return false;
      break;
    }
  for (int k = 0; k < 5; k++)
    if (a[k] != hi[k]) return a[k] < hi[k];
  return true;
}

template <class F>
int idx_lookup(const HostIndex& I, uint64_t key, F&& test) {
  const uint64_t b = key >> I.shift;
  if (!((I.bitmap[b >> 5] >> (b & 31)) & 1u)) return -1;
  auto it = std::upper_bound(I.lo.begin(), I.lo.end(), key);
  if (it == I.lo.begin()) return -1;
  const size_t s = (size_t)(it - I.lo.begin()) - 1;
  if (key > I.hi[s]) return -1;
  for (uint32_t j = I.off[s]; j < I.off[s + 1]; j++)
    if (test(I.pid[j])) return (int)I.pid[j];
  return -1;
}

int b32_value(char c) {
  const char* p = strchr(BECH32_CHARSET, c);
  return c && p ? (int)(p - BECH32_CHARSET) : -1;
}

// Address matching on the CPU: the same decisions as the GPU kernels, with the
// address string built (lazily) where the GPU would compute digits or a checksum.
// a = the 20-byte hash the address encodes (for P2SH: the script hash).
class Checker {
 public:
  // slot: the GPU kernel variant of the chain (engine_secp.cu), kept in Hit::pad
  Checker(const PatternSet& ps, uint32_t slot, uint32_t tid, std::vector<Hit>& out)
      : ps_(ps), ch_(ps.chain), evm_(ps.chain == Chain::EVM), slot_(slot), tid_(tid), out_(out) {}

  void check(const uint32_t a[5], uint64_t m, int32_t idx, uint32_t flags) {
    have_ = false;
    a_ = a;
    int hp = -1;
    for (uint32_t p = 0; p < ps_.cfg.npat && hp < 0; p++)
      if (match(p)) hp = (int)p;
    for (int k = 0; k < 2 && hp < 0; k++) {
      const HostIndex& I = ps_.idx[k];
      if (I.empty()) continue;
      hp = idx_lookup(I, key(k), [&](uint32_t p) { return p >= ps_.dev.size() || match(p); });
    }
    if (hp >= 0) out_.push_back(Hit{tid_, (uint32_t)hp, m, idx, flags, 0, slot_, {0}});
    if (ps_.score != Score::NONE) {
      int score;
      if (evm_) {
        auto nib = [&](int i) { return (a[i >> 3] >> (28 - 4 * (i & 7))) & 15u; };
        if (ps_.score == Score::REPEAT) {
          int L = 1, R = 1;
          while (L < 40 && nib(L) == nib(0)) L++;
          while (R < 40 && nib(39 - R) == nib(39)) R++;
          score = L + R;
        } else {  // letters of either case first; the EIP-55 case only for the survivors
          const uint64_t m22 = (uint64_t)ps_.cfg.cls_hi << 32 | ps_.cfg.cls_lo;
          const uint64_t ci = (m22 & 0xFFFFu) | (((m22 >> 16) & 0x3Fu) << 10);
          auto in = [&](int i) { return (ci >> nib(i)) & 1u; };
          int L = 0, R = 0;
          while (L < 40 && in(L)) L++;
          while (R < 40 && in(39 - R)) R++;
          score = L == 40 ? 40 : L + R;
          if (score >= ps_.min_score) score = score_address(ps_, str());
        }
      } else {
        score = score_address(ps_, str());
      }
      if (score >= ps_.min_score) out_.push_back(Hit{tid_, BEAUTY_HIT, m, idx, flags, (uint32_t)score, slot_, {0}});
    }
  }

 private:
  const PatternSet& ps_;
  const Chain ch_;
  const bool evm_;
  const uint32_t slot_;
  const uint32_t tid_;
  std::vector<Hit>& out_;
  const uint32_t* a_ = nullptr;
  bool have_ = false;
  std::string s_;

  const std::string& str() {
    if (have_) return s_;
    uint8_t b[20];
    for (int k = 0; k < 5; k++) {
      uint32_t w = a_[k];
      b[4 * k] = (uint8_t)(w >> 24);
      b[4 * k + 1] = (uint8_t)(w >> 16);
      b[4 * k + 2] = (uint8_t)(w >> 8);
      b[4 * k + 3] = (uint8_t)w;
    }
    switch (ch_) {
      case Chain::EVM: s_ = hex(b, 20); break;
      case Chain::TRON: s_ = tron_from20(b); break;
      case Chain::BTC: s_ = btc_p2wpkh(b); break;
      case Chain::BTC_LEGACY: s_ = btc_p2pkh(b); break;
      default: s_ = b58check(0x05, b, 20); break;
    }
    have_ = true;
    return s_;
  }

  bool match(uint32_t p) {
    const DevPattern& P = ps_.dev[p];
    const uint32_t* a = a_;
    if (evm_ || ch_ == Chain::BTC) {
      const uint32_t* val = evm_ ? P.hval : P.bval;
      const uint32_t* msk = evm_ ? P.hmask : P.bmask;
      uint32_t d = 0;
      for (int k = 0; k < 5; k++) d |= (a[k] ^ val[k]) & msk[k];
      if (d) return false;
      return evm_ || !P.bmask[5] || match_one(ps_.pats[p], str());  // checksum characters
    }
    if (P.nrange) {
      bool in = false;
      for (uint32_t r = 0; r < P.nrange && !in; r++) in = in_range5(a, P.rlo[r], P.rhi[r]);
      if (!in) return false;
    }
    return !P.ndig || match_one(ps_.pats[p], str());
  }

  uint64_t key(int k) {
    const uint32_t* a = a_;
    if (k == 0) return (uint64_t)a[0] << 32 | a[1];
    if (evm_) return nibrev64((uint64_t)a[3] << 32 | a[4]);
    const std::string& s = str();  // last characters, last one most significant
    uint64_t v = 0;
    if (ch_ == Chain::BTC) {
      for (int i = 0; i < 12; i++) v = v << 5 | (uint64_t)b32_value(s[s.size() - 1 - i]);
      return v << 4;
    }
    for (int i = 0; i < 10; i++) v = v * 58 + (uint64_t)base58_value(s[s.size() - 1 - i]);
    return v << 5;
  }
};

}  // namespace

int cpu_default_threads() {
  unsigned n = std::thread::hardware_concurrency();
  return n > 1 ? (int)n - 1 : 1;
}

CpuSecp::CpuSecp(const PatternSet& ps, const SPt& P0, int nthreads)
    : CpuSecp(std::vector<const PatternSet*>{&ps}, P0, nthreads) {}

CpuSecp::CpuSecp(std::vector<const PatternSet*> sets, const SPt& P0, int nthreads)
    : sets_(std::move(sets)), P0_(P0) {
  if (!rho_pi_table_ok()) throw std::logic_error("keccak rho/pi table");
  for (int w = 0; w < nthreads; w++) pool_.emplace_back(&CpuSecp::worker, this, CPU_TID0 + (uint32_t)w);
}

CpuSecp::~CpuSecp() {
  stop_ = true;
  for (auto& t : pool_) t.join();
}

void CpuSecp::take_hits(std::vector<Hit>& out) {
  std::lock_guard<std::mutex> g(mu_);
  out.insert(out.end(), hits_.begin(), hits_.end());
  hits_.clear();
}

void CpuSecp::worker(uint32_t tid) {
  // below the GPU feeding thread, which needs to react quickly
  setpriority(PRIO_PROCESS, (id_t)syscall(SYS_gettid), 10);

  constexpr int HALF = SECP_HALF, GRP = SECP_GRP;
  const SPt G = s_gen();
  std::vector<Fe> gx(HALF), gy(HALF);
  {
    SPt acc = G;
    for (int i = 0; i < HALF; i++) {
      gx[i] = fe_of(acc.x);
      gy[i] = fe_of(acc.y);
      acc = s_add(acc, G);
    }
  }
  const SPt G2 = s_mul(U256::from_u64(GRP), G);
  const Fe g2x = fe_of(G2.x), g2y = fe_of(G2.y);
  const Fe beta = fe_of(SECP_BETA);
  U256 off;
  off.w[0] = HALF;
  off.w[1] = tid;
  const SPt start = s_add(P0_, s_mul(off, G));  // centre of group m = 0: d = tid*2^64 + HALF
  Fe cx = fe_of(start.x), cy = fe_of(start.y);

  std::vector<Hit> local;
  std::vector<Fe> subp(HALF);
  // checkers by the hash they need; slot numbers as in engine_secp.cu
  std::vector<Checker> kec, h160, p2sh;
  for (const PatternSet* p : sets_) {
    switch (p->chain) {
      case Chain::EVM: kec.emplace_back(*p, 0, tid, local); break;
      case Chain::TRON: kec.emplace_back(*p, 1, tid, local); break;
      case Chain::BTC: h160.emplace_back(*p, 2, tid, local); break;
      case Chain::BTC_LEGACY: h160.emplace_back(*p, 3, tid, local); break;
      case Chain::BTC_P2SH: p2sh.emplace_back(*p, 4, tid, local); break;
      default: throw std::logic_error("CpuSecp: not a secp256k1 chain");
    }
  }
  const bool use_kec = !kec.empty(), btc = !h160.empty() || !p2sh.empty();

  // Keccak (EVM/TRON): 8 keys per batch, inputs in lane-major order.
  // Bitcoin: 16 keys per SHA-256 + RIPEMD-160 batch.
  alignas(64) uint64_t in[8][8];
  alignas(64) v16 bw[16];  // SHA-256 message words of the compressed keys
  struct Meta {
    uint64_t m;
    int32_t idx;
    uint32_t flags;
  } meta_k[8], meta_b[16];
  int nk = 0, nb = 0;
  auto flush_b = [&]() {
    for (int i = 9; i < 15; i++) bw[i] = splat(0);
    bw[15] = splat(33 * 8);
    v16 h[8], a5[5];
    for (int i = 0; i < 8; i++) h[i] = splat(SHA_IV[i]);
    sha256_16(h, bw);
    ripemd160_16(h, a5);
    for (int l = 0; l < nb; l++) {
      const uint32_t a[5] = {a5[0][l], a5[1][l], a5[2][l], a5[3][l], a5[4][l]};
      for (Checker& c : h160) c.check(a, meta_b[l].m, meta_b[l].idx, meta_b[l].flags);
    }
    if (!p2sh.empty()) {  // hash160 of the redeem script 0x00 0x14 || key hash
      v16 w[16];
      w[0] = splat(0x00140000u) | (a5[0] >> 16);
      for (int i = 1; i < 5; i++) w[i] = (a5[i - 1] << 16) | (a5[i] >> 16);
      w[5] = (a5[4] << 16) | 0x8000u;
      for (int i = 6; i < 15; i++) w[i] = splat(0);
      w[15] = splat(22 * 8);
      for (int i = 0; i < 8; i++) h[i] = splat(SHA_IV[i]);
      sha256_16(h, w);
      ripemd160_16(h, a5);
      for (int l = 0; l < nb; l++) {
        const uint32_t a[5] = {a5[0][l], a5[1][l], a5[2][l], a5[3][l], a5[4][l]};
        for (Checker& c : p2sh) c.check(a, meta_b[l].m, meta_b[l].idx, meta_b[l].flags);
      }
    }
    nb = 0;
  };
  auto flush_k = [&]() {
    v8 A[25];
    for (int i = 0; i < 25; i++) A[i] = v8{0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < 8; i++) memcpy(&A[i], in[i], 64);
    A[8] = v8{1, 1, 1, 1, 1, 1, 1, 1};
    const uint64_t pad = 0x8000000000000000ull;
    A[16] = v8{pad, pad, pad, pad, pad, pad, pad, pad};
    keccakf8(A);
    for (int l = 0; l < nk; l++) {
      const uint64_t s1 = A[1][l], s2 = A[2][l], s3 = A[3][l];
      const uint32_t a[5] = {bswap32((uint32_t)(s1 >> 32)), bswap32((uint32_t)s2), bswap32((uint32_t)(s2 >> 32)),
                             bswap32((uint32_t)s3), bswap32((uint32_t)(s3 >> 32))};
      for (Checker& c : kec) c.check(a, meta_k[l].m, meta_k[l].idx, meta_k[l].flags);
    }
    nk = 0;
  };
  uint64_t m = 0;
  // the 6 keys of one point: (x, ±y), (βx, ±y), (β²x, ±y)
  auto point = [&](Fe x, Fe y, int32_t idx) {
    Fe ny, xs = x;
    fe_canon(y);
    if (use_kec) {
      fe_sub(ny, Fe{{0, 0, 0, 0}}, y);
      fe_canon(ny);
    }
    for (int e = 0; e < 3; e++) {
      if (e) fe_mul(xs, xs, beta);
      Fe xc = xs;
      fe_canon(xc);
      for (int n = 0; n < 2; n++) {
        const Meta mt{m, idx, (uint32_t)(n | (e << 1))};
        if (btc) {  // 02|03 || x as SHA-256 words; -y flips the parity
          uint32_t X[8];
          for (int i = 0; i < 4; i++) {
            X[2 * i] = (uint32_t)(xc.v[3 - i] >> 32);
            X[2 * i + 1] = (uint32_t)xc.v[3 - i];
          }
          const uint32_t odd = (uint32_t)(y.v[0] & 1) ^ (uint32_t)n;
          bw[0][nb] = ((0x02u | odd) << 24) | (X[0] >> 8);
          for (int i = 1; i < 8; i++) bw[i][nb] = (X[i - 1] << 24) | (X[i] >> 8);
          bw[8][nb] = (X[7] << 24) | 0x00800000u;
          meta_b[nb] = mt;
          if (++nb == 16) flush_b();
        }
        if (use_kec) {
          const Fe& yy = n ? ny : y;
          for (int i = 0; i < 4; i++) {
            in[i][nk] = __builtin_bswap64(xc.v[3 - i]);
            in[4 + i][nk] = __builtin_bswap64(yy.v[3 - i]);
          }
          meta_k[nk] = mt;
          if (++nk == 8) flush_k();
        }
      }
    }
  };

  while (!stop_.load(std::memory_order_relaxed)) {
    point(cx, cy, 0);
    Fe acc, dx;
    fe_sub(acc, gx[0], cx);
    subp[0] = acc;
    for (int i = 1; i < HALF; i++) {
      fe_sub(dx, gx[i], cx);
      fe_mul(acc, acc, dx);
      subp[i] = acc;
    }
    Fe dx2;
    fe_sub(dx2, g2x, cx);
    fe_mul(acc, acc, dx2);
    Fe inv = fe_inv(acc), dxinv, nx, ny;
    fe_mul(dxinv, inv, subp[HALF - 1]);
    fe_mul(inv, inv, dx2);
    affine_add(nx, ny, cx, cy, g2x, g2y, dxinv);
    for (int i = HALF - 1; i >= 0; i--) {
      fe_sub(dx, gx[i], cx);
      if (i > 0) {
        fe_mul(dxinv, inv, subp[i - 1]);
        fe_mul(inv, inv, dx);
      } else {
        dxinv = inv;
      }
      Fe px, py, ngy;
      affine_add(px, py, cx, cy, gx[i], gy[i], dxinv);
      point(px, py, i + 1);
      if (i != HALF - 1) {  // -HALF belongs to the previous group
        fe_sub(ngy, Fe{{0, 0, 0, 0}}, gy[i]);
        affine_add(px, py, cx, cy, gx[i], ngy, dxinv);
        point(px, py, -(i + 1));
      }
    }
    if (nk) flush_k();  // keys are counted per group, so finish the batches
    if (nb) flush_b();
    cx = nx;
    cy = ny;
    m++;
    keys_.fetch_add((uint64_t)GRP * 6, std::memory_order_relaxed);
    if (!local.empty()) {
      std::lock_guard<std::mutex> g(mu_);
      if (hits_.size() < MAX_HITS) hits_.insert(hits_.end(), local.begin(), local.end());
      local.clear();
    }
  }
}
