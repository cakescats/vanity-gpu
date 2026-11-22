#include "hostcrypto.h"

#include <vector>

#include "constants.h"

namespace hc {

// ---------------------------------------------------------------- utilities

std::string hex(const uint8_t* p, size_t n) {
  static const char* H = "0123456789abcdef";
  std::string s;
  s.reserve(2 * n);
  for (size_t i = 0; i < n; i++) {
    s += H[p[i] >> 4];
    s += H[p[i] & 15];
  }
  return s;
}

bool unhex(std::string s, uint8_t* out, size_t n) {
  if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
  if (s.size() != 2 * n) return false;
  for (size_t i = 0; i < 2 * n; i++) {
    char ch = s[i];
    int v;
    if (ch >= '0' && ch <= '9') v = ch - '0';
    else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
    else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
    else return false;
    if (i % 2 == 0) out[i / 2] = (uint8_t)(v << 4);
    else out[i / 2] |= (uint8_t)v;
  }
  return true;
}

// ---------------------------------------------------------------- keccak256

static inline uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

static void keccakf(uint64_t st[25]) {
  static const uint64_t RC[24] = {KECCAK_RC_LIST};
  static const int rotc[24] = {KECCAK_ROTC_LIST};
  static const int piln[24] = {KECCAK_PILN_LIST};
  for (int r = 0; r < 24; r++) {
    uint64_t bc[5];
    for (int i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    for (int i = 0; i < 5; i++) {
      uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
      for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
    }
    uint64_t t = st[1];
    for (int j = 0; j < 24; j++) {
      int k = piln[j];
      uint64_t tmp = st[k];
      st[k] = rotl64(t, rotc[j]);
      t = tmp;
    }
    for (int j = 0; j < 25; j += 5) {
      for (int i = 0; i < 5; i++) bc[i] = st[j + i];
      for (int i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }
    st[0] ^= RC[r];
  }
}

void keccak256(const uint8_t* in, size_t len, uint8_t out[32]) {
  const size_t rate = 136;
  uint64_t st[25] = {0};
  uint8_t blk[rate];
  while (len >= rate) {
    for (size_t i = 0; i < rate / 8; i++) {
      uint64_t v = 0;
      for (int b = 0; b < 8; b++) v |= (uint64_t)in[8 * i + b] << (8 * b);
      st[i] ^= v;
    }
    keccakf(st);
    in += rate;
    len -= rate;
  }
  memset(blk, 0, rate);
  memcpy(blk, in, len);
  blk[len] ^= 0x01;
  blk[rate - 1] ^= 0x80;
  for (size_t i = 0; i < rate / 8; i++) {
    uint64_t v = 0;
    for (int b = 0; b < 8; b++) v |= (uint64_t)blk[8 * i + b] << (8 * b);
    st[i] ^= v;
  }
  keccakf(st);
  for (int i = 0; i < 32; i++) out[i] = (uint8_t)(st[i / 8] >> (8 * (i % 8)));
}

// ---------------------------------------------------------------- sha256 / sha512

static inline uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static std::vector<uint8_t> md_pad(const uint8_t* in, size_t len, size_t block, size_t lenbytes) {
  std::vector<uint8_t> m(in, in + len);
  m.push_back(0x80);
  while (m.size() % block != block - lenbytes) m.push_back(0);
  uint64_t bits = (uint64_t)len * 8;
  for (size_t i = 0; i < lenbytes; i++) {
    size_t sh = 8 * (lenbytes - 1 - i);
    m.push_back(sh < 64 ? (uint8_t)(bits >> sh) : 0);
  }
  return m;
}

void sha256(const uint8_t* in, size_t len, uint8_t out[32]) {
  static const uint32_t K[64] = {SHA256_K_LIST};
  uint32_t h[8] = {SHA256_IV_LIST};
  std::vector<uint8_t> m = md_pad(in, len, 64, 8);
  for (size_t off = 0; off < m.size(); off += 64) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
      w[i] = (uint32_t)m[off + 4 * i] << 24 | (uint32_t)m[off + 4 * i + 1] << 16 |
             (uint32_t)m[off + 4 * i + 2] << 8 | m[off + 4 * i + 3];
    for (int i = 16; i < 64; i++) {
      uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
      uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; i++) {
      uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
      uint32_t ch = (e & f) ^ (~e & g);
      uint32_t t1 = hh + S1 + ch + K[i] + w[i];
      uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
      uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
      uint32_t t2 = S0 + mj;
      hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  for (int i = 0; i < 32; i++) out[i] = (uint8_t)(h[i / 4] >> (24 - 8 * (i % 4)));
}

void sha512(const uint8_t* in, size_t len, uint8_t out[64]) {
  static const uint64_t K[80] = {SHA512_K_LIST};
  uint64_t h[8] = {SHA512_IV_LIST};
  std::vector<uint8_t> m = md_pad(in, len, 128, 16);
  for (size_t off = 0; off < m.size(); off += 128) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
      w[i] = 0;
      for (int b = 0; b < 8; b++) w[i] = (w[i] << 8) | m[off + 8 * i + b];
    }
    for (int i = 16; i < 80; i++) {
      uint64_t s0 = ror64(w[i - 15], 1) ^ ror64(w[i - 15], 8) ^ (w[i - 15] >> 7);
      uint64_t s1 = ror64(w[i - 2], 19) ^ ror64(w[i - 2], 61) ^ (w[i - 2] >> 6);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 80; i++) {
      uint64_t S1 = ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41);
      uint64_t ch = (e & f) ^ (~e & g);
      uint64_t t1 = hh + S1 + ch + K[i] + w[i];
      uint64_t S0 = ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39);
      uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
      uint64_t t2 = S0 + mj;
      hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  for (int i = 0; i < 64; i++) out[i] = (uint8_t)(h[i / 8] >> (56 - 8 * (i % 8)));
}

// ---------------------------------------------------------------- base58

std::string base58(const uint8_t* in, size_t len) {
  static const char* A = BASE58_ALPHABET;
  size_t zeros = 0;
  while (zeros < len && in[zeros] == 0) zeros++;
  std::vector<uint8_t> b58((len - zeros) * 138 / 100 + 1, 0);
  size_t length = 0;
  for (size_t i = zeros; i < len; i++) {
    int carry = in[i];
    size_t k = 0;
    for (auto it = b58.rbegin(); (carry != 0 || k < length) && it != b58.rend(); ++it, ++k) {
      carry += 256 * (*it);
      *it = (uint8_t)(carry % 58);
      carry /= 58;
    }
    length = k;
  }
  auto it = b58.begin() + (b58.size() - length);
  while (it != b58.end() && *it == 0) ++it;
  std::string s(zeros, '1');
  for (; it != b58.end(); ++it) s += A[*it];
  return s;
}

int base58_value(char c) {
  const char* A = BASE58_ALPHABET;
  for (int i = 0; i < 58; i++)
    if (A[i] == c) return i;
  return -1;
}

// ---------------------------------------------------------------- fields

static void mul512(const U256& a, const U256& b, uint64_t t[8]) {
  memset(t, 0, 8 * sizeof(uint64_t));
  for (int i = 0; i < 4; i++) {
    uint64_t carry = 0;
    for (int j = 0; j < 4; j++) {
      u128 cur = (u128)a.w[i] * b.w[j] + t[i + j] + carry;
      t[i + j] = (uint64_t)cur;
      carry = (uint64_t)(cur >> 64);
    }
    t[i + 4] = carry;
  }
}

U256 Field::mul(const U256& a, const U256& b) const {
  uint64_t t[8];
  mul512(a, b, t);
  // fold the high half: hi * 2^256 ≡ hi * c
  U256 r;
  u128 acc = 0;
  for (int i = 0; i < 4; i++) {
    acc += (u128)t[i] + (u128)t[4 + i] * c;
    r.w[i] = (uint64_t)acc;
    acc >>= 64;
  }
  u128 x = acc * c;
  u128 s = (u128)r.w[0] + (uint64_t)x;
  r.w[0] = (uint64_t)s;
  s >>= 64;
  s += (uint64_t)(x >> 64);
  for (int i = 1; i < 4; i++) {
    s += r.w[i];
    r.w[i] = (uint64_t)s;
    s >>= 64;
  }
  if (s) {  // wrapped once more; r is tiny now so this cannot overflow
    u128 s2 = (u128)r.w[0] + c;
    r.w[0] = (uint64_t)s2;
    for (int i = 1; i < 4 && (s2 >>= 64); i++) {
      s2 += r.w[i];
      r.w[i] = (uint64_t)s2;
    }
  }
  while (cmp(r, p) >= 0) sub_b(r, r, p);
  return r;
}

U256 Field::pow(const U256& a, const U256& e) const {
  U256 r = U256::from_u64(1);
  for (int i = 255; i >= 0; i--) {
    r = sqr(r);
    if (e.bit(i)) r = mul(r, a);
  }
  return r;
}

U256 Field::inv(const U256& a) const {
  U256 e;
  sub_b(e, p, U256::from_u64(2));
  return pow(a, e);
}

const Field FP = {U256::from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
                  0x1000003D1ULL};
const Field F25519 = {U256::from_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"),
                      38};

// ---------------------------------------------------------------- secp256k1

const U256 SECP_N = U256::from_hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const U256 SECP_BETA = U256::from_hex("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");
const U256 SECP_LAMBDA = U256::from_hex("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");

U256 n_add(const U256& a, const U256& b) { return addmod(a, b, SECP_N); }
U256 n_mul(const U256& a, const U256& b) { return mulmod_slow(a, b, SECP_N); }
U256 n_neg(const U256& a) { return submod(U256(), a, SECP_N); }

SPt s_gen() {
  SPt g;
  g.x = U256::from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
  g.y = U256::from_hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
  g.inf = false;
  return g;
}

SPt s_add(const SPt& a, const SPt& b) {
  if (a.inf) return b;
  if (b.inf) return a;
  U256 lam;
  if (a.x == b.x) {
    if (a.y != b.y || a.y.is_zero()) return SPt();  // P + (-P)
    U256 x2 = FP.sqr(a.x);
    U256 num = FP.add(FP.add(x2, x2), x2);
    lam = FP.mul(num, FP.inv(FP.add(a.y, a.y)));
  } else {
    lam = FP.mul(FP.sub(b.y, a.y), FP.inv(FP.sub(b.x, a.x)));
  }
  SPt r;
  r.inf = false;
  r.x = FP.sub(FP.sub(FP.sqr(lam), a.x), b.x);
  r.y = FP.sub(FP.mul(lam, FP.sub(a.x, r.x)), a.y);
  return r;
}

// Jacobian coordinates (x = X/Z^2, y = Y/Z^3) so a scalar multiplication needs one inversion.
namespace {
struct SJac {
  U256 X, Y, Z;
  bool inf = true;
};

SJac sj_dbl(const SJac& p) {
  if (p.inf || p.Y.is_zero()) return SJac();
  const Field& F = FP;
  U256 A = F.sqr(p.X), B = F.sqr(p.Y), C = F.sqr(B);
  U256 D = F.sub(F.sub(F.sqr(F.add(p.X, B)), A), C);
  D = F.add(D, D);
  U256 E = F.add(F.add(A, A), A), Fv = F.sqr(E);
  SJac r;
  r.inf = false;
  r.X = F.sub(Fv, F.add(D, D));
  U256 C8 = F.add(C, C);
  C8 = F.add(C8, C8);
  C8 = F.add(C8, C8);
  r.Y = F.sub(F.mul(E, F.sub(D, r.X)), C8);
  r.Z = F.mul(F.add(p.Y, p.Y), p.Z);
  return r;
}

SJac sj_add_affine(const SJac& p, const SPt& q) {
  if (q.inf) return p;
  if (p.inf) return SJac{q.x, q.y, U256::from_u64(1), false};
  const Field& F = FP;
  U256 z2 = F.sqr(p.Z);
  U256 u2 = F.mul(q.x, z2), s2 = F.mul(q.y, F.mul(z2, p.Z));
  U256 h = F.sub(u2, p.X), r = F.sub(s2, p.Y);
  if (h.is_zero()) return r.is_zero() ? sj_dbl(p) : SJac();
  U256 h2 = F.sqr(h), h3 = F.mul(h2, h), xh2 = F.mul(p.X, h2);
  SJac o;
  o.inf = false;
  o.X = F.sub(F.sub(F.sqr(r), h3), F.add(xh2, xh2));
  o.Y = F.sub(F.mul(r, F.sub(xh2, o.X)), F.mul(p.Y, h3));
  o.Z = F.mul(p.Z, h);
  return o;
}
}  // namespace

SPt s_mul(const U256& k, const SPt& p) {
  SJac r;
  for (int i = 255; i >= 0; i--) {
    r = sj_dbl(r);
    if (k.bit(i)) r = sj_add_affine(r, p);
  }
  SPt o;
  if (r.inf) return o;
  U256 zi = FP.inv(r.Z), zi2 = FP.sqr(zi);
  o.x = FP.mul(r.X, zi2);
  o.y = FP.mul(r.Y, FP.mul(zi2, zi));
  o.inf = false;
  return o;
}

bool s_on_curve(const SPt& p) {
  if (p.inf) return false;
  U256 lhs = FP.sqr(p.y);
  U256 rhs = FP.add(FP.mul(FP.sqr(p.x), p.x), U256::from_u64(7));
  return lhs == rhs && cmp(p.x, FP.p) < 0 && cmp(p.y, FP.p) < 0;
}

bool s_parse_pubkey(const std::string& hexstr, SPt& out) {
  std::string s = hexstr;
  if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
  uint8_t b[65];
  if (s.size() == 128) s = "04" + s;
  if (s.size() == 130) {
    if (!unhex(s, b, 65) || b[0] != 4) return false;
    out.x = U256::from_be(b + 1);
    out.y = U256::from_be(b + 33);
  } else if (s.size() == 66) {
    if (!unhex(s, b, 33) || (b[0] != 2 && b[0] != 3)) return false;
    out.x = U256::from_be(b + 1);
    if (cmp(out.x, FP.p) >= 0) return false;
    U256 rhs = FP.add(FP.mul(FP.sqr(out.x), out.x), U256::from_u64(7));
    U256 e;  // (p + 1) / 4
    add_c(e, FP.p, U256::from_u64(1));
    for (int i = 0; i < 2; i++) {
      for (int j = 0; j < 3; j++) e.w[j] = (e.w[j] >> 1) | (e.w[j + 1] << 63);
      e.w[3] >>= 1;
    }
    out.y = FP.pow(rhs, e);
    if ((out.y.w[0] & 1) != (uint64_t)(b[0] & 1)) out.y = FP.neg(out.y);
  } else {
    return false;
  }
  out.inf = false;
  return s_on_curve(out);
}

void evm_addr20(const SPt& p, uint8_t out[20]) {
  uint8_t xy[64], h[32];
  p.x.to_be(xy);
  p.y.to_be(xy + 32);
  keccak256(xy, 64, h);
  memcpy(out, h + 12, 20);
}

std::string evm_address(const SPt& p) {
  uint8_t a[20];
  evm_addr20(p, a);
  return hex(a, 20);
}

std::string eip55(const std::string& lower40) {
  uint8_t h[32];
  keccak256(reinterpret_cast<const uint8_t*>(lower40.data()), lower40.size(), h);
  std::string r = "0x";
  for (size_t i = 0; i < lower40.size(); i++) {
    char ch = lower40[i];
    int nib = (h[i / 2] >> (i % 2 ? 0 : 4)) & 15;
    if (ch >= 'a' && ch <= 'f' && nib >= 8) ch = (char)(ch - 'a' + 'A');
    r += ch;
  }
  return r;
}

std::string b58check(uint8_t version, const uint8_t* payload, size_t n) {
  std::vector<uint8_t> b(1 + n + 4);
  b[0] = version;
  memcpy(b.data() + 1, payload, n);
  uint8_t h[32];
  sha256(b.data(), 1 + n, h);
  sha256(h, 32, h);
  memcpy(b.data() + 1 + n, h, 4);
  std::string s = base58(b.data(), b.size());
  for (auto& x : b) x = 0;
  return s;
}

std::string tron_from20(const uint8_t a20[20]) { return b58check(0x41, a20, 20); }

std::string tron_address(const SPt& p) {
  uint8_t a[20];
  evm_addr20(p, a);
  return tron_from20(a);
}

// ---------------------------------------------------------------- Bitcoin

static inline uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void ripemd160(const uint8_t* in, size_t len, uint8_t out[20]) {
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
  auto f = [](int j, uint32_t x, uint32_t y, uint32_t z) -> uint32_t {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  };
  uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
  std::vector<uint8_t> m(in, in + len);
  m.push_back(0x80);
  while (m.size() % 64 != 56) m.push_back(0);
  const uint64_t bits = (uint64_t)len * 8;
  for (int i = 0; i < 8; i++) m.push_back((uint8_t)(bits >> (8 * i)));
  for (size_t off = 0; off < m.size(); off += 64) {
    uint32_t X[16];
    for (int i = 0; i < 16; i++)
      X[i] = (uint32_t)m[off + 4 * i] | (uint32_t)m[off + 4 * i + 1] << 8 | (uint32_t)m[off + 4 * i + 2] << 16 |
             (uint32_t)m[off + 4 * i + 3] << 24;
    uint32_t a1 = h[0], b1 = h[1], c1 = h[2], d1 = h[3], e1 = h[4];
    uint32_t a2 = h[0], b2 = h[1], c2 = h[2], d2 = h[3], e2 = h[4];
    for (int j = 0; j < 80; j++) {
      uint32_t t = rol32(a1 + f(j, b1, c1, d1) + X[R1[j]] + K1[j / 16], S1[j]) + e1;
      a1 = e1; e1 = d1; d1 = rol32(c1, 10); c1 = b1; b1 = t;
      t = rol32(a2 + f(79 - j, b2, c2, d2) + X[R2[j]] + K2[j / 16], S2[j]) + e2;
      a2 = e2; e2 = d2; d2 = rol32(c2, 10); c2 = b2; b2 = t;
    }
    uint32_t t = h[1] + c1 + d2;
    h[1] = h[2] + d1 + e2;
    h[2] = h[3] + e1 + a2;
    h[3] = h[4] + a1 + b2;
    h[4] = h[0] + b1 + c2;
    h[0] = t;
  }
  for (int i = 0; i < 20; i++) out[i] = (uint8_t)(h[i / 4] >> (8 * (i % 4)));
}

void hash160(const uint8_t* in, size_t len, uint8_t out[20]) {
  uint8_t h[32];
  sha256(in, len, h);
  ripemd160(h, 32, out);
}

void btc_hash160(const SPt& p, uint8_t out[20]) {
  uint8_t c[33];
  c[0] = (p.y.w[0] & 1) ? 0x03 : 0x02;
  p.x.to_be(c + 1);
  hash160(c, 33, out);
}

const char* const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t bech32_step(uint32_t c, uint32_t v) {
  static const uint32_t GEN[5] = {0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u};
  const uint32_t b = c >> 25;
  c = ((c & 0x1ffffffu) << 5) ^ v;
  for (int i = 0; i < 5; i++)
    if ((b >> i) & 1) c ^= GEN[i];
  return c;
}

uint32_t bech32_bc_v0_state() {
  uint32_t c = 1;
  for (uint32_t v : {3u, 3u, 0u, 2u, 3u, 0u}) c = bech32_step(c, v);  // hrp "bc" expanded, version 0
  return c;
}

std::string btc_p2wpkh(const uint8_t h20[20]) {
  uint32_t vals[38];
  for (int i = 0; i < 32; i++) {  // 160 bits as 32 groups of 5
    int bit = 5 * i;
    uint32_t w = (uint32_t)h20[bit / 8] << 8 | (bit / 8 + 1 < 20 ? h20[bit / 8 + 1] : 0);
    vals[i] = (w >> (11 - bit % 8)) & 31;
  }
  uint32_t c = bech32_bc_v0_state();
  for (int i = 0; i < 32; i++) c = bech32_step(c, vals[i]);
  for (int i = 0; i < 6; i++) c = bech32_step(c, 0);
  c ^= 1;
  for (int i = 0; i < 6; i++) vals[32 + i] = (c >> (5 * (5 - i))) & 31;
  std::string s = "bc1q";
  for (uint32_t v : vals) s += BECH32_CHARSET[v];
  return s;
}

std::string btc_p2pkh(const uint8_t h20[20]) { return b58check(0x00, h20, 20); }

void btc_p2sh_hash(const uint8_t h20[20], uint8_t out[20]) {
  uint8_t script[22] = {0x00, 0x14};
  memcpy(script + 2, h20, 20);
  hash160(script, 22, out);
}

std::string btc_p2sh_p2wpkh(const uint8_t h20[20]) {
  uint8_t sh[20];
  btc_p2sh_hash(h20, sh);
  return b58check(0x05, sh, 20);
}

std::string btc_wif(const U256& key) {
  uint8_t b[33];
  key.to_be(b);
  b[32] = 0x01;  // compressed public key
  std::string s = b58check(0x80, b, 33);
  for (auto& x : b) x = 0;
  return s;
}

// ---------------------------------------------------------------- ed25519

static U256 ed_d() {
  // d = -121665 / 121666
  return F25519.neg(F25519.mul(U256::from_u64(121665), F25519.inv(U256::from_u64(121666))));
}
const U256 ED_D = ed_d();

EPt e_base() {
  EPt b;
  b.x = U256::from_hex("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a");
  b.y = F25519.mul(U256::from_u64(4), F25519.inv(U256::from_u64(5)));
  return b;
}

// Complete twisted Edwards addition (a = -1), affine.
EPt e_add(const EPt& a, const EPt& b) {
  const Field& F = F25519;
  U256 x1y2 = F.mul(a.x, b.y), y1x2 = F.mul(a.y, b.x);
  U256 x1x2 = F.mul(a.x, b.x), y1y2 = F.mul(a.y, b.y);
  U256 t = F.mul(ED_D, F.mul(x1x2, y1y2));
  U256 one = U256::from_u64(1);
  EPt r;
  r.x = F.mul(F.add(x1y2, y1x2), F.inv(F.add(one, t)));
  r.y = F.mul(F.add(y1y2, x1x2), F.inv(F.sub(one, t)));
  return r;
}

// Extended coordinates (x = X/Z, y = Y/Z, xy = T/Z); the addition law is complete,
// so it also doubles. One inversion per scalar multiplication.
namespace {
struct EExt {
  U256 X, Y, Z, T;
};

EExt ee_add(const EExt& p, const EExt& q) {
  const Field& F = F25519;
  U256 A = F.mul(F.sub(p.Y, p.X), F.sub(q.Y, q.X));
  U256 B = F.mul(F.add(p.Y, p.X), F.add(q.Y, q.X));
  U256 C = F.mul(F.mul(p.T, q.T), F.add(ED_D, ED_D));
  U256 D = F.mul(p.Z, q.Z);
  D = F.add(D, D);
  U256 E = F.sub(B, A), Fv = F.sub(D, C), G = F.add(D, C), H = F.add(B, A);
  return EExt{F.mul(E, Fv), F.mul(G, H), F.mul(Fv, G), F.mul(E, H)};
}
}  // namespace

EPt e_mul(const U256& k, const EPt& p) {
  const Field& F = F25519;
  const EExt P{p.x, p.y, U256::from_u64(1), F.mul(p.x, p.y)};
  EExt r{U256(), U256::from_u64(1), U256::from_u64(1), U256()};
  for (int i = 255; i >= 0; i--) {
    r = ee_add(r, r);
    if (k.bit(i)) r = ee_add(r, P);
  }
  U256 zi = F.inv(r.Z);
  return EPt{F.mul(r.X, zi), F.mul(r.Y, zi)};
}

bool e_on_curve(const EPt& p) {
  const Field& F = F25519;
  U256 x2 = F.sqr(p.x), y2 = F.sqr(p.y);
  U256 lhs = F.sub(y2, x2);
  U256 rhs = F.add(U256::from_u64(1), F.mul(ED_D, F.mul(x2, y2)));
  return lhs == rhs;
}

void ed_pubkey(const uint8_t seed[32], uint8_t pub[32]) {
  uint8_t h[64];
  sha512(seed, 32, h);
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  U256 a = U256::from_le(h);
  EPt A = e_mul(a, e_base());
  A.y.to_le(pub);
  pub[31] |= (uint8_t)((A.x.w[0] & 1) << 7);
}

std::string sol_address(const uint8_t pub[32]) { return base58(pub, 32); }

// ---------------------------------------------------------------- TON

// Representation hash of the wallet_v5r1 code cell (wallet_v5.compiled.json, re-derived from the BOC).
const uint8_t TON_W5_CODE_HASH[32] = {0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f,
                                      0xb4, 0x57, 0xb8, 0x4e, 0x74, 0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37,
                                      0xd4, 0xf6, 0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f};

namespace {
struct BitWriter {
  uint8_t b[64] = {0};
  int pos = 0;
  void bit(int v) {
    if (v) b[pos / 8] |= (uint8_t)(0x80 >> (pos % 8));
    pos++;
  }
  void uint(uint64_t v, int n) {
    for (int i = n - 1; i >= 0; i--) bit((v >> i) & 1);
  }
};
}  // namespace

void ton_account_hash(const uint8_t pub[32], uint32_t wallet_id, uint8_t out[32]) {
  // data cell: is_signature_allowed:1, seqno:32, wallet_id:32, public_key:256, extensions:dict(empty)
  BitWriter d;
  d.bit(1);
  d.uint(0, 32);
  d.uint(wallet_id, 32);
  for (int i = 0; i < 32; i++) d.uint(pub[i], 8);
  d.bit(0);
  const int nbits = d.pos;  // 322
  d.bit(1);                 // completion tag: bit count is not a multiple of 8
  const int nbytes = (nbits + 7) / 8;
  uint8_t repr[2 + 64];
  repr[0] = 0;                                                // d1: no refs, ordinary, level 0
  repr[1] = (uint8_t)(nbits / 8 + (nbits + 7) / 8);           // d2
  memcpy(repr + 2, d.b, nbytes);
  uint8_t data_hash[32];
  sha256(repr, 2 + nbytes, data_hash);

  // StateInit cell: split_depth:nothing, special:nothing, code:just, data:just, library:empty
  uint8_t si[3 + 4 + 64];
  si[0] = 2;     // two refs
  si[1] = 1;     // 5 data bits
  si[2] = 0x34;  // 00110 + completion tag
  si[3] = (uint8_t)(TON_W5_CODE_DEPTH >> 8);
  si[4] = (uint8_t)TON_W5_CODE_DEPTH;
  si[5] = 0;  // data cell depth
  si[6] = 0;
  memcpy(si + 7, TON_W5_CODE_HASH, 32);
  memcpy(si + 39, data_hash, 32);
  sha256(si, sizeof si, out);
}

static uint16_t crc16_xmodem(const uint8_t* p, size_t n) {
  uint32_t crc = 0;
  for (size_t i = 0; i < n; i++) {
    crc ^= (uint32_t)p[i] << 8;
    for (int k = 0; k < 8; k++) crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) : (crc << 1);
    crc &= 0xFFFF;
  }
  return (uint16_t)crc;
}

std::string ton_address(const uint8_t hash[32], bool bounceable) {
  static const char* A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  uint8_t b[36];
  b[0] = bounceable ? 0x11 : 0x51;
  b[1] = 0;  // workchain 0
  memcpy(b + 2, hash, 32);
  uint16_t crc = crc16_xmodem(b, 34);
  b[34] = (uint8_t)(crc >> 8);
  b[35] = (uint8_t)crc;
  std::string s;
  for (int i = 0; i < 36; i += 3) {
    uint32_t v = (uint32_t)b[i] << 16 | (uint32_t)b[i + 1] << 8 | b[i + 2];
    for (int k = 3; k >= 0; k--) s += A[(v >> (6 * k)) & 63];
  }
  return s;
}

}  // namespace hc
