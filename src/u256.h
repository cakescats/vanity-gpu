// 256-bit unsigned integer for host-side (CPU) arithmetic.
#pragma once
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

typedef unsigned __int128 u128;

struct U256 {
  uint64_t w[4] = {0, 0, 0, 0};  // little-endian 64-bit limbs

  static U256 from_u64(uint64_t v) { U256 r; r.w[0] = v; return r; }

  static U256 from_hex(std::string s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
    if (s.empty() || s.size() > 64) throw std::runtime_error("bad 256-bit hex value");
    U256 r;
    for (char ch : s) {
      int v;
      if (ch >= '0' && ch <= '9') v = ch - '0';
      else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
      else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
      else throw std::runtime_error("bad hex digit in '" + s + "'");
      for (int i = 3; i > 0; i--) r.w[i] = (r.w[i] << 4) | (r.w[i - 1] >> 60);
      r.w[0] = (r.w[0] << 4) | (uint64_t)v;
    }
    return r;
  }
  static U256 from_be(const uint8_t b[32]) {
    U256 r;
    for (int i = 0; i < 32; i++) r.w[3 - i / 8] |= (uint64_t)b[i] << (8 * (7 - i % 8));
    return r;
  }
  static U256 from_le(const uint8_t b[32]) {
    U256 r;
    for (int i = 0; i < 32; i++) r.w[i / 8] |= (uint64_t)b[i] << (8 * (i % 8));
    return r;
  }
  static U256 from_u32(const uint32_t o[8]) {
    U256 r;
    for (int i = 0; i < 4; i++) r.w[i] = (uint64_t)o[2 * i] | ((uint64_t)o[2 * i + 1] << 32);
    return r;
  }
  void to_be(uint8_t b[32]) const {
    for (int i = 0; i < 32; i++) b[i] = (uint8_t)(w[3 - i / 8] >> (8 * (7 - i % 8)));
  }
  void to_le(uint8_t b[32]) const {
    for (int i = 0; i < 32; i++) b[i] = (uint8_t)(w[i / 8] >> (8 * (i % 8)));
  }
  void to_u32(uint32_t o[8]) const {
    for (int i = 0; i < 4; i++) { o[2 * i] = (uint32_t)w[i]; o[2 * i + 1] = (uint32_t)(w[i] >> 32); }
  }
  std::string hex() const {
    static const char* H = "0123456789abcdef";
    std::string s(64, '0');
    for (int i = 0; i < 64; i++) s[63 - i] = H[(w[i / 16] >> (4 * (i % 16))) & 15];
    return s;
  }
  bool is_zero() const { return (w[0] | w[1] | w[2] | w[3]) == 0; }
  bool bit(int i) const { return (w[i >> 6] >> (i & 63)) & 1; }
  bool operator==(const U256& o) const { return memcmp(w, o.w, sizeof w) == 0; }
  bool operator!=(const U256& o) const { return !(*this == o); }
};

inline int cmp(const U256& a, const U256& b) {
  for (int i = 3; i >= 0; i--)
    if (a.w[i] != b.w[i]) return a.w[i] < b.w[i] ? -1 : 1;
  return 0;
}

inline uint64_t add_c(U256& r, const U256& a, const U256& b) {
  u128 c = 0;
  for (int i = 0; i < 4; i++) { c += (u128)a.w[i] + b.w[i]; r.w[i] = (uint64_t)c; c >>= 64; }
  return (uint64_t)c;
}

inline uint64_t sub_b(U256& r, const U256& a, const U256& b) {
  uint64_t borrow = 0;
  for (int i = 0; i < 4; i++) {
    u128 t = (u128)a.w[i] - b.w[i] - borrow;
    r.w[i] = (uint64_t)t;
    borrow = (uint64_t)(t >> 64) ? 1 : 0;
  }
  return borrow;
}

// Generic modular helpers (operands must already be < m).
inline U256 addmod(const U256& a, const U256& b, const U256& m) {
  U256 r;
  if (add_c(r, a, b) || cmp(r, m) >= 0) sub_b(r, r, m);
  return r;
}
inline U256 submod(const U256& a, const U256& b, const U256& m) {
  U256 r;
  if (sub_b(r, a, b)) add_c(r, r, m);
  return r;
}
// Slow but obviously-correct double-and-add multiplication; used for scalars only.
inline U256 mulmod_slow(const U256& a, const U256& b, const U256& m) {
  U256 r;
  for (int i = 255; i >= 0; i--) {
    r = addmod(r, r, m);
    if (b.bit(i)) r = addmod(r, a, m);
  }
  return r;
}
