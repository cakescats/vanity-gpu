// secp256k1 base field: p = 2^256 - 2^32 - 977. Values are kept fully reduced (< p).
#pragma once
#include "common.cuh"

namespace secp {

DI void fe_reduce(uint32_t r[8], const uint32_t t[16]) {
  // t = lo + hi * 2^256, and 2^256 ≡ 2^32 + 977 (mod p)
  uint32_t u[8];
  uint64_t acc = 0;
#pragma unroll
  for (int j = 0; j < 8; j++) {
    acc += (uint64_t)t[j] + (uint64_t)t[8 + j] * 977u;
    if (j > 0) acc += t[7 + j];
    u[j] = (uint32_t)acc;
    acc >>= 32;
  }
  acc += t[15];
  uint64_t c = acc;  // < 2^34
  acc = (uint64_t)u[0] + c * 977u;
  u[0] = (uint32_t)acc;
  acc >>= 32;
  acc += (uint64_t)u[1] + c;
  u[1] = (uint32_t)acc;
  acc >>= 32;
#pragma unroll
  for (int j = 2; j < 8; j++) {
    acc += u[j];
    u[j] = (uint32_t)acc;
    acc >>= 32;
  }
  uint32_t k = (uint32_t)acc;  // 0 or 1; if set, u is tiny so this cannot overflow
  ADD_CC(u[0], u[0], 977u * k);
  ADDC_CC(u[1], u[1], k);
#pragma unroll
  for (int j = 2; j < 7; j++) ADDC_CC(u[j], u[j], 0);
  ADDC(u[7], u[7], 0);
  // canonical: u >= p  <=>  u + (2^32 + 977) overflows
  uint32_t v[8], c2;
  ADD_CC(v[0], u[0], 0x3D1u);
  ADDC_CC(v[1], u[1], 1u);
#pragma unroll
  for (int j = 2; j < 8; j++) ADDC_CC(v[j], u[j], 0);
  ADDC(c2, 0, 0);
#pragma unroll
  for (int j = 0; j < 8; j++) r[j] = c2 ? v[j] : u[j];
}

DI void fe_mul(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
  uint32_t t[16];
  mul_wide(t, a, b);
  fe_reduce(r, t);
}

DI void fe_sqr(uint32_t r[8], const uint32_t a[8]) { fe_mul(r, a, a); }

DI void fe_add(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
  uint32_t s[8], u[8], c, c2;
  ADD_CC(s[0], a[0], b[0]);
#pragma unroll
  for (int j = 1; j < 8; j++) ADDC_CC(s[j], a[j], b[j]);
  ADDC(c, 0, 0);
  ADD_CC(u[0], s[0], 0x3D1u);
  ADDC_CC(u[1], s[1], 1u);
#pragma unroll
  for (int j = 2; j < 8; j++) ADDC_CC(u[j], s[j], 0);
  ADDC(c2, 0, 0);
  bool use_u = (c | c2) != 0;
#pragma unroll
  for (int j = 0; j < 8; j++) r[j] = use_u ? u[j] : s[j];
}

DI void fe_sub(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
  uint32_t s[8], bw;
  SUB_CC(s[0], a[0], b[0]);
#pragma unroll
  for (int j = 1; j < 8; j++) SUBC_CC(s[j], a[j], b[j]);
  SUBC(bw, 0, 0);  // 0xffffffff on borrow
  ADD_CC(r[0], s[0], 0xFFFFFC2Fu & bw);
  ADDC_CC(r[1], s[1], 0xFFFFFFFEu & bw);
#pragma unroll
  for (int j = 2; j < 7; j++) ADDC_CC(r[j], s[j], bw);
  ADDC(r[7], s[7], bw);
}

DI void fe_neg(uint32_t r[8], const uint32_t a[8]) {
  const uint32_t z[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  fe_sub(r, z, a);
}

DI void fe_sqr_n(uint32_t r[8], int n) {
#pragma unroll 1
  for (int i = 0; i < n; i++) fe_sqr(r, r);
}

// a^(p-2), addition chain from libsecp256k1.
DI void fe_inv(uint32_t r[8], const uint32_t a[8]) {
  uint32_t x2[8], x3[8], x6[8], x9[8], x11[8], x22[8], x44[8], x88[8], x176[8], x220[8], x223[8], t[8];
  fe_sqr(x2, a); fe_mul(x2, x2, a);
  fe_sqr(x3, x2); fe_mul(x3, x3, a);
  copy8(x6, x3); fe_sqr_n(x6, 3); fe_mul(x6, x6, x3);
  copy8(x9, x6); fe_sqr_n(x9, 3); fe_mul(x9, x9, x3);
  copy8(x11, x9); fe_sqr_n(x11, 2); fe_mul(x11, x11, x2);
  copy8(x22, x11); fe_sqr_n(x22, 11); fe_mul(x22, x22, x11);
  copy8(x44, x22); fe_sqr_n(x44, 22); fe_mul(x44, x44, x22);
  copy8(x88, x44); fe_sqr_n(x88, 44); fe_mul(x88, x88, x44);
  copy8(x176, x88); fe_sqr_n(x176, 88); fe_mul(x176, x176, x88);
  copy8(x220, x176); fe_sqr_n(x220, 44); fe_mul(x220, x220, x44);
  copy8(x223, x220); fe_sqr_n(x223, 3); fe_mul(x223, x223, x3);
  copy8(t, x223); fe_sqr_n(t, 23); fe_mul(t, t, x22);
  fe_sqr_n(t, 5); fe_mul(t, t, a);
  fe_sqr_n(t, 3); fe_mul(t, t, x2);
  fe_sqr_n(t, 2); fe_mul(r, t, a);
}

}  // namespace secp
