// Keccak-256, SHA-256, SHA-512 and ChaCha20 specialised for the fixed-size inputs we hash.
#pragma once
#include "common.cuh"
#include "constants.h"

static __constant__ uint64_t c_keccak_rc[24] = {KECCAK_RC_LIST};
static __constant__ uint32_t c_sha256_k[64] = {SHA256_K_LIST};
static __constant__ uint64_t c_sha512_k[80] = {SHA512_K_LIST};

DI uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }
DI uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
DI uint32_t rotr32(uint32_t x, int n) { return __funnelshift_r(x, x, n); }
DI uint32_t rotl32(uint32_t x, int n) { return __funnelshift_l(x, x, n); }

DI void keccakf(uint64_t st[25]) {
  const int rotc[24] = {KECCAK_ROTC_LIST};
  const int piln[24] = {KECCAK_PILN_LIST};
#pragma unroll
  for (int r = 0; r < 24; r++) {
    uint64_t bc[5];
#pragma unroll
    for (int i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
#pragma unroll
    for (int i = 0; i < 5; i++) {
      uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
#pragma unroll
      for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
    }
    uint64_t t = st[1];
#pragma unroll
    for (int j = 0; j < 24; j++) {
      int k = piln[j];
      uint64_t tmp = st[k];
      st[k] = rotl64(t, rotc[j]);
      t = tmp;
    }
#pragma unroll
    for (int j = 0; j < 25; j += 5) {
#pragma unroll
      for (int i = 0; i < 5; i++) bc[i] = st[j + i];
#pragma unroll
      for (int i = 0; i < 5; i++) st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }
    st[0] ^= c_keccak_rc[r];
  }
}

// Ethereum address of the public key (x, y): last 20 bytes of keccak256(x||y),
// returned as 5 big-endian words.
DI void keccak_addr(const uint32_t x[8], const uint32_t y[8], uint32_t a[5]) {
  uint64_t st[25];
#pragma unroll
  for (int i = 0; i < 4; i++) {
    st[i] = ((uint64_t)bswap32(x[6 - 2 * i]) << 32) | bswap32(x[7 - 2 * i]);
    st[4 + i] = ((uint64_t)bswap32(y[6 - 2 * i]) << 32) | bswap32(y[7 - 2 * i]);
  }
  st[8] = 1;
#pragma unroll
  for (int i = 9; i < 25; i++) st[i] = 0;
  st[16] = 0x8000000000000000ull;
  keccakf(st);
  a[0] = bswap32((uint32_t)(st[1] >> 32));
  a[1] = bswap32((uint32_t)st[2]);
  a[2] = bswap32((uint32_t)(st[2] >> 32));
  a[3] = bswap32((uint32_t)st[3]);
  a[4] = bswap32((uint32_t)(st[3] >> 32));
}

DI void sha256_compress(uint32_t h[8], uint32_t w[16]) {
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
#pragma unroll
  for (int i = 0; i < 64; i++) {
    uint32_t wi;
    if (i < 16) {
      wi = w[i];
    } else {
      uint32_t w15 = w[(i - 15) & 15], w2 = w[(i - 2) & 15];
      uint32_t s0 = rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 >> 3);
      uint32_t s1 = rotr32(w2, 17) ^ rotr32(w2, 19) ^ (w2 >> 10);
      wi = w[i & 15] = w[i & 15] + s0 + w[(i - 7) & 15] + s1;
    }
    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = hh + S1 + ch + c_sha256_k[i] + wi;
    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + S0 + mj;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

// First word of sha256(sha256(VER || a[20 bytes])): the base58check checksum
// (TRON: 0x41, Bitcoin P2PKH: 0x00, P2SH: 0x05).
template <uint32_t VER>
DI uint32_t b58check_checksum(const uint32_t a[5]) {
  uint32_t w[16], h[8] = {SHA256_IV_LIST};
  w[0] = (VER << 24) | (a[0] >> 8);
#pragma unroll
  for (int i = 1; i < 5; i++) w[i] = (a[i - 1] << 24) | (a[i] >> 8);
  w[5] = (a[4] << 24) | 0x00800000u;
#pragma unroll
  for (int i = 6; i < 15; i++) w[i] = 0;
  w[15] = 21 * 8;
  sha256_compress(h, w);
#pragma unroll
  for (int i = 0; i < 8; i++) w[i] = h[i];
  w[8] = 0x80000000u;
#pragma unroll
  for (int i = 9; i < 15; i++) w[i] = 0;
  w[15] = 256;
  uint32_t h2[8] = {SHA256_IV_LIST};
  sha256_compress(h2, w);
  return h2[0];
}

// ---------------------------------------------------------------- Bitcoin

// RIPEMD-160 of a 32-byte message given as 8 big-endian words (a SHA-256 digest);
// the 20-byte result as 5 big-endian words.
DI void ripemd160_32(const uint32_t in[8], uint32_t out[5]) {
  const int R1[80] = {0, 1, 2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 7,  4,  13, 1,
                      10, 6, 15, 3,  12, 0,  9,  5,  2,  14, 11, 8,  3,  10, 14, 4,  9,  15, 8,  1,
                      2,  7, 0,  6,  13, 11, 5,  12, 1,  9,  11, 10, 0,  8,  12, 4,  13, 3,  7,  15,
                      14, 5, 6,  2,  4,  0,  5,  9,  7,  12, 2,  10, 14, 1,  3,  8,  11, 6,  15, 13};
  const int R2[80] = {5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12, 6,  11, 3,  7,
                      0,  13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,  15, 5,  1,  3,  7,  14, 6,  9,
                      11, 8,  12, 2,  10, 0,  4,  13, 8,  6,  4,  1,  3,  11, 15, 0,  5,  12, 2,  13,
                      9,  7,  10, 14, 12, 15, 10, 4,  1,  5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11};
  const int S1[80] = {11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,  7,  6,  8,  13,
                      11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12, 11, 13, 6,  7,  14, 9,  13, 15,
                      14, 8,  13, 6,  5,  12, 7,  5,  11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,
                      8,  6,  5,  12, 9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6};
  const int S2[80] = {8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,  9,  13, 15, 7,
                      12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11, 9,  7,  15, 11, 8,  6,  6,  14,
                      12, 13, 5,  14, 13, 13, 7,  5,  15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,
                      12, 5,  15, 8,  8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11};
  const uint32_t K1[5] = {0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xA953FD4Eu};
  const uint32_t K2[5] = {0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x7A6D76E9u, 0x00000000u};
  uint32_t X[16];
#pragma unroll
  for (int i = 0; i < 8; i++) X[i] = bswap32(in[i]);
  X[8] = 0x80u;
#pragma unroll
  for (int i = 9; i < 16; i++) X[i] = 0;
  X[14] = 256;
  const uint32_t h0 = 0x67452301u, h1 = 0xEFCDAB89u, h2 = 0x98BADCFEu, h3 = 0x10325476u, h4 = 0xC3D2E1F0u;
  uint32_t a1 = h0, b1 = h1, c1 = h2, d1 = h3, e1 = h4;
  uint32_t a2 = h0, b2 = h1, c2 = h2, d2 = h3, e2 = h4;
#pragma unroll
  for (int j = 0; j < 80; j++) {
    uint32_t f1, f2;
    const int r = j >> 4;
    if (r == 0) f1 = b1 ^ c1 ^ d1;
    else if (r == 1) f1 = (b1 & c1) | (~b1 & d1);
    else if (r == 2) f1 = (b1 | ~c1) ^ d1;
    else if (r == 3) f1 = (b1 & d1) | (c1 & ~d1);
    else f1 = b1 ^ (c1 | ~d1);
    if (r == 4) f2 = b2 ^ c2 ^ d2;
    else if (r == 3) f2 = (b2 & c2) | (~b2 & d2);
    else if (r == 2) f2 = (b2 | ~c2) ^ d2;
    else if (r == 1) f2 = (b2 & d2) | (c2 & ~d2);
    else f2 = b2 ^ (c2 | ~d2);
    uint32_t t = rotl32(a1 + f1 + X[R1[j]] + K1[r], S1[j]) + e1;
    a1 = e1; e1 = d1; d1 = rotl32(c1, 10); c1 = b1; b1 = t;
    t = rotl32(a2 + f2 + X[R2[j]] + K2[r], S2[j]) + e2;
    a2 = e2; e2 = d2; d2 = rotl32(c2, 10); c2 = b2; b2 = t;
  }
  out[0] = bswap32(h1 + c1 + d2);
  out[1] = bswap32(h2 + d1 + e2);
  out[2] = bswap32(h3 + e1 + a2);
  out[3] = bswap32(h4 + a1 + b2);
  out[4] = bswap32(h0 + b1 + c2);
}

// hash160 of the compressed public key (02|03 || x); x as 8 little-endian limbs.
DI void hash160_comp(const uint32_t x[8], uint32_t odd, uint32_t a[5]) {
  uint32_t w[16], h[8] = {SHA256_IV_LIST};
  w[0] = ((0x02u | odd) << 24) | (x[7] >> 8);
#pragma unroll
  for (int i = 1; i < 8; i++) w[i] = (x[8 - i] << 24) | (x[7 - i] >> 8);
  w[8] = (x[0] << 24) | 0x00800000u;
#pragma unroll
  for (int i = 9; i < 15; i++) w[i] = 0;
  w[15] = 33 * 8;
  sha256_compress(h, w);
  ripemd160_32(h, a);
}

// hash160 of the P2SH-P2WPKH redeem script 0x00 0x14 || k (k = key hash, 5 big-endian words).
DI void hash160_p2sh(const uint32_t k[5], uint32_t a[5]) {
  uint32_t w[16], h[8] = {SHA256_IV_LIST};
  w[0] = 0x00140000u | (k[0] >> 16);
#pragma unroll
  for (int i = 1; i < 5; i++) w[i] = (k[i - 1] << 16) | (k[i] >> 16);
  w[5] = (k[4] << 16) | 0x8000u;
#pragma unroll
  for (int i = 6; i < 15; i++) w[i] = 0;
  w[15] = 22 * 8;
  sha256_compress(h, w);
  ripemd160_32(h, a);
}

// 5-bit group i of a big-endian bit string (bech32 character i after "bc1q").
DI uint32_t b5_at(const uint32_t* S, int i) {
  const int b = 5 * i, w = b >> 5, off = b & 31;
  uint32_t v = S[w] << off;
  if (off > 27) v |= S[w + 1] >> (32 - off);
  return v >> 27;
}

DI uint32_t bech32_step(uint32_t c, uint32_t v) {
  const uint32_t b = c >> 25;
  c = ((c & 0x1ffffffu) << 5) ^ v;
  c ^= (0u - (b & 1u)) & 0x3b6a57b2u;
  c ^= (0u - ((b >> 1) & 1u)) & 0x26508e6du;
  c ^= (0u - ((b >> 2) & 1u)) & 0x1ea119fau;
  c ^= (0u - ((b >> 3) & 1u)) & 0x3d4233ddu;
  c ^= (0u - ((b >> 4) & 1u)) & 0x2a1462b3u;
  return c;
}

// 30-bit bech32 checksum of a P2WPKH program (the last 6 characters of a bc1q address).
DI uint32_t bech32_checksum(const uint32_t a[5], uint32_t init) {
  uint32_t c = init;
#pragma unroll
  for (int i = 0; i < 32; i++) c = bech32_step(c, b5_at(a, i));
#pragma unroll
  for (int i = 0; i < 6; i++) c = bech32_step(c, 0);
  return c ^ 1u;
}

// EIP-55: keccak256 of the 40 lowercase hex characters; its first 40 nibbles as 5
// big-endian words (nibble >= 8 makes the letter at that position upper case).
// Rare (only for --only candidates), so kept out of line.
static __device__ __noinline__ void eip55_hash(const uint32_t a[5], uint32_t hn[5]) {
  uint64_t st[25];
#pragma unroll
  for (int i = 0; i < 25; i++) st[i] = 0;
  for (int j = 0; j < 40; j++) {
    const uint32_t nib = (a[j >> 3] >> (28 - 4 * (j & 7))) & 15u;
    const uint64_t ch = nib < 10 ? '0' + nib : 'a' + nib - 10;
    st[j >> 3] |= ch << (8 * (j & 7));
  }
  st[5] ^= 0x01ull;
  st[16] ^= 0x8000000000000000ull;
  keccakf(st);
  for (int k = 0; k < 5; k++) hn[k] = 0;
  for (int k = 0; k < 20; k++) hn[k >> 2] = (hn[k >> 2] << 8) | (uint32_t)((st[k >> 3] >> (8 * (k & 7))) & 0xFFu);
}

// sha512 of a 32-byte message given as 8 little-endian words (ChaCha output).
DI void sha512_32(const uint32_t s[8], uint64_t out[4]) {
  uint64_t w[16];
#pragma unroll
  for (int k = 0; k < 4; k++) w[k] = ((uint64_t)bswap32(s[2 * k]) << 32) | bswap32(s[2 * k + 1]);
  w[4] = 0x8000000000000000ull;
#pragma unroll
  for (int k = 5; k < 15; k++) w[k] = 0;
  w[15] = 256;
  const uint64_t iv[8] = {SHA512_IV_LIST};
  uint64_t a = iv[0], b = iv[1], c = iv[2], d = iv[3], e = iv[4], f = iv[5], g = iv[6], hh = iv[7];
#pragma unroll
  for (int i = 0; i < 80; i++) {
    uint64_t wi;
    if (i < 16) {
      wi = w[i];
    } else {
      uint64_t w15 = w[(i - 15) & 15], w2 = w[(i - 2) & 15];
      uint64_t s0 = rotr64(w15, 1) ^ rotr64(w15, 8) ^ (w15 >> 7);
      uint64_t s1 = rotr64(w2, 19) ^ rotr64(w2, 61) ^ (w2 >> 6);
      wi = w[i & 15] = w[i & 15] + s0 + w[(i - 7) & 15] + s1;
    }
    uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
    uint64_t ch = (e & f) ^ (~e & g);
    uint64_t t1 = hh + S1 + ch + c_sha512_k[i] + wi;
    uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
    uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + S0 + mj;
  }
  out[0] = iv[0] + a;
  out[1] = iv[1] + b;
  out[2] = iv[2] + c;
  out[3] = iv[3] + d;
}

#define CHACHA_QR(a, b, c, d)                    \
  a += b; d ^= a; d = rotl32(d, 16);             \
  c += d; b ^= c; b = rotl32(b, 12);             \
  a += b; d ^= a; d = rotl32(d, 8);              \
  c += d; b ^= c; b = rotl32(b, 7);

// One ChaCha20 block with a 64-bit block counter (words 12-13) and zero nonce.
DI void chacha20_block(const uint32_t key[8], uint64_t ctr, uint32_t out[16]) {
  uint32_t s[16] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
                    key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
                    (uint32_t)ctr, (uint32_t)(ctr >> 32), 0u, 0u};
  uint32_t x[16];
#pragma unroll
  for (int i = 0; i < 16; i++) x[i] = s[i];
#pragma unroll
  for (int r = 0; r < 10; r++) {
    CHACHA_QR(x[0], x[4], x[8], x[12]);
    CHACHA_QR(x[1], x[5], x[9], x[13]);
    CHACHA_QR(x[2], x[6], x[10], x[14]);
    CHACHA_QR(x[3], x[7], x[11], x[15]);
    CHACHA_QR(x[0], x[5], x[10], x[15]);
    CHACHA_QR(x[1], x[6], x[11], x[12]);
    CHACHA_QR(x[2], x[7], x[8], x[13]);
    CHACHA_QR(x[3], x[4], x[9], x[14]);
  }
#pragma unroll
  for (int i = 0; i < 16; i++) out[i] = x[i] + s[i];
}
