// CPU reference implementations. Deliberately simple and independent of the
// CUDA code: every GPU result is re-derived with these before it is reported.
#pragma once
#include <cstdint>
#include <string>

#include "u256.h"

namespace hc {

std::string hex(const uint8_t* p, size_t n);
bool unhex(std::string s, uint8_t* out, size_t n);

void keccak256(const uint8_t* in, size_t len, uint8_t out[32]);
void sha256(const uint8_t* in, size_t len, uint8_t out[32]);
void sha512(const uint8_t* in, size_t len, uint8_t out[64]);
std::string base58(const uint8_t* in, size_t len);
int base58_value(char c);  // -1 if not in alphabet

// Prime field with 2^256 ≡ c (mod p); values are kept fully reduced.
struct Field {
  U256 p;
  uint64_t c;
  U256 add(const U256& a, const U256& b) const { return addmod(a, b, p); }
  U256 sub(const U256& a, const U256& b) const { return submod(a, b, p); }
  U256 neg(const U256& a) const { return submod(U256(), a, p); }
  U256 mul(const U256& a, const U256& b) const;
  U256 sqr(const U256& a) const { return mul(a, a); }
  U256 pow(const U256& a, const U256& e) const;
  U256 inv(const U256& a) const;
};
extern const Field FP;      // secp256k1 base field
extern const Field F25519;  // 2^255 - 19

// ---- secp256k1 ----
extern const U256 SECP_N, SECP_BETA, SECP_LAMBDA;
U256 n_add(const U256& a, const U256& b);
U256 n_mul(const U256& a, const U256& b);
U256 n_neg(const U256& a);

struct SPt {
  U256 x, y;
  bool inf = true;
};
SPt s_gen();
SPt s_add(const SPt& a, const SPt& b);
SPt s_mul(const U256& k, const SPt& p);
bool s_on_curve(const SPt& p);
bool s_parse_pubkey(const std::string& hex, SPt& out);

void evm_addr20(const SPt& p, uint8_t out[20]);
std::string evm_address(const SPt& p);    // 40 lowercase hex chars, no 0x
std::string eip55(const std::string& lower40);  // checksummed, with 0x
std::string tron_address(const SPt& p);
std::string tron_from20(const uint8_t a20[20]);
std::string b58check(uint8_t version, const uint8_t* payload, size_t n);

// ---- Bitcoin (compressed public keys only)
void ripemd160(const uint8_t* in, size_t len, uint8_t out[20]);
void hash160(const uint8_t* in, size_t len, uint8_t out[20]);  // ripemd160(sha256(in))
void btc_hash160(const SPt& p, uint8_t out[20]);               // of the 33-byte compressed key
extern const char* const BECH32_CHARSET;
uint32_t bech32_bc_v0_state();                     // polymod state after hrp "bc" + version 0
std::string btc_p2wpkh(const uint8_t h20[20]);     // bc1q...
std::string btc_p2pkh(const uint8_t h20[20]);      // 1...
void btc_p2sh_hash(const uint8_t h20[20], uint8_t out[20]);  // hash160(0x0014 || h20)
std::string btc_p2sh_p2wpkh(const uint8_t h20[20]);          // 3...
std::string btc_wif(const U256& key);              // compressed WIF (K... / L...)

// ---- ed25519 ----
struct EPt {
  U256 x, y;
};
extern const U256 ED_D;
EPt e_base();
EPt e_add(const EPt& a, const EPt& b);
EPt e_mul(const U256& k, const EPt& p);
bool e_on_curve(const EPt& p);
void ed_pubkey(const uint8_t seed[32], uint8_t pub[32]);
std::string sol_address(const uint8_t pub[32]);

// ---- TON wallet v5r1 (W5), workchain 0
extern const uint8_t TON_W5_CODE_HASH[32];
constexpr uint16_t TON_W5_CODE_DEPTH = 6;
constexpr uint32_t TON_WALLET_ID_MAINNET = 0x7FFFFF11u;  // -239 ^ client context(wc 0, v5r1, subwallet 0)
void ton_account_hash(const uint8_t pub[32], uint32_t wallet_id, uint8_t out[32]);
std::string ton_address(const uint8_t hash[32], bool bounceable);  // user-friendly base64url

}  // namespace hc
