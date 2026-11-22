#include "pattern.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <functional>
#include <set>
#include <stdexcept>
#include <thread>
#include <unordered_set>

#include "constants.h"
#include "hostcrypto.h"

const char* chain_name(Chain c) {
  switch (c) {
    case Chain::EVM: return "EVM";
    case Chain::TRON: return "TRON";
    case Chain::SOL: return "SOL";
    case Chain::TON: return "TON";
    case Chain::BTC: return "BTC";
    case Chain::BTC_LEGACY: return "BTC-legacy";
    case Chain::BTC_P2SH: return "BTC-p2sh";
  }
  return "?";
}

int default_min_score(Chain c) {
  switch (c) {
    case Chain::EVM: return 12;
    case Chain::TON: return 7;
    case Chain::BTC: return 10;
    default: return 8;
  }
}

static const char* B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int b64_value(char c) {
  const char* p = strchr(B64URL, c);
  return c && p ? (int)(p - B64URL) : -1;
}

static int b32_value(char c) {
  const char* p = strchr(hc::BECH32_CHARSET, c);
  return c && p ? (int)(p - hc::BECH32_CHARSET) : -1;
}

static bool is_b58(Chain c) {
  return c == Chain::TRON || c == Chain::SOL || c == Chain::BTC_LEGACY || c == Chain::BTC_P2SH;
}

// Set the `width` bits of character `pos` in the big-endian bit string bmask/bval
// (TON: 6-bit base64 chars of the 36-byte address; BTC: 5-bit bech32 chars after bc1q).
static void set_bits(DevPattern& d, int pos, int v, int width) {
  for (int k = 0; k < width; k++) {
    int b = width * pos + k;
    uint32_t bit = 1u << (31 - (b & 31));
    d.bmask[b >> 5] |= bit;
    if ((v >> (width - 1 - k)) & 1) d.bval[b >> 5] |= bit;
  }
}

// First character position that counts for the score, and how many characters do.
static int score_start(Chain c, Score s) {
  switch (c) {
    case Chain::TRON: case Chain::BTC_LEGACY: case Chain::BTC_P2SH: return 1;
    case Chain::TON: return s == Score::CLASS ? 3 : 2;  // UQ, then A-D
    case Chain::BTC: return 4;                          // bc1q
    default: return 0;
  }
}

int score_positions(Chain c, Score s) {
  switch (c) {
    case Chain::EVM: return 40;
    case Chain::SOL: return 44;
    case Chain::TON: return 48 - score_start(c, s);
    case Chain::BTC: return 38;
    default: return 33;
  }
}

// ---------------------------------------------------------------- tiny bigint

namespace {

struct Big {  // non-negative, little-endian 32-bit limbs, always trimmed
  std::vector<uint32_t> d;
  Big(uint64_t v = 0) {
    while (v) { d.push_back((uint32_t)v); v >>= 32; }
  }
  void trim() { while (!d.empty() && d.back() == 0) d.pop_back(); }
  Big& mul_add(uint32_t m, uint32_t a) {
    uint64_t c = a;
    for (auto& x : d) { c += (uint64_t)x * m; x = (uint32_t)c; c >>= 32; }
    if (c) d.push_back((uint32_t)c);
    trim();
    return *this;
  }
  static Big pow2(int k) {
    Big r;
    r.d.assign(k / 32 + 1, 0);
    r.d[k / 32] = 1u << (k % 32);
    return r;
  }
};

int cmpb(const Big& a, const Big& b) {
  if (a.d.size() != b.d.size()) return a.d.size() < b.d.size() ? -1 : 1;
  for (size_t i = a.d.size(); i-- > 0;)
    if (a.d[i] != b.d[i]) return a.d[i] < b.d[i] ? -1 : 1;
  return 0;
}

Big addb(const Big& a, const Big& b) {
  Big r;
  uint64_t c = 0;
  size_t n = std::max(a.d.size(), b.d.size());
  for (size_t i = 0; i < n; i++) {
    c += (i < a.d.size() ? a.d[i] : 0) + (uint64_t)(i < b.d.size() ? b.d[i] : 0);
    r.d.push_back((uint32_t)c);
    c >>= 32;
  }
  if (c) r.d.push_back((uint32_t)c);
  r.trim();
  return r;
}

Big subb(const Big& a, const Big& b) {  // a >= b
  Big r;
  int64_t br = 0;
  for (size_t i = 0; i < a.d.size(); i++) {
    int64_t t = (int64_t)a.d[i] - (i < b.d.size() ? b.d[i] : 0) - br;
    br = t < 0;
    r.d.push_back((uint32_t)(t + (br ? (1LL << 32) : 0)));
  }
  r.trim();
  return r;
}

Big shr_words(const Big& a, int words) {
  Big r;
  if ((int)a.d.size() > words) r.d.assign(a.d.begin() + words, a.d.end());
  return r;
}

Big mulpow58(Big a, int k) {
  while (k-- > 0) a.mul_add(58, 0);
  return a;
}

double to_double(const Big& a) {
  double r = 0;
  for (size_t i = a.d.size(); i-- > 0;) r = r * 4294967296.0 + a.d[i];
  return r;
}

void to_words_be(const Big& a, uint32_t* out, int nw) {
  if ((int)a.d.size() > nw) throw std::logic_error("range bound too large");
  for (int i = 0; i < nw; i++) out[nw - 1 - i] = i < (int)a.d.size() ? a.d[i] : 0;
}

Big b58_value(const std::string& s) {
  Big v;
  for (char c : s) v.mul_add(58, (uint32_t)hc::base58_value(c));
  return v;
}

int b58_ndigits(const Big& x) {  // x > 0
  int D = 1;
  Big pw(58);
  while (cmpb(x, pw) >= 0) {
    pw.mul_add(58, 0);
    D++;
  }
  return D;
}

// ---------------------------------------------------------------- per chain

bool is_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }

void set_nibble(DevPattern& d, int pos, int v) {
  int word = pos / 8, sh = 28 - 4 * (pos % 8);
  d.hmask[word] |= 0xFu << sh;
  d.hval[word] |= (uint32_t)v << sh;
}

// All 20-byte payloads A whose 34-character base58check address
// (version byte, A, 4 checksum bytes) can start with `head`; inclusive range.
bool b58check_range(const std::string& head, uint32_t version, Big& amin, Big& amax) {
  int k = 34 - (int)head.size();
  Big p = b58_value(head);
  Big lo = mulpow58(p, k);
  Big hi = subb(mulpow58(addb(p, Big(1)), k), Big(1));
  Big base = Big::pow2(192);
  base.mul_add(version, 0);
  Big top = subb(addb(base, Big::pow2(192)), Big(1));
  if (cmpb(hi, base) < 0 || cmpb(lo, top) > 0) return false;
  if (cmpb(hi, top) > 0) hi = top;
  amin = cmpb(lo, base) >= 0 ? shr_words(subb(lo, base), 1) : Big(0);
  amax = shr_words(subb(hi, base), 1);
  return cmpb(amin, amax) <= 0;
}

std::string second_chars(char head, uint32_t version) {
  std::string ok;
  const char* A = BASE58_ALPHABET;
  for (int i = 0; i < 58; i++) {
    Big lo, hi;
    if (b58check_range(std::string(1, head) + A[i], version, lo, hi)) ok += A[i];
  }
  return ok;
}

// Ranges of an nbits-bit number N with exactly z leading zero bytes whose base58 form
// starts with `rest` (which does not start with '1'). The address is then one '1' per
// zero byte (plus the version '1' for Bitcoin) followed by base58(N). Bounds are shifted
// right by `drop_words` 32-bit words (the Bitcoin checksum) and stored as nw words.
// At most the two widest ranges are kept (a third, if any, is a negligible sliver).
int b58_ranges(const std::string& rest, int z, int nbits, int drop_words, int nw, DevPattern& d, double& frac) {
  frac = 0;
  const Big nlo = Big::pow2(nbits - 8 * z - 8);
  const Big nhi = subb(Big::pow2(nbits - 8 * z), Big(1));
  std::vector<std::pair<Big, Big>> rs;
  if (rest.empty()) {
    rs.push_back({nlo, nhi});
  } else {
    const Big p = b58_value(rest);
    for (int D = b58_ndigits(nlo); D <= b58_ndigits(nhi); D++) {
      int k = D - (int)rest.size();
      if (k < 0) continue;
      Big lo = mulpow58(p, k);
      Big hi = subb(mulpow58(addb(p, Big(1)), k), Big(1));
      Big blo = mulpow58(Big(1), D - 1), bhi = subb(mulpow58(Big(1), D), Big(1));
      if (cmpb(blo, nlo) < 0) blo = nlo;
      if (cmpb(bhi, nhi) > 0) bhi = nhi;
      if (cmpb(lo, blo) < 0) lo = blo;
      if (cmpb(hi, bhi) > 0) hi = bhi;
      if (cmpb(lo, hi) <= 0) rs.push_back({lo, hi});
    }
  }
  std::sort(rs.begin(), rs.end(), [](const std::pair<Big, Big>& a, const std::pair<Big, Big>& b) {
    return cmpb(subb(a.second, a.first), subb(b.second, b.first)) > 0;
  });
  if (rs.size() > 2) rs.resize(2);
  int n = 0;
  for (auto& r : rs) {
    frac += to_double(addb(subb(r.second, r.first), Big(1))) / std::ldexp(1.0, nbits);
    to_words_be(shr_words(r.first, drop_words), d.rlo[n], nw);
    to_words_be(shr_words(r.second, drop_words), d.rhi[n], nw);
    n++;
  }
  d.nrange = n;
  return n;
}

void add_digit(DevPattern& d, int pos, char c, bool from_start) {
  if (d.ndig >= MAX_DIG) throw std::runtime_error("pattern has too many fixed characters");
  d.dpos[d.ndig] = (uint8_t)pos;
  d.dval[d.ndig] = (uint8_t)hc::base58_value(c);
  d.dstart[d.ndig] = from_start ? 1 : 0;
  d.ndig++;
}

}  // namespace

// ---------------------------------------------------------------- scores

std::string describe(const PatternSet& ps, uint32_t pid) {
  const Pattern& p = ps.pats[pid];
  std::string t = p.text(), s = "pattern " + t;
  const std::string& src = p.src < ps.src.size() ? ps.src[p.src] : t;
  if (!src.empty() && t.find(src) == std::string::npos) s += " (from " + src + ")";
  return s;
}

bool match_one(const Pattern& p, const std::string& addr) {
  if (addr.size() < p.prefix.size() || addr.size() < p.suffix.size()) return false;
  for (size_t i = 0; i < p.prefix.size(); i++)
    if (p.prefix[i] != '?' && p.prefix[i] != addr[i]) return false;
  size_t off = addr.size() - p.suffix.size();
  for (size_t i = 0; i < p.suffix.size(); i++)
    if (p.suffix[i] != '?' && p.suffix[i] != addr[off + i]) return false;
  return true;
}

int beauty_score(Chain c, const std::string& a) {
  int s0 = score_start(c, Score::REPEAT);
  int len = (int)a.size();
  int lead = 1;
  while (s0 + lead < len && a[s0 + lead] == a[s0]) lead++;
  int trail = 1;
  while (trail < len - s0 && a[len - 1 - trail] == a[len - 1]) trail++;
  return lead + trail;
}

// Leading + trailing run of class characters; the whole address scores its length.
static int class_score(Chain c, const std::string& a, const std::string& cls) {
  const int s0 = score_start(c, Score::CLASS), len = (int)a.size(), n = len - s0;
  auto in = [&](char ch) { return cls.find(ch) != std::string::npos; };
  int L = 0;
  while (L < n && in(a[s0 + L])) L++;
  if (L == n) return n;
  int R = 0;
  while (R < n && in(a[len - 1 - R])) R++;
  return L + R;
}

int score_address(const PatternSet& ps, const std::string& addr) {
  if (ps.score == Score::REPEAT) return beauty_score(ps.chain, addr);
  if (ps.score == Score::CLASS)
    return class_score(ps.chain, ps.chain == Chain::EVM ? hc::eip55(addr).substr(2) : addr, ps.cls);
  return 0;
}

std::string score_what(const PatternSet& ps, int score) {
  char r[48];
  snprintf(r, sizeof r, " (1 in 2^%.1f)", score_bits(ps, score));
  if (ps.score == Score::REPEAT) return "beauty score " + std::to_string(score) + r;
  return "only " + ps.cls_name + ": score " + std::to_string(score) + r;
}

bool may_overmatch(const PatternSet& ps, uint32_t pid) {
  if (pid >= ps.dev.size()) return true;  // key-only
  if (!is_b58(ps.chain)) return false;
  return ps.chain != Chain::SOL && ps.dev[pid].ndig == 0;
}

static double beauty_probability(int alphabet, int min_score) {
  // lead and trail runs are ~geometric with q = 1/alphabet
  double q = 1.0 / alphabet, p = 0;
  for (int a = 1; a < 80; a++) {
    double pa = std::pow(q, a - 1) * (1 - q);
    int need = min_score - a;
    p += pa * (need <= 1 ? 1.0 : std::pow(q, need - 1));
  }
  return p;
}

static int alphabet_size(Chain c) {
  return c == Chain::EVM ? 16 : c == Chain::TON ? 64 : c == Chain::BTC ? 32 : 58;
}

static std::string display_alphabet(Chain c) {
  switch (c) {
    case Chain::EVM: return "0123456789abcdefABCDEF";  // EIP-55 checksum case
    case Chain::TON: return B64URL;
    case Chain::BTC: return hc::BECH32_CHARSET;
    default: return BASE58_ALPHABET;
  }
}

// Probability that one character is in the class.
static double class_char_prob(Chain c, const std::string& cls) {
  if (c != Chain::EVM) return (double)cls.size() / alphabet_size(c);
  double p = 0;
  for (char ch : cls) p += (ch >= '0' && ch <= '9') ? 1.0 / 16 : 1.0 / 32;  // a letter's case is a coin flip
  return p;
}

// Rough speed of each chain on an RTX 3090, only used to pick a default --min-score.
static double nominal_rate(Chain c) {
  switch (c) {
    case Chain::SOL: return 2.3e8;
    case Chain::TON: return 2.0e8;
    case Chain::BTC: case Chain::BTC_LEGACY: return 3.8e9;
    case Chain::BTC_P2SH: return 2.1e9;
    default: return 1.8e9;
  }
}

static std::string class_chars(Chain chain, const std::string& spec) {
  std::string want;
  size_t i = 0;
  while (i <= spec.size()) {
    size_t j = spec.find('+', i);
    if (j == std::string::npos) j = spec.size();
    std::string part = spec.substr(i, j - i);
    i = j + 1;
    if (part.empty()) continue;
    if (part == "digits" || part == "digit" || part == "numbers") want += "0123456789";
    else if (part == "lower" || part == "lowercase") want += "abcdefghijklmnopqrstuvwxyz";
    else if (part == "upper" || part == "uppercase") want += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    else if (part == "letters" || part == "alpha") want += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    else
      for (size_t k = 0; k < part.size(); k++) {  // literal characters, a-z style ranges allowed
        if (k + 2 < part.size() && part[k + 1] == '-') {
          for (char ch = part[k]; ch <= part[k + 2]; ch++) want += ch;
          k += 2;
        } else {
          want += part[k];
        }
      }
  }
  if (chain == Chain::BTC)  // bech32 has no case
    for (char& ch : want) ch = (char)tolower((unsigned char)ch);
  std::string cls;
  for (char ch : display_alphabet(chain))
    if (want.find(ch) != std::string::npos) cls += ch;
  if (cls.empty())
    throw std::runtime_error("--only " + spec + ": none of these characters can appear in " +
                             std::string(chain_name(chain)) + " addresses");
  return cls;
}

// ---------------------------------------------------------------- one concrete pattern

static void compile_one(Chain chain, const std::string& arg, Pattern& p, DevPattern& d) {
  size_t dd = arg.find("..");
  std::string pre = dd == std::string::npos ? arg : arg.substr(0, dd);
  std::string suf = dd == std::string::npos ? "" : arg.substr(dd + 2);
  memset(&d, 0, sizeof d);

  if (chain == Chain::EVM) {
    for (auto* s : {&pre, &suf})
      for (char& c : *s) c = (char)tolower((unsigned char)c);
    if (pre.size() >= 2 && pre[0] == '0' && pre[1] == 'x') pre = pre.substr(2);
    for (const std::string& s : {pre, suf})
      for (char c : s)
        if (!is_hex(c) && c != '?')
          throw std::runtime_error("'" + arg + "': EVM addresses use only 0-9 a-f (and ? as wildcard)");
    if (pre.size() + suf.size() > 40) throw std::runtime_error("'" + arg + "': longer than an address");
    int fixed = 0;
    for (size_t i = 0; i < pre.size(); i++)
      if (pre[i] != '?') { set_nibble(d, (int)i, (int)strtol(std::string(1, pre[i]).c_str(), 0, 16)); fixed++; }
    for (size_t i = 0; i < suf.size(); i++)
      if (suf[i] != '?') {
        set_nibble(d, 40 - (int)suf.size() + (int)i, (int)strtol(std::string(1, suf[i]).c_str(), 0, 16));
        fixed++;
      }
    p.p = std::pow(16.0, -fixed);
  } else if (chain == Chain::BTC) {
    for (auto* s : {&pre, &suf})
      for (char& c : *s) c = (char)tolower((unsigned char)c);
    if (pre.rfind("bc1q", 0) == 0) pre = pre.substr(4);
    else if (pre.rfind("bc1", 0) == 0)
      throw std::runtime_error("'" + arg + "': only native SegWit addresses (bc1q...) are supported, not taproot (bc1p)");
    for (const std::string& s : {pre, suf})
      for (char c : s)
        if (c != '?' && b32_value(c) < 0)
          throw std::runtime_error("'" + arg + "': '" + std::string(1, c) +
                                   "' is not a bech32 character (bech32 has no 1 b i o)");
    if (pre.size() + suf.size() > 38) throw std::runtime_error("'" + arg + "': longer than an address");
    int fixed = 0;
    for (size_t i = 0; i < pre.size(); i++)
      if (pre[i] != '?') { set_bits(d, (int)i, b32_value(pre[i]), 5); fixed++; }
    for (size_t i = 0; i < suf.size(); i++)
      if (suf[i] != '?') { set_bits(d, 38 - (int)suf.size() + (int)i, b32_value(suf[i]), 5); fixed++; }
    p.p = std::pow(32.0, -fixed);
    if (!pre.empty()) pre = "bc1q" + pre;
  } else if (chain == Chain::TON) {
    for (const std::string& s : {pre, suf})
      for (char c : s)
        if (c != '?' && b64_value(c) < 0)
          throw std::runtime_error("'" + arg + "': '" + std::string(1, c) +
                                   "' is not a base64url character (A-Z a-z 0-9 - _)");
    if (pre.rfind("EQ", 0) == 0)
      throw std::runtime_error("'" + arg + "': patterns match the non-bounceable form that wallets show (UQ...)");
    if (!pre.empty() && pre.rfind("UQ", 0) != 0) pre = "UQ?" + pre;
    if (pre.size() + suf.size() > 48) throw std::runtime_error("'" + arg + "': longer than an address");
    if (pre.size() > 2 && pre[2] != '?' && !(pre[2] >= 'A' && pre[2] <= 'D'))
      throw std::runtime_error("'" + arg + "': the 3rd character of a TON wallet address is always A, B, C or D");
    double pr = 1.0;
    for (size_t i = 2; i < pre.size(); i++)
      if (pre[i] != '?') {
        set_bits(d, (int)i, b64_value(pre[i]), 6);
        pr /= i == 2 ? 4.0 : 64.0;
      }
    for (size_t i = 0; i < suf.size(); i++)
      if (suf[i] != '?') {
        int pos = 48 - (int)suf.size() + (int)i;
        if (pos == 2 && !(suf[i] >= 'A' && suf[i] <= 'D'))
          throw std::runtime_error("'" + arg + "': the 3rd character of a TON wallet address is always A, B, C or D");
        if (pos < 2) continue;
        set_bits(d, pos, b64_value(suf[i]), 6);
        pr /= pos == 2 ? 4.0 : 64.0;
      }
    p.p = pr;
  } else {  // base58: TRON, SOL, BTC legacy, BTC p2sh
    const char head_char = chain == Chain::TRON ? 'T' : chain == Chain::BTC_P2SH ? '3'
                           : chain == Chain::BTC_LEGACY ? '1' : 0;
    const uint32_t version = chain == Chain::TRON ? 0x41 : 0x05;
    const int addr_len = chain == Chain::SOL ? 44 : 34;
    for (const std::string& s : {pre, suf})
      for (char c : s)
        if (c != '?' && hc::base58_value(c) < 0)
          throw std::runtime_error("'" + arg + "': '" + std::string(1, c) +
                                   "' is not a base58 character (0 O I l are not allowed)");
    if (head_char && !pre.empty() && pre[0] != head_char) pre = std::string(1, head_char) + pre;
    if ((int)(pre.size() + suf.size()) > addr_len)
      throw std::runtime_error("'" + arg + "': longer than an address");
    size_t head_len = pre.find('?');
    if (head_len == std::string::npos) head_len = pre.size();
    std::string head = pre.substr(0, head_len);
    double frac = 1.0;
    if (chain == Chain::TRON || chain == Chain::BTC_P2SH) {
      if (head.size() >= 2) {
        Big amin, amax;
        if (!b58check_range(head, version, amin, amax))
          throw std::runtime_error("'" + arg + "': no " + std::string(chain_name(chain)) +
                                   " address can start like this. Second char must be one of: " +
                                   second_chars(head_char, version));
        to_words_be(amin, d.rlo[0], 5);
        to_words_be(amax, d.rhi[0], 5);
        d.nrange = 1;
        frac = to_double(addb(subb(amax, amin), Big(1))) / std::ldexp(1.0, 160);
      }
    } else if (chain == Chain::BTC_LEGACY) {
      if (head.size() >= 2) {
        std::string rest = head.substr(1);
        int z = 0;
        while (z < (int)rest.size() && rest[z] == '1') z++;
        if (z >= 19) throw std::runtime_error("'" + arg + "': too many leading 1s");
        if (b58_ranges(rest.substr(z), z, 192, 1, 5, d, frac) == 0)
          throw std::runtime_error("'" + arg + "': no Bitcoin address can start like this");
      }
    } else if (!head.empty()) {
      const int z = head[0] == '1' ? 1 : 0;
      std::string rest = head.substr(z);
      if (!rest.empty() && rest[0] == '1')
        throw std::runtime_error("'" + head + "': Solana addresses starting with 11 are not supported");
      if (b58_ranges(rest, z, 256, 0, 8, d, frac) == 0)
        throw std::runtime_error("'" + arg + "': no Solana address can start like this");
    }
    int ndig = 0;
    for (size_t i = head_len; i < pre.size(); i++)
      if (pre[i] != '?') { add_digit(d, (int)i, pre[i], true); ndig++; }
    for (size_t i = 0; i < suf.size(); i++)
      if (suf[i] != '?') { add_digit(d, (int)(suf.size() - 1 - i), suf[i], false); ndig++; }
    p.p = frac * std::pow(58.0, -ndig);
    // suffix-only constraints need just the low base58 digits
    int maxpos = -1;
    bool from_start = false;
    for (uint32_t k = 0; k < d.ndig; k++) {
      if (d.dstart[k]) from_start = true;
      maxpos = std::max(maxpos, (int)d.dpos[k]);
    }
    d.npass = from_start ? 0 : (uint32_t)(maxpos / 5 + 1);
  }
  if (pre.empty() && suf.empty()) throw std::runtime_error("empty pattern");
  p.prefix = pre;
  p.suffix = suf;
}

// Probability that the first scored character is in the class. On base58 chains it is far
// from uniform (TRON's second character is nearly always upper case), so it is taken from
// the same prefix ranges the patterns use.
static double first_char_prob(Chain c, const std::string& cls) {
  if (!is_b58(c)) return class_char_prob(c, cls);
  const std::string head = c == Chain::TRON ? "T" : c == Chain::BTC_P2SH ? "3" : c == Chain::BTC_LEGACY ? "1" : "";
  double p = 0;
  for (char ch : cls) {
    try {
      Pattern q;
      DevPattern d;
      compile_one(c, head + ch, q, d);
      p += q.p;
    } catch (const std::runtime_error&) {
    }
  }
  return std::min(p, 1.0);
}

// P(lead run + trail run >= s): the lead run starts with the first character (q0), the
// other characters are in the class with probability q.
static double class_probability(Chain c, const std::string& cls, int s) {
  const double q = class_char_prob(c, cls), q0 = first_char_prob(c, cls);
  const int n = score_positions(c, Score::CLASS);
  if (s >= n) return q0 * std::pow(q, n - 1);
  auto lead_ge = [&](int a) { return a <= 0 ? 1.0 : q0 * std::pow(q, a - 1); };
  double p = lead_ge(s);
  for (int a = 0; a < s; a++) p += (lead_ge(a) - lead_ge(a + 1)) * std::pow(q, s - a);
  return p;
}

double score_probability(const PatternSet& ps, int s) {
  if (ps.score == Score::REPEAT) return beauty_probability(alphabet_size(ps.chain), s);
  if (ps.score == Score::CLASS) return class_probability(ps.chain, ps.cls, s);
  return 0;
}

double score_bits(const PatternSet& ps, int s) {
  const double p = score_probability(ps, s);
  return p > 0 ? -std::log2(std::min(p, 1.0)) : INFINITY;
}

// ---------------------------------------------------------------- expansion (-i, -l, -c, [..])

static const char* const LOOKALIKE[] = {"0oO", "1iIl", "2zZ", "3eE", "4aA", "5sS", "6bG", "7tT", "8B", "9gq"};
constexpr size_t MAX_EXPAND = 1u << 20;       // concrete patterns per written pattern
constexpr size_t DEFAULT_MAX_TOTAL = 20000000;  // concrete patterns in total

static bool valid_char(Chain c, char ch) {
  if (c == Chain::EVM) return is_hex(ch);
  if (c == Chain::TON) return b64_value(ch) >= 0;
  if (c == Chain::BTC) return b32_value(ch) >= 0;
  return hc::base58_value(ch) >= 0;
}

static void add_unique(std::string& s, char c) {
  if (s.find(c) == std::string::npos) s += c;
}

static std::string variants(char ch, const MatchOptions& mo) {
  std::string s(1, ch);
  for (int round = 0; round < 2; round++) {
    if (mo.ignore_case)
      for (char c : std::string(s)) {
        add_unique(s, (char)tolower((unsigned char)c));
        add_unique(s, (char)toupper((unsigned char)c));
      }
    if (mo.similar)
      for (char c : std::string(s))
        for (const char* g : LOOKALIKE)
          if (strchr(g, c))
            for (const char* q = g; *q; q++) add_unique(s, *q);
  }
  return s;
}

static std::string filter_chars(Chain chain, const std::string& s) {
  std::string ok;
  const bool lower = chain == Chain::EVM || chain == Chain::BTC;
  for (char v : s) {
    char u = lower ? (char)tolower((unsigned char)v) : v;
    if (valid_char(chain, u)) add_unique(ok, u);
  }
  return ok;
}

// The fixed start of the address (never varied) and the rest of a written pattern.
static void split_head(Chain chain, const std::string& arg0, std::string& fixed, std::string& arg) {
  arg = arg0;
  fixed.clear();
  const bool has_prefix = !arg.empty() && arg.rfind("..", 0) != 0;
  auto starts_ci = [&](const char* h) {
    size_t n = strlen(h);
    if (arg.size() < n) return false;
    for (size_t i = 0; i < n; i++)
      if (tolower((unsigned char)arg[i]) != h[i]) return false;
    return true;
  };
  if (chain == Chain::EVM) {
    if (starts_ci("0x")) arg = arg.substr(2);
  } else if (chain == Chain::BTC) {
    if (has_prefix) {
      if (starts_ci("bc1q")) arg = arg.substr(4);
      if (!starts_ci("bc1")) fixed = "bc1q";  // "bc1p..." is left to compile_one to explain
    }
  } else if (has_prefix && (chain == Chain::TRON || chain == Chain::BTC_LEGACY || chain == Chain::BTC_P2SH)) {
    const char h = chain == Chain::TRON ? 'T' : chain == Chain::BTC_LEGACY ? '1' : '3';
    fixed = std::string(1, h);
    if (arg[0] == h) arg = arg.substr(1);
  } else if (chain == Chain::TON && has_prefix) {
    if (arg.rfind("UQ", 0) == 0) {
      fixed = "UQ";
      arg = arg.substr(2);
    } else if (arg.rfind("EQ", 0) != 0) {
      fixed = "UQ?";
    }
  }
}

size_t pattern_body_len(Chain chain, const std::string& arg0) {
  std::string fixed, arg;
  split_head(chain, arg0, fixed, arg);
  size_t n = 0;
  for (size_t i = 0; i < arg.size(); i++) {
    if (arg[i] == '?' || arg[i] == '.') continue;
    if (arg[i] == '[') {
      size_t j = arg.find(']', i);
      if (j != std::string::npos) i = j;
    }
    n++;
  }
  return n;
}

// word, Word, WORD for each part of PREFIX..SUFFIX; [..] classes are left alone.
static std::vector<std::string> case_forms(const std::string& arg) {
  std::vector<std::string> out = {arg};
  for (int mode = 0; mode < 3; mode++) {  // lower, Capitalized, UPPER
    std::string s = arg;
    bool in_class = false, first = true;
    for (size_t i = 0; i < s.size(); i++) {
      char& c = s[i];
      if (c == '[') in_class = true;
      if (in_class) {
        if (c == ']') in_class = false;
        first = false;
        continue;
      }
      if (c == '.' && i + 1 < s.size() && s[i + 1] == '.') {
        first = true;
        i++;
        continue;
      }
      if (!isalpha((unsigned char)c)) {
        if (c != '?') first = false;
        continue;
      }
      bool up = mode == 2 || (mode == 1 && first);
      c = (char)(up ? toupper((unsigned char)c) : tolower((unsigned char)c));
      first = false;
    }
    if (std::find(out.begin(), out.end(), s) == out.end()) out.push_back(s);
  }
  return out;
}

// Per character of a written pattern: "?" = wildcard, ".." = separator, else the allowed
// chars. kind tells which choices count as a substitution (for --subs).
struct CSet {
  std::string chars;
  int8_t kind;  // 0 "?" or "..", 1 chars[0] is the written char, 2 every choice is a change, 3 [..] class
};

static std::vector<CSet> char_sets(Chain chain, const std::string& arg0, const std::string& arg,
                                   const MatchOptions& mo) {
  std::vector<CSet> sets;
  for (size_t i = 0; i < arg.size(); i++) {
    char ch = arg[i];
    if (ch == '.' && i + 1 < arg.size() && arg[i + 1] == '.') {
      sets.push_back({"..", 0});
      i++;
      continue;
    }
    if (ch == '?') {
      sets.push_back({"?", 0});
      continue;
    }
    std::string raw, shown(1, ch);
    if (ch == '[') {
      size_t j = arg.find(']', i);
      if (j == std::string::npos || j == i + 1)
        throw std::runtime_error("'" + arg0 + "': '[' needs a closing ']' with characters inside, e.g. [aA4]");
      raw = arg.substr(i + 1, j - i - 1);
      shown = arg.substr(i, j - i + 1);
      i = j;
    } else {
      raw = variants(ch, mo);
    }
    std::string ok = filter_chars(chain, raw);
    if (ok.empty()) {
      std::string msg = "'" + arg0 + "': '" + shown + "' cannot appear in " + std::string(chain_name(chain)) + " addresses";
      MatchOptions m2 = mo;
      m2.similar = m2.ignore_case = true;
      std::string alt = shown.size() == 1 ? filter_chars(chain, variants(ch, m2)) : "";
      if (!alt.empty()) msg += " (with -i/-l it would match " + alt + ")";
      if (is_b58(chain)) msg += "; base58 has no 0 O I l";
      if (chain == Chain::EVM) msg += "; hex is 0-9 a-f";
      if (chain == Chain::BTC) msg += "; bech32 has no 1 b i o";
      throw std::runtime_error(msg);
    }
    if (shown.size() > 1) {
      sets.push_back({ok, 3});
    } else {
      const bool lower = chain == Chain::EVM || chain == Chain::BTC;
      const char orig = lower ? (char)tolower((unsigned char)ch) : ch;
      const size_t at = ok.find(orig);
      if (at == std::string::npos) {
        sets.push_back({ok, 2});
      } else {
        std::swap(ok[0], ok[at]);
        sets.push_back({ok, 1});
      }
    }
  }
  return sets;
}

// Number of variants with at most `subs` changed characters (subs < 0: no limit), capped.
static size_t count_sets(const std::vector<CSet>& sets, int subs) {
  const size_t CAP = MAX_EXPAND + 1;
  if (subs < 0) {
    size_t n = 1;
    for (const CSet& c : sets)
      if (c.kind) n = std::min<size_t>(n * c.chars.size(), CAP);
    return n;
  }
  std::vector<size_t> dp(subs + 1, 0);  // dp[j]: variants so far with j changes
  dp[0] = 1;
  for (const CSet& c : sets) {
    if (!c.kind) continue;
    const size_t n = c.chars.size();
    const size_t same = c.kind == 1 ? 1 : c.kind == 3 ? n : 0, diff = n - same;
    std::vector<size_t> nd(subs + 1, 0);
    for (int j = 0; j <= subs; j++) {
      nd[j] = std::min(CAP, nd[j] + std::min(CAP, dp[j] * same));
      if (j + 1 <= subs) nd[j + 1] = std::min(CAP, nd[j + 1] + std::min(CAP, dp[j] * diff));
    }
    dp.swap(nd);
  }
  size_t t = 0;
  for (size_t v : dp) t = std::min(CAP, t + v);
  return t;
}

static void expand_one(Chain chain, const std::string& arg0, const std::string& fixed, const std::string& arg,
                       const MatchOptions& mo, std::vector<std::string>& out) {
  const std::vector<CSet> sets = char_sets(chain, arg0, arg, mo);
  if (count_sets(sets, mo.max_subs) > MAX_EXPAND)
    throw std::runtime_error("'" + arg0 + "': more than " + std::to_string(MAX_EXPAND) +
                             " variants; use a shorter pattern or fewer substitutions (--subs)");
  const int budget = mo.max_subs < 0 ? 1 << 30 : mo.max_subs;
  std::string v = fixed;
  std::function<void(size_t, int)> rec = [&](size_t k, int left) {
    if (k == sets.size()) {
      out.push_back(v);
      return;
    }
    const CSet& c = sets[k];
    if (!c.kind) {
      v += c.chars;
      rec(k + 1, left);
      v.resize(v.size() - c.chars.size());
      return;
    }
    for (size_t i = 0; i < c.chars.size(); i++) {
      const bool change = c.kind == 2 || (c.kind == 1 && i > 0);
      if (change && left == 0) continue;
      v += c.chars[i];
      rec(k + 1, left - (change ? 1 : 0));
      v.pop_back();
    }
  };
  rec(0, budget);
}

std::vector<std::string> expand_pattern(Chain chain, const std::string& arg0, const MatchOptions& mo) {
  // A leading 0x / T / UQ / bc1q / 1 / 3 is the fixed start of the address and is never
  // varied. Without it the pattern starts after that part, so that is made explicit here
  // (otherwise a case variant of the first letter could turn into it).
  std::string fixed, arg;
  split_head(chain, arg0, fixed, arg);
  if (chain == Chain::TON && arg.rfind("EQ", 0) == 0) return {arg0};  // compile_one explains
  if (chain == Chain::BTC && fixed.empty() && !arg.empty() && arg.rfind("..", 0) != 0) return {arg0};
  std::vector<std::string> out;
  if (!mo.caps) {
    expand_one(chain, arg0, fixed, arg, mo, out);
    return out;
  }
  std::string first_err;
  for (const std::string& form : case_forms(arg)) {
    try {
      expand_one(chain, arg0, fixed, form, mo, out);
    } catch (const std::runtime_error& e) {
      if (first_err.empty()) first_err = e.what();
    }
  }
  if (out.empty()) throw std::runtime_error(first_err);
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  if (out.size() > MAX_EXPAND)
    throw std::runtime_error("'" + arg0 + "': more than " + std::to_string(MAX_EXPAND) + " variants");
  return out;
}

// Upper bound of expand_pattern(...).size() without building the strings (0 if invalid).
static size_t count_variants(Chain chain, const std::string& arg0, const MatchOptions& mo) {
  std::string fixed, arg;
  split_head(chain, arg0, fixed, arg);
  if ((chain == Chain::TON && arg.rfind("EQ", 0) == 0) ||
      (chain == Chain::BTC && fixed.empty() && !arg.empty() && arg.rfind("..", 0) != 0))
    return 1;
  size_t total = 0;
  for (const std::string& form : mo.caps ? case_forms(arg) : std::vector<std::string>{arg}) {
    try {
      total += count_sets(char_sets(chain, arg0, form, mo), mo.max_subs);
    } catch (const std::runtime_error&) {
    }
  }
  return std::min<size_t>(total, MAX_EXPAND + 1);
}

// ---------------------------------------------------------------- index for long lists

namespace {

using Range = std::pair<uint64_t, uint64_t>;

int run_from(const std::string& s, size_t start) {
  int n = 0;
  for (size_t i = start; i < s.size() && s[i] != '?'; i++) n++;
  return n;
}

int run_back(const std::string& s) {
  int n = 0;
  for (size_t i = s.size(); i-- > 0 && s[i] != '?';) n++;
  return n;
}

// The `bits` most significant bits of the key equal v.
Range top_range(uint64_t v, int bits) {
  if (bits >= 64) return {v, v};
  uint64_t lo = v << (64 - bits);
  return {lo, lo | (~0ull >> bits)};
}

int hexval(char c) { return c <= '9' ? c - '0' : c - 'a' + 10; }

uint64_t w2(const uint32_t* w) { return (uint64_t)w[0] << 32 | w[1]; }

// Key ranges for the leading characters (index 0). Keys, as computed by the engines:
//  EVM : address bits 0..63            TRON/BTC base58: payload bits 0..63
//  SOL : public key bits 0..63         TON : address string bits 18..81 (chars 3..13)
//  BTC : hash160 bits 0..63 (chars 0..11 after bc1q, 5 bits each, then 4 bits of char 12)
// exact ("key-only"): the pattern is just a run of fixed characters at one end. The GPU
// then tests only the key; characters beyond the key's reach (and base58 range edges)
// are checked on the CPU, which drops the rare false hits (~alphabet^-keychars per pattern).
int lead_ranges(Chain c, const Pattern& p, const DevPattern& d, Range out[2], bool& exact) {
  exact = false;
  if (c == Chain::EVM) {
    int L = std::min(run_from(p.prefix, 0), 16);
    if (!L) return 0;
    uint64_t v = 0;
    for (int i = 0; i < L; i++) v = v << 4 | hexval(p.prefix[i]);
    out[0] = top_range(v, 4 * L);
    exact = p.suffix.empty() && run_from(p.prefix, 0) == (int)p.prefix.size();
    return 1;
  }
  if (c == Chain::TON) {
    int L = std::min(run_from(p.prefix, 3), 10);
    if (!L) return 0;
    uint64_t v = 0;
    for (int i = 0; i < L; i++) v = v << 6 | b64_value(p.prefix[3 + i]);
    out[0] = top_range(v, 6 * L);
    exact = p.suffix.empty() && p.prefix[2] == '?' && run_from(p.prefix, 3) == (int)p.prefix.size() - 3;
    return 1;
  }
  if (c == Chain::BTC) {
    int L = std::min(run_from(p.prefix, 4), 12);
    if (!L) return 0;
    uint64_t v = 0;
    for (int i = 0; i < L; i++) v = v << 5 | b32_value(p.prefix[4 + i]);
    out[0] = top_range(v, 5 * L);
    exact = p.suffix.empty() && run_from(p.prefix, 4) == (int)p.prefix.size() - 4;
    return 1;
  }
  // A long prefix may cover only a few key values, and an address whose key equals an edge
  // value may lie just outside the pattern's range. That happens about once per 2^64
  // addresses per pattern; the CPU check drops such hits, so the key range is the test.
  int n = 0;
  exact = p.suffix.empty() && d.ndig == 0;
  for (uint32_t k = 0; k < d.nrange && k < 2; k++) {
    out[n] = {w2(d.rlo[k]), w2(d.rhi[k])};
    n++;
  }
  if (!n) exact = false;
  return n;
}

// Key ranges for the trailing characters (index 1), last character most significant:
//  EVM : nibbles 39, 38, .. 24         TRON/SOL/BTC base58: base58 digits 0..9 as a number, << 5
//  TON : base64 chars 47, 46, .. 38    BTC : bech32 chars 37, 36, .. 26 (5 bits each), << 4
int trail_ranges(Chain c, const Pattern& p, Range out[2], bool& exact) {
  const std::string& s = p.suffix;
  const int n = (int)s.size();
  const int maxL = c == Chain::EVM ? 16 : c == Chain::BTC ? 12 : 10;
  const int L = std::min(run_back(s), maxL);
  exact = false;
  if (!L) return 0;
  uint64_t v = 0;
  if (c == Chain::EVM) {
    for (int i = 0; i < L; i++) v = v << 4 | hexval(s[n - 1 - i]);
    out[0] = top_range(v, 4 * L);
  } else if (c == Chain::TON) {
    for (int i = 0; i < L; i++) v = v << 6 | b64_value(s[n - 1 - i]);
    out[0] = top_range(v, 6 * L);
  } else if (c == Chain::BTC) {
    for (int i = 0; i < L; i++) v = v << 5 | b32_value(s[n - 1 - i]);
    out[0] = top_range(v, 5 * L);
  } else {
    uint64_t m = 1;
    for (int i = 0; i < L; i++) v = v * 58 + hc::base58_value(s[n - 1 - i]);
    for (int i = L; i < 10; i++) m *= 58;
    out[0] = {(v * m) << 5, (((v + 1) * m - 1) << 5) | 31};
  }
  exact = p.prefix.empty() && run_back(s) == n;
  return 1;
}

double range_bits(const Range* r, int n) {
  long double w = 0;
  for (int i = 0; i < n; i++) w += (long double)(r[i].second - r[i].first) + 1.0L;
  return 64.0 - (double)std::log2(w);
}

struct Ent {
  uint64_t lo, hi;
  uint32_t pid;
};

void build_index(std::vector<Ent>& ents, size_t npat, HostIndex& I) {
  if (ents.empty()) return;
  using u128 = unsigned __int128;
  I.npat = npat;
  struct Ev {
    u128 pos;
    int64_t e;  // entry, or ~entry for its end
    bool operator<(const Ev& o) const { return pos < o.pos || (pos == o.pos && e < o.e); }
  };
  std::vector<Ev> ev;
  ev.reserve(2 * ents.size());
  for (size_t i = 0; i < ents.size(); i++) {
    ev.push_back({(u128)ents[i].lo, (int64_t)i});
    ev.push_back({(u128)ents[i].hi + 1, ~(int64_t)i});
  }
  std::sort(ev.begin(), ev.end());
  std::set<std::pair<uint64_t, uint32_t>> act;  // (width, entry): most specific first
  for (size_t k = 0; k < ev.size();) {
    const u128 pos = ev[k].pos;
    for (; k < ev.size() && ev[k].pos == pos; k++) {
      int64_t e = ev[k].e;
      if (e >= 0) act.insert({ents[e].hi - ents[e].lo, (uint32_t)e});
      else act.erase({ents[~e].hi - ents[~e].lo, (uint32_t)~e});
    }
    if (act.empty() || k == ev.size()) continue;
    I.lo.push_back((uint64_t)pos);
    I.hi.push_back((uint64_t)(ev[k].pos - 1));
    I.off.push_back((uint32_t)I.pid.size());
    for (auto& a : act) I.pid.push_back(ents[a.second].pid);
    if (I.pid.size() > (size_t)1 << 31)
      throw std::runtime_error("pattern list too nested (many patterns share the same start); split it");
  }
  I.off.push_back((uint32_t)I.pid.size());
  std::vector<Ev>().swap(ev);

  int B = 12;  // bitmap of 2^B bits, ~1/1024 full for long patterns (at most 512 MB)
  while (B < 32 && (1ull << B) < ents.size() * 1024ull) B++;
  I.shift = 64 - B;
  I.bitmap.assign((1ull << B) / 32, 0);
  for (size_t s = 0; s < I.lo.size(); s++) {
    uint64_t b0 = I.lo[s] >> I.shift, b1 = I.hi[s] >> I.shift;
    for (uint64_t b = b0; b <= b1;) {
      if ((b & 31) == 0 && b + 31 <= b1) {
        I.bitmap[b >> 5] = ~0u;
        b += 32;
      } else {
        I.bitmap[b >> 5] |= 1u << (b & 31);
        b++;
      }
    }
  }
}

// One compiled concrete pattern, before the set is put in order.
struct Item {
  Pattern p;
  Range r[2];
  int8_t nr = 0;
  int8_t where = -1;  // -1 small list, 0 lead index, 1 trail index
  bool exact = false;
  int32_t dev = -1;   // index into the chunk's DevPatterns (patterns that are not key-only)
};

struct Chunk {
  std::vector<Item> items;
  std::vector<DevPattern> devs;
  std::vector<std::pair<size_t, std::string>> skipped;  // (line, why)
  size_t err_line = (size_t)-1;
  std::string err;
};

void compile_arg(Chain chain, const std::string& arg, uint32_t ai, const MatchOptions& mo, Chunk& out) {
  std::vector<std::string> vars = expand_pattern(chain, arg, mo);
  std::string first_err;
  size_t added = 0;
  for (const std::string& v : vars) {
    Item it;
    DevPattern d;
    try {
      compile_one(chain, v, it.p, d);
    } catch (const std::runtime_error& e) {
      if (first_err.empty()) first_err = e.what();
      continue;  // e.g. a variant with an impossible TRON 2nd character
    }
    it.p.src = ai;
    Range lr[2], tr[2];
    bool le = false, te = false;
    const int nl = lead_ranges(chain, it.p, d, lr, le);
    const int nt = trail_ranges(chain, it.p, tr, te);
    const double bl = nl ? range_bits(lr, nl) : -1, bt = nt ? range_bits(tr, nt) : -1;
    // the trailing key costs a checksum on TRON/TON/BTC, so prefer the leading one
    if (nl && (bl >= 16 || bl >= bt)) {
      it.where = 0;
      it.nr = (int8_t)nl;
      it.r[0] = lr[0];
      it.r[1] = lr[1];
      it.exact = le;
    } else if (nt) {
      it.where = 1;
      it.nr = (int8_t)nt;
      it.r[0] = tr[0];
      it.exact = te;
    }
    if (!it.exact) {
      it.dev = (int32_t)out.devs.size();
      out.devs.push_back(d);
    }
    out.items.push_back(std::move(it));
    added++;
  }
  if (!added) throw std::runtime_error(first_err);
}

}  // namespace

// ---------------------------------------------------------------- the set

// The score whose rarity is closest to `bits` (scores move in steps of log2(alphabet)).
static int pick_by_rarity(const PatternSet& ps, int npos, double bits) {
  int best = npos;
  double bd = INFINITY;
  for (int s = 2; s <= npos; s++) {
    const double d = std::fabs(score_bits(ps, s) - bits);
    if (d < bd) {
      bd = d;
      best = s;
    }
  }
  return best;
}

PatternSet compile_patterns(Chain chain, const std::vector<std::string>& args, bool beauty, int min_score,
                            const MatchOptions& mo, size_t skip_from) {
  CompileOptions o;
  o.match = mo;
  o.score = beauty ? Score::REPEAT : Score::NONE;
  o.min_score = min_score;
  o.skip_from = skip_from;
  return compile_patterns(chain, args, o);
}

PatternSet compile_patterns(Chain chain, const std::vector<std::string>& args, const CompileOptions& o) {
  PatternSet ps;
  ps.chain = chain;
  ps.score = o.score;
  ps.src = args;
  ps.lines = args.size();
  const size_t max_total = o.max_patterns ? o.max_patterns : DEFAULT_MAX_TOTAL;
  const size_t list_from = o.list_from != (size_t)-1 ? o.list_from : o.skip_from;
  MatchOptions list_mo = o.match;  // list lines: at most list_subs changed characters per word
  if (list_mo.max_subs < 0) list_mo.max_subs = o.list_subs;

  const size_t CH = 256;
  const size_t nch = (args.size() + CH - 1) / CH;
  const unsigned nth =
      nch > 1 ? std::max(1u, std::min<unsigned>(std::thread::hardware_concurrency(), (unsigned)nch)) : 1;
  auto parallel = [&](const std::function<void(size_t)>& per_chunk) {
    std::atomic<size_t> next{0};
    auto work = [&]() {
      for (size_t c; (c = next++) < nch;) per_chunk(c);
    };
    std::vector<std::thread> pool;
    for (unsigned t = 1; t < nth; t++) pool.emplace_back(work);
    work();
    for (auto& t : pool) t.join();
  };

  // ---- count the variants first (no strings built), so a list that would explode
  // fails at once instead of filling the memory
  {
    std::atomic<size_t> est{0};
    parallel([&](size_t c) {
      size_t n = 0;
      for (size_t ai = c * CH; ai < std::min(args.size(), (c + 1) * CH); ai++)
        n += count_variants(chain, args[ai], ai >= list_from ? list_mo : o.match);
      est += n;
    });
    if (est > max_total) {
      char b[400];
      snprintf(b, sizeof b,
               "about %.3g patterns after expansion, the limit is %.3g (--max-patterns; each takes ~400 bytes "
               "of RAM while compiling). Use --min-len, a shorter list, or fewer of -i (the biggest multiplier), "
               "-c, -l",
               (double)est, (double)max_total);
      throw std::runtime_error(b);
    }
  }

  // ---- expand and compile every written pattern, in parallel
  std::vector<Chunk> chunks(nch);
  parallel([&](size_t c) {
    Chunk& out = chunks[c];
    for (size_t ai = c * CH; ai < std::min(args.size(), (c + 1) * CH); ai++) {
      try {
        compile_arg(chain, args[ai], (uint32_t)ai, ai >= list_from ? list_mo : o.match, out);
      } catch (const std::runtime_error& e) {
        if (ai >= o.skip_from) {
          out.skipped.push_back({ai, e.what()});
        } else if (out.err_line == (size_t)-1) {
          out.err_line = ai;
          out.err = e.what();
        }
      }
    }
    out.items.shrink_to_fit();
  });
  for (const Chunk& c : chunks)
    if (c.err_line != (size_t)-1) throw std::runtime_error(c.err);

  // ---- merge in input order, without duplicates
  std::vector<Item> items;
  std::vector<DevPattern> devs;
  {
    size_t n = 0;
    for (const Chunk& c : chunks) n += c.items.size();
    items.reserve(n);
    std::unordered_set<uint64_t> seen;
    std::hash<std::string> H;
    for (Chunk& c : chunks) {
      for (auto& s : c.skipped) ps.skipped.push_back(s.second);
      for (Item& it : c.items) {
        if (!seen.insert(H(it.p.prefix + '\x01' + it.p.suffix)).second) continue;
        if (it.dev >= 0) {
          devs.push_back(c.devs[it.dev]);
          it.dev = (int32_t)devs.size() - 1;
        }
        items.push_back(std::move(it));
        if (items.size() > max_total)
          throw std::runtime_error("more than " + std::to_string(max_total) + " patterns after expansion");
      }
      std::vector<Item>().swap(c.items);
      std::vector<DevPattern>().swap(c.devs);
    }
  }
  if (items.empty() && o.score == Score::NONE) throw std::runtime_error("no valid patterns");
  ps.lines -= ps.skipped.size();

  // ---- put in order: small list, indexed patterns that need a test, key-only patterns
  const size_t N = items.size();
  if (N <= MAX_PATTERNS) {
    ps.cfg.npat = (uint32_t)N;
    for (Item& it : items) {
      DevPattern d;
      Pattern q;
      compile_one(chain, it.p.text(), q, d);  // key-only patterns kept no DevPattern
      ps.dev.push_back(d);
      ps.pats.push_back(std::move(it.p));
    }
    ps.cfg.ndev = (uint32_t)N;
  } else {
    std::vector<uint32_t> order;
    order.reserve(N);
    for (int pass = 0; pass < 3; pass++)
      for (size_t i = 0; i < N; i++) {
        const Item& it = items[i];
        int g = it.where < 0 ? 0 : it.exact ? 2 : 1;
        if (g == pass) order.push_back((uint32_t)i);
      }
    size_t n_small = 0, n_dev = 0;
    for (const Item& it : items) {
      if (it.where < 0) n_small++;
      if (!it.exact) n_dev++;
    }
    if (n_small > MAX_PATTERNS)
      throw std::runtime_error(std::to_string(n_small) +
                               " patterns have no fixed characters at the start or the end; at most " +
                               std::to_string(MAX_PATTERNS) + " such patterns are supported");
    ps.cfg.npat = (uint32_t)n_small;
    ps.cfg.ndev = (uint32_t)n_dev;
    std::vector<Ent> ents[2];
    size_t cnt[2] = {0, 0};
    ps.pats.reserve(N);
    ps.dev.reserve(n_dev);
    for (size_t k = 0; k < N; k++) {
      Item& it = items[order[k]];
      if (it.dev >= 0) ps.dev.push_back(devs[it.dev]);
      if (it.where >= 0) {
        cnt[it.where]++;
        for (int r = 0; r < it.nr; r++) ents[it.where].push_back({it.r[r].first, it.r[r].second, (uint32_t)k});
      }
      ps.pats.push_back(std::move(it.p));
    }
    std::vector<Item>().swap(items);
    std::vector<DevPattern>().swap(devs);
    std::thread t1([&]() { build_index(ents[1], cnt[1], ps.idx[1]); });
    build_index(ents[0], cnt[0], ps.idx[0]);
    t1.join();
  }

  // ---- --beauty / --only
  const int npos = score_positions(chain, o.score);
  if (o.score == Score::CLASS) {
    ps.cls = class_chars(chain, o.only);
    ps.cls_name = o.only;
    if (o.min_score > npos)
      throw std::runtime_error("--min-score " + std::to_string(o.min_score) + ": at most " + std::to_string(npos) +
                               " characters count for " + std::string(chain_name(chain)));
    if (o.min_score > 0) {
      ps.min_score = o.min_score;
    } else if (o.rarity > 0) {
      ps.min_score = pick_by_rarity(ps, npos, o.rarity);
    } else {
      ps.min_score = npos;  // a hit about every 30 s at full speed, or the whole address
      for (int s = 1; s <= npos; s++)
        if (class_probability(chain, ps.cls, s) * nominal_rate(chain) <= 1.0 / 30) {
          ps.min_score = s;
          break;
        }
    }
  } else if (o.score == Score::REPEAT && o.min_score <= 0 && o.rarity > 0) {
    ps.min_score = pick_by_rarity(ps, npos, o.rarity);
  } else {
    ps.min_score = o.min_score > 0 ? o.min_score : default_min_score(chain);
  }

  DevConfig& cfg = ps.cfg;
  cfg.score = o.score == Score::REPEAT ? 1 : o.score == Score::CLASS ? 2 : 0;
  cfg.min_score = (uint32_t)ps.min_score;
  cfg.b_start = (uint32_t)score_start(chain, o.score);
  cfg.bech_init = hc::bech32_bc_v0_state();
  if (o.score == Score::CLASS) {
    uint64_t m = 0;
    if (chain == Chain::EVM) {
      const std::string al = display_alphabet(chain);  // 0-9 a-f A-F
      for (size_t v = 0; v < al.size(); v++)
        if (ps.cls.find(al[v]) != std::string::npos) m |= 1ull << v;
      for (int l = 0; l < 6; l++)  // a letter allowed in one case only: the checksum decides
        if (((m >> (10 + l)) & 1) != ((m >> (16 + l)) & 1)) cfg.cls_case = 1;
    } else {
      const std::string al = chain == Chain::TON ? B64URL : chain == Chain::BTC ? hc::BECH32_CHARSET : BASE58_ALPHABET;
      for (size_t v = 0; v < al.size(); v++)
        if (ps.cls.find(al[v]) != std::string::npos) m |= 1ull << v;
    }
    cfg.cls_lo = (uint32_t)m;
    cfg.cls_hi = (uint32_t)(m >> 32);
  }
  if (o.score == Score::REPEAT && (chain == Chain::TRON || chain == Chain::BTC_P2SH)) {
    // lead run needed when the trailing run is at most 4 (score = lead + trail)
    const int k = std::min(ps.min_score - 4, 6);
    const long double ver = chain == Chain::TRON ? 0x41 : 0x05, two192 = std::ldexp(1.0L, 192);
    const long double p33 = std::pow(58.0L, 33);
    const long double d0 = std::floor(ver * two192 / p33), d1 = std::floor(((ver + 1) * two192 - 1) / p33);
    // the first character is the same for every address and all have 34 characters
    if (k >= 2 && d0 == d1 && (ver + 1) * two192 < std::pow(58.0L, 34)) {
      const long double pk = std::pow(58.0L, k);
      cfg.lead_k = (uint32_t)k;
      cfg.lead_mul = (unsigned long long)std::llround(std::ldexp(1.0L, 199) / std::pow(58.0L, 33 - k));
      cfg.lead_base = (unsigned long long)std::llround(d0 * pk);
      cfg.lead_rep = (unsigned long long)std::llround((pk - 1) / 57);
      cfg.lead_inv = (float)(1.0L / cfg.lead_rep);
    }
  }
  cfg.need_digits = o.score != Score::NONE ? 1 : 0;
  for (const DevPattern& d : ps.dev)
    if (d.ndig || (chain == Chain::TON && (d.bmask[8] & 0xFFFFu)) || (chain == Chain::BTC && d.bmask[5]))
      cfg.need_digits = 1;
  if ((chain == Chain::TON || chain == Chain::BTC) && !ps.idx[1].empty()) cfg.need_digits = 1;

  double log_miss = 0;
  for (const Pattern& p : ps.pats) log_miss += std::log1p(-std::min(p.p, 0.999999));
  if (o.score == Score::REPEAT) ps.p_score = beauty_probability(alphabet_size(chain), ps.min_score);
  if (o.score == Score::CLASS) ps.p_score = class_probability(chain, ps.cls, ps.min_score);
  log_miss += std::log1p(-std::min(ps.p_score, 0.999999));
  ps.p_match = -std::expm1(log_miss);
  return ps;
}
