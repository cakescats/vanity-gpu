#include <algorithm>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "hostcrypto.h"
#include "pattern.h"
#include "report.h"
#include "cpu_secp.h"

static void usage() {
  printf(
      "vanity-gpu — GPU vanity address generator (EVM, TRON, Bitcoin, Solana, TON)\n"
      "\n"
      "usage:\n"
      "  vanity-gpu <evm|tron|btc|sol|ton> [PATTERN...] [options]\n"
      "      PATTERN  PREFIX, PREFIX..SUFFIX or ..SUFFIX; '?' matches any character\n"
      "               evm:  dead..beef   0x0000   ..c0ffee   (case-insensitive hex)\n"
      "               tron: TXyz   T?abc..888                (base58, case-sensitive)\n"
      "               btc:  bc1qdead  ..cafe   (bech32, no 1 b i o)   1Love  (legacy)   3Cat  (P2SH)\n"
      "                     the first pattern picks the type; or say btc-segwit / btc-legacy / btc-p2sh\n"
      "               sol:  Abc   ..pump                     (base58, case-sensitive)\n"
      "               ton:  cool  UQA?cool  ..ton            (base64url, case-sensitive;\n"
      "                     matched against the UQ... form, wallet W5 / v5r1)\n"
      "               [abc] = any of a, b, c (e.g. [aA4]pple)\n"
      "  -f, --file FILE       read patterns from FILE, one per line (# comments); millions\n"
      "                        of patterns cost about as much as one\n"
      "      --min-len N       skip list lines with fewer than N fixed characters\n"
      "      --at start|end|both  where plain list words go (default start)\n"
      "  -i, --ignore-case     letters match in both cases (tron/sol/ton/btc legacy)\n"
      "  -c, --caps            word, Word and WORD (fewer variants than -i)\n"
      "  -l, --similar         look-alike characters match too: o=0 i=l=1 z=2 e=3 a=4 s=5\n"
      "                        b=6=G t=7 B=8 g=9 (e.g. evm 'coffee' -> c0ffee, sol 'elon' -> e1on)\n"
      "      --subs N          at most N changed characters per word with -i/-l\n"
      "                        (default: 3 for list lines, no limit for patterns given here)\n"
      "  -b, --beauty          also report addresses with long runs of one character\n"
      "                        at the start and the end (score = lead run + trail run)\n"
      "      --only CLASS      also report addresses made of one kind of character:\n"
      "                        digits, lower, upper, letters (join with +, e.g. digits+upper)\n"
      "                        or the characters themselves (e.g. 0-9A-F). Score = leading\n"
      "                        + trailing run of such characters; the whole address = its\n"
      "                        length. evm: upper/lower is the EIP-55 checksum case\n"
      "      --min-score N     score threshold (beauty default: evm 12, btc 10, tron/sol 8,\n"
      "                        ton 7; --only default: about one hit per 30 s)\n"
      "  -n, --count N         stop after N results (default 1, 0 = run until Ctrl-C)\n"
      "  -o, --out FILE        results file, created with mode 0600 (default vanity-results.txt)\n"
      "  -k, --show-keys       print private keys to the terminal too\n"
      "      --pubkey HEX      evm/tron/btc split-key mode: search an offset for YOUR public\n"
      "                        key; this machine never learns the final private key\n"
      "      --cpu N|max       evm/tron/btc: also search on N CPU threads (max = all but one);\n"
      "                        adds ~5-10%% on a fast CPU, uses a lot of power\n"
      "      --max-patterns N  limit after expansion (default 20000000)\n"
      "      --bench SEC       run for SEC seconds and print the speed\n"
      "      --device N  --blocks N  --threads N\n"
      "\n"
      "      --rarity BITS     pick the score threshold so a hit is ~1 in 2^BITS (the same\n"
      "                        meaning on every chain; 40 = evm 13, btc 11, tron/sol 9, ton 9)\n"
      "\n"
      "  vanity-gpu multi <CHAINS> [PATTERN...] [options]\n"
      "      one pass, every key checked in each chain (all secp256k1 or all ed25519):\n"
      "      CHAINS   evm,tron,btc  btc-all (= btc,btc-legacy,btc-p2sh)  secp (= evm,tron,btc)\n"
      "               sol,ton (= ed)\n"
      "      PATTERN  chain:PATTERN for one chain (evm:dead, btc:bc1qcafe); a plain pattern\n"
      "               goes to every chain it is valid for (..777)\n"
      "      --beauty / --only use one threshold for all chains: --rarity BITS (default 36,\n"
      "               sol/ton 32); --min-score evm=14,tron=10 sets chains by hand\n"
      "\n"
      "  vanity-gpu combine <evm|tron|btc...> <your_private_key> <a> <b>\n"
      "  vanity-gpu derive  <chain> <private_key_hex | ed25519_seed_hex>\n"
      "  vanity-gpu selftest\n"
      "  vanity-gpu --version\n");
}

static Chain parse_chain(const std::string& s) {
  if (s == "evm" || s == "eth") return Chain::EVM;
  if (s == "tron" || s == "trx") return Chain::TRON;
  if (s == "sol" || s == "solana") return Chain::SOL;
  if (s == "ton") return Chain::TON;
  if (s == "btc" || s == "bitcoin" || s == "btc-segwit" || s == "btc-bech32") return Chain::BTC;
  if (s == "btc-legacy" || s == "btc-p2pkh" || s == "btc1") return Chain::BTC_LEGACY;
  if (s == "btc-p2sh" || s == "btc3") return Chain::BTC_P2SH;
  throw std::runtime_error("unknown chain '" + s + "' (use evm, tron, btc, sol or ton)");
}

// "btc" picks the address type from the patterns: bc1q..., 1..., 3...
static Chain btc_type(const std::vector<std::string>& pats) {
  int seen = -1;
  for (const std::string& p : pats) {
    if (p.empty() || p.rfind("..", 0) == 0) continue;
    int t = -1;
    if (p.size() >= 3 && tolower((unsigned char)p[0]) == 'b' && tolower((unsigned char)p[1]) == 'c' && p[2] == '1') t = 0;
    else if (p[0] == '1') t = 1;
    else if (p[0] == '3') t = 2;
    if (t < 0) continue;
    if (seen >= 0 && t != seen)
      throw std::runtime_error("patterns for different Bitcoin address types (bc1q / 1 / 3); use one type per run");
    seen = t;
  }
  return seen == 1 ? Chain::BTC_LEGACY : seen == 2 ? Chain::BTC_P2SH : Chain::BTC;
}

static std::string secp_address(Chain c, const hc::SPt& P) {
  using namespace hc;
  if (c == Chain::EVM) return eip55(evm_address(P));
  if (c == Chain::TRON) return tron_address(P);
  uint8_t h[20];
  btc_hash160(P, h);
  if (c == Chain::BTC) return btc_p2wpkh(h);
  if (c == Chain::BTC_LEGACY) return btc_p2pkh(h);
  return btc_p2sh_p2wpkh(h);
}

static int cmd_derive(int argc, char** argv) {
  if (argc != 4) { usage(); return 2; }
  Chain c = parse_chain(argv[2]);
  if (is_ed25519(c)) {
    uint8_t kp[64];
    if (!hc::unhex(argv[3], kp, 32)) throw std::runtime_error("seed must be 64 hex chars");
    hc::ed_pubkey(kp, kp + 32);
    if (c == Chain::TON) {
      uint8_t acct[32];
      hc::ton_account_hash(kp + 32, hc::TON_WALLET_ID_MAINNET, acct);
      printf("%s %s\n", hc::ton_address(acct, false).c_str(), hc::hex(kp + 32, 32).c_str());
    } else {
      printf("%s %s\n", hc::sol_address(kp + 32).c_str(), hc::hex(kp + 32, 32).c_str());
    }
  } else {
    U256 k = U256::from_hex(argv[3]);
    hc::SPt P = hc::s_mul(k, hc::s_gen());
    printf("%s %s%s", secp_address(c, P).c_str(), P.x.hex().c_str(), P.y.hex().c_str());
    if (is_btc(c)) printf(" %s", hc::btc_wif(k).c_str());
    printf("\n");
  }
  return 0;
}

static int cmd_combine(int argc, char** argv) {
  if (argc != 6) { usage(); return 2; }
  Chain c = parse_chain(argv[2]);
  if (is_ed25519(c)) throw std::runtime_error("combine is only for evm/tron/btc split keys");
  U256 k = U256::from_hex(argv[3]), a = U256::from_hex(argv[4]), b = U256::from_hex(argv[5]);
  U256 key = hc::n_add(hc::n_mul(a, k), b);
  hc::SPt P = hc::s_mul(key, hc::s_gen());
  if (is_btc(c))
    printf("address     = %s\nprivate_key = %s (WIF)\n", secp_address(c, P).c_str(), hc::btc_wif(key).c_str());
  else
    printf("address     = %s\nprivate_key = %s%s\n", secp_address(c, P).c_str(), c == Chain::EVM ? "0x" : "",
           key.hex().c_str());
  return 0;
}

static bool check(const char* name, bool ok) {
  printf("  %-60s %s\n", name, ok ? "ok" : "FAIL");
  return ok;
}

static double run_engine(const PatternSet& ps, const EngineOptions& eo, Reporter& rep) {
  return is_ed25519(ps.chain) ? run_ed(ps, eo, rep) : run_secp(ps, eo, rep);
}

static int cmd_selftest(const EngineOptions& eo) {
  using namespace hc;
  bool ok = true;
  printf("CPU reference:\n");
  uint8_t h[64];
  keccak256(nullptr, 0, h);
  ok &= check("keccak256(\"\")", hex(h, 32) == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  sha256((const uint8_t*)"abc", 3, h);
  ok &= check("sha256(\"abc\")", hex(h, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  sha512((const uint8_t*)"abc", 3, h);
  ok &= check("sha512(\"abc\")",
              hex(h, 64) ==
                  "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd"
                  "454d4423643ce80e2a9ac94fa54ca49f");
  ripemd160((const uint8_t*)"abc", 3, h);
  ok &= check("ripemd160(\"abc\")", hex(h, 20) == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
  ok &= check("secp256k1 G on curve", s_on_curve(s_gen()));
  SPt one = s_mul(U256::from_u64(1), s_gen());
  ok &= check("EVM address of key 1", evm_address(one) == "7e5f4552091a69125d5dfcb7b8c2659029395bdf");
  {
    uint8_t k1[20];
    btc_hash160(one, k1);
    ok &= check("BTC bc1q address of key 1 (BIP-173 vector)",
                btc_p2wpkh(k1) == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    ok &= check("BTC legacy address of key 1", btc_p2pkh(k1) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
    ok &= check("BTC P2SH-P2WPKH address of key 1", btc_p2sh_p2wpkh(k1) == "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN");
    ok &= check("BTC WIF of key 1", btc_wif(U256::from_u64(1)) == "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");
  }
  SPt lg = s_mul(SECP_LAMBDA, s_gen());
  ok &= check("endomorphism: lambda*G == (beta*Gx, Gy)",
              lg.x == FP.mul(SECP_BETA, s_gen().x) && lg.y == s_gen().y);
  ok &= check("n*G == infinity", s_mul(SECP_N, s_gen()).inf);
  ok &= check("ed25519 base point on curve", e_on_curve(e_base()));
  uint8_t seed[32], pub[32];
  unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32);
  ed_pubkey(seed, pub);
  ok &= check("ed25519 RFC 8032 test 1", hex(pub, 32) == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
  {
    // A live mainnet wallet v5r1 (toncenter: wallet_type "wallet v5 r1", wallet_id 2147483409);
    // public key taken from its on-chain data cell.
    uint8_t acct[32];
    unhex("3b26e906af38b3aa45aacbecc4bee94169aa9becc9d8aeb94e9b97519d2088b0", pub, 32);
    ton_account_hash(pub, TON_WALLET_ID_MAINNET, acct);
    ok &= check("TON W5 address (real mainnet wallet)",
                ton_address(acct, false) == "UQA-OSGVswlJOJzD6ijqpDtNS5J8VnNtnx4QOzWomN0vNoT1");
  }
  {
    MatchOptions il{true, true}, l{false, true}, c{false, false, true};
    auto has = [](const std::vector<std::string>& v, const std::string& x) {
      return std::find(v.begin(), v.end(), x) != v.end();
    };
    auto e1 = expand_pattern(Chain::EVM, "coffee", l);
    ok &= check("expand evm 'coffee' -l -> c0ffee", e1.size() == 4 && has(e1, "c0ffee") && has(e1, "c0ff33"));
    auto e2 = expand_pattern(Chain::SOL, "elon", il);
    ok &= check("expand sol 'elon' -i -l (18 variants)", e2.size() == 18 && has(e2, "E1oN") && has(e2, "3Lon"));
    auto e3 = expand_pattern(Chain::TRON, "trx", MatchOptions{true, false});
    ok &= check("expand tron 'trx' -i keeps the leading T", e3.size() == 8 && has(e3, "TtRx") && has(e3, "TTRX"));
    auto e4 = expand_pattern(Chain::TON, "[aA4]b..z", MatchOptions{});
    ok &= check("expand ton '[aA4]b..z'", e4.size() == 3 && has(e4, "UQ?Ab..z") && has(e4, "UQ?4b..z"));
    auto e5 = expand_pattern(Chain::SOL, "degen..pump", c);
    ok &= check("expand sol 'degen..pump' -c", e5.size() == 3 && has(e5, "Degen..Pump") && has(e5, "DEGEN..PUMP"));
    auto e8 = expand_pattern(Chain::SOL, "moon", c);
    ok &= check("expand sol 'moon' -c drops MOON (no O in base58)", e8.size() == 2 && has(e8, "Moon"));
    auto e6 = expand_pattern(Chain::BTC, "dead", l);
    ok &= check("expand btc 'dead' -l (bech32)", e6.size() == 4 && has(e6, "bc1qd34d") && has(e6, "bc1qdead"));
    auto e7 = expand_pattern(Chain::BTC_LEGACY, "Cat", c);
    ok &= check("expand btc-legacy 'Cat' -c keeps the leading 1", e7.size() == 3 && has(e7, "1CAT") && has(e7, "1cat"));
    ok &= check("pattern_body_len", pattern_body_len(Chain::TRON, "TAb?c..[xy]z") == 5 &&
                                        pattern_body_len(Chain::BTC, "bc1qdead") == 4);
    bool threw = false;
    try { expand_pattern(Chain::EVM, "coffee", MatchOptions{}); } catch (const std::exception&) { threw = true; }
    ok &= check("evm 'coffee' without -l is an error", threw);
    threw = false;
    try { compile_patterns(Chain::BTC, {"bitcoin"}, false, 0); } catch (const std::exception&) { threw = true; }
    ok &= check("btc 'bitcoin' is an error (bech32 has no b, i, o)", threw);
  }
  if (!ok) {
    printf("CPU self-test FAILED\n");
    return 1;
  }

  printf("GPU end-to-end (each hit re-derived on the CPU):\n");
  struct Case {
    Chain c;
    std::vector<std::string> pats;
    Score score;
    int min_score;
    bool cpu_only = false;  // CPU workers (--cpu) without the GPU
    std::string only = "";
  };
  const Score N = Score::NONE, B = Score::REPEAT, O = Score::CLASS;
  std::vector<Case> all = {
      {Chain::EVM, {"0", "a..b", "..??1"}, N, 0},
      {Chain::EVM, {}, B, 7},
      {Chain::EVM, {}, O, 9, false, "digits"},
      {Chain::EVM, {}, O, 6, false, "upper"},  // EIP-55 case
      {Chain::TRON, {"TT", "T?a", "..z"}, N, 0},
      {Chain::TRON, {}, B, 5},
      {Chain::TRON, {}, O, 5, false, "lower"},
      {Chain::BTC, {"q", "..q", "?p", "bc1q??z..0?"}, N, 0},
      {Chain::BTC, {}, B, 5},
      {Chain::BTC, {}, O, 5, false, "digits"},
      {Chain::BTC_LEGACY, {"1A", "1?b", "..z", "11"}, N, 0},
      {Chain::BTC_LEGACY, {}, B, 5},
      {Chain::BTC_LEGACY, {}, O, 6, false, "upper"},
      {Chain::BTC_P2SH, {"3A", "3?b", "..z"}, N, 0},
      {Chain::BTC_P2SH, {}, B, 5},
      {Chain::SOL, {"A", "..z", "?b"}, N, 0},
      {Chain::SOL, {}, B, 4},
      {Chain::SOL, {}, O, 3, false, "digits"},
      {Chain::TON, {"A", "UQC?x", "..?k", "a..b"}, N, 0},
      {Chain::TON, {}, B, 4},
      {Chain::TON, {}, O, 4, false, "upper"},
      {Chain::SOL, {"1A", "1?b", "1..z"}, N, 0},
  };
  // pattern lists (> MAX_PATTERNS) go through the GPU index; most of these are key-only
  auto list_case = [](Chain c) {
    std::vector<std::string> v;
    if (c == Chain::EVM) v = {"0a", "1b", "2c", "3d", "4e", "5f", "..a0", "..b1", "..c2", "..d3", "e4..5", "f5..6", "?7..8", "a?a"};
    if (c == Chain::TRON) v = {"TA", "TB", "TC", "TD", "TE", "..a", "..b", "..c", "..dd", "TF..e", "T?a", "TG?h"};
    if (c == Chain::BTC) v = {"bc1qa", "bc1qc", "bc1qd", "bc1qe", "..a", "..c", "..d", "..ee", "bc1qf..g", "bc1q?h", "bc1qj?k"};
    if (c == Chain::BTC_LEGACY) v = {"1A", "1B", "1C", "1D", "..a", "..b", "..c", "..dd", "1E..f", "1?g", "1H?j", "11"};
    if (c == Chain::BTC_P2SH) v = {"3A", "3B", "3C", "3D", "..a", "..b", "..c", "..dd", "3E..f", "3?g", "3H?j"};
    if (c == Chain::SOL) v = {"A", "B", "C", "D", "E", "..a", "..b", "..c", "1A", "1?b", "?Fb", "..dd", "Gx..y"};
    if (c == Chain::TON) v = {"A", "B", "C", "D", "E", "..a", "..b", "..c", "UQA?x", "..dd", "Fx..y", "UQB"};
    for (int i = 0; i < 30; i++)  // rare fillers so the list exceeds MAX_PATTERNS
      v.push_back(std::string(c == Chain::EVM ? "..ffffff" : c == Chain::BTC ? "..zzzzzz" : "..zzzzzz") +
                  char('2' + i % 8) + "?" + char('2' + i / 8));
    return v;
  };
  for (Chain c : {Chain::EVM, Chain::TRON, Chain::BTC, Chain::BTC_LEGACY, Chain::BTC_P2SH, Chain::SOL, Chain::TON})
    all.push_back({c, list_case(c), N, 0});
  for (Chain c : {Chain::EVM, Chain::TRON, Chain::BTC, Chain::BTC_LEGACY, Chain::BTC_P2SH})
    all.push_back({c, list_case(c), N, 0, true});
  all.push_back({Chain::EVM, {"0", "a..b", "..??1"}, N, 0, true});
  all.push_back({Chain::EVM, {}, B, 7, true});
  all.push_back({Chain::EVM, {}, O, 6, true, "upper"});
  all.push_back({Chain::TRON, {"TT", "T?a", "..z"}, N, 0, true});
  all.push_back({Chain::TRON, {}, B, 5, true});
  all.push_back({Chain::BTC, {"q", "..q", "?p"}, N, 0, true});
  all.push_back({Chain::BTC, {}, O, 5, true, "digits"});
  all.push_back({Chain::BTC_LEGACY, {"1A", "1?b", "..z"}, N, 0, true});
  all.push_back({Chain::BTC_P2SH, {"3A", "3?b", "..z"}, N, 0, true});
  all.push_back({Chain::BTC_P2SH, {}, B, 5, true});
  for (auto& cs : all) {
    CompileOptions co;
    co.score = cs.score;
    co.min_score = cs.min_score;
    co.only = cs.only;
    PatternSet ps = compile_patterns(cs.c, cs.pats, co);
    Reporter rep(ps, "", false, 24, true);
    EngineOptions e2 = eo;
    if (cs.cpu_only) {
      e2.cpu = 4;
      e2.no_gpu = true;
    }
    run_engine(ps, e2, rep);
    std::string kind = cs.score == B   ? " beauty"
                       : cs.score == O ? " only " + cs.only
                       : ps.idx[0].empty() && ps.idx[1].empty() ? " patterns"
                                                                : " list";
    std::string name = std::string(chain_name(cs.c)) + (cs.cpu_only ? " CPU" : "") + kind + ": " +
                       std::to_string(rep.found_count()) + " verified, " + std::to_string(rep.rejected()) +
                       " rejected";
    ok &= check(name.c_str(), rep.found_count() >= 24 && rep.rejected() == 0);
  }
  printf("Hit rate (every key counted as checked must really be checked):\n");
  struct RateCase {
    Chain c;
    std::vector<std::string> pats;
    double secs;
    bool cpu_only = false;
    Score score = Score::NONE;
    int min_score = 0;
    std::string only = "";
  };
  std::vector<RateCase> rall = {
      {Chain::EVM, {"abcdef", "..123456"}, 3},
      {Chain::TRON, {"TTab", "..wxyz"}, 3},
      {Chain::BTC, {"bc1qacdef", "..wxyz7"}, 3},
      {Chain::BTC_LEGACY, {"1Abcd", "..wxyz"}, 3},
      {Chain::BTC_P2SH, {"3Abcd", "..wxyz"}, 3},
      {Chain::SOL, {"Abcd", "..wxyz"}, 6},
      {Chain::TON, {"UQ?abcd", "..wxyz"}, 6},
      {Chain::EVM, {}, 3, false, Score::CLASS, 36, "digits"},
      {Chain::TRON, {}, 3, false, Score::CLASS, 21, "upper"},
      {Chain::BTC, {}, 3, false, Score::REPEAT, 7},
      {Chain::TRON, {}, 3, false, Score::REPEAT, 6},  // base58 beauty prefilter (k = 2, 3)
      {Chain::TRON, {}, 6, false, Score::REPEAT, 7},
      {Chain::BTC_P2SH, {}, 3, false, Score::REPEAT, 6},
  };
  // random lists of 300 prefixes + 300 suffixes (fixed seed; test data, not keys)
  uint64_t rs = 0x9E3779B97F4A7C15ull;
  auto rnd = [&]() { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; };
  auto rand_list = [&](Chain c, int plen, int slen) {
    const std::string al = c == Chain::EVM ? "0123456789abcdef"
                           : c == Chain::TON ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                           : c == Chain::BTC ? BECH32_CHARSET
                                             : "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    const std::string head = c == Chain::TRON ? "T" : c == Chain::BTC ? "bc1q" : c == Chain::BTC_LEGACY ? "1"
                             : c == Chain::BTC_P2SH ? "3" : "";
    std::vector<std::string> v;
    while (v.size() < 600) {
      bool pre = v.size() < 300;
      std::string w = pre ? head : "..";
      for (int i = 0; i < (pre ? plen : slen); i++) w += al[rnd() % al.size()];
      if (pre && (c == Chain::SOL || c == Chain::BTC_LEGACY) && w[head.size()] == '1') continue;
      try { compile_patterns(c, {w}, false, 0); } catch (const std::exception&) { continue; }
      v.push_back(w);
    }
    return v;
  };
  rall.push_back({Chain::EVM, rand_list(Chain::EVM, 8, 8), 3});
  rall.push_back({Chain::TRON, rand_list(Chain::TRON, 5, 5), 3});
  rall.push_back({Chain::BTC, rand_list(Chain::BTC, 6, 6), 3});
  rall.push_back({Chain::BTC_LEGACY, rand_list(Chain::BTC_LEGACY, 5, 5), 3});
  rall.push_back({Chain::BTC_P2SH, rand_list(Chain::BTC_P2SH, 5, 5), 3});
  rall.push_back({Chain::SOL, rand_list(Chain::SOL, 5, 5), 6});
  rall.push_back({Chain::TON, rand_list(Chain::TON, 5, 5), 6});
  rall.push_back({Chain::EVM, {"abcde", "..12345"}, 4, true});
  rall.push_back({Chain::TRON, {"TTab", "TTcd"}, 4, true});
  rall.push_back({Chain::BTC, {"bc1qacd", "..wxy"}, 4, true});
  rall.push_back({Chain::BTC_P2SH, {"3Abc", "..xyz"}, 4, true});
  for (auto& rc : rall) {
    CompileOptions co;
    co.score = rc.score;
    co.min_score = rc.min_score;
    co.only = rc.only;
    PatternSet ps = compile_patterns(rc.c, rc.pats, co);
    Reporter rep(ps, "", false, 0, true);
    EngineOptions e2 = eo;
    e2.bench = rc.secs;
    if (rc.cpu_only) {
      e2.cpu = cpu_default_threads();
      e2.no_gpu = true;
    }
    double keys = run_engine(ps, e2, rep);
    double expect = keys * ps.p_match, got = (double)rep.found_count();
    std::vector<std::string> a = rep.addresses();
    std::sort(a.begin(), a.end());
    bool dup = std::adjacent_find(a.begin(), a.end()) != a.end();
    char name[200];
    snprintf(name, sizeof name, "%s%s%s: %.0f found / %.0f expected%s", chain_name(rc.c),
             rc.cpu_only ? " CPU" : rc.pats.size() > MAX_PATTERNS ? " list of 600" : "",
             rc.score == Score::CLASS ? (" only " + rc.only).c_str() : rc.score == Score::REPEAT ? " beauty" : "", got, expect,
             dup ? ", DUPLICATES" : "");
    ok &= check(name, expect >= 50 && got >= 0.6 * expect && got <= 1.5 * expect && !dup && rep.rejected() == 0);
  }
  printf("Multi mode (one key walk, every chain counted on its own):\n");
  struct MultiCase {
    std::vector<Chain> chains;
    Score score;
    std::string only;
    double rarity, secs;
    std::vector<std::string> pats = {};  // "chain:pattern" or plain
    bool cpu_only = false;
  };
  const std::vector<Chain> secp5 = {Chain::EVM, Chain::TRON, Chain::BTC, Chain::BTC_LEGACY, Chain::BTC_P2SH};
  std::vector<MultiCase> mall = {
      {secp5, Score::REPEAT, "", 21, 3},
      {secp5, Score::CLASS, "digits", 21, 3},
      {{Chain::EVM, Chain::BTC_P2SH}, Score::NONE, "", 0, 3, {"evm:abcdef", "evm:..12345", "btc-p2sh:3Abcd", "btc-p2sh:..wxyz"}},
      {secp5, Score::REPEAT, "", 15, 3, {}, true},
      {{Chain::SOL, Chain::TON}, Score::REPEAT, "", 18, 5},
      {{Chain::SOL, Chain::TON}, Score::NONE, "", 0, 7, {"..wxyz", "sol:Abcd"}},
  };
  for (auto& mc : mall) {
    std::vector<std::unique_ptr<PatternSet>> sets;
    std::vector<const PatternSet*> view;
    for (Chain c : mc.chains) {
      std::vector<std::string> args;
      for (const std::string& p : mc.pats) {
        size_t colon = p.find(':');
        if (colon == std::string::npos) args.push_back(p);
        else if (parse_chain(p.substr(0, colon)) == c) args.push_back(p.substr(colon + 1));
      }
      CompileOptions co;
      co.score = mc.score;
      co.only = mc.only;
      co.rarity = mc.rarity;
      sets.emplace_back(new PatternSet(compile_patterns(c, args, co)));
      view.push_back(sets.back().get());
    }
    Reporter rep(view, "", false, 0, true);
    EngineOptions e2 = eo;
    e2.bench = mc.secs;
    if (mc.cpu_only) {
      e2.cpu = cpu_default_threads();
      e2.no_gpu = true;
    }
    double keys = is_ed25519(mc.chains[0]) ? run_ed(view, e2, rep) : run_secp(view, e2, rep);
    std::string name = rep.label() + (mc.cpu_only ? " CPU" : "") +
                       (mc.score == Score::REPEAT ? " beauty" : mc.score == Score::CLASS ? " only " + mc.only : " patterns");
    bool good = rep.rejected() == 0;
    std::string detail;
    for (const PatternSet* p : view) {
      double expect = keys * p->p_match, got = (double)rep.found_count(p->chain);
      good &= expect >= 50 && got >= 0.6 * expect && got <= 1.5 * expect;
      char b[64];
      snprintf(b, sizeof b, " %s %.0f/%.0f", chain_name(p->chain), got, expect);
      detail += b;
    }
    std::vector<std::string> a = rep.addresses();
    std::sort(a.begin(), a.end());
    good &= std::adjacent_find(a.begin(), a.end()) == a.end();
    printf("  %s:%s  %s\n", name.c_str(), detail.c_str(), good ? "ok" : "FAIL");
    ok &= good;
  }
  {  // one rarity, comparable thresholds
    CompileOptions co;
    co.score = Score::REPEAT;
    co.rarity = 40;
    int e = compile_patterns(Chain::EVM, {}, co).min_score, b = compile_patterns(Chain::BTC, {}, co).min_score,
        t = compile_patterns(Chain::TRON, {}, co).min_score, n = compile_patterns(Chain::TON, {}, co).min_score;
    ok &= check(("--rarity 40: evm 13, btc 11, tron 9, ton 9 (got " + std::to_string(e) + ", " + std::to_string(b) +
                 ", " + std::to_string(t) + ", " + std::to_string(n) + ")").c_str(),
                e == 13 && b == 11 && t == 9 && n == 9);
  }
  printf(ok ? "all tests passed\n" : "SELF-TEST FAILED\n");
  return ok ? 0 : 1;
}

static void on_sigint(int) { g_stop = 1; }

// ---------------------------------------------------------------- shared by single and multi runs

// List lines for one chain: --at places plain words, --min-len drops short ones.
static std::vector<std::string> list_lines(Chain chain, const std::vector<std::string>& file_pats, const std::string& at,
                                           size_t min_len, size_t& too_short) {
  std::vector<std::string> lines;
  lines.reserve(file_pats.size() * (at == "both" ? 2 : 1));
  too_short = 0;
  for (const std::string& l : file_pats) {
    if (min_len && pattern_body_len(chain, l) < min_len) {
      too_short++;
      continue;
    }
    if (l.find("..") != std::string::npos || at == "start") lines.push_back(l);
    else if (at == "end") lines.push_back(".." + l);
    else {
      lines.push_back(l);
      lines.push_back(".." + l);
    }
  }
  return lines;
}

// A pattern that essentially never matches, so --bench measures only the raw speed.
static std::string bench_pattern(Chain chain) {
  return chain == Chain::EVM          ? "ffffffffffffffffffffffff"
         : chain == Chain::TRON       ? "TTTTTTTTTTTTTTTT"
         : chain == Chain::TON        ? "UQAzzzzzzzzzzzzzzz"
         : chain == Chain::BTC        ? "bc1qzzzzzzzzzzzzzzzz"
         : chain == Chain::BTC_LEGACY ? "1zzzzzzzzzzzzzzz"
         : chain == Chain::BTC_P2SH   ? "3Mzzzzzzzzzzzzzz"
                                      : "zzzzzzzzzzzzzzzz";
}

static void print_summary(const PatternSet& ps, size_t too_short, size_t min_len) {
  const Chain chain = ps.chain;
  if (too_short) fprintf(stderr, "[%s] %zu list line(s) shorter than --min-len %zu left out\n", chain_name(chain),
                         too_short, min_len);
  if (!ps.skipped.empty()) {
    fprintf(stderr, "[%s] skipped %zu invalid line(s) of the list, e.g.:\n", chain_name(chain), ps.skipped.size());
    for (size_t i = 0; i < ps.skipped.size() && i < 3; i++) fprintf(stderr, "    %s\n", ps.skipped[i].c_str());
  }
  std::string what = std::to_string(ps.pats.size()) + " pattern(s)";
  if (ps.pats.size() != ps.lines) what += " from " + std::to_string(ps.lines) + " written";
  if (!ps.idx[0].empty() || !ps.idx[1].empty())
    what += " (indexed: " + std::to_string(ps.idx[0].npat) + " by start, " + std::to_string(ps.idx[1].npat) +
            " by end)";
  std::string sc;
  char bits[48];
  snprintf(bits, sizeof bits, " (1 in 2^%.1f)", score_bits(ps, ps.min_score));
  if (ps.score == Score::REPEAT) sc = "beauty >= " + std::to_string(ps.min_score) + bits;
  if (ps.score == Score::CLASS)
    sc = "only " + ps.cls_name + " [" + ps.cls + "] score >= " + std::to_string(ps.min_score) + " of " +
         std::to_string(score_positions(chain, ps.score)) + " chars" + bits;
  std::string desc = ps.pats.empty() ? "" : what;
  if (!sc.empty()) desc += (desc.empty() ? "" : " + ") + sc;
  fprintf(stderr, "[%s] %s; ~%.3g keys per hit on average\n", chain_name(chain), desc.c_str(), 1.0 / ps.p_match);
}

static const char* cli_chain(Chain c) {
  switch (c) {
    case Chain::EVM: return "evm";
    case Chain::TRON: return "tron";
    case Chain::SOL: return "sol";
    case Chain::TON: return "ton";
    case Chain::BTC: return "btc";
    case Chain::BTC_LEGACY: return "btc-legacy";
    default: return "btc-p2sh";
  }
}

// "evm,tron,btc" (or with +); secp = evm,tron,btc; btc-all = the three Bitcoin types; ed = sol,ton
static std::vector<Chain> parse_chain_list(const std::string& spec) {
  std::vector<Chain> out;
  auto add = [&](Chain c) {
    if (std::find(out.begin(), out.end(), c) == out.end()) out.push_back(c);
  };
  size_t i = 0;
  while (i <= spec.size()) {
    size_t j = spec.find_first_of(",+", i);
    if (j == std::string::npos) j = spec.size();
    std::string t = spec.substr(i, j - i);
    i = j + 1;
    if (t.empty()) continue;
    if (t == "secp" || t == "all") {
      add(Chain::EVM); add(Chain::TRON); add(Chain::BTC);
    } else if (t == "btc-all") {
      add(Chain::BTC); add(Chain::BTC_LEGACY); add(Chain::BTC_P2SH);
    } else if (t == "ed") {
      add(Chain::SOL); add(Chain::TON);
    } else {
      add(parse_chain(t));
    }
  }
  if (out.empty()) throw std::runtime_error("multi: no chains given (e.g. multi evm,tron,btc)");
  bool ed = false, secp = false;
  for (Chain c : out) (is_ed25519(c) ? ed : secp) = true;
  if (ed && secp)
    throw std::runtime_error("multi: sol/ton (ed25519) and evm/tron/btc (secp256k1) cannot share keys; "
                             "use multi evm,tron,btc or multi sol,ton");
  return out;
}

// --min-score in multi mode: "evm=13,btc=11"
static std::vector<std::pair<Chain, int>> parse_score_map(const std::string& spec) {
  std::vector<std::pair<Chain, int>> out;
  size_t i = 0;
  while (i <= spec.size()) {
    size_t j = spec.find(',', i);
    if (j == std::string::npos) j = spec.size();
    std::string t = spec.substr(i, j - i);
    i = j + 1;
    if (t.empty()) continue;
    size_t eq = t.find_first_of("=:");
    if (eq == std::string::npos)
      throw std::runtime_error("multi: --min-score takes chain=N pairs (e.g. evm=13,btc=11); "
                               "for one threshold for all chains use --rarity BITS");
    out.push_back({parse_chain(t.substr(0, eq)), std::stoi(t.substr(eq + 1))});
  }
  return out;
}

static double nominal_speed(Chain c) {
  return c == Chain::SOL ? 2.3e8 : c == Chain::TON ? 2.0e8 : c == Chain::BTC_P2SH ? 2.1e9
         : is_btc(c) ? 3.8e9 : 1.8e9;
}

// multi CHAINS: one key walk, every key checked in each chain. Patterns "chain:PATTERN" go to
// that chain, plain ones to every chain they are valid for; list lines are skipped per chain
// where invalid. --beauty / --only use one rarity (bits) for all chains, since a score means
// very different odds on hex, bech32, base58 and base64 addresses.
static int run_multi(const std::vector<Chain>& chains, const std::vector<std::string>& pats,
                     const std::vector<std::string>& file_pats, CompileOptions co, const std::string& min_score_spec,
                     double rarity, const std::string& at, size_t min_len, EngineOptions eo, std::string out,
                     bool show_keys, long long count) {
  const bool ed = is_ed25519(chains[0]);
  const std::string label = [&]() {
    std::string l;
    for (Chain c : chains) l += (l.empty() ? "" : "+") + std::string(chain_name(c));
    return l;
  }();
  std::vector<std::pair<Chain, int>> scores;
  if (!min_score_spec.empty()) scores = parse_score_map(min_score_spec);
  for (auto& sc : scores)
    if (std::find(chains.begin(), chains.end(), sc.first) == chains.end())
      throw std::runtime_error(std::string("--min-score: ") + chain_name(sc.first) + " is not one of " + label);
  if (co.score != Score::NONE && rarity <= 0) rarity = ed ? 32 : 36;

  // ---- route the patterns
  std::vector<std::vector<std::string>> own(chains.size());
  std::vector<std::string> bare;
  for (const std::string& p : pats) {
    const size_t colon = p.find(':');
    if (colon == std::string::npos || colon == 0) {
      bare.push_back(p);
      continue;
    }
    const std::string name = p.substr(0, colon), body = p.substr(colon + 1);
    Chain c;
    try {
      c = parse_chain(name);
    } catch (const std::exception&) {
      throw std::runtime_error("pattern " + p + ": '" + name + "' is not a chain");
    }
    if (name == "btc" || name == "bitcoin") c = btc_type({body});
    auto it = std::find(chains.begin(), chains.end(), c);
    if (it == chains.end())
      throw std::runtime_error("pattern " + p + ": " + chain_name(c) + " is not one of " + label + " (add " +
                               cli_chain(c) + " to the chain list)");
    own[it - chains.begin()].push_back(body);
  }
  std::vector<int> fits(bare.size(), 0);

  if (eo.bench > 0 && pats.empty() && file_pats.empty() && co.score == Score::NONE) {
    for (size_t k = 0; k < chains.size(); k++) own[k].push_back(bench_pattern(chains[k]));
    count = 0;
    out = "";
  }
  if (pats.empty() && file_pats.empty() && co.score == Score::NONE && eo.bench == 0) {
    usage();
    return 2;
  }
  if (eo.cpu && ed) {
    fprintf(stderr, "[%s] --cpu ignored: ed25519 on the CPU would add well under 1%% to the GPU\n", label.c_str());
    eo.cpu = 0;
  }
  if (!eo.pubkey.empty() && ed)
    throw std::runtime_error("--pubkey works only for evm/tron/btc (ed25519 wallet keys are seeds, see README)");

  // ---- plain patterns go to every chain they are valid for
  std::vector<std::vector<std::string>> chain_args = own;
  for (size_t k = 0; k < chains.size(); k++) {
    const Chain c = chains[k];
    std::vector<std::string>& args = chain_args[k];
    for (size_t b = 0; b < bare.size(); b++) {
      CompileOptions t;
      t.match = co.match;
      t.max_patterns = co.max_patterns;
      try {
        compile_patterns(c, {bare[b]}, t);
      } catch (const std::exception&) {
        continue;
      }
      args.push_back(bare[b]);
      fits[b]++;
    }
  }
  for (size_t b = 0; b < bare.size(); b++)
    if (!fits[b]) throw std::runtime_error("pattern " + bare[b] + " is not valid for any of " + label);

  // ---- one pattern set per chain
  std::vector<std::unique_ptr<PatternSet>> sets;
  for (size_t k = 0; k < chains.size(); k++) {
    const Chain c = chains[k];
    std::vector<std::string> args = std::move(chain_args[k]);
    size_t too_short = 0;
    std::vector<std::string> lines = list_lines(c, file_pats, at, min_len, too_short);
    CompileOptions cc = co;
    cc.skip_from = cc.list_from = args.size();
    args.insert(args.end(), lines.begin(), lines.end());
    std::vector<std::string>().swap(lines);
    if (args.empty() && co.score == Score::NONE) {
      fprintf(stderr, "[%s] no patterns for this chain, left out\n", chain_name(c));
      continue;
    }
    cc.min_score = 0;
    for (auto& sc : scores)
      if (sc.first == c) cc.min_score = sc.second;
    cc.rarity = rarity;
    if (args.size() > 100000) fprintf(stderr, "[%s] compiling %zu patterns...\n", chain_name(c), args.size());
    std::unique_ptr<PatternSet> ps;
    try {
      ps.reset(new PatternSet(compile_patterns(c, args, cc)));
    } catch (const std::exception& e) {
      if (!file_pats.empty() && own[k].empty() && co.score == Score::NONE) {  // every list line invalid here
        fprintf(stderr, "[%s] %s, left out\n", chain_name(c), e.what());
        continue;
      }
      throw std::runtime_error(std::string(chain_name(c)) + ": " + e.what());
    }
    print_summary(*ps, too_short, min_len);
    sets.push_back(std::move(ps));
  }
  if (sets.empty()) throw std::runtime_error("no valid patterns for any of " + label);

  std::vector<const PatternSet*> view;
  double per_s = 0, slowest = 1e30;
  for (auto& p : sets) {
    view.push_back(p.get());
    per_s += p->p_match;
    slowest = std::min(slowest, nominal_speed(p->chain));
  }
  per_s *= slowest;
  if (view.size() > 1)
    fprintf(stderr, "[%s] one pass: every key is checked in all %zu chains\n", label.c_str(), view.size());
  if (per_s > 20 && count != 1 && eo.bench == 0)
    fprintf(stderr, "[!] expect roughly %.0f hits per second: use longer words, a higher --rarity or -n N\n", per_s);
  if (!eo.pubkey.empty())
    fprintf(stderr, "[%s] split-key mode: results contain only offsets (a, b) for your key\n", label.c_str());
  Reporter rep(view, out, show_keys, (uint64_t)std::max(0LL, count), false);
  if (ed) run_ed(view, eo, rep);
  else run_secp(view, eo, rep);
  if (rep.rejected())
    fprintf(stderr, "WARNING: %llu GPU candidates failed CPU verification\n", (unsigned long long)rep.rejected());
  return 0;
}

int main(int argc, char** argv) {
  try {
    if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
      usage();
      return argc < 2 ? 2 : 0;
    }
    std::string cmd = argv[1];
    if (cmd == "--version" || cmd == "version") {
#ifndef VG_VERSION
#define VG_VERSION "dev"
#endif
      printf("vanity-gpu %s\n", VG_VERSION);
      return 0;
    }
    if (cmd == "derive") return cmd_derive(argc, argv);
    if (cmd == "combine") return cmd_combine(argc, argv);

    EngineOptions eo;
    std::vector<std::string> pats, file_pats;
    bool show_keys = false;
    CompileOptions co;
    long long count = 1;
    size_t min_len = 0;
    std::string out = "vanity-results.txt", at = "start", min_score_spec;
    double rarity = 0;
    std::vector<Chain> multi;
    int first = 2;
    if (cmd == "multi") {
      if (argc < 3) { usage(); return 2; }
      multi = parse_chain_list(argv[2]);
      first = 3;
    }
    for (int i = first; i < argc; i++) {
      std::string a = argv[i];
      auto next = [&]() -> std::string {
        if (i + 1 >= argc) throw std::runtime_error("missing value for " + a);
        return argv[++i];
      };
      if (a == "-b" || a == "--beauty") co.score = Score::REPEAT;
      else if (a == "--only") {
        co.score = Score::CLASS;
        co.only = next();
      }
      else if (a == "-i" || a == "--ignore-case") co.match.ignore_case = true;
      else if (a == "-c" || a == "--caps") co.match.caps = true;
      else if (a == "-l" || a == "--similar" || a == "--leet") co.match.similar = true;
      else if (a == "-f" || a == "--file") {
        std::string fn = next();
        std::ifstream in(fn);
        if (!in) throw std::runtime_error("cannot read " + fn);
        std::string line;
        while (std::getline(in, line)) {
          size_t b = line.find_first_not_of(" \t\r"), e = line.find_last_not_of(" \t\r");
          if (b == std::string::npos || line[b] == '#') continue;
          file_pats.push_back(line.substr(b, e - b + 1));
        }
      }
      else if (a == "--min-len") min_len = (size_t)std::stoul(next());
      else if (a == "--at") {
        at = next();
        if (at != "start" && at != "end" && at != "both") throw std::runtime_error("--at takes start, end or both");
      }
      else if (a == "--subs") co.match.max_subs = co.list_subs = std::stoi(next());
      else if (a == "--max-patterns") co.max_patterns = (size_t)std::stoull(next());
      else if (a == "--min-score") min_score_spec = next();
      else if (a == "--rarity" || a == "--bits") rarity = std::stod(next());
      else if (a == "-n" || a == "--count") count = std::stoll(next());
      else if (a == "-o" || a == "--out") out = next();
      else if (a == "-k" || a == "--show-keys") show_keys = true;
      else if (a == "--pubkey") eo.pubkey = next();
      else if (a == "--cpu") {
        std::string v = next();
        eo.cpu = v == "max" || v == "all" ? cpu_default_threads() : std::stoi(v);
      }
      else if (a == "--no-gpu") eo.no_gpu = true;
      else if (a == "--bench") eo.bench = std::stod(next());
      else if (a == "--device") eo.device = std::stoi(next());
      else if (a == "--blocks") eo.blocks = std::stoi(next());
      else if (a == "--threads") eo.threads = std::stoi(next());
      else if (a.size() > 1 && a[0] == '-' && a[1] == '-') throw std::runtime_error("unknown option " + a);
      else pats.push_back(a);
    }
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    if (cmd == "selftest") return cmd_selftest(eo);
    if (!multi.empty())
      return run_multi(multi, pats, file_pats, co, min_score_spec, rarity, at, min_len, eo, out, show_keys, count);
    if (!min_score_spec.empty()) co.min_score = std::stoi(min_score_spec);
    co.rarity = rarity;

    Chain chain = parse_chain(cmd);
    if (cmd == "btc" || cmd == "bitcoin") {
      std::vector<std::string> all = pats;
      all.insert(all.end(), file_pats.begin(), file_pats.end());
      chain = btc_type(all);
    }

    size_t too_short = 0;
    file_pats = list_lines(chain, file_pats, at, min_len, too_short);
    co.skip_from = pats.size();  // invalid lines of list files are skipped, not fatal
    pats.insert(pats.end(), file_pats.begin(), file_pats.end());
    std::vector<std::string>().swap(file_pats);

    if (eo.bench > 0 && pats.empty() && co.score == Score::NONE) {
      // patterns that essentially never match, so only raw speed is measured
      pats.push_back(bench_pattern(chain));
      count = 0;
      out = "";
    }
    if (pats.empty() && co.score == Score::NONE) {
      if (too_short) throw std::runtime_error("every list line is shorter than --min-len");
      usage();
      return 2;
    }
    if (eo.cpu && is_ed25519(chain)) {
      fprintf(stderr, "[%s] --cpu ignored: ed25519 on the CPU would add well under 1%% to the GPU\n", chain_name(chain));
      eo.cpu = 0;
    }
    if (!eo.pubkey.empty() && is_ed25519(chain))
      throw std::runtime_error("--pubkey works only for evm/tron/btc (ed25519 wallet keys are seeds, see README)");

    const size_t n_written = pats.size();
    if (n_written > 100000) fprintf(stderr, "[%s] compiling %zu patterns...\n", chain_name(chain), n_written);
    PatternSet ps = compile_patterns(chain, pats, co);
    std::vector<std::string>().swap(pats);
    print_summary(ps, too_short, min_len);
    const double per_s = ps.p_match * nominal_speed(chain);
    if (per_s > 20 && count != 1 && eo.bench == 0)
      fprintf(stderr, "[!] expect roughly %.0f hits per second: use longer words (--min-len), a higher "
                      "--min-score or -n N\n", per_s);
    if (!eo.pubkey.empty())
      fprintf(stderr, "[%s] split-key mode: results contain only offsets (a, b) for your key\n", chain_name(chain));
    Reporter rep(ps, out, show_keys, (uint64_t)std::max(0LL, count), false);
    run_engine(ps, eo, rep);
    if (rep.rejected())
      fprintf(stderr, "WARNING: %llu GPU candidates failed CPU verification\n", (unsigned long long)rep.rejected());
    return 0;
  } catch (const std::exception& e) {
    fprintf(stderr, "error: %s\n", e.what());
    return 1;
  }
}
