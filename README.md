# vanity-gpu

**English** | [Русский](README.ru.md)

A CUDA vanity address generator for EVM (Ethereum, BSC, Polygon, Arbitrum and others: one address works on all chains), TRON, Bitcoin (`bc1q…`, `1…`, `3…`), Solana and TON (W5 wallet).

Speed on an RTX 3090:

| chain | speed | 4 chars | 6 chars | 8 chars |
|-------|-------|---------|---------|---------|
| EVM (hex)       | ~1.9 Gkey/s | instant | ~10 ms  | ~2 s   |
| TRON (base58)   | ~1.8 Gkey/s | instant | ~20 s   | ~19 h  |
| Bitcoin `bc1q…` (bech32) | ~3.9 Gkey/s | instant | ~0.3 s | ~5 min |
| Bitcoin `1…` (base58)    | ~3.8 Gkey/s | instant | ~10 s  | ~9.5 h |
| Bitcoin `3…` (base58)    | ~2.1 Gkey/s | instant | ~18 s  | ~17 h  |
| Solana (base58) | ~255 Mkey/s | instant | ~2.7 min | ~6 days |
| TON (base64)    | ~210 Mkey/s | instant | ~5.5 min | ~16 days |

The times in the table are the average wait for a prefix, ignoring case on EVM. Before it starts, the program shows the expected time for your pattern. TRON suffixes are slower (~1.1 Gkey/s) because they need the address checksum (double SHA-256). EVM and TRON are bound by keccak-256, which runs at ~80% of the 3090's peak integer throughput. Moving its rotations onto the multipliers (IMAD, a separate pipeline) was tested: it came out 1–12% slower, and `mul.hi` runs at half speed on this card. Bitcoin is twice as fast: SHA-256 + RIPEMD-160 of a compressed key is cheaper than keccak. A `3…` address computes hash160 twice, so it is slower. `bc1q…` suffixes (~3.0 Gkey/s) require the bech32 checksum.

Solana and TON build a 2.4 GB multiplication table in video memory at startup (~3 s, using ~2.5 GB of RAM during that time). If less than ~5.5 GB of video memory is free, a small 50 MB table is used instead: the speed is about 25% lower.

## Comparison with other generators

Measured back to back on the same RTX 3090 (driver 595, CUDA 12.4), with the card warmed up, using patterns that will never be found. The other tools were built from their GitHub sources (November 2026) and run in their benchmark or search mode.

| chain | tool | speed | keys |
|---|---|---|---|
| EVM | **vanity-gpu** | **1.80 Gkey/s** (1.92 with `--cpu max`) | getrandom, split-key, every hit re-checked on the CPU |
| EVM | [vanity-eth-address](https://github.com/MrSpike63/vanity-eth-address) | 1.63 Gkey/s | `/dev/urandom`, full key on the GPU |
| EVM | [ProVanity](https://github.com/WooMai/ProVanity) 1.1.2 | 1.11 Gkey/s | not described in its README |
| EVM | [profanity2](https://github.com/1inch/profanity2) | 0.84 Gkey/s | split-key |
| TRON, prefix | **vanity-gpu** | **1.78 Gkey/s** | as above |
| TRON, prefix | ProVanity | 0.99 Gkey/s | |
| TRON, suffix | **vanity-gpu** | **1.07 Gkey/s** | |
| TRON, suffix | ProVanity | 0.75 Gkey/s (8 characters at most) | |
| Bitcoin `1…` | **vanity-gpu** | **3.79 Gkey/s** | |
| Bitcoin `1…` | [VanitySearch](https://github.com/JeanLucPons/VanitySearch) | 3.87 Gkey/s | random base key, optional split-key |
| Bitcoin `bc1q…` | **vanity-gpu** | **3.85 Gkey/s** | |
| Bitcoin `bc1q…` | VanitySearch | 3.87 Gkey/s | |
| Bitcoin `3…` | **vanity-gpu** | **2.19 Gkey/s** | |
| Bitcoin `3…` | VanitySearch | 2.00 Gkey/s | |

ProVanity was built with CUDA 13.5 and measured with its own `provanity bench` (60 s, autotuned parameters); TRON with its interactive search and an unreachable pattern.

- **EVM**: 10% faster than the fastest generator found, 1.6× faster than ProVanity and twice as fast as profanity2. Keccak is the bottleneck for all of them.
- **Bitcoin**: on par with VanitySearch (−2% to +9%). It is the same class of algorithm: walking neighbouring points, batched inversion, the endomorphism. VanitySearch searches only the start of the address; here you also get suffixes, `--beauty` and lists.
- **Solana**: solanity (ChorusOne) warns in its README that it does not use a cryptographically secure RNG and its keys are not safe. The mcf-rocks fork takes entropy from the OS and says 5 characters take 12 minutes on average on a Tesla V100. Here it takes ~3 seconds on an RTX 3090. Different cards, but the gap is orders of magnitude.
- **TON**: no GPU generator of wallet keys was found: vaniton searches mnemonics on the CPU. [ton-org/vanity](https://github.com/ton-org/vanity) is far faster but solves a different problem: it finds a salt for a smart-contract address that you then deploy. A regular wallet imported from a key ends up at a different address.
- **TRON**: of the tools found, only ProVanity supports TRON. We are 1.8× faster for prefixes and 1.4× for suffixes, and suffixes can be of any length.
- None of them searches several chains in one pass or compares "beauty" across chains by rarity.

## Build

```bash
cmake -S . -B build && cmake --build build -j
./build/vanity-gpu selftest
```

Requires CUDA 12.x and g++-13: nvcc 12.4 does not support gcc 15, and CMake picks g++-13 by itself. The default GPU architecture is sm_86 (RTX 30xx). For another card, pass `-DCMAKE_CUDA_ARCHITECTURES=89` (40xx) or `120` (50xx).

Requirements, options, release binaries and the GitHub Actions build: [docs/BUILD.md](docs/BUILD.md). All measurements and how competitors were run: [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Usage

```bash
vanity-gpu evm dead..beef            # starts with dead, ends with beef
vanity-gpu evm 0x00000000 -n 5       # 5 addresses
vanity-gpu evm '??c0ffee'            # ? matches any character
vanity-gpu tron TRX..888             # TRON: base58, case-sensitive
vanity-gpu sol Pump ..pump           # several patterns in one run
vanity-gpu ton cool                  # TON: UQ?cool...
vanity-gpu ton UQAAAA                # TON: UQ + AAAA
vanity-gpu evm --beauty --min-score 14 -n 0   # "beautiful" addresses: long repeats at the start and at the end
vanity-gpu sol -f words.txt -n 0     # pattern list from a file (even 100,000 lines)
vanity-gpu sol elon -i -l            # approximately: ELoN, E1on, 3lon, 31oN ...
vanity-gpu evm coffee -l             # o → 0: c0ffee, c0ff33 ...
vanity-gpu ton '[Tt][Oo]n..[Tt]on'   # [..] matches any of the listed characters
vanity-gpu evm dead --cpu max        # + all CPU cores (≈ +7%)
vanity-gpu btc bc1qdead              # Bitcoin native SegWit (bech32: no 1 b i o)
vanity-gpu btc 1Love                 # Bitcoin legacy; the address type is taken from the pattern
vanity-gpu btc 3Cat ..cat            # Bitcoin P2SH-SegWit
vanity-gpu evm --only digits         # an address made of digits only (found in a fraction of a second)
vanity-gpu evm --only upper --min-score 16     # long runs of UPPERCASE letters in EIP-55 form (~20 s)
vanity-gpu sol --only lower+digits   # no uppercase letters
tools/wordlist.sh -m 8 > words.txt   # word list from the installed aspell
vanity-gpu sol -f words.txt -c -l --at both -n 0   # words + mutations at the start and at the end
```

## Lists, dictionaries and mutations

- **`-f FILE`**: patterns from a file, one per line; `#` starts a comment. The syntax is the same as on the command line: `word`, `..word`, `start..end`, `?`, `[..]`. Invalid lines are skipped with an explanation; the rest are searched.
- **`--at start|end|both`**: where to put plain words from the list: at the start (default), at the end, or both.
- **`--min-len N`**: skip words shorter than N characters. Short words are found thousands of times per second and only clutter the results.
- **`[abc]`**: any of these characters matches at this position: `[aA4]pple`.
- **`-c`**: three forms of a word: `word`, `Word`, `WORD`. This is usually enough, and there are far fewer variants than with `-i`.
- **`-i`**: letters in any case at every position (TRON, Solana, TON, Bitcoin `1…`/`3…`; EVM and `bc1q` have no case).
- **`-l`**: look-alike characters: `o=0`, `i=l=1`, `z=2`, `e=3`, `a=4`, `s=5`, `b=6=G`, `t=7`, `B=8`, `g=9`. Variants that are not in the chain's alphabet are dropped. That is why the EVM pattern `coffee -l` searches for `c0ffee`, `c0ff33` and so on, while without `-l` the program tells you that `o` does not exist in hex.
- **`--subs N`**: at most N changed characters per word (case or a look-alike character). The default is 3 for lines from a file and unlimited for patterns on the command line. Without this limit, a 12-letter word with `-l` produces hundreds of thousands of unreadable variants like `3x4mp135`.

Every variant is a separate pattern: `elon -i -l` on Solana produces 18 variants, and all of them are searched at the same time. At startup the program prints how many patterns were produced and how many keys it takes on average to find one. If more than ~20 hits per second are expected, it warns you.

### Where to get dictionaries

- `tools/wordlist.sh` builds a list from the aspell dictionaries that are already installed (English has about 127 thousand words with forms): `tools/wordlist.sh -m 8 > words.txt`. Options: `-d ru` and similar select another dictionary (`aspell dicts`), `-f file` adds your own list, `-m`/`-M` set the length, `-t evm|btc|base58|ton` keeps only the words that fit the chain without `-l`.
- `examples/words-crypto.txt`: about a hundred crypto words (moon, hodl, wagmi, satoshi, …).
- Any text file with one word per line. For example, the large English list `words_alpha.txt` (github.com/dwyl/english-words, ~370 thousand words) or the BIP-39 list. Download it yourself and pass it with `-f`.

### How it works and what it costs

Up to 16 patterns are checked one by one. Longer lists go through an index in video memory. The first and last characters are taken from the address, a bitmap (up to 512 MB) rejects almost all addresses with a single lookup, and the rest are checked by binary search. Word variants are generated once at startup, and the per-key check costs O(1) regardless of list size. There is therefore no need to generate variants on the GPU: the bottleneck is the key math, not the word lookup.

A plain word at the start or at the end ("key-only") is stored in the index without a descriptor: the GPU checks only the 64-bit key, and the CPU examines the characters beyond it (false candidates show up about once every few minutes and are discarded silently). So a pattern takes about 400 bytes of memory while the list is being compiled and about 60 bytes of video memory. The limit is 20 million variants (`--max-patterns`). Before generating, the program quickly counts how many variants there will be and reports right away if there are too many.

| aspell dictionary, -c -l | variants | speed | RAM at startup |
|---|---|---|---|
| Solana, words ≥ 9 letters | 11.7 million | 238 Mkey/s (no loss) | 5.6 GB, ~15 s |
| TRON, ≥ 10 letters, start and end | 13.7 million | 725 Mkey/s (suffixes need the checksum) | 4.7 GB, ~30 s |
| Bitcoin `bc1q`, ≥ 10 letters, start and end | 0.7 million | 2.7 Gkey/s | 0.75 GB |

A pattern must have at least one fixed character at the start (after `T` / `UQ?` / `bc1q` / `1` / `3`) or at the end. Patterns like `?abc` with no fixed start or end are limited to 16 per run.

## Digits only, letters only (`--only`)

`--only CLASS` searches for addresses made of characters of one kind: `digits`, `lower`, `upper`, `letters`, combinations joined with `+` (`digits+upper`), or the characters themselves (`0-9A-F`). The score is the length of the leading run of such characters plus the length of the trailing run. If the whole address matches, the score equals its length. The threshold is set with `--min-score`. By default it is chosen so that a hit comes about every 30 seconds, or the whole address if that is easier. For convenience, the program shows at startup which characters fell into the class and how many positions are counted.

- **EVM**: case means the EIP-55 checksum case, in which MetaMask and Etherscan display the address. `upper` is uppercase `A-F`, `lower` is lowercase. An address made only of digits (`--only digits`, 40 of 40) is found in a fraction of a second, and an address with no lowercase letters (`--only digits+upper`) instantly.
- **TRON, Solana, Bitcoin `1…`/`3…`, TON**: case as in the address. The second TRON character is almost always uppercase, and the time estimate accounts for this.
- **Bitcoin `bc1q`**: there is no case, so `upper` and `lower` mean the same thing: letters.

`--beauty` (runs of one character) and `--only` are two different scoring modes; only one of them works in a given run.

## Several chains in one pass (`multi`)

EVM, TRON and all three Bitcoin types derive the address from the same secp256k1 key. The most expensive part is walking the curve points. It is done once, and only the hash is computed per chain: keccak is shared by EVM and TRON, and hash160 is shared by all Bitcoin types. Solana and TON share an ed25519 key. secp256k1 and ed25519 cannot be mixed in one pass: they are different keys.

```bash
vanity-gpu multi evm,tron,btc --beauty -n 0 --cpu max      # beautiful addresses on three chains at once
vanity-gpu multi evm,tron,btc --beauty --rarity 40 -n 0    # rarer and more beautiful: ~1 in 2^40 on each chain
vanity-gpu multi btc-all --beauty -n 0                     # bc1q, 1… and 3… at the same time
vanity-gpu multi sol,ton --only digits -n 0
vanity-gpu multi evm,tron,btc ..777 evm:dead btc:bc1qcafe  # patterns: shared and for a single chain
```

- Chains: comma-separated. Shortcuts: `secp` = `evm,tron,btc`, `btc-all` = `btc,btc-legacy,btc-p2sh`, `ed` = `sol,ton`.
- A `chain:PATTERN` pattern is searched only on that chain. A pattern without a prefix is searched on every chain where it is valid. For example, `..777` fits any chain, while `dead` fits only EVM. Lines of an `-f` list that are invalid for a given chain are skipped for it.
- A found address is printed with the chain name. Its key is an ordinary key of that chain, and importing works the same as when searching a single chain.

**Equal "beauty" across chains.** A score of 10 means very different things on different chains. A run of 10 identical hex characters on EVM is much more common than a run of 10 base58 characters on TRON: EVM has 16 possible characters, Bitcoin `bc1q` has 32, TRON and Solana 58, TON 64. That is why `multi` sets the threshold as rarity in bits: `--rarity 40` means an address of this beauty occurs about once per 2^40 ≈ 1.1·10^12 keys. For each chain, the score closest to this rarity is chosen:

| `--rarity` | EVM | Bitcoin `bc1q` | TRON, `1…`, `3…`, Solana | TON |
|---|---|---|---|---|
| 36 (default; for sol,ton 32: scores 8 and 8) | 12 (2^36.6) | 10 (2^36.9) | 9 (2^38.0) | 8 (2^33.2) |
| 40 | 13 (2^40.5) | 11 (2^41.7) | 9 (2^38.0) | 9 (2^39.0) |
| 44 | 14 (2^44.4) | 11 (2^41.7) | 10 (2^43.7) | 10 (2^44.9) |

The score changes only in whole steps: 4 bits on EVM, 5 on Bitcoin, 5.9 on base58, 6 on TON. So the match is approximate, within ±3 bits. The exact rarity of each hit is printed next to it, for example `beauty score 13 (1 in 2^40.5)`. This lets you compare hits from different chains. To set the score for individual chains by hand: `--min-score evm=14,tron=10`. The other chains then take their threshold from `--rarity`. `--rarity` also works in single-chain searches, in place of `--min-score`. For `--only`, rarity works the same way.

**Speed** (RTX 3090), per chain. "One by one" means the same chains run as separate processes, with equal time given to each.

| chains | patterns | `--beauty` | one by one, `--beauty` |
|---|---|---|---|
| evm,tron | 1.6 Gkey/s | 1.0 Gkey/s | 0.7 Gkey/s |
| evm,tron,btc | 1.15 Gkey/s | 0.8 Gkey/s | 0.56 Gkey/s |
| evm,tron,btc-all | — | 0.46 Gkey/s | 0.3 Gkey/s |
| sol,ton | — | 210 Mkey/s | 114 Mkey/s |

Beauty on TRON and `1…`/`3…` is more expensive than a pattern at the start. The last characters of the address depend on the checksum (double SHA-256), so it has to be computed for every key.

## CPU and integrated GPU

`--cpu N` (or `--cpu max`, all threads but one) also runs the EVM/TRON/Bitcoin search on the CPU. The CPU walks its own ranges of the same split-key scheme. Keccak is computed for 8 keys at once with AVX-512, SHA-256 + RIPEMD-160 for 16. Every CPU hit is re-checked the same way as GPU hits.

On a Ryzen 7 7800X3D: 13 Mkey/s per thread, 136 Mkey/s on 15 threads. Together with the 3090 this gives EVM 1.89 → 2.02 Gkey/s and TRON 1.82 → 1.94 Gkey/s, that is +7%. For Bitcoin `bc1q`: 3.86 → 4.0 Gkey/s (+4%). The CPU runs at full load and heat. For TRON suffixes the gain is about 3%: the CPU has to build a base58 string for every key.

`--cpu` is not used for Solana and TON: ed25519 on the CPU would add less than 1% to the GPU.

The integrated Radeon GPU (Raphael, 2 compute units) is intentionally not supported. Its integer throughput is about 30 times lower than the 3090's, which is +2–3% at best. All the kernels would have to be rewritten for Vulkan. It also shares a single power limit with the CPU, so combined with `--cpu` the gain would be even smaller.

## Results

Findings are appended to `vanity-results.txt`. The file is created with mode 0600, and the path is set with `-o`. The key is printed to the terminal only with the `-k` flag. Stop with Ctrl-C.

Importing a key into a wallet:
- **EVM**: the `private_key` value (0x…) → MetaMask / Rabby, "Import account → Private key".
- **TRON**: `private_key` (64 hex characters) → TronLink, "Import wallet → Private key".
- **TON**: `private_key` (64 hex) → MyTonWallet, "Import wallet" → paste the key into the words field. The wallet must be version **W5**.
- **Bitcoin**: `private_key_wif` (compressed WIF, starts with K or L). In Electrum: "Create wallet → Import Bitcoin addresses or private keys", paste the `electrum_import` string; it already carries the right type (`p2wpkh:`, `p2pkh:` or `p2wpkh-p2sh:`), otherwise Electrum will show a different address. Sparrow and other wallets that accept WIF also work: choose the same address type.
- **Solana**: `private_key_base58` → Phantom / Solflare, "Import private key". For the CLI, save `keypair_json` to a file and use it with `solana-keygen`.

## Key security

In 2022 a bug in profanity cost Wintermute about $160M. Profanity ran the whole search from a 32-bit seed, so any address it found could be traced back to its private key within hours. Here it works as follows:

1. **There is only one source of randomness**: the OS `getrandom()`, 256 bits (`src/rng.cpp`). No mt19937, rand or time-based seeds. If getrandom returns an error, the program exits.
2. **EVM/TRON/Bitcoin use split-key.** The CPU picks a random key k0 and gives the GPU only the public point k0·G. The GPU searches for the offset. The final key `±λ^e·(k0 + d) mod n` is assembled on the CPU. The full key never reaches video memory.
3. **`--pubkey` mode**, for when this machine should not be trusted:
   ```bash
   # on an offline machine: your own key k0 and its public key (hex, compressed or not)
   vanity-gpu evm dead --pubkey 02ab...      # on the machine with the GPU: outputs only a and b
   vanity-gpu combine evm <k0> <a> <b>       # offline again: the final key
   ```
   The formula is simple: `key = (a·k0 + b) mod n`. The key cannot be recovered from a and b without k0.
4. **Solana and TON**: the wallet key is a seed, and the scalar = SHA-512(seed), so split-key is not possible here. Seeds come from ChaCha20 with a 256-bit key from getrandom, and each block has its own counter.
5. **Every hit is re-checked on the CPU.** Separate, deliberately simple code (`src/hostcrypto.cpp`) derives the address from the key again. If the address does not match the pattern, the result is not output and a warning is printed. The CPU code itself is checked against the `cryptography` library by the script `tests/crosscheck.py`.

A beautiful address is no less and no more secure than an ordinary one. Just beware of address "poisoning": attackers generate addresses with the same first and last characters. Check the whole address before sending.

## Internals

- `multi`: one kernel for all selected secp256k1 chains (or Solana+TON). Each chain has its own set of patterns in its own constant-memory slot. A hit remembers its chain and is re-checked on the CPU by the rules of that chain. In `--beauty` mode for TRON and `3…`, the top 64 bits of the number are first used to check whether the leading run can reach the threshold at all, and only then are all 34 base58 digits computed (a separate kernel variant: without `--beauty`, the mere presence of this code slowed the `3…` search by 16%). The error of this check is less than 2 and the tolerance is set to ±2, so no hits are lost.
- `src/engine_secp.cu`: EVM/TRON/Bitcoin. Each thread walks its own window of points P0 + d·G in groups of 512. Each group takes one batch inversion (Montgomery's trick). Each point yields 6 keys: ±y and the endomorphism β, β². The address is computed through keccak256. For TRON the prefix is checked by comparing a 160-bit number against a precomputed range, without base58 or sha256. Full base58 (sha256d + division) is needed only for suffixes, `?` and `--beauty`. For Bitcoin, hash160 of the compressed key is computed instead of keccak (the sign of y changes only the 02/03 prefix). `bc1q` is compared with 5-bit masks directly on hash160, and the bech32 checksum is needed only for the last 6 characters. `1…` and `3…` use base58 ranges like TRON.
- `src/engine_ed.cu`: Solana and TON: ChaCha20 → SHA-512 → multiplication by the base point: 12 additions with a table of 22-bit signed-digit windows, branch-free (the first is just a point load, one multiplication instead of seven; the last one does not compute T) → batch inversion of Z over 64 keys → range or base58 comparison. For TON the W5 wallet address is computed next: the hash of the data cell and the StateInit (3 SHA-256 calls), then comparison with 6-bit base64 masks. crc16 (the last 3 characters) is computed only when the pattern or `--beauty` touches them.
- `src/pattern.cpp`: pattern parsing, `-i`/`-l`/`[..]`, base58 ranges, the index for lists, difficulty estimation.
- `src/cpu_secp.cpp`: EVM/TRON/Bitcoin search on the CPU (`--cpu`): the secp256k1 field on 64-bit words, keccak for 8 keys, SHA-256/RIPEMD-160 for 16.
- `cuda/`: field arithmetic in PTX, hashes.

## Testing

```bash
./build/vanity-gpu selftest                              # vectors, -i/-l expansion, GPU hits, CPU
                                                         # and through the list index with re-checking; hit rate
                                                         # against theory (catches "misses")
tests/bench.sh build/vanity-gpu 8                        # speed of all modes
python3 -I tests/crosscheck.py build/vanity-gpu 100      # CPU reference against cryptography + hashlib (all chains,
                                                         # three Bitcoin types and WIF)
./build/vanity-gpu evm --bench 30                        # speed measurement
```

## TON

The address is a **W5 (wallet v5r1)** wallet, mainnet, workchain 0, subwallet 0. The pattern is compared with the non-bounceable `UQ…` form, which wallets show today. The bounceable `EQ…` form is also printed; it differs in the 1st character and the last 3.

- The first two characters are always `UQ`, and the third is only `A`, `B`, `C` or `D`. A pattern without a leading `UQ` is searched from the 4th character: `cool` → `UQ?cool…`.
- The alphabet is base64url: `A-Z a-z 0-9 - _`, case-sensitive.
- The address code was checked against a real W5 wallet on mainnet. Its public key was taken from the contract data, and the recomputed address matched the address on the blockchain. This wallet is checked in `selftest` and `tests/crosscheck.py`.
- Standard TON wallets are restored from 24 words (PBKDF2 with 100,000 iterations per candidate), so addresses from 24 words are not searched here. The key is imported as a private key. According to the MyTonWallet documentation, it supports this for W5. **Before sending funds, import the key and make sure the wallet shows the same address.**

## License

MIT, see [LICENSE](LICENSE).
