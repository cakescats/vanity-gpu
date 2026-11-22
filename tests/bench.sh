#!/bin/bash
# Speed of every search path. usage: tests/bench.sh [build/vanity-gpu] [seconds]
BIN=${1:-build/vanity-gpu}; SEC=${2:-8}
run() { printf '%-30s' "$1"; shift; "$BIN" "$@" --bench "$SEC" -n 0 -o "" 2>&1 | tr '\r' '\n' | grep 'key/s' | tail -1 | sed -E 's/.*\] ([0-9.]+ [KMG]?key\/s).*/\1/'; }
run "evm prefix"              evm ffffffffffffffff
run "evm prefix + cpu max"    evm ffffffffffffffff --cpu max
run "evm beauty"              evm --beauty --min-score 30
run "evm only digits"         evm --only digits --min-score 40
run "evm only upper (EIP-55)" evm --only upper --min-score 30
run "tron prefix"             tron TTTTTTTTTTTTTT
run "tron prefix + cpu max"   tron TTTTTTTTTTTTTT --cpu max
run "tron suffix"             tron ..zzzzzzzzzzzz
run "tron beauty"             tron --beauty --min-score 30
run "btc bc1q prefix"         btc bc1qzzzzzzzzzzzzzz
run "btc bc1q prefix + cpu max" btc bc1qzzzzzzzzzzzzzz --cpu max
run "btc bc1q suffix"         btc ..zzzzzzzzzzzz
run "btc legacy prefix"       btc 1zzzzzzzzzzzzz
run "btc legacy suffix"       btc-legacy ..zzzzzzzzzzzz
run "btc p2sh prefix"         btc 3Mzzzzzzzzzzzz
run "sol prefix"              sol zzzzzzzzzzzz
run "sol suffix"              sol ..zzzzzzzzzzzz
run "ton prefix"              ton UQAzzzzzzzzzzzz
run "ton suffix"              ton ..zzzzzzzzzzzz
run "multi evm,tron"           multi evm,tron
run "multi evm,tron,btc"       multi evm,tron,btc
run "multi evm,tron,btc beauty" multi evm,tron,btc --beauty --rarity 60
run "multi secp all 5 beauty"  multi evm,tron,btc-all --beauty --rarity 60
run "multi sol,ton beauty"     multi sol,ton --beauty --rarity 60
