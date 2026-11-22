#!/bin/bash
# Build word lists for `vanity-gpu -f` from the dictionaries installed on this machine.
#
#   tools/wordlist.sh [options] > words.txt
#     -d DICT    aspell dictionary (default en; `aspell dicts` lists them), may repeat
#     -f FILE    also read words from FILE (one per line, e.g. your own list)
#     -m N       minimum length (default 6)    -M N   maximum length (default 20)
#     -t CHAIN   keep only words that fit CHAIN as written (evm, btc, base58, ton);
#                leave it out when you use -l / -i, vanity-gpu skips what cannot fit
#
# Nothing is downloaded. Bigger English lists (for example the 370k-word "words_alpha.txt"
# from github.com/dwyl/english-words or the BIP-39 word list) can be passed with -f.
set -euo pipefail
dicts=(); files=(); min=6; max=20; chain=""
while getopts "d:f:m:M:t:h" o; do
  case $o in
    d) dicts+=("$OPTARG") ;;
    f) files+=("$OPTARG") ;;
    m) min=$OPTARG ;;
    M) max=$OPTARG ;;
    t) chain=$OPTARG ;;
    *) sed -n '2,13p' "$0"; exit 2 ;;
  esac
done
[ ${#dicts[@]} -eq 0 ] && [ ${#files[@]} -eq 0 ] && dicts=(en)
case $chain in
  "") keep='.' ;;
  evm) keep='^[0-9a-f]+$' ;;
  btc) keep='^[02-9ac-hj-np-z]+$' ;;
  base58|tron|sol) keep='^[1-9A-HJ-NP-Za-km-z]+$' ;;
  ton) keep='^[A-Za-z0-9_-]+$' ;;
  *) echo "unknown chain $chain" >&2; exit 2 ;;
esac
{
  for d in "${dicts[@]}"; do aspell -d "$d" dump master | aspell -l "$d" expand 2>/dev/null || aspell -d "$d" dump master; done
  for f in "${files[@]}"; do cat "$f"; done
} | tr -s ' ' '\n' | grep -E '^[A-Za-z0-9]+$' | tr 'A-Z' 'a-z' | awk -v a="$min" -v b="$max" 'length >= a && length <= b' \
  | grep -E "$keep" | sort -u
