#!/usr/bin/env bash
# Rebuild publish-out/ for the openai/math anchors WITHOUT touching the chain.
#
# This script never loads a private key, so it cannot sign or spend anything.
# It only reads the chain: points every record at its earliest copy (reconcile),
# verifies all records, and writes the README and state files to upload.
#
#   RPC=http://<node>:8789 GITHUB_OWNER=<you> bash anchor/publish-openai-math.sh
set -euo pipefail
export RUST_BACKTRACE=0

: "${RPC:?set RPC, e.g. http://127.0.0.1:8789}"
: "${GITHUB_OWNER:?set GITHUB_OWNER}"

A=target/release/csd_anchor
M7=anchor/manifests/manifest-2026-10-07.json
M6=anchor/manifests/manifest-2026-10-06.json
S7=anchor-state.json
S6=state-10-06.json
OUT=publish-out

[ -x "$A" ] || { echo "build first: cargo build --release --bin csd_anchor"; exit 1; }
[ -f "$S7" ] && [ -f "$S6" ] || { echo "run this from the folder holding $S7 and $S6"; exit 1; }

say() { printf '\n== %s\n' "$*"; }

say "Pointing every record at its earliest copy (read-only on chain)"
$A reconcile --rpc "$RPC" --manifest "$M7" --state "$S7" --write
$A reconcile --rpc "$RPC" --manifest "$M6" --state "$S6" --write

say "Verifying"
V7=$($A verify --rpc "$RPC" --manifest "$M7" --state "$S7"); echo "$V7"
V6=$($A verify --rpc "$RPC" --manifest "$M6" --state "$S6"); echo "$V6"
echo "$V7" | grep -Eq '^on chain, match +758$' || { echo "expected 758 matching Oct 7 records"; exit 1; }
echo "$V6" | grep -Eq '^on chain, match +1$'   || { echo "expected the Oct 6 root on chain"; exit 1; }

ROOT7=$(echo "$V7" | awk '/^root proposal/{print $3}')
HEIGHTS=$(echo "$V7" | awk '/^block heights/{print $3}')
ROOT6=$(echo "$V6" | awk '/^root proposal/{print $3}')
DUPS=$(( $(echo "$V7" | awk '/^duplicates/{print $2}') + $(echo "$V6" | awk '/^duplicates/{print $2}') ))

say "Writing $OUT/"
mkdir -p "$OUT/openai-math"
if [ "$DUPS" -gt 0 ]; then
  DUP_ROW="| Duplicate records | $DUPS identical extra copies of some records were created by a resubmission bug in the anchoring tool. Each entry in \`anchor-state.json\` points to the earliest copy and lists the later ones under \`duplicates\`. |"
else
  DUP_ROW=""
fi
awk -v row="$DUP_ROW" '{ if ($0 == "DUP_ROW") { if (row != "") print row } else print }' \
    anchor/publish/README.template.md > "$OUT/README.tmp"
sed -e "s/GITHUB_OWNER/$GITHUB_OWNER/g" \
    -e "s/ROOT_TXID_1006/$ROOT6/g" \
    -e "s/ROOT_TXID/$ROOT7/g" \
    -e "s/HEIGHT_RANGE/$HEIGHTS/g" \
    "$OUT/README.tmp" > "$OUT/README.md"
rm -f "$OUT/README.tmp"
cp "$S7" "$OUT/openai-math/anchor-state.json"
cp "$S6" "$OUT/openai-math/anchor-state-2026-10-06.json"

cat <<EOF

Done. Nothing was signed or spent.
  Oct 7 root proposal  $ROOT7
  Oct 6 root proposal  $ROOT6
  block heights        $HEIGHTS
  duplicate records    $DUPS

Upload to github.com/$GITHUB_OWNER/compute-substrate-anchors:
  $OUT/README.md                                  -> repo root (replaces README.md)
  $OUT/openai-math/anchor-state.json              -> openai-math/
  $OUT/openai-math/anchor-state-2026-10-06.json   -> openai-math/
EOF
