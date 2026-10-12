#!/usr/bin/env bash
# Anchor both openai/math releases on Compute Substrate, end to end.
#
# Run from the compute-substrate repo root, after `cargo build --release --bin csd_anchor`:
#
#   RPC=http://127.0.0.1:8789 \
#   KEY=key.hex \
#   GITHUB_OWNER=<your-github-name> \
#   URI_1007='https://raw.githubusercontent.com/.../manifest-2026-10-07.json' \
#   URI_1006='https://raw.githubusercontent.com/.../manifest-2026-10-06.json' \
#   bash anchor/run-openai-math.sh
#
# Produces publish-out/README.md and publish-out/openai-math/anchor-state.json:
# upload those two files to the compute-substrate-anchors repo and you are done.
# Safe to re-run at any point: finished work is skipped, nothing is paid twice.
set -euo pipefail
export RUST_BACKTRACE=0

: "${RPC:?set RPC, e.g. http://127.0.0.1:8789}"
: "${KEY:?set KEY to the private key file}"
: "${GITHUB_OWNER:?set GITHUB_OWNER}"
: "${URI_1007:?set URI_1007 to the published manifest-2026-10-07.json address}"
: "${URI_1006:?set URI_1006 to the published manifest-2026-10-06.json address}"

A=target/release/csd_anchor
M7=anchor/manifests/manifest-2026-10-07.json
M6=anchor/manifests/manifest-2026-10-06.json
S7=anchor-state.json
S6=state-10-06.json
OUT=publish-out
POLL=30

[ -x "$A" ] || { echo "build first: cargo build --release --bin csd_anchor"; exit 1; }
[ -f "$KEY" ] || { echo "key file not found: $KEY"; exit 1; }

say() { printf '\n== %s\n' "$*"; }

# --- 0. the published manifests must be byte-identical to the local ones --------
say "Checking the published manifests"
check_published() {
  local uri=$1 local_file=$2 tmp
  tmp=$(mktemp)
  curl -fsSL "$uri" -o "$tmp" || { echo "cannot download $uri"; exit 1; }
  if ! cmp -s "$tmp" "$local_file"; then
    echo "MISMATCH: $uri is not byte-identical to $local_file"
    echo "Re-upload the file unchanged and use its commit-pinned raw address."
    exit 1
  fi
  echo "ok  $uri"
  rm -f "$tmp"
}
check_published "$URI_1007" "$M7"
check_published "$URI_1006" "$M6"

# --- 1. show the cost and ask once ---------------------------------------------
say "Plan"
$A plan --manifest "$M7"
echo "+ Oct 6 release, root record only: 1 proposal (0.25 CSD)"
echo "Signing address: $(CSD_PRIVKEY=$(cat "$KEY") $A fanout --rpc "$RPC" --manifest "$M7" --state "$S7" 2>/dev/null | awk '/^address/{print $2}')"
read -r -p "Spend about 190 CSD in fees to anchor both releases? Type yes: " ok
[ "$ok" = "yes" ] || { echo "stopped, nothing sent"; exit 0; }

# --- 2. prepare coins and submit, in rounds until every record is in -----------
# A fan-out can only spend confirmed coins, and its change is unconfirmed until the
# next block, so a wallet holding few large coins needs several rounds. Each round
# prepares what it can, submits what is ready, then waits for the next block.
anchor_release() {
  local manifest=$1 state=$2 uri=$3 mode=$4 log rc
  while true; do
    if log=$($A fanout --rpc "$RPC" --privkey-file "$KEY" --manifest "$manifest" --state "$state" \
                --mode "$mode" --send 2>&1); then
      echo "$log" | grep -E "fan-out submitted|partial fan-out" | sed 's/^/  /' || true
    elif echo "$log" | grep -q "not enough confirmed funds"; then
      echo "  waiting for confirmed funds: $(echo "$log" | grep -o 'need .* spendable')"
    else
      echo "$log"; exit 1
    fi

    set +e
    log=$($A submit --rpc "$RPC" --privkey-file "$KEY" --manifest "$manifest" --state "$state" \
               --manifest-uri "$uri" --mode "$mode" --send 2>&1)
    rc=$?
    set -e
    case $rc in
      0) echo "  $(echo "$log" | grep -E '^submitted')"; return 0 ;;
      3) echo "  $(echo "$log" | grep -E '^submitted' | cut -d';' -f1); next round after the next block..."
         sleep "$POLL" ;;
      *) echo "$log"; exit 1 ;;
    esac
  done
}

say "Oct 7 release: preparing coins and submitting 758 records"
anchor_release "$M7" "$S7" "$URI_1007" all
say "Oct 6 release: root record"
anchor_release "$M6" "$S6" "$URI_1006" root

# --- 4. wait for everything to be mined and verified -----------------------------
verify_until_done() {
  local manifest=$1 state=$2 log
  while true; do
    log=$($A verify --rpc "$RPC" --manifest "$manifest" --state "$state" 2>&1) || { echo "$log"; exit 1; }
    if echo "$log" | grep -Eq '^not yet mined +0$'; then
      echo "$log"
      return 0
    fi
    echo "  $(echo "$log" | grep "^on chain") / $(echo "$log" | grep "^not yet mined") - waiting..." >&2
    sleep "$POLL"
  done
}
say "Waiting for the Oct 7 records to be mined"
V7=$(verify_until_done "$M7" "$S7"); echo "$V7"
say "Waiting for the Oct 6 root to be mined"
V6=$(verify_until_done "$M6" "$S6"); echo "$V6"

echo "$V7" | grep -Eq '^on chain, match +758$' || { echo "expected 758 matching records"; exit 1; }

# --- 4b. if any record was proposed more than once, point to the earliest copy --
say "Checking for duplicate records"
$A reconcile --rpc "$RPC" --manifest "$M7" --state "$S7" --write | grep -E "duplicates|now point|root proposal|not found"
$A reconcile --rpc "$RPC" --manifest "$M6" --state "$S6" --write | grep -E "duplicates|now point|root proposal|not found"
V7=$($A verify --rpc "$RPC" --manifest "$M7" --state "$S7")
V6=$($A verify --rpc "$RPC" --manifest "$M6" --state "$S6")
echo "$V7" | grep -Eq '^on chain, match +758$' || { echo "expected 758 matching records after reconcile"; echo "$V7"; exit 1; }
DUPS=$(( $(echo "$V7" | awk '/^duplicates/{print $2}') + $(echo "$V6" | awk '/^duplicates/{print $2}') ))

ROOT7=$(echo "$V7" | awk '/^root proposal/{print $3}')
HEIGHTS=$(echo "$V7" | awk '/^block heights/{print $3}')
ROOT6=$(echo "$V6" | awk '/^root proposal/{print $3}')

# --- 5. write the finished README ------------------------------------------------
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

Done.
  Oct 7 root proposal  $ROOT7
  Oct 6 root proposal  $ROOT6
  block heights        $HEIGHTS

Upload to github.com/$GITHUB_OWNER/compute-substrate-anchors:
  $OUT/README.md                                  -> repo root (replaces README.md)
  $OUT/openai-math/anchor-state.json              -> openai-math/
  $OUT/openai-math/anchor-state-2026-10-06.json   -> openai-math/
EOF
