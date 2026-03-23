#!/usr/bin/env bash
set -euo pipefail

echo "[csd-node] starting..."

# ----------------- config -----------------

BIN="${BIN:-/usr/local/bin/csd}"
DATADIR="${DATADIR:-/var/lib/csd/node}"
RPC="${RPC:-0.0.0.0:8789}"
GENESIS="${GENESIS:-/etc/csd/genesis.bin}"
P2P_LISTEN="${P2P_LISTEN:-/ip4/0.0.0.0/tcp/17999}"
BOOTNODES="${BOOTNODES:-}"

# ----------------- required checks -----------------

if [[ ! -x "$BIN" ]]; then
  echo "[csd-node] ERROR: binary not found or not executable: $BIN"
  exit 1
fi

if [[ ! -f "$GENESIS" ]]; then
  echo "[csd-node] ERROR: genesis file missing: $GENESIS"
  exit 1
fi

# ----------------- sanity -----------------

echo "[csd-node] config:"
echo "  bin:        $BIN"
echo "  datadir:    $DATADIR"
echo "  rpc:        $RPC"
echo "  p2p:        $P2P_LISTEN"
echo "  bootnodes:  ${BOOTNODES:-<none>}"
echo "  genesis:    $GENESIS"

GENESIS_HASH=$(sha256sum "$GENESIS" | awk '{print $1}')
echo "[csd-node] genesis sha256: $GENESIS_HASH"

mkdir -p "$DATADIR"

# ----------------- port check -----------------

RPC_PORT="${RPC##*:}"
if ss -ltn | grep -q ":$RPC_PORT "; then
  echo "[csd-node] ERROR: RPC port already in use: $RPC_PORT"
  exit 1
fi

# ----------------- bootnodes normalize -----------------

BOOT_ARGS=()
if [[ -n "$BOOTNODES" ]]; then
  BOOT_ARGS=(--bootnodes "$BOOTNODES")
fi

echo "[csd-node] launching..."

exec "$BIN" node \
  --datadir "$DATADIR" \
  --rpc "$RPC" \
  --genesis "$GENESIS" \
  --p2p-listen "$P2P_LISTEN" \
  "${BOOT_ARGS[@]}"
