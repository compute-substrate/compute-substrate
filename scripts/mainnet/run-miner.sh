#!/usr/bin/env bash
set -euo pipefail

echo "[csd-miner] starting..."

# ----------------- config -----------------

BIN="${BIN:-/usr/local/bin/csd}"
DATADIR="${DATADIR:-/var/lib/csd/miner}"
RPC="${RPC:-0.0.0.0:8789}"
GENESIS="${GENESIS:-/etc/csd/genesis.bin}"
P2P_LISTEN="${P2P_LISTEN:-/ip4/0.0.0.0/tcp/17999}"
BOOTNODES="${BOOTNODES:-}"
MINER_ADDR20="${MINER_ADDR20:-}"

# ----------------- required checks -----------------

if [[ -z "$MINER_ADDR20" ]]; then
  echo "[csd-miner] ERROR: MINER_ADDR20 is required"
  exit 1
fi

if [[ ! "$MINER_ADDR20" =~ ^0x[a-fA-F0-9]{40}$ ]]; then
  echo "[csd-miner] ERROR: MINER_ADDR20 must be 20-byte hex (0x...)"
  exit 1
fi

if [[ ! -x "$BIN" ]]; then
  echo "[csd-miner] ERROR: binary not found or not executable: $BIN"
  exit 1
fi

if [[ ! -f "$GENESIS" ]]; then
  echo "[csd-miner] ERROR: genesis file missing: $GENESIS"
  exit 1
fi

# ----------------- sanity checks -----------------

echo "[csd-miner] config:"
echo "  bin:        $BIN"
echo "  datadir:    $DATADIR"
echo "  rpc:        $RPC"
echo "  p2p:        $P2P_LISTEN"
echo "  bootnodes:  ${BOOTNODES:-<none>}"
echo "  miner:      $MINER_ADDR20"
echo "  genesis:    $GENESIS"

GENESIS_HASH=$(sha256sum "$GENESIS" | awk '{print $1}')
echo "[csd-miner] genesis sha256: $GENESIS_HASH"

mkdir -p "$DATADIR"

# ----------------- port check -----------------

RPC_PORT="${RPC##*:}"
if ss -ltn | grep -q ":$RPC_PORT "; then
  echo "[csd-miner] ERROR: RPC port already in use: $RPC_PORT"
  exit 1
fi

# ----------------- bootnodes normalize -----------------

BOOT_ARGS=()
if [[ -n "$BOOTNODES" ]]; then
  BOOT_ARGS=(--bootnodes "$BOOTNODES")
fi

echo "[csd-miner] launching..."

exec "$BIN" node \
  --datadir "$DATADIR" \
  --rpc "$RPC" \
  --mine \
  --miner-addr20 "$MINER_ADDR20" \
  --genesis "$GENESIS" \
  --p2p-listen "$P2P_LISTEN" \
  "${BOOT_ARGS[@]}"
