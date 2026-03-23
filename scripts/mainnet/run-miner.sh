#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$HOME/compute-substrate}"
BIN_PATH="${BIN_PATH:-$ROOT_DIR/target/release/csd}"
GENESIS_PATH="${GENESIS_PATH:-$ROOT_DIR/genesis.bin}"

DATADIR="${DATADIR:-$HOME/.csd/mainnet-miner}"
RPC_ADDR="${RPC_ADDR:-0.0.0.0:8790}"
P2P_LISTEN="${P2P_LISTEN:-/ip4/0.0.0.0/tcp/18000}"
BOOTNODES="${BOOTNODES:-}"
MINER_ADDR20="${MINER_ADDR20:-}"
RUST_LOG="${RUST_LOG:-info}"

mkdir -p "$DATADIR"

if [[ ! -x "$BIN_PATH" ]]; then
  echo "[run-miner] missing binary at $BIN_PATH" >&2
  exit 1
fi

if [[ ! -f "$GENESIS_PATH" ]]; then
  echo "[run-miner] missing genesis at $GENESIS_PATH" >&2
  exit 1
fi

if [[ -z "$MINER_ADDR20" ]]; then
  echo "[run-miner] MINER_ADDR20 is required" >&2
  exit 1
fi

CMD=(
  "$BIN_PATH" node
  --datadir "$DATADIR"
  --rpc "$RPC_ADDR"
  --genesis "$GENESIS_PATH"
  --p2p-listen "$P2P_LISTEN"
  --mine
  --miner-addr20 "$MINER_ADDR20"
)

if [[ -n "$BOOTNODES" ]]; then
  CMD+=(--bootnodes "$BOOTNODES")
fi

echo "[run-miner] ROOT_DIR=$ROOT_DIR"
echo "[run-miner] DATADIR=$DATADIR"
echo "[run-miner] RPC_ADDR=$RPC_ADDR"
echo "[run-miner] P2P_LISTEN=$P2P_LISTEN"
echo "[run-miner] MINER_ADDR20=$MINER_ADDR20"
if [[ -n "$BOOTNODES" ]]; then
  echo "[run-miner] BOOTNODES=$BOOTNODES"
fi

export RUST_LOG
exec "${CMD[@]}"
