#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$HOME/compute-substrate}"
BIN_PATH="${BIN_PATH:-$ROOT_DIR/target/release/csd}"
GENESIS_PATH="${GENESIS_PATH:-$ROOT_DIR/genesis.bin}"

DATADIR="${DATADIR:-$HOME/.csd/mainnet-node}"
RPC_ADDR="${RPC_ADDR:-0.0.0.0:8789}"
P2P_LISTEN="${P2P_LISTEN:-/ip4/0.0.0.0/tcp/17999}"
BOOTNODES="${BOOTNODES:-}"
RUST_LOG="${RUST_LOG:-info}"

mkdir -p "$DATADIR"

if [[ ! -x "$BIN_PATH" ]]; then
  echo "[run-node] missing binary at $BIN_PATH" >&2
  exit 1
fi

if [[ ! -f "$GENESIS_PATH" ]]; then
  echo "[run-node] missing genesis at $GENESIS_PATH" >&2
  exit 1
fi

CMD=(
  "$BIN_PATH" node
  --datadir "$DATADIR"
  --rpc "$RPC_ADDR"
  --genesis "$GENESIS_PATH"
  --p2p-listen "$P2P_LISTEN"
)

if [[ -n "$BOOTNODES" ]]; then
  CMD+=(--bootnodes "$BOOTNODES")
fi

echo "[run-node] ROOT_DIR=$ROOT_DIR"
echo "[run-node] DATADIR=$DATADIR"
echo "[run-node] RPC_ADDR=$RPC_ADDR"
echo "[run-node] P2P_LISTEN=$P2P_LISTEN"
if [[ -n "$BOOTNODES" ]]; then
  echo "[run-node] BOOTNODES=$BOOTNODES"
fi

export RUST_LOG
exec "${CMD[@]}"
