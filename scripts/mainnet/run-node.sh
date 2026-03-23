#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-/usr/local/bin/csd}"
DATADIR="${DATADIR:-/var/lib/csd/node}"
RPC="${RPC:-0.0.0.0:8789}"
GENESIS="${GENESIS:-/etc/csd/genesis.bin}"
P2P_LISTEN="${P2P_LISTEN:-/ip4/0.0.0.0/tcp/17999}"
BOOTNODES="${BOOTNODES:-}"

mkdir -p "$DATADIR"

exec "$BIN" node \
  --datadir "$DATADIR" \
  --rpc "$RPC" \
  --genesis "$GENESIS" \
  --p2p-listen "$P2P_LISTEN" \
  --bootnodes "$BOOTNODES"
