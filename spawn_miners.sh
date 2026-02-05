#!/usr/bin/env bash
set -e

BOOTNODE="/ip4/77.42.82.161/tcp/17999/p2p/12D3KooWR7xJWh6mfVsm8FoxzXtCXe6HdmmzPL4fU72TFsvYSSfW"
GENESIS="genesis.bin"
BASE_P2P_PORT=18000

ADDRS=(
  0x47370e9135d31c7cb096c41250e60b14d3b287db
  0x1111111111111111111111111111111111111111
  0x2222222222222222222222222222222222222222
  0x3333333333333333333333333333333333333333
  0x4444444444444444444444444444444444444444
)

for i in "${!ADDRS[@]}"; do
  IDX=$((i+1))
  DATADIR="/var/lib/csd/miner${IDX}"
  P2P_PORT=$((BASE_P2P_PORT + i))

  echo "Starting miner${IDX} on p2p ${P2P_PORT}"

  mkdir -p "$DATADIR"

  nohup ./target/release/csd node \
    --datadir "$DATADIR" \
    --mine \
    --miner-addr20 "${ADDRS[$i]}" \
    --genesis "$GENESIS" \
    --p2p-listen "/ip4/0.0.0.0/tcp/${P2P_PORT}" \
    --bootnodes "$BOOTNODE" \
    > "miner${IDX}.log" 2>&1 &
done
