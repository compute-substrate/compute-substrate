#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$HOME/compute-substrate}"
BIN_PATH="${BIN_PATH:-${ROOT_DIR}/target/release/csd}"
GENESIS_PATH="${GENESIS_PATH:-${ROOT_DIR}/genesis.bin}"

RUN_ROOT="${RUN_ROOT:-$HOME/csd-staging}"
SESSION_PREFIX="${SESSION_PREFIX:-csd-staging}"
RUST_LOG="${RUST_LOG:-info}"

A_RPC="${A_RPC:-127.0.0.1:8789}"
B_RPC="${B_RPC:-127.0.0.1:8790}"
C_RPC="${C_RPC:-127.0.0.1:8791}"

A_P2P_PORT="${A_P2P_PORT:-17999}"
B_P2P_PORT="${B_P2P_PORT:-18000}"
C_P2P_PORT="${C_P2P_PORT:-18001}"

A_P2P_LISTEN="/ip4/0.0.0.0/tcp/${A_P2P_PORT}"
B_P2P_LISTEN="/ip4/0.0.0.0/tcp/${B_P2P_PORT}"
C_P2P_LISTEN="/ip4/0.0.0.0/tcp/${C_P2P_PORT}"

# Optional override. If not set, script auto-discovers node-a PeerId from log.
BOOTNODE="${BOOTNODE:-}"

B_MINER_ADDR20="${B_MINER_ADDR20:-0xc2f200694c0798c50601342778a1d3d5ab8ab574}"

A_DATADIR="${A_DATADIR:-${RUN_ROOT}/boot}"
B_DATADIR="${B_DATADIR:-${RUN_ROOT}/miner1}"
C_DATADIR="${C_DATADIR:-${RUN_ROOT}/node3}"

A_LOG="${A_LOG:-${RUN_ROOT}/boot.log}"
B_LOG="${B_LOG:-${RUN_ROOT}/miner1.log}"
C_LOG="${C_LOG:-${RUN_ROOT}/node3.log}"

usage() {
  cat <<EOF
Usage:
  $(basename "$0") up
  $(basename "$0") down
  $(basename "$0") restart
  $(basename "$0") restart-c
  $(basename "$0") crash-c <failpoint>
  $(basename "$0") status
  $(basename "$0") clean
  $(basename "$0") logs a|b|c
  $(basename "$0") peerid
  $(basename "$0") health
  $(basename "$0") tips
  $(basename "$0") wait-sync [timeout_secs]
  $(basename "$0") check-converged

Env overrides:
  ROOT_DIR=$ROOT_DIR
  BIN_PATH=$BIN_PATH
  GENESIS_PATH=$GENESIS_PATH
  RUN_ROOT=$RUN_ROOT
  BOOTNODE=$BOOTNODE
  B_MINER_ADDR20=$B_MINER_ADDR20
EOF
}

require_tmux() {
  command -v tmux >/dev/null 2>&1 || {
    echo "[staging] tmux is required"
    exit 1
  }
}

require_jq() {
  command -v jq >/dev/null 2>&1 || {
    echo "[staging] jq is required"
    exit 1
  }
}

ensure_binary() {
  if [[ ! -x "$BIN_PATH" ]]; then
    echo "[staging] building release binary..."
    (cd "$ROOT_DIR" && cargo build --release)
  fi

  [[ -x "$BIN_PATH" ]] || {
    echo "[staging] missing binary at $BIN_PATH"
    exit 1
  }
}

ensure_genesis() {
  [[ -f "$GENESIS_PATH" ]] || {
    echo "[staging] missing genesis at $GENESIS_PATH"
    exit 1
  }
}

prepare_dirs() {
  mkdir -p "$RUN_ROOT" "$A_DATADIR" "$B_DATADIR" "$C_DATADIR"

  # Fresh logs every run to avoid confusion with stale output
  : > "$A_LOG"
  : > "$B_LOG"
  : > "$C_LOG"
}

session_name() {
  echo "${SESSION_PREFIX}-$1"
}

kill_session_if_exists() {
  local sess="$1"
  if tmux has-session -t "$sess" 2>/dev/null; then
    tmux kill-session -t "$sess"
  fi
}

current_a_peerid() {
  if [[ -f "$A_LOG" ]]; then
    grep -oE '\[p2p\] peer_id: [A-Za-z0-9]+' "$A_LOG" | tail -n 1 | awk '{print $3}'
  fi
}

wait_for_a_peerid() {
  local tries="${1:-30}"
  local sleep_s="${2:-1}"
  local i peer

  for ((i=1; i<=tries; i++)); do
    peer="$(current_a_peerid || true)"
    if [[ -n "${peer:-}" ]]; then
      echo "$peer"
      return 0
    fi
    sleep "$sleep_s"
  done

  return 1
}

current_b_peerid() {
  if [[ -f "$B_LOG" ]]; then
    grep -oE '\[p2p\] peer_id: [A-Za-z0-9]+' "$B_LOG" | tail -n 1 | awk '{print $3}'
  fi
}

wait_for_b_peerid() {
  local tries="${1:-30}"
  local sleep_s="${2:-1}"
  local i peer

  for ((i=1; i<=tries; i++)); do
    peer="$(current_b_peerid || true)"
    if [[ -n "${peer:-}" ]]; then
      echo "$peer"
      return 0
    fi
    sleep "$sleep_s"
  done

  return 1
}

make_bootnode_from_b() {
  local peer_id="$1"
  echo "/ip4/127.0.0.1/tcp/${B_P2P_PORT}/p2p/${peer_id}"
}

make_bootnode_from_a() {
  local peer_id="$1"
  echo "/ip4/127.0.0.1/tcp/${A_P2P_PORT}/p2p/${peer_id}"
}

rpc_url_for() {
  case "$1" in
    a) echo "http://${A_RPC}" ;;
    b) echo "http://${B_RPC}" ;;
    c) echo "http://${C_RPC}" ;;
    *)
      echo "[staging] unknown node '$1'" >&2
      return 1
      ;;
  esac
}

health_json() {
  local node="$1"
  curl -fsS "$(rpc_url_for "$node")/health"
}

tip_tuple() {
  local node="$1"
  local j
  j="$(health_json "$node")"
  local tip height chainwork peers
  tip="$(jq -r '.tip' <<<"$j")"
  height="$(jq -r '.height' <<<"$j")"
  chainwork="$(jq -r '.chainwork' <<<"$j")"
  peers="$(jq -r '.peer_count // 0' <<<"$j")"
  printf '%s %s %s %s\n' "$tip" "$height" "$chainwork" "$peers"
}

start_a() {
  local sess
  sess="$(session_name a)"
  kill_session_if_exists "$sess"

  tmux new-session -d -s "$sess" "bash -lc '
    set -euo pipefail
    export RUST_LOG=\"${RUST_LOG}\"
    exec \"${BIN_PATH}\" node \
      --datadir \"${A_DATADIR}\" \
      --rpc \"${A_RPC}\" \
      --genesis \"${GENESIS_PATH}\" \
      --p2p-listen \"${A_P2P_LISTEN}\" \
      2>&1 | tee -a \"${A_LOG}\"
  '"
}

start_b() {
  local bootnode="$1"
  local sess
  sess="$(session_name b)"
  kill_session_if_exists "$sess"

  tmux new-session -d -s "$sess" "bash -lc '
    set -euo pipefail
    export RUST_LOG=\"${RUST_LOG}\"
    exec \"${BIN_PATH}\" node \
      --datadir \"${B_DATADIR}\" \
      --rpc \"${B_RPC}\" \
      --mine \
      --miner-addr20 \"${B_MINER_ADDR20}\" \
      --genesis \"${GENESIS_PATH}\" \
      --p2p-listen \"${B_P2P_LISTEN}\" \
      --bootnodes \"${bootnode}\" \
      2>&1 | tee -a \"${B_LOG}\"
  '"
}

start_c() {
  local bootnodes="$1"
  local failpoint="${2:-}"
  local sess
  sess="$(session_name c)"
  kill_session_if_exists "$sess"

  if [[ -n "$failpoint" ]]; then
    tmux new-session -d -s "$sess" "bash -lc '
      set -euo pipefail
      exec env \
        RUST_LOG=\"${RUST_LOG}\" \
        CSD_CRASH_AT=\"${failpoint}\" \
        \"${BIN_PATH}\" node \
          --datadir \"${C_DATADIR}\" \
          --rpc \"${C_RPC}\" \
          --genesis \"${GENESIS_PATH}\" \
          --p2p-listen \"${C_P2P_LISTEN}\" \
          --bootnodes \"${bootnodes}\" \
          2>&1 | tee -a \"${C_LOG}\"
    '"
  else
    tmux new-session -d -s "$sess" "bash -lc '
      set -euo pipefail
      exec env \
        RUST_LOG=\"${RUST_LOG}\" \
        \"${BIN_PATH}\" node \
          --datadir \"${C_DATADIR}\" \
          --rpc \"${C_RPC}\" \
          --genesis \"${GENESIS_PATH}\" \
          --p2p-listen \"${C_P2P_LISTEN}\" \
          --bootnodes \"${bootnodes}\" \
          2>&1 | tee -a \"${C_LOG}\"
    '"
  fi
}

discover_a_bootnode() {
  local a_peerid
  if [[ -n "$BOOTNODE" ]]; then
    echo "$BOOTNODE"
    return 0
  fi

  a_peerid="$(wait_for_a_peerid 30 1)" || {
    echo "[staging] failed to discover node-a peer id from $A_LOG" >&2
    return 1
  }
  make_bootnode_from_a "$a_peerid"
}

discover_b_bootnode() {
  local b_peerid
  b_peerid="$(wait_for_b_peerid 30 1)" || {
    echo "[staging] failed to discover node-b peer id from $B_LOG" >&2
    return 1
  }
  make_bootnode_from_b "$b_peerid"
}

compose_c_bootnodes() {
  local a_bootnode b_bootnode
  a_bootnode="$(discover_a_bootnode)"
  b_bootnode="$(discover_b_bootnode)"
  echo "${a_bootnode},${b_bootnode}"
}

up() {
  require_tmux
  ensure_binary
  ensure_genesis
  prepare_dirs

  echo "[staging] starting node-a"
  start_a

  local a_peerid a_bootnode
  local b_peerid b_bootnode
  local c_bootnodes

  if [[ -n "$BOOTNODE" ]]; then
    a_bootnode="$BOOTNODE"
    echo "[staging] using BOOTNODE override:"
    echo "  $a_bootnode"
  else
    echo "[staging] waiting for node-a peer id..."
    a_peerid="$(wait_for_a_peerid 30 1)" || {
      echo "[staging] failed to discover node-a peer id from $A_LOG"
      echo "[staging] inspect with: $(basename "$0") logs a"
      exit 1
    }
    a_bootnode="$(make_bootnode_from_a "$a_peerid")"
    echo "[staging] discovered node-a peer id:"
    echo "  $a_peerid"
    echo "[staging] bootnode A:"
    echo "  $a_bootnode"
  fi

  echo "[staging] starting node-b"
  start_b "$a_bootnode"
  sleep 1

  echo "[staging] waiting for node-b peer id..."
  b_peerid="$(wait_for_b_peerid 30 1)" || {
    echo "[staging] failed to discover node-b peer id from $B_LOG"
    echo "[staging] inspect with: $(basename "$0") logs b"
    exit 1
  }
  b_bootnode="$(make_bootnode_from_b "$b_peerid")"
  echo "[staging] discovered node-b peer id:"
  echo "  $b_peerid"
  echo "[staging] bootnode B:"
  echo "  $b_bootnode"

  c_bootnodes="${a_bootnode},${b_bootnode}"

  echo "[staging] starting node-c"
  start_c "$c_bootnodes"
  sleep 1

  echo "[staging] launched"
  echo "  node-a rpc=$A_RPC p2p=$A_P2P_LISTEN"
  echo "  node-b rpc=$B_RPC p2p=$B_P2P_LISTEN"
  echo "  node-c rpc=$C_RPC p2p=$C_P2P_LISTEN"
  echo "  node-c bootnodes=$c_bootnodes"
}

down() {
  kill_session_if_exists "$(session_name a)"
  kill_session_if_exists "$(session_name b)"
  kill_session_if_exists "$(session_name c)"
  echo "[staging] stopped"
}

restart() {
  down
  sleep 1
  up
}

restart_c() {
  require_tmux
  ensure_binary
  ensure_genesis

  local c_bootnodes
  c_bootnodes="$(compose_c_bootnodes)"
  echo "[staging] restarting node-c with bootnodes:"
  echo "  $c_bootnodes"
  start_c "$c_bootnodes"
  sleep 1
}

crash_c() {
  require_tmux
  ensure_binary
  ensure_genesis

  local failpoint="${1:-}"
  if [[ -z "$failpoint" ]]; then
    echo "usage: $(basename "$0") crash-c <failpoint>"
    exit 1
  fi

  local c_bootnodes
  c_bootnodes="$(compose_c_bootnodes)"
  echo "[staging] starting node-c with failpoint:"
  echo "  $failpoint"
  echo "[staging] bootnodes:"
  echo "  $c_bootnodes"
  start_c "$c_bootnodes" "$failpoint"
  sleep 1
}

status() {
  local n sess
  for n in a b c; do
    sess="$(session_name "$n")"
    if tmux has-session -t "$sess" 2>/dev/null; then
      echo "node-$n: UP ($sess)"
    else
      echo "node-$n: DOWN"
    fi
  done
}

logs() {
  case "${1:-}" in
    a) tail -n 120 -f "$A_LOG" ;;
    b) tail -n 120 -f "$B_LOG" ;;
    c) tail -n 120 -f "$C_LOG" ;;
    *)
      echo "usage: $(basename "$0") logs a|b|c"
      exit 1
      ;;
  esac
}

clean() {
  down
  rm -rf "$RUN_ROOT"
  echo "[staging] cleaned $RUN_ROOT"
}

peerid() {
  local p
  p="$(current_a_peerid || true)"
  if [[ -n "${p:-}" ]]; then
    echo "$p"
  else
    echo "[staging] no node-a peer id found yet"
    exit 1
  fi
}

health() {
  require_jq
  for n in a b c; do
    echo "===== node-$n ====="
    if ! health_json "$n" | jq; then
      echo "[staging] node-$n health unavailable"
    fi
    echo
  done
}

tips() {
  require_jq
  for n in a b c; do
    if tuple="$(tip_tuple "$n" 2>/dev/null)"; then
      read -r tip height chainwork peers <<<"$tuple"
      echo "node-$n tip=$tip height=$height chainwork=$chainwork peers=$peers"
    else
      echo "node-$n unavailable"
    fi
  done
}

check_converged() {
  require_jq

  local ta tb tc
  ta="$(tip_tuple a 2>/dev/null || true)"
  tb="$(tip_tuple b 2>/dev/null || true)"
  tc="$(tip_tuple c 2>/dev/null || true)"

  if [[ -z "$ta" || -z "$tb" || -z "$tc" ]]; then
    echo "[staging] one or more nodes unavailable"
    return 1
  fi

  local tip_a h_a w_a p_a
  local tip_b h_b w_b p_b
  local tip_c h_c w_c p_c

  read -r tip_a h_a w_a p_a <<<"$ta"
  read -r tip_b h_b w_b p_b <<<"$tb"
  read -r tip_c h_c w_c p_c <<<"$tc"

  echo "node-a tip=$tip_a height=$h_a chainwork=$w_a peers=$p_a"
  echo "node-b tip=$tip_b height=$h_b chainwork=$w_b peers=$p_b"
  echo "node-c tip=$tip_c height=$h_c chainwork=$w_c peers=$p_c"

  if [[ "$tip_a" == "$tip_b" && "$tip_b" == "$tip_c" \
     && "$h_a" == "$h_b" && "$h_b" == "$h_c" \
     && "$w_a" == "$w_b" && "$w_b" == "$w_c" ]]; then
    echo "[staging] converged"
    return 0
  fi

  echo "[staging] NOT converged"
  return 1
}

wait_sync() {
  require_jq
  local timeout="${1:-120}"
  local start now elapsed

  start="$(date +%s)"

  while true; do
    if check_converged >/dev/null 2>&1; then
      echo "[staging] converged"
      check_converged
      return 0
    fi

    now="$(date +%s)"
    elapsed=$((now - start))
    if (( elapsed >= timeout )); then
      echo "[staging] wait-sync timed out after ${timeout}s"
      check_converged || true
      return 1
    fi

    sleep 2
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  restart) restart ;;
  restart-c) restart_c ;;
  crash-c) crash_c "${2:-}" ;;
  status) status ;;
  logs) logs "${2:-}" ;;
  clean) clean ;;
  peerid) peerid ;;
  health) health ;;
  tips) tips ;;
  wait-sync) wait_sync "${2:-120}" ;;
  check-converged) check_converged ;;
  *)
    usage
    exit 1
    ;;
esac
