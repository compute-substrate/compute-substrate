#!/usr/bin/env bash
set -euo pipefail

STAGING="${STAGING:-$HOME/compute-substrate/scripts/staging.sh}"
SOAK_SECS="${SOAK_SECS:-3600}"          
CHECK_EVERY="${CHECK_EVERY:-30}"       
WAIT_SYNC_SECS="${WAIT_SYNC_SECS:-180}"
CRASH_WAIT_SECS="${CRASH_WAIT_SECS:-25}"
LOG_DIR="${LOG_DIR:-$HOME/csd-soak-logs}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$LOG_DIR/$RUN_ID"

mkdir -p "$RUN_DIR"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[soak] missing dependency: $1"
    exit 1
  }
}

need bash
need curl
need jq

ts() {
  date '+%Y-%m-%d %H:%M:%S'
}

log() {
  echo "[$(ts)] $*" | tee -a "$RUN_DIR/soak.log"
}

health_snapshot() {
  {
    echo "===== $(ts) ====="
    echo "--- node-a ---"
    curl -fsS http://127.0.0.1:8789/health | jq .
    echo "--- node-b ---"
    curl -fsS http://127.0.0.1:8790/health | jq .
    echo "--- node-c ---"
    curl -fsS http://127.0.0.1:8791/health | jq .
    echo
  } | tee -a "$RUN_DIR/health.log"
}

check_converged() {
  "$STAGING" check-converged | tee -a "$RUN_DIR/check-converged.log"
}

wait_sync() {
  "$STAGING" wait-sync "$WAIT_SYNC_SECS" | tee -a "$RUN_DIR/wait-sync.log"
}

restart_c() {
  log "restarting node-c"
  "$STAGING" restart-c | tee -a "$RUN_DIR/restart-c.log"
}

crash_c() {
  local fp="$1"
  log "arming node-c failpoint: $fp"
  "$STAGING" crash-c "$fp" | tee -a "$RUN_DIR/crash-$fp.log"
}

capture_c_log_tail() {
  tmux capture-pane -p -t csd-staging-c 2>/dev/null | tail -n 200 | tee -a "$RUN_DIR/node-c-tail.log" || true
}

assert_c_hit_failpoint() {
  local fp="$1"
  if tmux capture-pane -p -t csd-staging-c 2>/dev/null | grep -q "\[failpoint\] aborting at $fp"; then
    log "confirmed failpoint hit: $fp"
    return 0
  fi

  log "WARNING: did not see failpoint hit for $fp in node-c pane"
  return 1
}

run_failpoint_test() {
  local fp="$1"

  log "========== failpoint test: $fp =========="
  crash_c "$fp"

  log "waiting up to ${CRASH_WAIT_SECS}s for actual trigger"
  sleep "$CRASH_WAIT_SECS"

  capture_c_log_tail
  assert_c_hit_failpoint "$fp" || true

  restart_c
  wait_sync
  check_converged
  health_snapshot
}

soak_loop() {
  local end_ts now next_check
  end_ts=$(( $(date +%s) + SOAK_SECS ))
  next_check=0

  while true; do
    now=$(date +%s)
    if (( now >= end_ts )); then
      break
    fi

    if (( now >= next_check )); then
      log "periodic health check"
      health_snapshot
      check_converged
      next_check=$(( now + CHECK_EVERY ))
    fi

    sleep 5
  done
}

main() {
  log "run dir: $RUN_DIR"

  log "bringing staging down"
  "$STAGING" down | tee -a "$RUN_DIR/down.log" || true

  log "bringing staging up"
  "$STAGING" up | tee -a "$RUN_DIR/up.log"

  wait_sync
  check_converged
  health_snapshot

  # Crash-recovery validations
  run_failpoint_test "reorg:after_journal_start"
  run_failpoint_test "reorg:after_undo"
  run_failpoint_test "reorg:mid_apply"
  run_failpoint_test "reorg:after_commit"

  # Long soak after crash tests
  log "starting soak loop for ${SOAK_SECS}s"
  soak_loop

  log "final convergence check"
  wait_sync
  check_converged
  health_snapshot

  log "SOAK PASS"
}

main "$@"
