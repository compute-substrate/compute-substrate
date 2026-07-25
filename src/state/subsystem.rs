// src/state/subsystem.rs
//
// Liveness for the long-lived background tasks.
//
// The p2p loop, the txid reconciler and the miner are all `tokio::spawn`ed and their JoinHandles
// are dropped. Tokio delivers a task panic AS the task's return value, so dropping the handle
// discards the panic with it: the subsystem is gone, nothing is logged, the process is healthy
// and /health still answers 200. That is the same "RPC up, tip frozen" shape as the 2026-06-13
// memory wedge, reachable from a different cause, and for the miner it means silently earning
// nothing.
//
// This is deliberately not a supervisor: restarting a subsystem whose invariants just broke is
// how you turn one bug into a loop. It records what died and makes it visible on /node/info, so
// the watchdog can alert on a fact instead of on an inference.

use std::sync::atomic::{AtomicU8, Ordering};

const STARTING: u8 = 0;
const RUNNING: u8 = 1;
const EXITED: u8 = 2;
const PANICKED: u8 = 3;
const DISABLED: u8 = 4;

/// One entry per long-lived task. Static so a handler can read it without threading state.
pub struct Subsystems {
    pub p2p: AtomicU8,
    pub txidx: AtomicU8,
    pub miner: AtomicU8,
}

pub static SUBSYSTEMS: Subsystems = Subsystems {
    p2p: AtomicU8::new(STARTING),
    txidx: AtomicU8::new(STARTING),
    miner: AtomicU8::new(DISABLED), // only a --mine process ever starts it
};

fn label(v: u8) -> &'static str {
    match v {
        STARTING => "starting",
        RUNNING => "running",
        EXITED => "exited",
        PANICKED => "panicked",
        _ => "disabled",
    }
}

impl Subsystems {
    pub fn mark_running(slot: &AtomicU8) {
        slot.store(RUNNING, Ordering::Relaxed);
    }

    /// True when every started subsystem is still running.
    pub fn all_healthy(&self) -> bool {
        [&self.p2p, &self.txidx, &self.miner]
            .iter()
            .all(|s| matches!(s.load(Ordering::Relaxed), RUNNING | STARTING | DISABLED))
    }

    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "p2p": label(self.p2p.load(Ordering::Relaxed)),
            "tx_index_reconciler": label(self.txidx.load(Ordering::Relaxed)),
            "miner": label(self.miner.load(Ordering::Relaxed)),
            "all_healthy": self.all_healthy(),
        })
    }
}

/// Spawn a task that is expected to run for the life of the process, and make its death loud.
///
/// `name` appears in the log line and `slot` is the entry reported on /node/info. A normal return
/// is recorded too, not just a panic: these tasks are infinite loops, so returning at all is a
/// defect worth seeing.
pub fn spawn_supervised<F>(name: &'static str, slot: &'static AtomicU8, fut: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    Subsystems::mark_running(slot);
    tokio::spawn(async move {
        let outcome = tokio::spawn(fut).await;
        match outcome {
            Ok(()) => {
                slot.store(EXITED, Ordering::Relaxed);
                eprintln!(
                    "[subsystem] {name} EXITED. It is not restarted on purpose: restarting a task whose \
                     invariants just broke turns one defect into a loop. See /node/info subsystems."
                );
            }
            Err(e) if e.is_panic() => {
                slot.store(PANICKED, Ordering::Relaxed);
                eprintln!(
                    "[subsystem] {name} PANICKED and is gone. The process is still up and the RPC will \
                     keep answering, which is exactly why this line exists. See /node/info subsystems."
                );
            }
            Err(_) => {
                slot.store(EXITED, Ordering::Relaxed);
                eprintln!("[subsystem] {name} was cancelled (runtime shutting down)");
            }
        }
    });
}
