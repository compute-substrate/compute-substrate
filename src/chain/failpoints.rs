// src/chain/failpoints.rs
//
// Test-only failpoints for crash-fuzzing reorg durability.
// Enabled ONLY when compiled with `--features test-bypass`.

#[inline]
pub fn hit(point: &str) {
    #[cfg(feature = "test-bypass")]
    {
        if let Ok(want) = std::env::var("CSD_CRASH_AT") {
            if want == point {
                eprintln!("[failpoint] aborting at {point}");
                std::process::abort();
            }
        }
    }

    let _ = point;
}
