// src/chain/failpoints.rs
//
// Test-only failpoints for crash-fuzzing reorg durability.
// In release/mainnet builds, failpoints are always inert.

#[cfg(test)]
#[inline]
pub fn hit(point: &str) {
    if let Ok(want) = std::env::var("CSD_CRASH_AT") {
        if want == point {
            eprintln!("[failpoint] aborting at {point}");
            std::process::abort();
        }
    }
}

#[cfg(not(test))]
#[inline]
pub fn hit(_point: &str) {
    // no-op in release/mainnet
}
