// Release guard: the `test-bypass` cargo feature exists only so the integration tests (tests/)
// can build toy chains and exercise the p2p fault seams; it must not ship in a release binary.
// This fires on any optimized build with the feature (`cargo build --release --features
// test-bypass` fails), while the debug-profile test lane (`cargo test --features test-bypass`)
// keeps working. The lane therefore runs in debug: `cargo test --release --features
// test-bypass` trips this guard by design.
#[cfg(all(feature = "test-bypass", not(debug_assertions)))]
compile_error!("test-bypass is a test-only feature: never build a release csd binary with it");

mod api;
mod chain;
mod cli;
mod codec;
mod crypto;
#[cfg(feature = "cuda")]
mod gpu;
mod net;
mod params;
mod state;
// The unit tests of these modules are compiled into this crate too, and some use the shared helpers.
#[cfg(test)]
#[allow(dead_code)]
mod testutil;
mod types;

// Global allocator: jemalloc instead of system glibc malloc. glibc's per-thread arenas pin freed
// memory (RSS climbs under RPC churn); jemalloc returns it to the OS via dirty/muzzy decay + a
// background thread. sled is pure-Rust so it allocates through this global allocator too.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    state::subsystem::install_panic_counter();
    cli::main::run().await
}
