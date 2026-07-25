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
mod types;

// Global allocator: jemalloc instead of system glibc malloc. glibc's per-thread arenas pin freed
// memory (RSS climbs under RPC churn); jemalloc returns it to the OS via dirty/muzzy decay + a
// background thread. sled is pure-Rust so it allocates through this global allocator too.
#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::main::run().await
}
