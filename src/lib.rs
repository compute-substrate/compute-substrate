// Release guard, twin of the guard in src/main.rs: the lib must not compile optimized with
// `test-bypass` (the PoW and genesis bypass of the integration tests) either, so
// `cargo build --release --features test-bypass` fails even for consumers that skip the bin.
// The debug test lane is unaffected.
#[cfg(all(feature = "test-bypass", not(debug_assertions)))]
compile_error!("test-bypass is a test-only feature: never build a release csd lib with it");

pub mod crypto;
pub mod params;
pub mod types;

pub mod api;
pub mod chain;
pub mod cli;
pub mod codec;
#[cfg(feature = "cuda")]
pub mod gpu;
pub mod net;
pub mod state;

pub mod testutil;
