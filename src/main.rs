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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::main::run().await
}
