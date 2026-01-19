mod params;
mod types;
mod crypto;
mod state;
mod chain;
mod net;
mod api;
mod cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::main::run().await
}
