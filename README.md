# compute-substrate

Compute Substrate (CSD) — a SHA-256d proof-of-work blockchain. This repository
holds the node (`csd`) and the core protocol.

## Mining

CSD can be mined through the community **CSD pool** with the open-source
**csd-pool-miner**, a standalone GPU/CPU miner that connects to the pool by
default — there is no node or pool flag to configure.

- **Miner + one-click installer:** https://github.com/dangraagu/CSD-Mining-pool-public
- **Backends:** auto-detects your GPU (NVIDIA via CUDA, AMD / other via OpenCL)
  and falls back to CPU. Speaks Stratum v1 to the pool.
- **Payout address:** your **addr20** — 40 lowercase hex characters (the same
  address you'd receive coinbase rewards on when solo mining).
- **Payouts:** PPLNS, settled hourly at the top of each hour (`:00`).
- **Community & support:** Discord — https://discord.gg/Gr9gCjzC9e

**Quick start (Windows, one click):** download `install-csd-miner.bat` from the
miner repo and double-click it — it fetches the right prebuilt binary, asks for
your addr20 once, and starts mining.

Run the binary directly:

```
csd-pool-miner --address <YOUR_ADDR20>
```
