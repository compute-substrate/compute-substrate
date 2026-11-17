# The Compute Substrate app

A Compute Substrate node on your own computer, with no terminal. Download it, open it, and leave it
running. It keeps its own full copy of the network, checks every block itself before keeping it, and
passes blocks and transactions on to other nodes.

While it runs, apps on the same computer can use your node instead of someone else's, at
`http://127.0.0.1:8789`. For example, Commonplace reads through it when you open
`https://commonplace.place/?node=http://127.0.0.1:8789` (the app has a button for that).

## Download

From [Releases](https://github.com/compute-substrate/compute-substrate/releases), the newest
`app-v…`:

- **macOS** (Apple Silicon and Intel): `Compute-Substrate-macOS.dmg`. Open it and drag the app to
  Applications.
- **Windows**: `Compute-Substrate-Windows-setup.exe`.

### The first time you open it

The app isn't signed by Apple or Microsoft (that costs money each year and ties the app to a
person or company), so your computer asks once whether you trust it:

- **macOS:** open it; when macOS says it can't verify the app, click *Done*. Then open *System
  Settings*, *Privacy & Security*, scroll down to the message about Compute Substrate and click
  *Open Anyway*.
- **Windows:** if *Windows protected your PC* appears, click *More info*, then *Run anyway*.

After that it opens normally.

## What it does

- Starts the node when it opens, and stops it cleanly when you close it (it saves everything first,
  which can take a moment).
- Shows how far it has synced, and how many other nodes it's connected to.
- *Start when I log in* keeps your node running in the background after a restart.
- The node's data lives in the app's own folder (*Show* opens it):
  - macOS: `~/Library/Application Support/network.computesubstrate.node/node`
  - Windows: `%APPDATA%\network.computesubstrate.node\node`

  `node.log` there is the node's log. Deleting the folder starts over with a fresh sync.

It makes the genesis block itself (`csd genesis`, which always gives the same block), so there is
nothing to download besides the app.

To reach other nodes it connects out on port 17999. Other nodes can only connect to yours if your
router forwards that port to this computer; without that, your node still syncs, checks and relays
everything through the connections it makes itself.

## How it's built

The app is a small window ([Tauri](https://tauri.app)) around the same `csd` program an operator
builds from this repository. It starts that program with:

```
csd node --datadir <its folder>/db --rpc 127.0.0.1:8789 --genesis <its folder>/genesis.bin \
  --p2p-listen /ip4/0.0.0.0/tcp/17999 --bootnodes <bootnodes.txt> \
  --rpc-allow-any-origin --stop-on-stdin-close
```

- `--rpc-allow-any-origin` lets web pages use the node from your browser.
- `--stop-on-stdin-close` lets the app stop it cleanly on every OS.

Neither changes anything about consensus. The RPC is only reachable from this computer.

Releases are built by GitHub Actions from the tagged source ([`.github/workflows/app.yml`](../.github/workflows/app.yml)),
not on anyone's own machine:

- The run's log shows every step.
- The release lists the SHA-256 of each file, including the `csd` program inside each app.
- To check it, build `csd` yourself from the same tag (`cargo build --release --locked`) and compare.
  Builds on different machines can differ in small ways, so a match isn't guaranteed.

If you'd rather not trust a build at all, build from source as the main README describes. The app
adds nothing a node needs.

### Building the app yourself

```
cargo build --release --locked --bin csd
mkdir -p app/src-tauri/binaries
cp target/release/csd app/src-tauri/binaries/csd-$(rustc -vV | sed -n 's/host: //p')
cargo install tauri-cli --version "^2" --locked
cd app/src-tauri && cargo tauri build
```

On Windows, copy `csd.exe` to `csd-x86_64-pc-windows-msvc.exe` instead.

To release: push a tag named `app-v<version>` (for example `app-v0.1.0`), and the workflow attaches
the files to that release.
