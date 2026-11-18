# Compute Substrate Node

A Compute Substrate node on your own computer, with no terminal. Download it, open it, and leave it
running. It keeps its own full copy of the network, checks every block itself before keeping it, and
passes blocks and transactions on to other nodes.

While it runs, apps on the same computer can use your node instead of someone else's, at
`http://127.0.0.1:8789`. For example, Commonplace reads through it when you open
`https://commonplace.place/?node=http://127.0.0.1:8789` (the app has a button for that).

## Download

- **macOS** (Apple Silicon and Intel): [Compute-Substrate-Node-macOS.dmg](https://github.com/compute-substrate/compute-substrate/releases/download/app-v0.1.0/Compute-Substrate-Node-macOS.dmg).
  Open it and drag the app to Applications.
- **Windows**: [Compute-Substrate-Node-Windows-setup.exe](https://github.com/compute-substrate/compute-substrate/releases/download/app-v0.1.0/Compute-Substrate-Node-Windows-setup.exe).

These are version 0.1.0. Newer versions, with their checksums, are on
[Releases](https://github.com/compute-substrate/compute-substrate/releases) under tags named `app-v…`.

### The first time you open it

The app isn't signed by Apple or Microsoft (that costs money each year and ties the app to a
person or company), so your computer asks once whether you trust it:

- **macOS:** open it; when macOS says it can't verify the app, click *Done*. Then open *System
  Settings*, *Privacy & Security*, scroll down to the message about Compute Substrate Node and click
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

It carries Commonplace, and opens it from your own computer: *Commonplace* in the
window, at `http://localhost:8790`. Commonplace is one example of an app built on the network, with
no special place there; anyone can build others over the same records.

- **Which copy:** `app/commonplace.json` pins the release by its commit and IPFS address. The build
  makes it from that commit and refuses to continue unless it comes out with exactly that address,
  so what ships is the published release, byte for byte.
- **What it reads:** your own node.
- **Signing in:** with a wallet, you get the same writing key as on commonplace.place. A passkey is
  tied to the address a page is served from, so a passkey made on `localhost` is a different key from
  one made on commonplace.place.

It also opens `.csd` names, from Cairn's name service (CNS, by InverseAltruism), through your own
node. Type a name into *Go to a name* in the window (just `commonplace`, say), or click a `web+csd:<name>` link anywhere on the computer; the app
registers itself for those links.

- **Reading:** it asks Cairn's server for the transactions in the name's history. It reads each one
  from your own node, which has checked every block itself, and checks it against its id and
  signature.
- **Resolving:** it replays them through Cairn's own resolver (`@inversealtruism/cairnx-core`).
- **Opening:** it goes where the name points: the link in its profile's `url`, or else its holder's
  page on Commonplace, read through your node. When the profile points to a site (`contenthash`,
  `ipfs://…`), the app opens it from this computer:
  - It downloads the site from an IPFS gateway and checks every block against the address the name
    points to, so a gateway can refuse to send it but can't change it. It keeps the checked copy in
    `sites/` in its folder, so later visits don't download it again.
  - It serves each name at an address of its own on this computer (`http://localhost:8801`, the next
    name `8802`, and so on), and opens that in your normal browser. Each name keeps its address, its
    storage and its logins, even when it points to a newer site.
  - The site must be pinned somewhere on IPFS for a first visit; whoever runs it keeps it pinned.

Names are registered and managed on Cairn; the app only reads them.

It makes the genesis block itself (`csd genesis`, which always gives the same block), so there is
nothing to download besides the app.

It finds other nodes from the list it ships with (`app/bootnodes.txt`): a few long-running nodes,
and a snapshot of others that accepted connections when the release was made. After the first
start it keeps every peer it meets in its own `peers.txt`, so it doesn't depend on that list
again. If an old copy of the app ever can't find anyone, paste a node's address into *Add a
peer* (it looks like `/ip4/1.2.3.4/tcp/17999/p2p/12D3Koo…`); it's kept in `added-peers.txt` and dialed
at every start. Anyone who runs a node can give you theirs.

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
(cd app/resolver && npm ci && npm run build)
cargo build --release --locked --bin csd
mkdir -p app/src-tauri/binaries
cp target/release/csd app/src-tauri/binaries/csd-$(rustc -vV | sed -n 's/host: //p')
cargo install tauri-cli --version "^2" --locked
cd app/src-tauri && cargo tauri build
```

On Windows, copy `csd.exe` to `csd-x86_64-pc-windows-msvc.exe` instead.

To release: push a tag named `app-v<version>` (for example `app-v0.1.0`), and the workflow attaches
the files to that release. The download links above, and the ones on Commonplace, name the
version, so update them with each release.
