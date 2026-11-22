# Doorway

Doorway opens sites named on Compute Substrate, from your own computer. Type a name, like
`commonplace`, or open `commonplace.localhost` in your browser: Doorway finds where the name points
through the network itself, fetches the site from any door, checks every byte, and your browser
shows it. No domain, no certificate authority, and no server anyone has to trust.

It also keeps the sites you open, lets you help keep them up for everyone, and publishes your own
site from a folder. To do all that it runs a node: its own full copy of the network, every block
checked here before it's kept.

## Download

- **macOS** (Apple Silicon and Intel): [Doorway-macOS.dmg](https://github.com/compute-substrate/compute-substrate/releases/download/app-v0.2.3/Doorway-macOS.dmg).
  Open it and drag Doorway to Applications.
- **Windows**: [Doorway-Windows-setup.exe](https://github.com/compute-substrate/compute-substrate/releases/download/app-v0.2.3/Doorway-Windows-setup.exe).

Newer versions, with their checksums, are on
[Releases](https://github.com/compute-substrate/compute-substrate/releases) under tags named `app-v…`.
Doorway used to be called Compute Substrate Node; it keeps the same data, so if you have that
installed, delete it after installing Doorway.

### The first time you open it

The app isn't signed by Apple or Microsoft (that costs money each year and ties the app to a
person or company), so your computer asks once whether you trust it:

- **macOS:** open it; when macOS says it can't verify the app, click *Done*. Then open *System
  Settings*, *Privacy & Security*, scroll down to the message about Doorway and click
  *Open Anyway*.
- **Windows:** if *Windows protected your PC* appears, click *More info*, then *Run anyway*.

After that it opens normally.

## What it does

Doorway stays out of the way. The first time it opens, it shows you a site working (Compute
Substrate's front page, which it carries, at `computesubstrate.localhost` in your browser) and starts at login from then on. After that it lives in the menu bar (the tray on
Windows): closing its window keeps it running, and its icon opens the window again or quits. It only
comes forward when a site asks to write with your key, in a small window on top: what the site
wants to write, what it costs, Allow or Decline. In Settings you can turn off starting at login, or
the menu bar icon (then closing the window quits, and opening Doorway again brings it back).


- Starts the node when it opens, and stops it cleanly when you quit (it saves everything first,
  which can take a moment).
- Each time it starts, the node rebuilds its copy of the network's state from the blocks it already
  has, so nothing half-written carries over; the window shows how far it's got. Then it catches up.
- Works within seconds of the first launch. Until its own node has caught up, it reads through the
  doors instead, and checks every answer the way the kit's light client does: each record's place
  in a block, and that block's place on the network's heaviest chain, by the anchors this release
  carries and the proof-of-work of every header since. Settings shows how far the node has got;
  once it's caught up, everything is read from it.
- Shows how far it has synced, and how many other nodes it's connected to.
- *Start when I log in* keeps your node running in the background after a restart.
- The node's data lives in the app's own folder (*Show* opens it):
  - macOS: `~/Library/Application Support/network.computesubstrate.node/node`
  - Windows: `%APPDATA%\network.computesubstrate.node\node`

  `node.log` there is the node's log. Deleting the folder starts over with a fresh sync.

It carries Commonplace, and opens it from your own computer: *Commonplace* in the
window, at `http://commonplace.localhost`. Commonplace is one example of an app built on the network, with
no special place there; anyone can build others over the same records.

- **Which copy:** `app/commonplace.json` pins the release by its commit and IPFS address. The build
  makes it from that commit and refuses to continue unless it comes out with exactly that address,
  so what ships is the published release, byte for byte.
- **What it reads:** your own node.
- **Signing in:** with a wallet, you get the same writing key as on commonplace.place. A passkey is
  tied to the address a page is served from, so a passkey made on `localhost` is a different key from
  one made on commonplace.place.

### Keeping a site up for years

Every site also has an address of its own that no change of name can take away:
`http://<its CID>.localhost` opens it in Doorway (paste the CID, or `ipfs://…`, into *Where to?*).

A site stays on the doors while a name points to it. The hourglass on a site keeps it up for longer,
a year at a time, whether or not a name still points to it: 0.25 CSD a year, from your key. Anyone can
add time to any site, so a site lasts as long as anyone thinks it should. A site that's kept shows
until when ("until 2051"), here and in the directory, and anyone can check that from the network.

### Your key

Doorway keeps one key for you, so you have one balance and one backup for every site you open
through it, not one per site. When a site wants to write (a post, a recommendation), Doorway's
window shows what it asks and what it costs, and signs only if you allow it. You can let a site
write without asking, up to 1 CSD a day, and stop that in Settings.

- Sites never see the key. They ask at their own address (`/.doorway/write` on `<name>.localhost`),
  and only a site's own page can ask in its name.
- Doorway signs records and attestations only: never a payment, and never more than 1 CSD at once.
- The first time, it takes one of the invites people leave for newcomers, so writing just works.
- *Settings* shows the key's address and balance, copies the key to back it up, and takes a key to
  use instead (the one before is kept in Doorway's folder as `wallet-….json`).
- Sites built with the kit use it by themselves (`writingKey()`); opened anywhere else, they keep a
  key in the browser as before.

It also opens `.csd` names, from Cairn's name service (CNS, by InverseAltruism), through your own
node. Type a name into *Go to a name* in the window (just `commonplace`, say), or click a `web+csd:<name>` link anywhere on the computer; the app
registers itself for those links.

- **Reading:** it asks Cairn's server for the transactions in the name's history. It reads each one
  from your own node, which has checked every block itself, and checks it against its id and
  signature.
- **Resolving:** it replays them through Cairn's own resolver (`@inversealtruism/cairnx-core`).
- **Opening:** it goes where the name points: the link in its profile's `url`, or else its holder's
  page on Commonplace, read through your node (or the doors, while it catches up). When the profile points to a site (`contenthash`,
  `ipfs://…`), the app opens it from this computer:
  - It downloads the site from an IPFS gateway and checks every block against the address the name
    points to, so a gateway can refuse to send it but can't change it. It keeps the checked copy in
    `sites/` in its folder, so later visits don't download it again.
  - It serves each name at its own address on this computer, **`http://<name>.localhost`**, and
    opens that in your normal browser. Browsers send every `.localhost` name to this computer by
    their own rule, with no DNS and no certificate, and treat it as secure, so wallets and passkeys
    work. Each name is an origin of its own, so sites can't read each other's storage. You can also
    type `<name>.localhost` straight into the browser (in Safari, with `http://` first): the app looks the name up and fetches it
    while the page waits. (Port 80 when the computer allows it; otherwise
    `http://<name>.localhost:8800`.)
  - It asks the doors first (below), and IPFS gateways too if no door has it.

Names are registered on Cairn. Doorway reads them, and points the ones its own key holds (below).

**Publishing a site.** *Publish a site* in the window: pick the site's folder (it needs an
`index.html`). The app packs it into one site with one address, the same one `npx ipfs-car pack`
gives, and keeps it. Then you type the name that should show it. If Doorway's key holds that name
(register it to that key's address on Cairn, or transfer it there), Doorway points it right away,
for 0.25 CSD. A name held in Cairn Wallet opens its page in Commonplace instead, with the new site
filled in, to approve there. As soon as the record is in a block, the app gives the site to the
doors, and it's live at `<name>.localhost` for anyone with the app, and on every door within
minutes.

Sites never get Cairn's records signed by Doorway's key, asked or not: a name it holds can only be
changed from Doorway's own window.

**Helping keep sites up.** Most home and mobile connections can't be reached from outside, so a
computer at home can't serve sites to others directly. *Doors* can: public nodes that also run a
site store ([`sites/`](../sites/README.md)), which keep the sites `.csd` names point to and serve them
to anyone.

- **Your sites:** each site you open is kept on this computer, listed in the window, and read from
  the doors first (IPFS gateways are a fallback). *Forget* removes it.
- **Help keep it up:** a switch on each site. On, the app gives that site to any door that doesn't
  have it yet, over connections it makes itself, so it works from behind any router. It's off for
  every site you open, since a name can point anywhere and passing a site on helps publish it, and
  on for the Commonplace the app carries.
- **Your own site:** *Settings, Put your site on the doors* gives the doors a `.car` you made
  (`npx ipfs-car pack <folder>`, say), once a name points to it.

Whoever downloads a site checks every block against the address its name points to, so a door is
trusted with nothing. A door keeps a site only while a name points to it, and its operator can
refuse any site.

The doors it uses: the ones in `app/doors.txt`, and every door that announced itself on the network
(a record under `csd.doors`), each tried before it's used. Anyone can run one: see the
[door guide](../docs/public-node.md).

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
