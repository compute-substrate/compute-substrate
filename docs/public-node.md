# Running a door

A *door* is a server that lets anyone use Compute Substrate from a browser, and keeps the sites
`.csd` names point to, so they stay up with nobody's own server. Run one and you're part of what
keeps the network open. No door is special and none has to be trusted: everything a door serves is
checked by whoever receives it, against the network's proof-of-work, byte for byte.

## Run one

**1. Rent a server.** Debian or Ubuntu, x86-64 or ARM. The cheapest one most providers rent is
usually enough to start; the node's data grows with the network. No domain needed.

**2. Run this on it, as root:**

```bash
curl -fsSL https://github.com/compute-substrate/compute-substrate/releases/download/app-v0.2.11/door.sh | bash
```

It installs a node, the site store and Caddy, and serves them over HTTPS at an address made from the
server's IP (`https://1-2-3-4.sslip.io`), with a certificate Caddy gets by itself. Every program it
downloads is checked against the release's checksums. It ends by printing the door's address and a
key's address.

**3. Send that key 0.3 CSD.** As soon as the node has synced far enough to see it, the door announces
itself on the network: a record under `csd.doors` whose text is its address. That's all it takes to
be found. Doorway and every other door read those records, try each door,
and use the ones that answer. Nobody keeps a list, and nobody approves yours.

Within minutes of syncing, your door copies every site a name points to from the other doors, and
from then on serves them to anyone.

### Checking on it

```bash
curl -s https://<your door>/tip          # the node's height; it climbs while it syncs
curl -s https://<your door>/sites        # the sites it keeps
journalctl -u csd-door-announce -n 5     # whether it has announced itself
```

### What you answer for

A door is a host: what it serves, you serve. If there's a site you won't keep, put its CID or its
`.csd` name in `/etc/csd/deny.txt`, one per line. It's dropped within a minute and refused from then
on. Readers get it from other doors or not at all; nothing on the network changes.

### Options

Pass them after `bash -s --`, as in `... | bash -s -- --domain example.org`:

- `--domain example.org`: a domain of yours, already pointing to the server
- `--invite <link>`: pay for the announcement with an invite link, not by sending CSD
- `--node http://127.0.0.1:8789`: use a node already running on the server
- `--announce-only --domain example.org`: only announce a door you set up by hand

If the provider has a firewall in its web panel, open TCP ports 80, 443 and 17999 there.

### Updating and stopping

Running the command again updates the programs and keeps everything else. To stop being a door:
`systemctl disable --now csd-door-announce.timer csd-sites csd`. Its announcement stays on the
network, and apps simply find it no longer answers.

The rest of this page is the same thing by hand, piece by piece, for anyone who wants to know exactly
what runs.

## By hand

There are two ways to open one. Do either or both.

- **Over HTTPS**, behind a web server with a domain name. Works everywhere, including pages served
  over HTTPS.
- **Over WebRTC**, with the [csd-gateway](../gateway/README.md). No domain name, web server or
  certificate authority: just a machine with a public IP and one UDP port open.

Both start from a node that's synced and running, as in [getting started](getting-started.md).
Keep its RPC on the machine itself (`RPC=127.0.0.1:8789`), so the only way in from outside is the
door, which passes on public routes alone.

## Over HTTPS, with Caddy

[Caddy](https://caddyserver.com) gets and renews the certificate by itself. Point a domain name (an
A record) at the machine, open TCP ports 80 and 443, install Caddy, and put this in
`/etc/caddy/Caddyfile`, with your own name:

```caddy
csd.example.org {
	# Any site's pages may read this node and submit to it: everything here is public, and a
	# transaction is only accepted if its owner signed it
	header {
		Access-Control-Allow-Origin "*"
		Access-Control-Allow-Methods "GET, POST, OPTIONS"
		Access-Control-Allow-Headers "content-type"
		Access-Control-Max-Age "600"
	}

	# The public routes; operator routes (/node/info, /peers, /metrics, /mempool) stay closed
	@read {
		method GET
		path /health /tip /domains /oracle /headers/* /proof/tx/* /tx/* /block/* /utxos/* /address/* /recent/* /proposals/* /proposal/* /attestations/* /window/* /top/* /topk/* /events/*
		not path /tx/template/*
	}
	@submit {
		method POST
		path /tx/submit
	}

	handle @read {
		reverse_proxy 127.0.0.1:8789
	}
	handle @submit {
		request_body {
			max_size 1MB
		}
		reverse_proxy 127.0.0.1:8789
	}
	# the site store, if this door keeps sites (below)
	handle /sites* {
		request_body {
			max_size 70MB
		}
		reverse_proxy 127.0.0.1:8795
	}
	@preflight method OPTIONS
	handle @preflight {
		respond 204
	}
	handle {
		respond 404
	}
}
```

Then `sudo systemctl reload caddy`, and check it from somewhere else:

```bash
curl https://csd.example.org/tip
curl -i https://csd.example.org/peers     # 404: closed, as it should be
```

The door's address is `https://csd.example.org`.

A simpler way, for a machine that runs nothing else: start the node with `--rpc-allow-any-origin`
and its RPC on `0.0.0.0:8789`, and pages can reach it at `http://<ip>:8789`. That leaves the
operator routes open too (they reveal the node's peers and mempool, not keys), and pages served over
HTTPS can't use a plain `http://` address, so the Caddy way is the better one.

## Over WebRTC, with csd-gateway

Build and run the gateway beside the node, open UDP port 18001, and keep its data folder (its key
and certificate are part of the address). The [gateway's README](../gateway/README.md) has the
commands and a systemd unit. It prints the door's address:

```
[browser] reachable at /ip4/203.0.113.7/udp/18001/webrtc-direct/certhash/uEiB…/p2p/12D3KooW…
```

Take the line with the machine's public IP. The gateway serves the same public routes as the Caddy
setup above, and nothing else.

## Helping keep sites up

A door can also keep the sites `.csd` names point to, which most home computers can't: behind a home
or mobile connection, nobody outside can reach them. A door can always be reached, so a site it
keeps opens for anyone, even when its author's computer is off.

The site store, [`csd-sites`](../sites/README.md), runs beside the node:

- **What it keeps:** a site only while some name's profile points to it (its `contenthash`,
  `ipfs://<CID>`), read from this machine's own node, and for 30 days after. Writing that record
  costs CSD, so nobody can fill your disk with sites no name points to. Up to 64 MB a site, 20 GB in
  all unless you set `--max-gb`.
- **Or someone keeps it:** a site anyone has paid to keep, with a record under `csd.keep` naming it
  (`ipfs://<CID>`), until that time runs out: a year a record, and a year for every 0.25 CSD it
  burns. So a site can outlive its name. The records cost their writers CSD, so nobody can fill your
  disk for nothing; a door that's full takes nothing more.
- **Where sites come from:** whoever has one gives it to the doors. Doorway
  does it by itself for every site it opens, from behind any router, since it only connects out.
- **From other doors:** every 10 minutes it copies, from the other announced doors, any site a name
  points to that it doesn't have yet. A new door has every named site within minutes, and a site
  survives any one door going away.
- **What it checks:** every block against its address, before keeping anything. Readers check again
  themselves, so nobody has to trust your door.

```bash
cd /opt/compute-substrate/sites && cargo build --release --locked
sudo install target/release/csd-sites /usr/local/bin/csd-sites
sudo mkdir -p /var/lib/csd/sites && sudo chown csd: /var/lib/csd/sites
```

```ini
# /etc/systemd/system/csd-sites.service
[Unit]
Description=Compute Substrate site store
After=csd.service

[Service]
User=csd
ExecStart=/usr/local/bin/csd-sites --node http://127.0.0.1:8789 --dir /var/lib/csd/sites --listen 127.0.0.1:8795
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now csd-sites
```

`--node` is your node's RPC address.

**What you serve is yours to answer for.** A door is a host: whatever it keeps, it serves to anyone.
List anything you won't keep in a deny file, one CID or `.csd` name per line, and add
`--deny /etc/csd/deny.txt` to the command. It's read again every minute; a listed site is dropped at
once and refused from then on, and a listed name's sites go with it. Readers then fetch those sites
from other doors, or not at all; nothing on the network changes. The Caddyfile above already passes `/sites` to it: reload
Caddy, and check from somewhere else:

```bash
curl https://csd.example.org/sites
```

It lists what it keeps, and how far it has read the names (`names_read_to`, which reaches the tip
within a minute or so). To have Doorway use your door, announce it: see *In one command* above for what the
announcement is, or run `scripts/door.sh` with `--node` on a door you set up by hand.

## Letting people use it

Give the address out: in a post, in your app, to friends. If you hold a `.csd` name, put the address
in its profile under `csd.rpc`, and people can choose your door by your name. In Commonplace, anyone
can paste the address or the name as their node, and in the kit it's `connect({ node: "https://csd.example.org" })`. Pages check every
answer, so a door can be listed anywhere without vouching for whoever runs it.

What it costs: a small machine is enough (the node is the heavy part, the door adds almost nothing),
and bandwidth grows with the number of visitors. Turning it off is fine too: pages that used it move
on to another door, and nothing is lost, because every node keeps the same records.
