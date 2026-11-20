# Running a public door

A *door* is a node that web pages can reach from anyone's browser. Apps on Compute Substrate read
and write through some node, and a visitor with no node of their own needs one that's open to them.

Anyone can run one. No door is special, and none has to be trusted: pages check what a door tells
them against the network's proof-of-work, so a door can refuse to answer, but it can't feed anyone a
false record. The more doors there are, run by more people, the less any app depends on one of them.

A door serves only what every node already makes public: blocks, records, balances, proofs, and
`POST /tx/submit` for transactions their owners signed. It never holds anyone's key.

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

	request_body {
		max_size 1MB
	}
	handle @read {
		reverse_proxy 127.0.0.1:8789
	}
	handle @submit {
		reverse_proxy 127.0.0.1:8789
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

## Letting people use it

Give the address out: in a post, in your app, to friends. In Commonplace, anyone can paste it as
their node, and in the kit it's `connect({ node: "https://csd.example.org" })`. Pages check every
answer, so a door can be listed anywhere without vouching for whoever runs it.

What it costs: a small machine is enough (the node is the heavy part, the door adds almost nothing),
and bandwidth grows with the number of visitors. Turning it off is fine too: pages that used it move
on to another door, and nothing is lost, because every node keeps the same records.
