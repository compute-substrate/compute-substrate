# csd-gateway

Lets browsers reach a Compute Substrate node directly, over WebRTC, with no web server, domain name
or certificate authority in between.

A web page connects to it by an address like this one, which names the machine and the hash of the
gateway's certificate:

```
/ip4/203.0.113.7/udp/18001/webrtc-direct/certhash/uEiBrXC2…/p2p/12D3KooW…
```

Then it asks what it would otherwise ask the node's HTTP RPC. Each request is one stream on
`/csd/rpc/1`: `{"method","path","body"}` out, `{"status","body"}` back, with the same JSON the RPC
gives. The gateway passes the request to the node's RPC on the same machine.

Pages check what they're told against the proof-of-work (`/headers` and `/proof/tx`). So a node
reached this way needn't be trusted any more than one reached over HTTPS, and anyone's gateway can
be listed.

## What it serves

- **Served:** the public read routes, and `POST /tx/submit`. This is what a public node already
  serves to anyone over HTTP.
- **Not served:** operator routes such as `/node/info`, `/peers`, `/metrics` and `/mempool`.

It is a program of its own, beside the node:

- The node is unchanged, and the WebRTC stack never enters its build.
- Browser connections never touch the node's peer-to-peer network.

Nothing here is consensus.

## Running it

Run it next to a node whose RPC is reachable on this machine:

```
cd gateway
cargo build --release --locked
./target/release/csd-gateway --rpc http://127.0.0.1:8789 \
  --listen /ip4/0.0.0.0/udp/18001/webrtc-direct --datadir /var/lib/csd-gateway
```

- **Firewall:** open UDP port 18001.
- **Address:** it prints the address browsers use:

  ```
  [browser] reachable at /ip4/<ip>/udp/18001/webrtc-direct/certhash/…/p2p/…
  ```

  Take the line with the machine's public IP. That is the address to publish.
- **Keep the data folder.** It holds the gateway's key and certificate, and both are part of the
  address, so deleting them changes it.

Limits:

- at most 512 browsers connected at once;
- 64 requests answered at once (more get a `503` to retry);
- answers up to 8 MiB.

A systemd unit, as for the node:

```ini
[Unit]
Description=Compute Substrate browser gateway
After=csd.service

[Service]
User=csd
ExecStart=/opt/compute-substrate/gateway/target/release/csd-gateway --rpc http://127.0.0.1:8789 --listen /ip4/0.0.0.0/udp/18001/webrtc-direct --datadir /var/lib/csd/gateway
Restart=always

[Install]
WantedBy=multi-user.target
```
