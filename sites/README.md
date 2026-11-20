# csd-sites

A door's site store. It keeps the sites that `.csd` names point to, and serves them, so a site stays
up when its author's own computer is off, or can't be reached from outside, as most home and mobile
connections can't.

- **What it keeps:** a site (an IPFS CID, as a `.car` file) only while some name's profile points to
  it (`contenthash`, `ipfs://<CID>`, in a CairnX `nprofile` record), read from this machine's own
  node, and for 30 days after it stops. Writing that record costs CSD, so nobody can fill a door with
  sites no name points to. Up to 64 MB a site, and `--max-gb` in all (20 GB by default).
- **From other doors:** every 10 minutes it copies any site a name points to that it doesn't have yet
  from the other doors announced on the network (`csd.doors`), or given with `--door`. `--url` is
  its own address, so it doesn't ask itself.
- **What it checks:** every block against its address, and that every block reachable from the root
  is there, before keeping anything. Readers check again themselves, so a door is trusted with
  nothing.
- **Where sites come from:** whoever has one gives it to the doors. The Compute Substrate Node app
  does this by itself for every site it opens, so a site its author opens once reaches every door
  the app knows.

```
GET  /sites/<cid>.car   the site (HEAD: whether this door has it)
POST /sites/<cid>.car   give this door a site
GET  /sites             what this door keeps
```

- **What it won't keep:** `--deny <file>`, a list of CIDs and `.csd` names, one per line. Read again
  every minute; listed sites are dropped at once and refused from then on. A door is a host, and
  its operator answers for what it serves.

Run it beside a node, behind the same web server as the node's public RPC. The
[door guide](../docs/public-node.md) has the steps.

```
cargo build --release --locked
./target/release/csd-sites --node http://127.0.0.1:8789 --dir /var/lib/csd/sites --listen 127.0.0.1:8795
```

Nothing here is consensus.
