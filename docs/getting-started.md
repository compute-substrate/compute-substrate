# Compute Substrate: Getting Started

This guide shows how to:

- install and run a node
- connect it to the network
- start a miner
- verify that it is syncing correctly

---

## 1. Install the binary

Build `csd` and place it somewhere stable, for example:

~~~bash
/usr/local/bin/csd
~~~

Verify it works:

~~~bash
csd node --help
~~~

Expected flags at the time of writing:

~~~text
--datadir
--rpc
--mine
--miner-addr20
--genesis
--p2p-listen
--bootnodes
~~~

---

## 2. Create the service user and directories

~~~bash
sudo useradd --system --home /var/lib/csd --create-home --shell /usr/sbin/nologin csd || true

sudo mkdir -p /etc/csd
sudo mkdir -p /var/lib/csd/node
sudo mkdir -p /var/lib/csd/miner

sudo chown -R csd:csd /var/lib/csd
sudo chmod 755 /var/lib/csd
~~~

---

## 3. Put the genesis file in place

Copy your mainnet genesis file to:

~~~bash
/etc/csd/genesis.bin
~~~

Verify it exists:

~~~bash
ls -l /etc/csd/genesis.bin
~~~

---

## 4. Install the operator scripts

Place these files in:

~~~bash
/opt/compute-substrate/scripts/mainnet/run-node.sh
/opt/compute-substrate/scripts/mainnet/run-miner.sh
~~~

Make them executable:

~~~bash
sudo chmod +x /opt/compute-substrate/scripts/mainnet/run-node.sh
sudo chmod +x /opt/compute-substrate/scripts/mainnet/run-miner.sh
~~~

These scripts should validate:

- binary exists
- genesis exists
- required env vars are present
- miner address is set for mining

---

## 5. Install the node service

Create:

~~~ini
/etc/systemd/system/csd.service
~~~

Example:

~~~ini
[Unit]
Description=Compute Substrate Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=csd
Group=csd
WorkingDirectory=/var/lib/csd
Environment=BIN=/usr/local/bin/csd
Environment=DATADIR=/var/lib/csd/node
Environment=RPC=0.0.0.0:8789
Environment=GENESIS=/etc/csd/genesis.bin
Environment=P2P_LISTEN=/ip4/0.0.0.0/tcp/17999
Environment=BOOTNODES=
ExecStart=/opt/compute-substrate/scripts/mainnet/run-node.sh
Restart=always
RestartSec=5
LimitNOFILE=65536

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/csd
ReadOnlyPaths=/etc/csd
MemoryDenyWriteExecute=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictRealtime=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
~~~

Reload systemd and start the node:

~~~bash
sudo systemctl daemon-reload
sudo systemctl enable csd
sudo systemctl start csd
~~~

Check logs:

~~~bash
journalctl -u csd -f
~~~

---

## 6. Get your Peer ID

Your node should log something like:

~~~text
[p2p] peer_id: 12D3KooW...
~~~

Your public bootnode address will look like:

~~~text
/ip4/YOUR_PUBLIC_IP/tcp/17999/p2p/YOUR_PEER_ID
~~~

This is what other nodes use in `BOOTNODES=`.

---

## 7. Join the network

Edit the service and set one or more bootnodes:

~~~ini
Environment=BOOTNODES=/ip4/1.2.3.4/tcp/17999/p2p/12D3KooW...
~~~

If using multiple bootnodes, separate with commas:

~~~ini
Environment=BOOTNODES=/ip4/1.2.3.4/tcp/17999/p2p/12D3KooW...,/ip4/5.6.7.8/tcp/17999/p2p/12D3KooW...
~~~

Then restart:

~~~bash
sudo systemctl daemon-reload
sudo systemctl restart csd
~~~

---

## 8. Verify node health

Check health endpoint:

~~~bash
curl http://127.0.0.1:8789/health | jq
~~~

You want to see:

- a valid tip
- nonzero height after sync progresses
- nonzero peer count

---

## 9. Install the miner service

Create:

~~~ini
/etc/systemd/system/csd-miner.service
~~~

Example:

~~~ini
[Unit]
Description=Compute Substrate Miner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=csd
Group=csd
WorkingDirectory=/var/lib/csd
Environment=BIN=/usr/local/bin/csd
Environment=DATADIR=/var/lib/csd/miner
Environment=RPC=0.0.0.0:8790
Environment=GENESIS=/etc/csd/genesis.bin
Environment=P2P_LISTEN=/ip4/0.0.0.0/tcp/18000
Environment=BOOTNODES=/ip4/1.2.3.4/tcp/17999/p2p/12D3KooW...
Environment=MINER_ADDR20=0xYOUR_MINER_ADDRESS
ExecStart=/opt/compute-substrate/scripts/mainnet/run-miner.sh
Restart=always
RestartSec=5
LimitNOFILE=65536

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/csd
ReadOnlyPaths=/etc/csd
MemoryDenyWriteExecute=true
LockPersonality=true
RestrictSUIDSGID=true
RestrictRealtime=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
~~~

Start it:

~~~bash
sudo systemctl daemon-reload
sudo systemctl enable csd-miner
sudo systemctl start csd-miner
~~~

Check logs:

~~~bash
journalctl -u csd-miner -f
~~~

---

## 10. Verify mining

Check miner RPC health:

~~~bash
curl http://127.0.0.1:8790/health | jq
~~~

You want to see:

- peer count > 0
- height increasing over time
- chainwork increasing over time

If height is not moving, verify:

- `MINER_ADDR20` is set correctly
- bootnodes are valid
- genesis matches the network
- firewall allows the configured P2P port

---

## 11. Useful commands

Node logs:

~~~bash
journalctl -u csd -f
~~~

Miner logs:

~~~bash
journalctl -u csd-miner -f
~~~

Node status:

~~~bash
systemctl status csd
~~~

Miner status:

~~~bash
systemctl status csd-miner
~~~

Node health:

~~~bash
curl http://127.0.0.1:8789/health | jq
~~~

Miner health:

~~~bash
curl http://127.0.0.1:8790/health | jq
~~~

Restart node:

~~~bash
sudo systemctl restart csd
~~~

Restart miner:

~~~bash
sudo systemctl restart csd-miner
~~~

---

## 12. Troubleshooting

### Node does not start

Check:

~~~bash
journalctl -u csd -n 100 --no-pager
~~~

Common causes:

- wrong `BIN` path
- missing genesis file
- invalid P2P listen multiaddr
- datadir permissions

### Miner does not start

Check:

~~~bash
journalctl -u csd-miner -n 100 --no-pager
~~~

Common causes:

- missing `MINER_ADDR20`
- wrong binary path
- missing genesis file
- invalid bootnode string

### Node has zero peers

Common causes:

- wrong bootnode peer ID
- wrong public IP in bootnode
- firewall closed on P2P port
- remote node offline
- wrong genesis

### Node does not sync

Common causes:

- network split
- bad bootnodes
- stale or isolated peers
- wrong genesis
- node connected only to weak or partial peers

---

## 13. Minimal mental model

- a node stores and syncs the chain
- a miner produces new blocks
- bootnodes help peers find the network
- chainwork decides fork choice
- no node has authority; only valid work accumulates

---

## 14. Recommended first operator flow

1. Install `csd`
2. Add `genesis.bin`
3. Install `run-node.sh`
4. Install `csd.service`
5. Start node
6. Confirm health and peer connectivity
7. Install `run-miner.sh`
8. Install `csd-miner.service`
9. Start miner
10. Watch height and chainwork increase
