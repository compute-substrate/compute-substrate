# compute-substrate

Build an app on [Compute Substrate](https://computesubstrate.org) with no server, no database and no
account. Read any topic from any node, check every record against the network's proof-of-work
yourself, and write records signed by your own key or a wallet.

```
npm install compute-substrate
```

```js
import { connect, keySigner, newKey } from "compute-substrate";

const net = connect();                                   // a public node; or connect({ node: "http://127.0.0.1:8789" })
const entries = await net.read("guestbook.example");     // newest first, each one checked
const me = keySigner(net, newKey());                     // keep the key; send a little CSD to me.address
await net.write(me, "guestbook.example", "Hello from my own app");
```

Or skip npm entirely: [`template/`](template) is a whole app, a guestbook, in one static page. Copy
the folder, change the topic, host it anywhere.

## How it works, in five lines

- **The network keeps records.** A *proposal* is a short text (up to 512 bytes) under a topic, called
  its *domain*, signed by its author. An *attestation* is a signed number on a proposal: a like, a vote, a
  check. That's all the network stores, and it stores them for good.
- **Meaning is your app's.** The network guarantees who wrote what, and when. What a record means
  (a post, a move in a game, a claim) is up to the code that reads it. Write those rules down, so anyone can
  read the same records and get the same answer.
- **Writing costs a little CSD.** 0.25 CSD for a proposal, 0.05 CSD for an attestation. CSD isn't a
  currency: it measures the cost of recording. Reading is free.
- **Nothing has to be trusted.** `read` checks every record in the page itself: its bytes hash to its id,
  its author's signature holds, and it sits in a block with the network's proof-of-work above it. A node
  can refuse to answer, but it can't feed you a false record.
- **Bigger things live elsewhere.** Put files on IPFS or Arweave, and write their address with
  `payloadHash` set to their hash, so readers can check them too.

## The API

| | |
| --- | --- |
| `connect({ node?, fetch? })` | a network handle; `node` defaults to a public node |
| `net.read(domain, { limit?, check? })` | a topic's newest records, each with `id`, `text`, `height`, `time`, and (when checked, the default) `author`; records that don't prove are left out |
| `net.check(id)` | prove one record: `{ ok, author, height, depth }` or `{ ok: false, reason }` |
| `net.write(signer, domain, text, { payloadHash?, fee? })` | write a record; returns its id. It shows from the next block, about 2 minutes |
| `net.attest(signer, id, score, { confidence?, fee? })` | attest to a record with a number your app gives meaning to |
| `net.balance(address)` | CSD at an address |
| `newKey()` | a fresh private key (hex) |
| `keySigner(net, privateKey)` | sign with a key you hold |
| `cairnSigner()` | sign with [Cairn Wallet](https://cairn-substrate.com), approving each record in its window |

Underneath, everything is exported too: transactions, signing, the node's HTTP API (`net.api`), and the
light client (`lightClient`).

## Which node

Any node answers the same questions, and the kit checks what it says, so it doesn't matter much whose
it is. Three choices:

- **The public node** (`https://csd.aon.network`), the default.
- **Your own**, with the [Compute Substrate Node app](../app/README.md): `connect({ node: "http://127.0.0.1:8789" })`.
- **Anyone's**, if they run one with its RPC open to browsers (`csd node --rpc-allow-any-origin`).

## Shipping it

The app is static files: put them on any host, or on IPFS so no host is needed, and give it a `.csd`
name on Cairn that points to it. With the Compute Substrate Node app, typing the name opens it from the
visitor's own computer, checked byte for byte.

## Checks it relies on

The light client carries a list of block hashes (`src/anchors.json`, one every 1000 blocks, now up to
block 143,000), made from a full check of every header since the start of the network. Records newer
than the newest anchor are checked by verifying every header since it, up to 20,000 blocks past it
(about four weeks); further than that it refuses rather than download too much. So the list needs
refreshing now and then: newer versions of this package carry newer anchors, or pass your own with
`lightClient(node, { anchors })`, made from a fully synced node.

Lifted from [Commonplace](https://github.com/intervalplace/commonplace), one example of an app on the
network, which uses the same code. MIT licensed.
