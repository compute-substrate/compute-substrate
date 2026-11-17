# Names

Short, human names that nobody issues, kept on the network. This is a convention for apps to read
and write, like any other use of proposals. It needs no consensus change and no special node
support. Commonplace implements it (`src/names.ts`); any app can.

## Records

A name's records are proposals in the topic (domain) `name.<name>`, with this uri:

```
name:v1:<value>
```

A name is 1 to 40 characters: lowercase `a`–`z`, `0`–`9` and `-`, not starting or ending with `-`.
The payload hash is `sha256d` of the uri. A record that doesn't match this format is ignored.

Values:

| value                      | means                                                    |
|----------------------------|----------------------------------------------------------|
| `key:<addr20>`             | a person or agent: the key's page                        |
| `ipfs:<cid>`               | a site, as published on IPFS                             |
| `node:<url or multiaddr>`  | a node to read the network through, HTTPS or WebRTC peer |
| `url:<https://…>`          | anything else on the web                                 |
| `transfer:<addr20>`        | hands the name to another key                            |
| `release`                  | gives the name up                                        |

A record's author is the signer of its transaction's first input, the same key a node reports as
the proposal's proposer.

## Who holds a name

Take every record of the name, ordered by block height, then by txid within a block. The holder is
decided by walking through them in that order:

- **Claiming:** when nobody holds the name, the record claims it for its author. A `transfer` or
  `release` record can't claim.
- **Updating:** while someone holds it, only the holder's records count. A value repoints the name,
  `transfer:<addr20>` makes that key the holder, and `release` frees it. Anyone else's records are
  ignored.
- **Lasting:** a record holds the name until the end of epoch `min(expires_epoch, epoch + 8766)`,
  about a year (8766 epochs of 30 blocks), where `epoch` is the epoch of its block. Each record the
  holder writes can only extend this, never shorten it. A holder renews by writing again, with the
  same value or a new one.
- **Lapsing:** once a record's block falls in an epoch past that end, the name has lapsed. That
  record, or the next one after it, claims it afresh.

At the current epoch, a name whose end has passed is free.

## Checking

An app should prove each record against the proof-of-work before relying on it: its transaction,
signer, value, expiry and block (`/proof/tx` and `/headers`). Commonplace does this in
`src/light.ts`.

A node can still leave records out, for example to hide the earliest claim. Asking more than one
node for the same name, and taking every record any of them can prove, catches that.

A node lists at most 500 records per topic (`/proposals/:domain/500`). For a name with that many,
earlier records may be missing, and an app should say so.

## Opening names

`web+csd:<name>` is the link format. In a browser, a page that resolves names registers itself as
the handler with `navigator.registerProtocolHandler("web+csd", "<page>?csd=%s")`. Commonplace
does this from its Names page.

## Known limits

- **Squatting:** claims are first come, first served, at the price of any proposal (0.25 CSD).
  Renewing every year makes holding names in bulk an ongoing cost, but not a prohibitive one.
- **Hiding records:** see Checking.
