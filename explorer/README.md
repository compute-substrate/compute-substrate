# Compute Substrate explorer

Blocks, transactions, proposals, attestations and topics, read straight from the network. A static
site with no server of its own: every page asks the network's doors directly (`node.js` picks the
most up to date one that answers, and falls back to the next), so there's nothing to keep running.

- Hosted anywhere static (Cloudflare Pages: upload this folder), or published with Doorway as a
  .csd name, where it reads this computer's own node.
- `?node=https://…` reads through that node only.
