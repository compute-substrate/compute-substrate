// Build on Compute Substrate: read a topic from any node, check every record yourself, and write
// records signed by your own key or a wallet. No server, no account, nobody's permission.
//
//   import { connect, keySigner, newKey } from "compute-substrate";
//   const net = connect();                                 // a public node, or connect({ node: "http://127.0.0.1:8789" })
//   const entries = await net.read("guestbook.example");   // newest first, each checked against the proof-of-work
//   const me = keySigner(net, newKey());                   // send a little CSD to me.address first
//   await net.write(me, "guestbook.example", "Hello from my own app");
//
// What a record means is up to your app: the network only guarantees who wrote what, and when.

import { MIN_FEE_ATTEST, MIN_FEE_PROPOSE, EPOCH_LEN, MAX_URI_BYTES, MAX_DOMAIN_BYTES, buildAppTx, buildSplitTx, bytesToHex, hexToBytes, keyFromPrivate, node, sha256d, utf8,
  type AppPayload, type Hex } from "./core";
import { lightClient, type Anchors } from "./light";
import { cairnConnect, cairnSubmit, discoverCairn, type CairnProvider } from "./cairn";

export * from "./core";
export { lightClient, GENESIS_HASH, type Verified } from "./light";
export { friendlyName } from "./friendly";
export { keepRecord, keptSites, keepCost, heightToDate, KEEP_TOPIC, BURN, YEAR_BLOCKS, PER_YEAR, MAX_YEARS } from "./keep";
import { keepRecord, keptSites, BURN } from "./keep";
export { discoverCairn, type CairnProvider } from "./cairn";
export { browserKey, writingKey, doorwayKey, claimInvite, inviteKeyFrom, makeInvites, openInvites, welcome, INVITES_MAX, WELCOME_TOPIC, type BrowserKey } from "./browser";

export const PUBLIC_NODE = "https://csd.aon.network";
// how long a record stays open for attestations: far beyond any reader's lifetime
export const KEEP_EPOCHS = 10_000_000n;

export type Entry = {
  id: Hex;            // the proposal's id (its transaction id)
  domain: string;     // the topic it was written under
  text: string;       // its uri: up to 512 bytes, as the app wrote it
  height: number;     // the block it's in
  time: number;       // the block's time, in seconds
  // written from this browser a moment ago and not in a block yet (about two minutes): show it,
  // marked as on its way; `height` is then the block it's expected in, `time` when it was sent
  pending?: boolean;
};

// Records this browser wrote that aren't in a block yet, per topic, so `read` can show them at once.
// Kept in the browser's storage (when there is one) so a reload doesn't lose them; dropped once
// they're in a block, or after a day.
const PENDING_FOR = 86_400_000;
const pendingStore = {
  key: (d: string) => `csd.pending.${d}`,
  get(d: string): (Entry & { author: Hex; at: number })[] {
    try { return JSON.parse((globalThis as any).localStorage?.getItem(this.key(d)) ?? "[]").filter((x: any) => Date.now() - x.at < PENDING_FOR); } catch { return []; }
  },
  set(d: string, xs: (Entry & { author: Hex; at: number })[]) {
    try { xs.length ? (globalThis as any).localStorage?.setItem(this.key(d), JSON.stringify(xs)) : (globalThis as any).localStorage?.removeItem(this.key(d)); } catch {}
  },
};
const memPending = new Map<string, (Entry & { author: Hex; at: number })[]>();
export type Checked = { ok: true; author: Hex; height: number; depth: number } | { ok: false; reason: string };

// Something that can sign and send a record: your own key, or a wallet
// `burn`: CSD also sent to the all-zero address, which nobody can spend (keeping a site, keep.ts)
export type Signer = { address: Hex; send: (app: AppPayload, fee: bigint, o?: { burn?: bigint }) => Promise<Hex> };

export function connect(opts: { node?: string; fetch?: typeof fetch; anchors?: Anchors } = {}) {
  const base = (opts.node ?? PUBLIC_NODE).replace(/\/$/, "");
  const api = node(base, opts.fetch);
  const light = lightClient(base, { fetch: opts.fetch, anchors: opts.anchors });

  // Prove a record from the node's answer alone: it's exactly these bytes, its author signed it,
  // and it sits in a block with the network's proof-of-work above it
  const check = async (id: Hex): Promise<Checked> => {
    try {
      const v = await light.checkTx(id);
      return v.author ? { ok: true, author: v.author, height: v.height, depth: v.depth } : { ok: false, reason: "no valid signature on it" };
    } catch (e: any) { return { ok: false, reason: String(e?.message ?? e) }; }
  };

  return {
    node: base,
    api,
    tip: () => api.tip(),
    check,
    // A topic's newest records (at most `limit`, newest first), as the node lists them. With
    // { check: true } each is proven too, and those that don't prove are left out.
    // Records this browser just wrote come first, with `pending: true`, until they're in a block.
    async read(domain: string, o: { limit?: number; check?: boolean } = {}): Promise<(Entry & { author?: Hex })[]> {
      const rows = (await api.proposalsIn(domain, o.limit ?? 200)).map(p => ({ id: p.proposal_id.toLowerCase() as Hex, domain: p.domain ?? domain, text: p.uri ?? "", height: Number(p.height), time: Number(p.time) }))
        .sort((a, b) => b.height - a.height);
      const out: (Entry & { author?: Hex })[] = [];
      if (o.check === false) out.push(...rows);
      else for (let i = 0; i < rows.length; i += 6) {
        const got = await Promise.all(rows.slice(i, i + 6).map(async r => ({ r, c: await check(r.id) })));
        for (const { r, c } of got) if (c.ok) out.push({ ...r, author: c.author });
      }
      const landed = new Set(rows.map(r => r.id));
      const waiting = [...(memPending.get(domain) ?? pendingStore.get(domain))].filter(p => !landed.has(p.id) && Date.now() - p.at < PENDING_FOR);
      memPending.set(domain, waiting); pendingStore.set(domain, waiting);
      return [...waiting.map(({ at: _, ...p }) => p), ...out];
    },
    // Write a record under `domain`. `text` is what readers get (up to 512 bytes); put anything
    // larger elsewhere (IPFS, Arweave) and write its address, with its hash as `payloadHash`.
    async write(signer: Signer, domain: string, text: string, o: { payloadHash?: Hex; fee?: bigint } = {}): Promise<Hex> {
      if (!domain || utf8(domain).length > MAX_DOMAIN_BYTES) throw new Error(`A domain is 1 to ${MAX_DOMAIN_BYTES} bytes.`);
      if (!text || utf8(text).length > MAX_URI_BYTES) throw new Error(`A record's text is 1 to ${MAX_URI_BYTES} bytes.`);
      const t = await api.tip();
      const payloadHash = o.payloadHash ? hexToBytes(o.payloadHash) : sha256d(utf8(text));
      const id = (await signer.send({ kind: "propose", domain, payloadHash, uri: text, expiresEpoch: BigInt(Math.floor(t.height / EPOCH_LEN)) + KEEP_EPOCHS }, o.fee ?? MIN_FEE_PROPOSE)).toLowerCase() as Hex;
      // shown by `read` at once, as on its way, until it's in a block
      const p = { id, domain, text, height: t.height + 1, time: Math.floor(Date.now() / 1000), pending: true, author: signer.address.toLowerCase() as Hex, at: Date.now() };
      const waiting = [p, ...(memPending.get(domain) ?? pendingStore.get(domain))];
      memPending.set(domain, waiting); pendingStore.set(domain, waiting);
      return id;
    },
    // Attest to a record: a signed number on it. What the number means is up to your app (a like,
    // a vote, a check that holds or fails).
    // Keep a site up for `years` (see keep.ts): anyone can, for any site, name or not
    async keep(signer: Signer, cid: string, years = 1): Promise<Hex> {
      const r = keepRecord(cid, years, (await api.tip()).height);
      return signer.send(r.app, r.fee, { burn: r.burn });
    },
    // Every site someone keeps, and until which block
    kept: () => keptSites(api as any),
    attest(signer: Signer, id: Hex, score: number, o: { confidence?: number; fee?: bigint } = {}): Promise<Hex> {
      return signer.send({ kind: "attest", proposalId: id, score, confidence: o.confidence ?? 1 }, o.fee ?? MIN_FEE_ATTEST);
    },
    // CSD at an address, in whole CSD
    async balance(address: Hex): Promise<number> {
      return Number((await api.utxos(address)).reduce((s, u) => s + u.value, 0n)) / 1e8;
    },
  };
}
export type Network = ReturnType<typeof connect>;

// A fresh private key, as hex. Keep it: whoever has it can write as you and spend its CSD.
export function newKey(): Hex {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}

// Sign with a private key you hold (hex). Coins come from the key's own address.
export function keySigner(net: Network, privateKey: Hex): Signer {
  const key = keyFromPrivate(hexToBytes(privateKey));
  return {
    address: key.addr20,
    async send(app, fee, o = {}) {
      const utxos = await net.api.utxos(key.addr20);
      const burn = o.burn ?? 0n;
      if (utxos.reduce((s, u) => s + u.value, 0n) < fee + burn) throw new Error(`Not enough CSD at ${key.addr20}: writing this costs ${Number(fee + burn) / 1e8} CSD.`);
      return (await net.api.submit(burn ? buildSplitTx(utxos, key, [{ to: BURN, value: burn }], fee, app) : buildAppTx(utxos, key, app, fee))).toLowerCase() as Hex;
    },
  };
}

// Sign with Cairn Wallet (a browser extension that keeps the key itself): each record is approved
// in its own window. Resolves once the wallet is found and the person has connected it.
export async function cairnSigner(timeoutMs = 4000): Promise<Signer> {
  const provider = await new Promise<CairnProvider>((resolve, reject) => {
    // the wallet can answer at once, before discoverCairn has returned, so stopping waits for it
    let found: CairnProvider | null = null, stop: (() => void) | null = null;
    const t = setTimeout(() => { stop?.(); reject(new Error("Cairn Wallet isn't installed in this browser.")); }, timeoutMs);
    stop = discoverCairn(p => { if (found) return; found = p; clearTimeout(t); stop?.(); resolve(p); });
    if (found) stop();
  });
  const address = await cairnConnect(provider);
  return { address, send: (app, fee, o) => { if (o?.burn) throw new Error("Cairn Wallet keeps a site a year at a time."); return cairnSubmit(provider, app, fee); } };
}
