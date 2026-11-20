// Compute Substrate (CSD), for browsers and Node: keys, transactions with an app payload, signing, and
// the node's HTTP API. Everything follows the consensus code in compute-substrate:
//   addresses     addr20 = ripemd160(sha256(compressed secp256k1 pubkey))       src/crypto/mod.rs
//   encoding      bincode, fixed-int, little endian                              src/codec/mod.rs
//   transaction   version u32, inputs, outputs, locktime u32, app AppPayload     src/types/mod.rs
//   txid          sha256d(tx with every script_sig emptied)                      src/crypto/mod.rs
//   sighash       sha256d(tagged("CSD_SIG_V1", stripped tx || CHAIN_ID_HASH))    src/crypto/mod.rs
//   script_sig    [64][sig64 compact low-S][33][pub33], 99 bytes                 src/state/utxo.rs
// (Lifted from Commonplace, whose tests check the encoding byte for byte against the node.)

import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { ripemd160 } from "@noble/hashes/legacy";

export type Hex = `0x${string}`;
export type Bytes = Uint8Array;

export const COIN = 100_000_000n;
export const MIN_FEE_PROPOSE = 25_000_000n; // params/mod.rs
export const MIN_FEE_ATTEST = 5_000_000n;
export const EPOCH_LEN = 30;
export const MAX_URI_BYTES = 512;
export const MAX_DOMAIN_BYTES = 128;

// sha256("compute-substrate-mainnet"), params/mod.rs CHAIN_ID_HASH
const CHAIN_ID_HASH = hexToBytes("0x1b17c7b04d05394674ca2c8e24f7433e251a1973cac2000c7b60966546e0b875");

// ── bytes ───────────────────────────────────────────────────────────────────
export function hexToBytes(h: string): Bytes {
  const s = h.startsWith("0x") ? h.slice(2) : h;
  if (s.length % 2 || /[^0-9a-f]/i.test(s)) throw new Error("BAD_HEX");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}
export const bytesToHex = (b: Bytes): Hex => ("0x" + Array.from(b, x => x.toString(16).padStart(2, "0")).join("")) as Hex;
export const utf8 = (s: string) => new TextEncoder().encode(s);
export function concat(...parts: Bytes[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
const u32 = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
const u64 = (n: bigint | number) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
const str = (s: string) => { const b = utf8(s); return concat(u64(b.length), b); };
export const sha256d = (b: Bytes) => sha256(sha256(b));
export const hash160 = (b: Bytes) => ripemd160(sha256(b));

// ── keys ────────────────────────────────────────────────────────────────────
export type CsdKey = { priv: Bytes; pub33: Bytes; addr20: Hex };

export function keyFromPrivate(priv: Bytes): CsdKey {
  const pub33 = secp256k1.getPublicKey(priv, true);
  return { priv, pub33, addr20: bytesToHex(hash160(pub33)) };
}

// (An app can derive its users' keys however it likes, e.g. from a wallet signature: see
// Commonplace's keyFromSignature for one way. The kit only needs a private key.)

export type AppPayload =
  | { kind: "none" }
  | { kind: "propose"; domain: string; payloadHash: Bytes; uri: string; expiresEpoch: bigint }
  | { kind: "attest"; proposalId: Hex; score: number; confidence: number };
export type TxIn = { txid: Hex; vout: number; scriptSig: Bytes };
export type TxOut = { value: bigint; addr20: Hex };
export type Tx = { version: number; inputs: TxIn[]; outputs: TxOut[]; locktime: number; app: AppPayload };

function encodeApp(a: AppPayload): Bytes {
  // enum variant index u32, then the fields in declaration order
  if (a.kind === "none") return u32(0);
  if (a.kind === "propose") {
    if (a.payloadHash.length !== 32) throw new Error("BAD_PAYLOAD_HASH");
    return concat(u32(1), str(a.domain), a.payloadHash, str(a.uri), u64(a.expiresEpoch));
  }
  const pid = hexToBytes(a.proposalId);
  if (pid.length !== 32) throw new Error("BAD_PROPOSAL_ID");
  return concat(u32(2), pid, u32(a.score), u32(a.confidence));
}

export function serializeTx(tx: Tx, stripScripts = false): Bytes {
  const parts: Bytes[] = [u32(tx.version), u64(tx.inputs.length)];
  for (const i of tx.inputs) {
    const s = stripScripts ? new Uint8Array(0) : i.scriptSig;
    parts.push(hexToBytes(i.txid), u32(i.vout), u64(s.length), s);
  }
  parts.push(u64(tx.outputs.length));
  for (const o of tx.outputs) {
    const a = hexToBytes(o.addr20);
    if (a.length !== 20) throw new Error("BAD_ADDR20");
    parts.push(u64(o.value), a);
  }
  parts.push(u32(tx.locktime), encodeApp(tx.app));
  return concat(...parts);
}

export const txid = (tx: Tx): Hex => bytesToHex(sha256d(serializeTx(tx, true)));

// The reverse of serializeTx, for a transaction a node sends back (light verification). Strict:
// every byte must be used, and lengths are bounded, so a malformed answer can't pass as a transaction.
export function deserializeTx(b: Bytes): Tx {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let o = 0;
  const need = (n: number) => { if (n < 0 || o + n > b.length) throw new Error("BAD_TX: short"); };
  const rU32 = () => { need(4); const x = v.getUint32(o, true); o += 4; return x; };
  const rU64 = () => { need(8); const x = v.getBigUint64(o, true); o += 8; return x; };
  const rLen = (max: number) => { const n = rU64(); if (n > BigInt(max)) throw new Error("BAD_TX: length"); return Number(n); };
  const rBytes = (n: number) => { need(n); const x = b.slice(o, o + n); o += n; return x; };
  const rStr = (max: number) => new TextDecoder("utf-8", { fatal: true }).decode(rBytes(rLen(max)));
  const version = rU32();
  const inputs: TxIn[] = [];
  for (let i = 0, n = rLen(10_000); i < n; i++) inputs.push({ txid: bytesToHex(rBytes(32)), vout: rU32(), scriptSig: rBytes(rLen(10_000)) });
  const outputs: TxOut[] = [];
  for (let i = 0, n = rLen(10_000); i < n; i++) outputs.push({ value: rU64(), addr20: bytesToHex(rBytes(20)) });
  const locktime = rU32();
  const kind = rU32();
  let app: AppPayload;
  if (kind === 0) app = { kind: "none" };
  else if (kind === 1) app = { kind: "propose", domain: rStr(MAX_DOMAIN_BYTES), payloadHash: rBytes(32), uri: rStr(MAX_URI_BYTES), expiresEpoch: rU64() };
  else if (kind === 2) app = { kind: "attest", proposalId: bytesToHex(rBytes(32)), score: rU32(), confidence: rU32() };
  else throw new Error("BAD_TX: app kind");
  if (o !== b.length) throw new Error("BAD_TX: trailing bytes");
  return { version, inputs, outputs, locktime, app };
}

// Who signed a transaction's first input, the way the node names a proposal's or attestation's author
// (state/app_state.rs sender_h160_from_tx), and whether that signature really signs this transaction.
// Null when the first input doesn't carry a [64][sig][33][pubkey] script or the signature is wrong.
export function signerOf(tx: Tx): Hex | null {
  const s = tx.inputs[0]?.scriptSig;
  if (!s || s.length < 99 || s[0] !== 64 || s[65] !== 33) return null;
  const sig = s.slice(1, 65), pub33 = s.slice(66, 99);
  try { if (!secp256k1.verify(sig, sighash(tx), pub33, { lowS: true })) return null; } catch { return null; }
  return bytesToHex(hash160(pub33));
}

export function sighash(tx: Tx): Bytes {
  const tag = sha256(utf8("CSD_SIG_V1"));
  return sha256d(sha256(concat(tag, tag, serializeTx(tx, true), CHAIN_ID_HASH)));
}

export function signTx(tx: Tx, key: CsdKey): Tx {
  const sig = secp256k1.sign(sighash(tx), key.priv, { lowS: true }).toCompactRawBytes();
  const scriptSig = concat(new Uint8Array([64]), sig, new Uint8Array([33]), key.pub33);
  return { ...tx, inputs: tx.inputs.map(i => ({ ...i, scriptSig })) };
}

export type Utxo = { txid: Hex; vout: number; value: bigint };

const SPLIT_MIN = 30_000_000n; // 0.3 CSD: enough for an entry with room to spare

// A transaction carrying `app`, paying `fee` from the key's coins, the rest back to the key
export function buildAppTx(utxos: Utxo[], key: CsdKey, app: AppPayload, fee: bigint): Tx {
  const sorted = [...utxos].sort((a, b) => (b.value > a.value ? 1 : b.value < a.value ? -1 : 0));
  const picked: Utxo[] = []; let total = 0n;
  // a transaction needs at least one output, so take coins until there is change to send back
  // (a coin worth exactly the fee alone would leave none, and the node refuses that)
  for (const u of sorted) { if (total >= fee + MIN_SEND) break; picked.push(u); total += u.value; }
  if (total <= fee) throw new Error("NOT_ENOUGH_CSD");
  // Change comes back as up to four coins rather than one. The node only spends coins that are
  // already in a block, so with a single coin, writing twice before the next block would fail;
  // with a few, the next entries and resonances have a coin ready.
  const change = total - fee, parts = change >= SPLIT_MIN * 2n ? BigInt(Math.min(4, Number(change / SPLIT_MIN))) : change > 0n ? 1n : 0n;
  const outputs: TxOut[] = [];
  for (let k = 0n; k < parts; k++) outputs.push({ value: k === 0n ? change - (change / parts) * (parts - 1n) : change / parts, addr20: key.addr20 });
  const unsigned: Tx = { version: 1, inputs: picked.map(u => ({ txid: u.txid, vout: u.vout, scriptSig: new Uint8Array(0) })), outputs, locktime: 0, app };
  return signTx(unsigned, key);
}

export const SEND_FEE = 100_000n;      // 0.001 CSD; the node asks only for a feerate above zero
export const MIN_SEND = 1_000_000n;    // 0.01 CSD, well clear of any dust rule

// Sends CSD out of the writing key. `amount` "all" empties every coin into one output, less the fee.
export function buildSendTx(utxos: Utxo[], key: CsdKey, to: Hex, amount: bigint | "all", fee = SEND_FEE): Tx {
  if (!/^0x[0-9a-f]{40}$/i.test(to)) throw new Error("BAD_ADDRESS");
  const dest = to.toLowerCase() as Hex;
  if (dest === key.addr20.toLowerCase()) throw new Error("SEND_TO_SELF");
  const sorted = [...utxos].sort((a, b) => (b.value > a.value ? 1 : b.value < a.value ? -1 : 0)).slice(0, 500);
  let picked: Utxo[], total = 0n, value: bigint;
  if (amount === "all") {
    picked = sorted; total = sorted.reduce((s, u) => s + u.value, 0n); value = total - fee;
  } else {
    picked = []; value = amount;
    for (const u of sorted) { if (total >= amount + fee) break; picked.push(u); total += u.value; }
    if (total < amount + fee) throw new Error("NOT_ENOUGH_CSD");
  }
  if (value < MIN_SEND) throw new Error("SEND_TOO_SMALL");
  const change = total - fee - value;
  const outputs: TxOut[] = [{ value, addr20: dest }];
  if (change > 0n) outputs.push({ value: change, addr20: key.addr20 });
  const unsigned: Tx = { version: 1, inputs: picked.map(u => ({ txid: u.txid, vout: u.vout, scriptSig: new Uint8Array(0) })), outputs, locktime: 0, app: { kind: "none" } };
  return signTx(unsigned, key);
}

// One payment to each of several addresses, in one transaction
// (with `app`, the same transaction also carries a record, and its fee is then the record's)
export function buildSplitTx(utxos: Utxo[], key: CsdKey, pays: { to: Hex; value: bigint }[], fee = SEND_FEE, app: AppPayload = { kind: "none" }): Tx {
  for (const p of pays) {
    if (!/^0x[0-9a-f]{40}$/i.test(p.to)) throw new Error("BAD_ADDRESS");
    if (p.value < MIN_SEND) throw new Error("SEND_TOO_SMALL");
  }
  const need = pays.reduce((s, p) => s + p.value, 0n) + fee;
  const sorted = [...utxos].sort((a, b) => (b.value > a.value ? 1 : b.value < a.value ? -1 : 0)).slice(0, 500);
  const picked: Utxo[] = []; let total = 0n;
  for (const u of sorted) { if (total >= need) break; picked.push(u); total += u.value; }
  if (total < need) throw new Error("NOT_ENOUGH_CSD");
  const outputs: TxOut[] = pays.map(p => ({ value: p.value, addr20: p.to.toLowerCase() as Hex }));
  if (total > need) outputs.push({ value: total - need, addr20: key.addr20 });
  const unsigned: Tx = { version: 1, inputs: picked.map(u => ({ txid: u.txid, vout: u.vout, scriptSig: new Uint8Array(0) })), outputs, locktime: 0, app };
  return signTx(unsigned, key);
}

// The node's /tx/submit JSON: serde's default shapes, byte arrays as number arrays
export function txToJson(tx: Tx) {
  const a = tx.app;
  const app = a.kind === "none" ? "None"
    : a.kind === "propose" ? { Propose: { domain: a.domain, payload_hash: Array.from(a.payloadHash), uri: a.uri, expires_epoch: Number(a.expiresEpoch) } }
    : { Attest: { proposal_id: Array.from(hexToBytes(a.proposalId)), score: a.score, confidence: a.confidence } };
  return {
    version: tx.version,
    inputs: tx.inputs.map(i => ({ prevout: { txid: Array.from(hexToBytes(i.txid)), vout: i.vout }, script_sig: Array.from(i.scriptSig) })),
    outputs: tx.outputs.map(o => ({ value: Number(o.value), script_pubkey: Array.from(hexToBytes(o.addr20)) })),
    locktime: tx.locktime,
    app,
  };
}

// ── the node's API ──────────────────────────────────────────────────────────
export type ProposalItem = { proposal_id: Hex; height: number; time: number; domain: string; payload_hash: Hex; uri: string };

// `f` is how to reach it: plain fetch for a URL, or a stand-in for a node reached another way
// (src/p2p.ts, over WebRTC)
export function node(base: string, f: typeof fetch = (...a) => fetch(...a)) {
  const url = (p: string) => `${base.replace(/\/$/, "")}${p}`;
  const get = async (p: string) => {
    const r = await f(url(p));
    if (!r.ok) throw new Error(`NODE_${r.status}`);
    return r.json();
  };
  const strip = (h: string) => h.replace(/^0x/, "");
  // A topic's attestations, per proposal. Nodes that keep them for good answer
  // /attestations/domain/:domain with every attestation ever made. Otherwise the per-topic recent
  // route (the last 10,000 blocks), and on nodes without that either, the network-wide list (the
  // 200 most attested proposals of the last 5,000 blocks), read once every half minute and
  // filtered by topic.
  let allTime = true, perTopic = true;
  let global: { at: number; items: Promise<any[]> } | null = null;
  const attestedIn = async (domain: string): Promise<any[]> => {
    // newer nodes keep every attestation for good: /attestations/domain/:domain
    if (allTime) {
      try { return (await get(`/attestations/domain/${encodeURIComponent(domain)}`)).items ?? []; }
      catch (e: any) { if (/NODE_404/.test(String(e?.message))) allTime = false; }
    }
    if (perTopic) {
      // a 404 means this node has no such route; anything else (a busy node sheds scans) is
      // answered from the network-wide list this time only
      try { return (await get(`/recent/attestations/${encodeURIComponent(domain)}/200`)).items ?? []; }
      catch (e: any) { if (/NODE_404/.test(String(e?.message))) perTopic = false; }
    }
    if (!global || Date.now() - global.at > 30_000) global = { at: Date.now(), items: get("/recent/attestations/200").then(j => j.items ?? []).catch(() => []) };
    return (await global.items).filter((r: any) => r.domain === domain);
  };
  return {
    tip: async (): Promise<{ height: number }> => ({ height: Number((await get("/tip")).height) }),
    header: async (height: number): Promise<{ bits: number; time: number }> => (await get(`/block/height/${height}`)).header,
    // coins at the address; by default only those not already being spent in the mempool
    utxos: async (addr20: Hex, includeSpending = false): Promise<Utxo[]> =>
      ((await get(`/utxos/${strip(addr20)}${includeSpending ? "" : "?available=true"}`)).utxos ?? []).map((u: any) => ({ txid: String(u.txid).toLowerCase() as Hex, vout: Number(u.vout), value: BigInt(u.value) })),
    // the newest proposals across all topics (the node returns at most 500), and per topic
    proposals: async (limit = 500): Promise<ProposalItem[]> => (await get(`/proposals/${limit}`)).proposals ?? [],
    proposalsIn: async (domain: string, limit = 500): Promise<ProposalItem[]> => (await get(`/proposals/${encodeURIComponent(domain)}/${limit}`)).proposals ?? [],
    proposal: async (id: Hex) => {
      const j = await get(`/proposal/${strip(id)}`);
      return j.ok ? (j.proposal as { proposer: Hex; fee: number; created_height: number; created_epoch: number; expires_epoch: number; domain: string; uri: string }) : null;
    },
    // every attestation ever, summed per proposal
    resonance: async (): Promise<Record<string, { count: number; weight: number }>> => {
      const j = await get("/top/all-time");
      const rows: any[] = j.items ?? j.top ?? j.proposals ?? (Array.isArray(j) ? j : []);
      const out: Record<string, { count: number; weight: number }> = {};
      for (const r of rows) out[String(r.proposal_id).toLowerCase()] = { count: Number(r.attest_count), weight: Number(r.economic_weight) };
      return out;
    },
    // attestations on one topic's proposals, counted over the node's last 10,000 blocks (about
    // two weeks); counts only, the node doesn't sum their weight here
    resonanceIn: async (domain: string): Promise<Record<string, number>> => {
      const out: Record<string, number> = {};
      for (const r of await attestedIn(domain)) out[String(r.proposal_id).toLowerCase()] = Number(r.attest_count);
      return out;
    },
    // the same, with the scores summed too: what the research memory reads its checks from
    checksIn: async (domain: string): Promise<Record<string, { count: number; scoreSum: number }>> => {
      const out: Record<string, { count: number; scoreSum: number }> = {};
      for (const r of await attestedIn(domain)) out[String(r.proposal_id).toLowerCase()] = { count: Number(r.attest_count), scoreSum: Number(r.score_sum) };
      return out;
    },
    topk: async (epoch: number, domain: string): Promise<{ proposal_id: Hex; score: number }[]> => {
      const j = await get(`/topk/${epoch}/${encodeURIComponent(domain)}`);
      return j.items ?? j.topk ?? j.rows ?? [];
    },
    // what an address has done: entries it made ("proposal"), resonances ("attestation"), coins in
    activity: async (addr20: Hex, limit = 200): Promise<{ kind: string; txid: Hex; height: number; time: number; domain?: string; proposal_id?: Hex; payload_hash?: Hex; uri?: string }[]> =>
      (await get(`/address/${strip(addr20)}/activity?limit=${limit}`)).activity ?? [],
    domains: async (): Promise<{ domain: string; proposals: number; attestations: number }[]> => (await get("/domains")).domains ?? [],
    // a topic's records block by block (proposals in it, and attestations on them), each its raw
    // transaction: up to 2000 blocks from `from`; null from a node without the route
    events: async (domain: string, from: number, count = 2000): Promise<{ to: number; tip: number; events: { txid: Hex; height: number; pos: number; tx_raw: string }[] } | null> => {
      try {
        const j = await get(`/events/${encodeURIComponent(domain)}/${from}/${count}`);
        return { to: Number(j.to), tip: Number(j.tip_height), events: j.events ?? [] };
      } catch (e: any) { if (/NODE_404/.test(String(e?.message))) return null; throw e; }
    },
    mempoolTxids: async (): Promise<Hex[]> => ((await get("/mempool/txids")).txids ?? []).map((t: any) => t.txid),
    tx: (id: Hex) => get(`/tx/${strip(id)}`),
    // how much `from` has sent `to` in plain transfers at or after a height, read from the
    // sender's activity and each transfer's outputs
    paidTo: async (from: Hex, to: Hex, sinceHeight: number): Promise<bigint> => {
      const acts = (await get(`/address/${strip(from)}/activity?limit=500`)).activity ?? [];
      const want = strip(to).toLowerCase();
      let sum = 0n;
      for (const a of acts) {
        if (a.kind !== "transfer" || Number(a.height) < sinceHeight) continue;
        const j = await get(`/tx/${strip(String(a.txid))}`).catch(() => null);
        for (const o of j?.tx?.outputs ?? []) if (strip(String(o.script_pubkey)).toLowerCase() === want) sum += BigInt(o.value);
      }
      return sum;
    },
    submit: async (tx: Tx): Promise<Hex> => {
      const r = await f(url("/tx/submit"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ tx: txToJson(tx) }) });
      const j = await r.json().catch(() => ({}));
      if (!j.ok) throw new Error(j.err ?? `NODE_${r.status}`);
      return j.txid;
    },
  };
}
export type Node = ReturnType<typeof node>;
