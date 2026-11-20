// Checking what a node says instead of trusting it (a light client).
//
// For any transaction the page shows (an entry, a reply, a resonance, a frontier result) this proves,
// from the node's answer alone, that:
//   - the transaction is exactly these bytes: its txid is their hash;
//   - its author signed it: the signature on its first input checks against its public key;
//   - it is in a block: the merkle branch leads from its txid to the block header's merkle root;
//   - that block is on the network's heaviest chain:
//       below the newest anchor, its header links by hash to the block hashes this release carries
//         (src/anchors.json, one every ANCHOR_EVERY blocks, made by scripts/anchors.mts from a full
//         check of every header since genesis);
//       above it, every header since the anchor has valid proof-of-work at exactly the difficulty
//         the network's rule (LWMA) demands, and links to the one before.
// A node can still leave things out (ask another node for those), but it can't invent, alter or
// misattribute anything without redoing the network's proof-of-work.
//
// Everything follows the consensus code in compute-substrate:
//   header        84 bytes: version u32, prev 32, merkle 32, time u64, bits u32, nonce u32 (LE)
//                 hash = sha256d(those bytes)                                  chain/index.rs
//   proof-of-work hash <= target(bits), both big-endian                        chain/pow.rs
//   difficulty    LWMA over the 45 headers before, solvetimes clamped [1, 12*120]  chain/pow.rs
//   merkle        sha256d(left || right), the last duplicated when odd          chain/mine.rs
import { bytesToHex, hexToBytes, sha256d, deserializeTx, serializeTx, signerOf, type Bytes, type Hex, type Tx } from "./core";
import anchorFile from "./anchors.json";

export const GENESIS_HASH: Hex = "0x00000052c2821f71b19c3d79dfabfb12d4076ba15d83b47d008e582aad6c0d52";
const TARGET_BLOCK_SECS = 120n;
const LWMA_WINDOW = 45;
const MAX_SOLVETIME = BigInt(12 * 120);
// 2^256, spelled out (a bundler's static evaluator chokes on BigInt arithmetic between literals)
const TWO_256 = BigInt("0x1" + "0".repeat(64));
const POW_LIMIT_BITS = 0x1e00ffff;
const INITIAL_BITS = 0x1e00ffff;
// at most this many headers above the newest anchor are checked in full (about four weeks of blocks)
const MAX_TAIL = 20_000;

// ── headers ─────────────────────────────────────────────────────────────────
export type Header = { version: number; prev: Hex; merkle: Hex; time: bigint; bits: number; nonce: number; hash: Hex };

export function parseHeader(raw: Bytes): Header {
  if (raw.length !== 84) throw new Error("BAD_HEADER: length");
  const v = new DataView(raw.buffer, raw.byteOffset, 84);
  return {
    version: v.getUint32(0, true),
    prev: bytesToHex(raw.slice(4, 36)),
    merkle: bytesToHex(raw.slice(36, 68)),
    time: v.getBigUint64(68, true),
    bits: v.getUint32(76, true),
    nonce: v.getUint32(80, true),
    hash: bytesToHex(sha256d(raw)),
  };
}

// ── proof-of-work (chain/pow.rs) ────────────────────────────────────────────
// compact bits -> target; 0n for an invalid encoding
export function bitsToTarget(bits: number): bigint {
  const exp = (bits >>> 24) & 0xff, mant = bits & 0x00ffffff;
  if (exp === 0 || mant === 0 || (mant & 0x00800000) !== 0 || exp > 32) return 0n;
  const t = exp <= 3 ? BigInt(mant) >> BigInt(8 * (3 - exp)) : BigInt(mant) << BigInt(8 * (exp - 3));
  return t > 0n && t < TWO_256 ? t : 0n;
}

export function targetToBits(t: bigint): number {
  if (t <= 0n) return 0;
  let hex = t.toString(16); if (hex.length % 2) hex = "0" + hex;
  let exp = hex.length / 2;
  let mant = exp <= 3 ? Number(t << BigInt(8 * (3 - exp))) & 0x00ffffff : parseInt(hex.slice(0, 6), 16);
  if (mant & 0x00800000) { mant >>>= 8; exp += 1; }
  return ((exp << 24) | (mant & 0x00ffffff)) >>> 0;
}

const LIMIT = bitsToTarget(POW_LIMIT_BITS);
const withinLimit = (bits: number) => { const t = bitsToTarget(bits); return t !== 0n && t <= LIMIT; };

export function powOk(hash: Hex, bits: number): boolean {
  if (!withinLimit(bits)) return false;
  return BigInt(hash) <= bitsToTarget(bits);
}

export const workOf = (bits: number): bigint => TWO_256 / (bitsToTarget(bits) + 1n);

// The difficulty a block at `height` must have, from the headers before it (oldest first, the
// parent last; at least min(45, height) of them)
export function expectedBits(before: Header[], height: number): number {
  if (height === 0) return INITIAL_BITS;
  const parent = before[before.length - 1];
  if (!parent || !withinLimit(parent.bits)) throw new Error("BAD_CHAIN: parent bits");
  if (height < 2) return parent.bits;
  const n = Math.min(LWMA_WINDOW, height);
  if (n < 2) return parent.bits;
  if (before.length < n) throw new Error("BAD_CHAIN: short difficulty window");
  const win = before.slice(before.length - n);
  const m = win.length;
  let weighted = BigInt(0), denom = BigInt(0); // not 0n: a bundler would "evaluate" weighted / denom as 0n / 0n
  for (let i = 1; i < m; i++) {
    const dt = win[i].time > win[i - 1].time ? win[i].time - win[i - 1].time : 0n;
    const st = dt < 1n ? 1n : dt > MAX_SOLVETIME ? MAX_SOLVETIME : dt;
    weighted += st * BigInt(i); denom += BigInt(i);
  }
  if (denom === 0n) return parent.bits;
  const avgSolve = weighted / denom;
  let sum = BigInt(0);
  for (const h of win) { const t = bitsToTarget(h.bits); if (!t) throw new Error("BAD_CHAIN: window bits"); sum += t; }
  let next = (sum / BigInt(m)) * avgSolve / TARGET_BLOCK_SECS;
  if (next > LIMIT) next = LIMIT;
  if (next === 0n || next >= TWO_256) return POW_LIMIT_BITS;
  const bits = targetToBits(next);
  return withinLimit(bits) ? bits : POW_LIMIT_BITS;
}

// Headers from height `from` on, checked against the ones before them (`context`, oldest first,
// ending at height from - 1, with enough of them for the difficulty rule): each links to the one
// before, has valid proof-of-work, and has exactly the difficulty the rule demands.
export function checkHeaders(context: Header[], from: number, headers: Header[]): void {
  const chain = [...context];
  headers.forEach((h, i) => {
    const height = from + i, parent = chain[chain.length - 1];
    if (!parent || h.prev !== parent.hash) throw new Error(`BAD_CHAIN: block ${height} doesn't follow block ${height - 1}`);
    if (h.bits !== expectedBits(chain.slice(-LWMA_WINDOW), height)) throw new Error(`BAD_CHAIN: block ${height} has the wrong difficulty`);
    if (!powOk(h.hash, h.bits)) throw new Error(`BAD_CHAIN: block ${height} has no valid proof-of-work`);
    chain.push(h);
  });
}

// ── merkle (chain/mine.rs) ──────────────────────────────────────────────────
// The root a txid leads to through its branch. The side of each step comes from the index, not
// from the node, and the branch must be exactly as long as the block's tree is deep.
export function merkleRootFrom(txid: Hex, index: number, branch: { hash: Hex }[]): Hex {
  let cur = hexToBytes(txid), i = index;
  for (const step of branch) {
    const sib = hexToBytes(step.hash);
    if (sib.length !== 32) throw new Error("BAD_PROOF: branch");
    const pair = new Uint8Array(64);
    if (i % 2 === 0) { pair.set(cur, 0); pair.set(sib, 32); } else { pair.set(sib, 0); pair.set(cur, 32); }
    cur = sha256d(pair); i = Math.floor(i / 2);
  }
  if (i !== 0) throw new Error("BAD_PROOF: index beyond the branch");
  return bytesToHex(cur);
}

// ── anchors ─────────────────────────────────────────────────────────────────
export type Anchors = { every: number; hashes: string[] };
const ANCHORS = anchorFile as Anchors;
export const ANCHOR_EVERY = ANCHORS.every;
// the newest anchored height
export const anchoredTo = () => (ANCHORS.hashes.length - 1) * ANCHORS.every;

// ── talking to a node ───────────────────────────────────────────────────────
export type Verified = {
  txid: Hex; tx: Tx; author: Hex | null; height: number; blockHash: Hex;
  // its position in the block (proven by the merkle branch)
  index: number;
  // how many blocks have been built on it, by the checked chain's count
  depth: number;
};

export function lightClient(base: string, opts: { fetch?: typeof fetch; anchors?: Anchors } = {}) {
  const f = opts.fetch ?? fetch;
  const anchors = opts.anchors ?? ANCHORS;
  const at = (h: number): Hex | null => (h % anchors.every === 0 && h / anchors.every < anchors.hashes.length ? anchors.hashes[h / anchors.every] as Hex : null);
  const top = (anchors.hashes.length - 1) * anchors.every;
  const url = (p: string) => `${base.replace(/\/$/, "")}${p}`;
  const get = async (p: string) => { const r = await f(url(p)); if (!r.ok) throw new Error(`NODE_${r.status}`); return r.json(); };

  // headers from..to inclusive, in requests of at most 2000
  const headers = async (from: number, to: number): Promise<Header[]> => {
    const out: Header[] = [];
    for (let s = from; s <= to; s += 2000) {
      const j = await get(`/headers/${s}/${Math.min(2000, to - s + 1)}`);
      const hs: string[] = j?.headers ?? [];
      if (!hs.length) break;
      for (const h of hs) out.push(parseHeader(hexToBytes("0x" + h.replace(/^0x/, ""))));
      if (hs.length < Math.min(2000, to - s + 1)) break;
    }
    return out;
  };

  // Above the newest anchor: every header to the node's tip, checked in full. Kept, and extended
  // as the tip moves; redone from the anchor if the node's chain no longer extends it (a reorg).
  let tail: { from: number; hs: Header[] } | null = null;
  let syncing: Promise<{ height: number; hash: Hex }> | null = null;
  const syncTail = (): Promise<{ height: number; hash: Hex }> => (syncing ??= doSync().finally(() => { syncing = null; }));
  const doSync = async (): Promise<{ height: number; hash: Hex }> => {
    for (let attempt = 0; attempt < 3; attempt++) {
      // the anchor, and the headers before it that the difficulty rule needs
      if (!tail) {
        // a release whose newest anchor is far behind would make every visitor fetch and check
        // that many headers: refuse rather than be slow (a new release brings new anchors)
        const tipH = Number((await get("/tip"))?.height);
        if (Number.isFinite(tipH) && tipH - top > MAX_TAIL) throw new Error(`STALE_ANCHORS: ${tipH - top} blocks past this release's newest anchor`);
        const start = Math.max(0, top - LWMA_WINDOW);
        const hs = await headers(start, top);
        if (hs.length !== top - start + 1 || hs[hs.length - 1].hash !== at(top)) throw new Error("BAD_CHAIN: the node's chain doesn't contain the anchored blocks");
        for (let i = 1; i < hs.length; i++) if (hs[i].prev !== hs[i - 1].hash) throw new Error("BAD_CHAIN: headers before the anchor don't link");
        tail = { from: start, hs };
      }
      const t = tail;
      let reorg = false;
      for (;;) {
        const next = t.from + t.hs.length;
        const more = await headers(next, next + 1999);
        if (!more.length) break;
        // the node's chain no longer extends ours (a reorg): start again from the anchor
        if (more[0].prev !== t.hs[t.hs.length - 1].hash) { reorg = true; break; }
        checkHeaders(t.hs.slice(-LWMA_WINDOW), next, more);
        t.hs.push(...more);
        if (more.length < 2000) break;
      }
      if (reorg) { tail = null; continue; }
      return { height: t.from + t.hs.length - 1, hash: t.hs[t.hs.length - 1].hash };
    }
    throw new Error("BAD_CHAIN: the node's chain keeps changing under us");
  };

  // Below the newest anchor: the stretch of up to `every` headers between two anchors, linked by
  // hash at both ends, fixes every block in it. Kept per stretch.
  const stretches = new Map<number, Promise<Header[]>>();
  const stretch = (k: number) => {
    let p = stretches.get(k);
    if (!p) {
      p = (async () => {
        const lo = k * anchors.every, hi = lo + anchors.every;
        const hs = await headers(lo, hi);
        if (hs.length !== hi - lo + 1 || hs[0].hash !== at(lo) || hs[hs.length - 1].hash !== at(hi)) throw new Error("BAD_CHAIN: headers don't match the anchors");
        for (let i = 1; i < hs.length; i++) if (hs[i].prev !== hs[i - 1].hash) throw new Error("BAD_CHAIN: headers between anchors don't link");
        return hs;
      })();
      p.catch(() => stretches.delete(k));
      stretches.set(k, p);
    }
    return p;
  };

  // The checked header at a height, and the checked chain's height
  const headerAt = async (height: number): Promise<{ h: Header; tip: number }> => {
    const t = await syncTail();
    if (height > t.height) throw new Error("BAD_PROOF: the block is beyond the node's own tip");
    if (height >= top) return { h: tail!.hs[height - tail!.from], tip: t.height };
    const k = Math.floor(height / anchors.every);
    return { h: (await stretch(k))[height - k * anchors.every], tip: t.height };
  };

  // One transaction, checked. Throws with a reason when the node's answer doesn't hold up.
  const checkTx = async (txid: Hex): Promise<Verified> => {
    const p = await get(`/proof/tx/${txid.replace(/^0x/, "")}`);
    if (!p?.ok) throw new Error(p?.error ? `NOT_FOUND: ${p.error}` : "NOT_FOUND");
    const raw = hexToBytes(p.tx_raw);
    const tx = deserializeTx(raw);
    const stripped = serializeTx(tx, true);
    // a 64-byte "transaction" could pose as a pair of merkle nodes
    if (stripped.length === 64) throw new Error("BAD_PROOF: transaction size");
    if (bytesToHex(sha256d(stripped)).toLowerCase() !== txid.toLowerCase()) throw new Error("BAD_PROOF: the transaction isn't the one asked for");
    const height = Number(p.height), index = Number(p.tx_index);
    if (!Number.isSafeInteger(height) || height < 1 || !Number.isSafeInteger(index) || index < 0) throw new Error("BAD_PROOF: position");
    const root = merkleRootFrom(txid, index, p.merkle_branch ?? []);
    const { h, tip } = await headerAt(height);
    if (root !== h.merkle) throw new Error("BAD_PROOF: not in that block");
    return { txid, tx, author: signerOf(tx), height, index, blockHash: h.hash, depth: tip - height + 1 };
  };

  return { syncTail, checkTx, headerAt };
}
