// Opens .csd names for the app: a web+csd:<name> link clicked anywhere on this computer comes here,
// is looked up, and opens where the name points.
//
// The names are Cairn's (CNS, by InverseAltruism): an on-chain convention on Compute Substrate whose
// rules and reference resolver are @inversealtruism/cairnx-core. This only reads them:
//   1. Cairn's server lists the transactions in the name's history (hints, not trusted). When it
//      doesn't answer, the app reads the network's whole CairnX history instead
//      (`/events/cairnx:v1/...`), so names keep working without Cairn's server.
//   2. Each one is read from THIS computer's own node, which has checked every block itself, and
//      must hash to its txid; its signer is the key whose signature is on it.
//      Until that node has caught up (the first minutes after installing, or after a long time
//      off), each one is read through the doors instead, and proven the way a light client proves
//      it (the kit's light.ts): its merkle branch leads to a block header, and that header is on
//      the network's heaviest chain, by the anchors this release carries and the proof-of-work of
//      every header since. Its author is the owner of the coin it spends. So a door can't invent
//      or alter a record; to keep it from leaving one out, the history is asked of two doors.
//   3. The events are replayed through cairnx-core's own resolver.
// What a name points to: its profile's `contenthash` (ipfs://<CIDv1>, a site), `url` (a link), else
// its address's page.
import { resolve, paidToFromOutputs, RESERVED_NAMES, ACTIVATION_HEIGHT } from "@inversealtruism/cairnx-core";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { ripemd160 } from "@noble/hashes/legacy";
import { lightClient, type Verified } from "../../../kit/src/light";
import { bytesToHex } from "../../../kit/src/core";

let NODE = "http://127.0.0.1:8789";
// which node names are read through (the app uses its own; a door, its own RPC)
export function useNode(url: string) { NODE = url.replace(/\/$/, ""); }
const CAIRN = "https://cairn-substrate.com";
// the copy of Commonplace this app carries, served from this computer (an example app on the network)
const COMMONPLACE = "http://localhost:8790";
const NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;
// sha256("compute-substrate-mainnet"), the node's CHAIN_ID_HASH
const CHAIN_ID = hex("0x1b17c7b04d05394674ca2c8e24f7433e251a1973cac2000c7b60966546e0b875");

export function hex(h: string): Uint8Array {
  const s = h.replace(/^0x/, "");
  const b = new Uint8Array(s.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return b;
}
const toHex = (b: Uint8Array) => "0x" + Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
const sha256d = (b: Uint8Array) => sha256(sha256(b));
const cat = (...p: Uint8Array[]) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const u32 = (n: number) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
const u64 = (n: bigint) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n, true); return b; };

// The node's transaction encoding (bincode, fixed-int, little endian), read strictly
type Tx = { raw: Uint8Array; stripped: Uint8Array; script0?: Uint8Array; outputs: { addr: string; value: bigint }[]; app: any };
export function parseTx(b: Uint8Array): Tx {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let o = 0;
  const need = (n: number) => { if (o + n > b.length) throw new Error("bad transaction"); };
  const r32 = () => { need(4); const x = v.getUint32(o, true); o += 4; return x; };
  const r64 = () => { need(8); const x = v.getBigUint64(o, true); o += 8; return x; };
  const len = (max: number) => { const n = r64(); if (n > BigInt(max)) throw new Error("bad transaction"); return Number(n); };
  const bytes = (n: number) => { need(n); const x = b.slice(o, o + n); o += n; return x; };
  const str = (max: number) => new TextDecoder("utf-8", { fatal: true }).decode(bytes(len(max)));
  const parts: Uint8Array[] = [u32(r32())];
  const nin = len(10_000); parts.push(u64(BigInt(nin)));
  let script0: Uint8Array | undefined;
  for (let i = 0; i < nin; i++) { const prev = bytes(36); const s = bytes(len(10_000)); if (i === 0) script0 = s; parts.push(prev, u64(0n)); }
  const nout = len(10_000); parts.push(u64(BigInt(nout)));
  const outputs: Tx["outputs"] = [];
  for (let i = 0; i < nout; i++) { const value = r64(), a = bytes(20); outputs.push({ addr: toHex(a), value }); parts.push(u64(value), a); }
  const appStart = o; parts.push(u32(r32()));
  const kind = r32();
  let app: any;
  if (kind === 0) app = { kind: "none" };
  else if (kind === 1) app = { kind: "propose", domain: str(128), payloadHash: toHex(bytes(32)), uri: str(512), expiresEpoch: Number(r64()) };
  else if (kind === 2) app = { kind: "attest", proposalId: toHex(bytes(32)), score: r32(), confidence: r32() };
  else throw new Error("bad transaction");
  if (o !== b.length) throw new Error("bad transaction");
  // stripped = the same bytes with every script emptied (locktime and app as they are)
  parts.push(b.slice(appStart + 4, b.length));
  return { raw: b, stripped: cat(...parts), script0, outputs, app };
}
// who signed the first input, if the signature really signs this transaction (state/app_state.rs)
export function signer(tx: Tx): string | null {
  const s = tx.script0;
  if (!s || s.length < 99 || s[0] !== 64 || s[65] !== 33) return null;
  const tag = sha256(new TextEncoder().encode("CSD_SIG_V1"));
  const msg = sha256d(sha256(cat(tag, tag, tx.stripped, CHAIN_ID)));
  try { if (!secp256k1.verify(s.slice(1, 65), msg, s.slice(66, 99), { lowS: true })) return null; } catch { return null; }
  return toHex(ripemd160(sha256(s.slice(66, 99))));
}

export async function getJson(url: string, ms = 15_000) {
  const r = await fetch(url, { signal: AbortSignal.timeout(ms) });
  if (!r.ok && r.status !== 404) throw new Error(`${new URL(url).host} answered ${r.status}`);
  return r.status === 404 ? null : r.json();
}

// a transaction as the resolver's event; it must hash to its id
export function eventOf(id: string, tx: Tx, height: number, pos: number) {
  if (toHex(sha256d(tx.stripped)) !== id.toLowerCase()) throw new Error("A record didn't match its id.");
  const who = signer(tx) ?? "0x" + "0".repeat(40);
  const paidTo = paidToFromOutputs(tx.outputs.map(o => ({ addr: o.addr, value: Number(o.value) })));
  if (tx.app.kind === "propose") return { kind: "propose", id: id.toLowerCase(), proposer: who, uri: tx.app.uri, payloadHash: tx.app.payloadHash, expiresEpoch: tx.app.expiresEpoch, height, pos, paidTo };
  if (tx.app.kind === "attest") return { kind: "attest", txid: id.toLowerCase(), proposalId: tx.app.proposalId, attester: who, score: tx.app.score, confidence: tx.app.confidence, height, pos, paidTo };
  return null;
}

// The network's whole CairnX history, from a node (this computer's, unless said), kept while the
// app runs
const histories = new Map<string, { to: number; events: any[] }>();
export async function allEvents(tip: number, base = NODE): Promise<any[]> {
  let history = histories.get(base);
  if (!history) histories.set(base, history = { to: ACTIVATION_HEIGHT - 1, events: [] });
  for (let from = history.to + 1; from <= tip; from += 2000) {
    const j = await getJson(`${base}/events/${encodeURIComponent("cairnx:v1")}/${from}/2000`);
    if (!j?.ok) throw new Error("Cairn's server didn't answer, and the node can't list the names' history (it needs a newer node).");
    for (const e of j.events) { const ev = eventOf(e.txid, parseTx(hex(e.tx_raw)), e.height, e.pos); if (ev) history.events.push(ev); }
    history.to = Math.min(tip, from + 1999);
  }
  return history.events;
}

// ── through the doors, while this computer's node catches up ────────────────
// Whether this computer's own node has caught up with the network: then it's the one to read.
export async function ownNodeReady(): Promise<boolean> {
  try {
    const h = await getJson(`${NODE}/health`, 4_000);
    return !!h && h.peer_count > 0 && h.best_peer_height != null && h.best_peer_height <= h.height + 1;
  } catch { return false; }
}
// The doors that answer, highest first (each one only ever a source of things to check)
async function answering(doors: string[]): Promise<string[]> {
  const r = await Promise.all(doors.map(async d => {
    try { const t = await getJson(`${d}/tip`, 6_000); return Number.isSafeInteger(t?.height) ? { d, h: t.height as number } : null; } catch { return null; }
  }));
  return r.filter((x): x is { d: string; h: number } => !!x).sort((a, b) => b.h - a.h).map(x => x.d);
}
type Light = ReturnType<typeof lightClient>;
const lights = new Map<string, Light>();
const light = (door: string) => { let l = lights.get(door); if (!l) { l = lightClient(door); lights.set(door, l); } return l; };
// a record proven through a door, as the resolver's event
export function eventOfVerified(v: Verified) {
  const who = (v.author ?? "0x" + "0".repeat(40)).toLowerCase();
  const paidTo = paidToFromOutputs(v.tx.outputs.map(o => ({ addr: o.addr20.toLowerCase(), value: Number(o.value) })));
  const id = v.txid.toLowerCase(), a = v.tx.app;
  if (a.kind === "propose") return { kind: "propose", id, proposer: who, uri: a.uri, payloadHash: bytesToHex(a.payloadHash).toLowerCase(), expiresEpoch: Number(a.expiresEpoch), height: v.height, pos: v.index, paidTo };
  if (a.kind === "attest") return { kind: "attest", txid: id, proposalId: a.proposalId.toLowerCase(), attester: who, score: a.score, confidence: a.confidence, height: v.height, pos: v.index, paidTo };
  return null;
}
const proven = new Map<string, Promise<any>>();
const prove = (l: Light, txid: string) => {
  const k = txid.toLowerCase().replace(/^0x/, "");
  let p = proven.get(k);
  if (!p) { p = l.checkTx(("0x" + k) as any).then(eventOfVerified); p.catch(() => proven.delete(k)); proven.set(k, p); }
  return p;
};
async function inBatches<T, R>(xs: T[], n: number, f: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(xs.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, xs.length) }, async () => { while (i < xs.length) { const k = i++; out[k] = await f(xs[k]); } }));
  return out;
}
// the network's whole CairnX history, listed by up to two doors (a record either lists counts), each
// record proven
let doorHistory: { to: number; ids: Set<string> } = { to: ACTIVATION_HEIGHT - 1, ids: new Set() };
async function allEventsThrough(doors: string[], l: Light, tip: number): Promise<any[]> {
  const from0 = doorHistory.to + 1;
  let listed = 0;
  for (const d of doors.slice(0, 2)) {
    try {
      for (let from = from0; from <= tip; from += 2000) {
        const j = await getJson(`${d}/events/${encodeURIComponent("cairnx:v1")}/${from}/2000`);
        if (!j?.ok) throw new Error("no history");
        for (const e of j.events) doorHistory.ids.add(String(e.txid).toLowerCase().replace(/^0x/, ""));
      }
      listed++;
    } catch {}
  }
  if (!listed) throw new Error("Neither Cairn's server nor the doors could list the names' history right now. Try again in a minute.");
  doorHistory.to = tip;
  return (await inBatches([...doorHistory.ids], 8, id => prove(l, id))).filter(Boolean);
}

export type Opened = { name: string; open?: string; why?: string; owner?: string; page?: string; node?: string; via?: string };

// `doors`: where to read while this computer's node is still catching up
export async function lookup(input: string, opts: { doors?: string[] } = {}): Promise<Opened> {
  const name = input.trim().toLowerCase().replace(/^web\+csd:(\/\/)?/, "").replace(/\.csd$/, "").replace(/\/+$/, "");
  if (!NAME_RE.test(name) || RESERVED_NAMES.has(name)) return { name, why: "That isn't a .csd name." };
  const own = await ownNodeReady();
  const doors = own ? [] : await answering(opts.doors ?? []);
  if (!own && !doors.length) {
    // nothing else answers: this computer's node, however far it has got
    if (!(await getJson(`${NODE}/tip`, 4_000).catch(() => null))) throw new Error("Can't reach the network right now. Is this computer online?");
  }
  const via = doors.length ? doors[0] : NODE;
  const l = doors.length ? light(doors[0]) : null;
  const tip = l ? (await l.syncTail()).height : (await getJson(`${NODE}/tip`))?.height ?? 0;
  let events: any[];
  const h = await getJson(`${CAIRN}/trade/api/cairnx/name-history/${encodeURIComponent(name)}`).catch(() => undefined);
  if (h && Array.isArray(h.events) && h.scopedReplaySufficient && l) {
    events = (await inBatches(h.events.map((e: any) => String(e.txid)), 6, id => prove(l, id).catch(err => {
      throw new Error(/NOT_FOUND/.test(String(err?.message)) ? "A door doesn't have one of this name's records yet. Try again in a minute." : `One of this name's records didn't check out (${err?.message ?? err}).`);
    }))).filter(Boolean);
  } else if (h && Array.isArray(h.events) && h.scopedReplaySufficient) {
    events = [];
    for (const e of h.events) {
      const p = await getJson(`${NODE}/proof/tx/${String(e.txid).replace(/^0x/, "")}`);
      if (!p?.ok) throw new Error("Your node doesn't have one of this name's records. Is it synced?");
      const ev = eventOf(String(e.txid), parseTx(hex(p.tx_raw)), p.height, p.tx_index);
      if (ev) events.push(ev);
    }
  } else if (h === null) {
    return { name, why: `Nobody holds ${name}.csd.` };
  } else {
    // Cairn's server didn't answer (or its list can't decide this name alone): the whole history,
    // from this computer's own node
    events = l ? await allEventsThrough(doors, l, tip) : await allEvents(tip);
  }
  const st = resolve(events, tip).names[name];
  if (!st || st.expired || st.pending) return { name, via, why: `Nobody holds ${name}.csd${st?.expired ? " now; its lease lapsed" : ""}.` };
  const p = st.profile ?? {};
  const ipfs = /^ipfs:\/\/(b[a-z2-7]{50,100})$/.exec(p["contenthash"] ?? "")?.[1];
  if (ipfs) return { name, via, owner: st.owner, open: `ipfs://${ipfs}` };
  if (/^https:\/\/\S+$/.test(p["url"] ?? "")) return { name, via, owner: st.owner, open: p["url"] };
  // no site or link: its holder's page, in the Commonplace this app carries, read where this was
  const addr = (st.addr ?? st.owner).toLowerCase();
  return { name, via, owner: st.owner, page: addr, node: via, open: `${COMMONPLACE}/?node=${encodeURIComponent(via)}#/p/${addr}` };
}

export { fetchSite, carRoot, filesFromCar, fileFromCar } from "./site";
export { listSites, siteFace, DIRECTORY } from "./directory";
export { packFolder } from "./pack";
