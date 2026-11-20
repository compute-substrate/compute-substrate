// Opens .csd names for the app: a web+csd:<name> link clicked anywhere on this computer comes here,
// is looked up, and opens where the name points.
//
// The names are Cairn's (CNS, by InverseAltruism): an on-chain convention on Compute Substrate whose
// rules and reference resolver are @inversealtruism/cairnx-core. This only reads them:
//   1. Cairn's server lists the transactions in the name's history (hints, not trusted). When it
//      doesn't answer, the app reads the network's whole CairnX history from its own node instead
//      (`/events/cairnx:v1/...`), so names keep working without Cairn's server.
//   2. Each one is read from THIS computer's own node, which has checked every block itself, and
//      must hash to its txid; its signer is the key whose signature is on it.
//   3. The events are replayed through cairnx-core's own resolver.
// What a name points to: its profile's `contenthash` (ipfs://<CIDv1>, a site), `url` (a link), else
// its address's page.
import { resolve, paidToFromOutputs, RESERVED_NAMES, ACTIVATION_HEIGHT } from "@inversealtruism/cairnx-core";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { ripemd160 } from "@noble/hashes/legacy";

let NODE = "http://127.0.0.1:8789";
// which node names are read through (the app uses its own; a door, its own RPC)
export function useNode(url: string) { NODE = url.replace(/\/$/, ""); }
const CAIRN = "https://cairn-substrate.com";
// the copy of Commonplace this app carries, served from this computer (an example app on the network)
const COMMONPLACE = "http://localhost:8790";
const NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;
// sha256("compute-substrate-mainnet"), the node's CHAIN_ID_HASH
const CHAIN_ID = hex("0x1b17c7b04d05394674ca2c8e24f7433e251a1973cac2000c7b60966546e0b875");

function hex(h: string): Uint8Array {
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

async function getJson(url: string) {
  const r = await fetch(url, { signal: AbortSignal.timeout(15_000) });
  if (!r.ok && r.status !== 404) throw new Error(`${new URL(url).host} answered ${r.status}`);
  return r.status === 404 ? null : r.json();
}

// a transaction as the resolver's event; it must hash to its id
function eventOf(id: string, tx: Tx, height: number, pos: number) {
  if (toHex(sha256d(tx.stripped)) !== id.toLowerCase()) throw new Error("A record didn't match its id.");
  const who = signer(tx) ?? "0x" + "0".repeat(40);
  const paidTo = paidToFromOutputs(tx.outputs.map(o => ({ addr: o.addr, value: Number(o.value) })));
  if (tx.app.kind === "propose") return { kind: "propose", id: id.toLowerCase(), proposer: who, uri: tx.app.uri, payloadHash: tx.app.payloadHash, expiresEpoch: tx.app.expiresEpoch, height, pos, paidTo };
  if (tx.app.kind === "attest") return { kind: "attest", txid: id.toLowerCase(), proposalId: tx.app.proposalId, attester: who, score: tx.app.score, confidence: tx.app.confidence, height, pos, paidTo };
  return null;
}

// The network's whole CairnX history, from this computer's node, kept while the app runs
let history: { to: number; events: any[] } = { to: ACTIVATION_HEIGHT - 1, events: [] };
async function allEvents(tip: number): Promise<any[]> {
  for (let from = history.to + 1; from <= tip; from += 2000) {
    const j = await getJson(`${NODE}/events/${encodeURIComponent("cairnx:v1")}/${from}/2000`);
    if (!j?.ok) throw new Error("Cairn's server didn't answer, and your node can't list the names' history (it needs a newer node).");
    for (const e of j.events) { const ev = eventOf(e.txid, parseTx(hex(e.tx_raw)), e.height, e.pos); if (ev) history.events.push(ev); }
    history.to = Math.min(tip, from + 1999);
  }
  return history.events;
}

export type Opened = { name: string; open?: string; why?: string; owner?: string };

export async function lookup(input: string): Promise<Opened> {
  const name = input.trim().toLowerCase().replace(/^web\+csd:(\/\/)?/, "").replace(/\.csd$/, "").replace(/\/+$/, "");
  if (!NAME_RE.test(name) || RESERVED_NAMES.has(name)) return { name, why: "That isn't a .csd name." };
  const tip = (await getJson(`${NODE}/tip`))?.height ?? 0;
  let events: any[];
  const h = await getJson(`${CAIRN}/trade/api/cairnx/name-history/${encodeURIComponent(name)}`).catch(() => undefined);
  if (h && Array.isArray(h.events) && h.scopedReplaySufficient) {
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
    events = await allEvents(tip);
  }
  const st = resolve(events, tip).names[name];
  if (!st || st.expired || st.pending) return { name, why: `Nobody holds ${name}.csd${st?.expired ? " now; its lease lapsed" : ""}.` };
  const p = st.profile ?? {};
  const ipfs = /^ipfs:\/\/(b[a-z2-7]{50,100})$/.exec(p["contenthash"] ?? "")?.[1];
  if (ipfs) return { name, owner: st.owner, open: `ipfs://${ipfs}` };
  if (/^https:\/\/\S+$/.test(p["url"] ?? "")) return { name, owner: st.owner, open: p["url"] };
  const addr = (st.addr ?? st.owner).toLowerCase();
  return { name, owner: st.owner, open: `${COMMONPLACE}/?node=${encodeURIComponent(NODE)}#/p/${addr}` };
}

export { fetchSite } from "./site";
