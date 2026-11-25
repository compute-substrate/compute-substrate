// Letters: slow, private correspondence between keys, with nobody in the middle.
//
// A convention on Compute Substrate (nothing here is consensus):
//
//   csd.letterbox  a record that opens a key's letterbox: its uri is ar://<id> of a small public
//                  document holding the key's two letter keys (X25519, and ML-KEM-768 for the day
//                  classical keys can be broken). The record's writer is the letterbox's owner.
//   csd.letters    a record per letter: its uri is ar://<id>#<eph>.<tag>, the encrypted letter on
//                  Arweave, plus a tag only the recipient can recognise. Nothing in it says who
//                  the letter is for.
//
// Both letter keys come from Doorway's key, so a key's backup restores its letters too.
//
// A letter is encrypted once, with a fresh content key, and that key is wrapped for each reader:
// the recipient, and the writer (so the writer can read what they sent). Each wrap combines an
// X25519 exchange with an ML-KEM-768 encapsulation, so reading it needs breaking both. The letter
// inside is signed by the writer's key, so the recipient knows who wrote it; only the recipient
// can see that signature.
//
// What stays public: that a key wrote a letter, when, and roughly how long it is (lengths are
// padded to whole kilobytes). Who it's to, and what it says, aren't. What can't be done: unsend,
// or rotate a key and protect past letters. Letters are kept for good, so a key that leaks later
// opens every letter it could read.
import { x25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { keyFromPrivate, hexToBytes, bytesToHex, concat, utf8, hash160, sha256d, EPOCH_LEN, MIN_FEE_PROPOSE, type Hex } from "../../../kit/src/core";
import { upload, readAr } from "./arweave";
import type { Ask } from "./wallet";

export const LETTERBOX = "csd.letterbox";
export const LETTERS = "csd.letters";
const V = 1;
const PAD = 1024;

const b64u = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s: string) => { const t = s.replace(/-/g, "+").replace(/_/g, "/"); return Uint8Array.from(atob(t + "=".repeat((4 - t.length % 4) % 4)), c => c.charCodeAt(0)); };
const info = (s: string) => utf8(`csd.letters/v${V} ${s}`);
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

export type LetterKeys = { x: { secret: Uint8Array; public: Uint8Array }; kem: { secretKey: Uint8Array; publicKey: Uint8Array } };
export type Letterbox = { x25519: Uint8Array; mlkem: Uint8Array };

// The two letter keys, from Doorway's key
export function letterKeys(key: Hex): LetterKeys {
  const seed = hkdf(sha256, hexToBytes(key), utf8("csd.letters"), info("keys"), 96);
  const xs = seed.slice(0, 32);
  return { x: { secret: xs, public: x25519.getPublicKey(xs) }, kem: ml_kem768.keygen(seed.slice(32)) };
}

// The public document a letterbox record points to
export function letterboxDoc(k: LetterKeys): Uint8Array {
  return utf8(JSON.stringify({ v: V, x25519: b64u(k.x.public), mlkem768: b64u(k.kem.publicKey) }));
}
export function readLetterbox(doc: Uint8Array): Letterbox {
  const j = JSON.parse(new TextDecoder().decode(doc));
  if (j?.v !== V) throw new Error("not a letterbox");
  const x = unb64u(String(j.x25519 ?? "")), m = unb64u(String(j.mlkem768 ?? ""));
  if (x.length !== 32 || m.length !== 1184) throw new Error("not a letterbox");
  return { x25519: x, mlkem: m };
}

async function gcm(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, open: boolean): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, [open ? "decrypt" : "encrypt"]);
  const out = await (open ? crypto.subtle.decrypt : crypto.subtle.encrypt).call(crypto.subtle, { name: "AES-GCM", iv: nonce as BufferSource }, k, data as BufferSource);
  return new Uint8Array(out);
}

// the recipient's tag: recognisable with the recipient's X25519 key alone, so an inbox is found
// from the records, without fetching every letter
const tagOf = (xShared: Uint8Array) => hkdf(sha256, xShared, undefined, info("tag"), 12);

type Wrap = { e: string; k: string; w: string };
async function wrapFor(box: Letterbox, contentKey: Uint8Array): Promise<{ wrap: Wrap; eph: Uint8Array; tag: Uint8Array }> {
  const es = x25519.utils.randomPrivateKey(), eph = x25519.getPublicKey(es);
  const xs = x25519.getSharedSecret(es, box.x25519);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(box.mlkem);
  const kek = hkdf(sha256, concat(xs, sharedSecret), concat(eph, box.x25519), info("wrap"), 32);
  // each wrap key is used once, so a fixed nonce is safe
  const w = await gcm(kek, new Uint8Array(12), contentKey, false);
  return { wrap: { e: b64u(eph), k: b64u(cipherText), w: b64u(w) }, eph, tag: tagOf(xs) };
}
async function unwrap(k: LetterKeys, wrap: Wrap): Promise<Uint8Array | null> {
  try {
    const eph = unb64u(wrap.e);
    const xs = x25519.getSharedSecret(k.x.secret, eph);
    const ms = ml_kem768.decapsulate(unb64u(wrap.k), k.kem.secretKey);
    const kek = hkdf(sha256, concat(xs, ms), concat(eph, k.x.public), info("wrap"), 32);
    return await gcm(kek, new Uint8Array(12), unb64u(wrap.w), true);
  } catch { return null; }
}

export type Letter = { from: Hex; to: Hex; at: number; subject: string; body: string; re?: string };

// what's signed: the letter without its signature, in a fixed order
const signed = (l: Letter) => utf8(JSON.stringify([V, l.from.toLowerCase(), l.to.toLowerCase(), l.at, l.subject, l.body, l.re ?? ""]));

// A letter, sealed for `to` (and for the writer): the bytes for Arweave, and what the record's
// uri carries after the Arweave id (#<eph>.<tag>)
export async function seal(key: Hex, toAddress: Hex, toBox: Letterbox, letter: { subject: string; body: string; re?: string }): Promise<{ bytes: Uint8Array; hint: string }> {
  const me = letterKeys(key), from = keyFromPrivate(hexToBytes(key)).addr20;
  const l: Letter = { from, to: toAddress, at: Date.now(), subject: letter.subject, body: letter.body, ...(letter.re ? { re: letter.re } : {}) };
  const sig = secp256k1.sign(sha256(signed(l)), hexToBytes(key), { lowS: true });
  const plain = utf8(JSON.stringify({ v: V, ...l, pub: bytesToHex(secp256k1.getPublicKey(hexToBytes(key), true)), sig: bytesToHex(sig.toCompactRawBytes()) }));
  // padded to whole kilobytes (zeros after the JSON), so a letter's length says little
  const padded = new Uint8Array(Math.ceil((plain.length + 1) / PAD) * PAD);
  padded.set(plain);
  const ck = crypto.getRandomValues(new Uint8Array(32)), nonce = crypto.getRandomValues(new Uint8Array(12));
  const c = await gcm(ck, nonce, padded, false);
  const them = await wrapFor(toBox, ck);
  const mine = await wrapFor({ x25519: me.x.public, mlkem: me.kem.publicKey }, ck);
  // the two wraps in a random order: which reader is which isn't written down
  const wraps = Math.random() < 0.5 ? [them.wrap, mine.wrap] : [mine.wrap, them.wrap];
  const bytes = utf8(JSON.stringify({ v: V, n: b64u(nonce), c: b64u(c), r: wraps }));
  return { bytes, hint: `${b64u(them.eph)}.${b64u(them.tag)}` };
}

// Whether a letters record is for this key, from its uri alone
export function isForMe(k: LetterKeys, uri: string): boolean {
  const m = /^ar:\/\/[A-Za-z0-9_-]{43}#([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{16})$/.exec(uri);
  if (!m) return false;
  try { return eq(tagOf(x25519.getSharedSecret(k.x.secret, unb64u(m[1]))), unb64u(m[2])); } catch { return false; }
}
export const arId = (uri: string) => /^ar:\/\/([A-Za-z0-9_-]{43})/.exec(uri)?.[1] ?? null;

export type Opened = Letter & { signedBy: Hex };
// A letter this key can read (as its recipient or its writer), checked: its signature is the
// writer's, and the writer is who the record says wrote it (`writer`, the record's proposer).
// Null when it isn't for this key, or doesn't check out.
export async function openLetter(key: Hex, bytes: Uint8Array, writer?: Hex): Promise<Opened | null> {
  let j: any;
  try { j = JSON.parse(new TextDecoder().decode(bytes)); } catch { return null; }
  if (j?.v !== V || !Array.isArray(j.r)) return null;
  const k = letterKeys(key);
  let ck: Uint8Array | null = null;
  for (const w of j.r.slice(0, 4)) if ((ck = await unwrap(k, w))) break;
  if (!ck) return null;
  let p: any;
  try {
    const padded = await gcm(ck, unb64u(String(j.n)), unb64u(String(j.c)), true);
    const end = padded.indexOf(0);
    p = JSON.parse(new TextDecoder().decode(end < 0 ? padded : padded.slice(0, end)));
  } catch { return null; }
  const l: Letter = { from: String(p.from).toLowerCase() as Hex, to: String(p.to).toLowerCase() as Hex, at: Number(p.at), subject: String(p.subject ?? ""), body: String(p.body ?? ""), ...(p.re ? { re: String(p.re) } : {}) };
  try {
    const pub = hexToBytes(String(p.pub) as Hex);
    if (!secp256k1.verify(hexToBytes(String(p.sig) as Hex), sha256(signed(l)), pub, { lowS: true })) return null;
    const by = bytesToHex(hash160(pub)).toLowerCase() as Hex;
    if (by !== l.from) return null;
    if (writer && writer.toLowerCase() !== l.from) return null;
    // a letter that lists someone else as its recipient was forwarded, not written to this key
    const me = keyFromPrivate(hexToBytes(key)).addr20.toLowerCase();
    if (l.to !== me && l.from !== me) return null;
    return { ...l, signedBy: by };
  } catch { return null; }
}

// ── On the network ──────────────────────────────────────────────────────────────────────────────
// Letters are stored on Arweave (free under 105 KB) and recorded on the network (0.25 CSD each).
// The inbox is read from the network's records: the newest letters records, filtered by the tag,
// then fetched and opened one by one.

const strip = (h: string) => h.replace(/^0x/i, "");
async function getJson(url: string, ms = 20_000): Promise<any> {
  const r = await fetch(url, { signal: AbortSignal.timeout(ms) });
  if (!r.ok) throw new Error(`NODE_${r.status}`);
  return r.json();
}
const record = (domain: string, uri: string, bytes: Uint8Array, tip: number): Ask =>
  ({ app: { kind: "propose", domain, uri, payloadHash: sha256d(bytes), expiresEpoch: BigInt(Math.floor(tip / EPOCH_LEN)) + 10_000_000n }, fee: MIN_FEE_PROPOSE, burn: 0n });

// Opening this key's letterbox: its public document stored, and the record pointing to it
export async function openBoxAsk(key: Hex, tip: number): Promise<Ask> {
  const doc = letterboxDoc(letterKeys(key));
  const id = await upload(key, doc, [{ name: "Content-Type", value: "application/json" }, { name: "App-Name", value: "Doorway Letters" }, { name: "Type", value: "letterbox" }]);
  return record(LETTERBOX, `ar://${id}`, doc, tip);
}

// An address's letterbox, the newest it opened: null when it has none
export async function findBox(node: string, address: Hex): Promise<Letterbox | null> {
  const acts = (await getJson(`${node}/address/${strip(address)}/activity?limit=500`)).activity ?? [];
  const boxes = acts.filter((a: any) => a.kind === "proposal" && a.domain === LETTERBOX && arId(String(a.uri ?? "")))
    .sort((a: any, b: any) => Number(b.height) - Number(a.height));
  for (const a of boxes) {
    try { return readLetterbox(await readAr(arId(a.uri)!, a.payload_hash)); } catch {}
  }
  return null;
}

// A letter to `to`: sealed, stored, and the record that sends it
export async function letterAsk(key: Hex, to: Hex, box: Letterbox, letter: { subject: string; body: string; re?: string }, tip: number): Promise<Ask> {
  const { bytes, hint } = await seal(key, to, box, letter);
  const id = await upload(key, bytes, [{ name: "Content-Type", value: "application/octet-stream" }, { name: "App-Name", value: "Doorway Letters" }]);
  return record(LETTERS, `ar://${id}#${hint}`, bytes, tip);
}

export type Held = Opened & { id: string; height: number; time: number };

// Letters to this key, newest first: those whose tag is this key's, opened and checked
export async function inbox(node: string, key: Hex, seen: Map<string, Held> = new Map()): Promise<Held[]> {
  const k = letterKeys(key);
  const j = await getJson(`${node}/proposals/${encodeURIComponent(LETTERS)}/500`, 60_000);
  const mine = (j.proposals ?? []).filter((p: any) => isForMe(k, String(p.uri ?? "")));
  const out: Held[] = [];
  for (const p of mine) {
    const id = String(p.proposal_id ?? p.txid).toLowerCase();
    if (seen.has(id)) { out.push(seen.get(id)!); continue; }
    try {
      // who wrote it: the record's writer, which the letter's own signature must match
      const writer = String((await getJson(`${node}/proposal/${strip(id)}`)).proposal?.proposer ?? "") as Hex;
      const l = await openLetter(key, await readAr(arId(p.uri)!, p.payload_hash), writer);
      if (l) out.push({ ...l, id, height: Number(p.height), time: Number(p.time) });
    } catch {}
  }
  return out.sort((a, b) => b.height - a.height);
}

// Letters this key sent, newest first, read back from its own records
export async function sent(node: string, key: Hex, seen: Map<string, Held> = new Map()): Promise<Held[]> {
  const me = keyFromPrivate(hexToBytes(key)).addr20.toLowerCase() as Hex;
  const acts = (await getJson(`${node}/address/${strip(me)}/activity?limit=500`)).activity ?? [];
  const out: Held[] = [];
  for (const a of acts) {
    if (a.kind !== "proposal" || a.domain !== LETTERS || !arId(String(a.uri ?? ""))) continue;
    const id = String(a.txid).toLowerCase();
    if (seen.has(id)) { out.push(seen.get(id)!); continue; }
    try {
      const l = await openLetter(key, await readAr(arId(a.uri)!, a.payload_hash), me);
      if (l) out.push({ ...l, id, height: Number(a.height), time: Number(a.time) });
    } catch {}
  }
  return out.sort((a, b) => b.height - a.height);
}
