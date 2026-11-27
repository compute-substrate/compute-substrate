// Letters: private correspondence kept by the network itself, and nothing else. Every part of a
// letter is a record on Compute Substrate, so as long as the network runs, a key can read back
// every letter it ever sent or got, from the records alone.
//
// A convention (nothing here is consensus), in two topics:
//
//   csd.letterbox  four records that open a key's letterbox: its two letter keys (X25519, and
//                  ML-KEM-768 for the day classical keys can be broken), split across records
//                  because a record holds 512 bytes. A letterbox is what lets strangers write to you.
//
//   csd.letters    two kinds of record:
//     opening      four records that start a conversation between two keys: an X25519 exchange
//                  and an ML-KEM-768 encapsulation to the other's letterbox, which together give
//                  both a shared secret (and a copy of that secret sealed for the writer, so the
//                  writer can recover it from the records too). Once per pair, either way round.
//     note         one record per part of a letter, sealed with the conversation's secret: about
//                  330 characters each, every one padded to the same size. A reply is just notes.
//
// Nothing in a record says who it's to. A recipient recognises an opening by a tag only its key
// can compute, and a note by a tag only the two in the conversation can compute. Who wrote a record
// is public (the network records its writer), and so is when; who it's for and what it says aren't.
// Letters can't be unsent, and a key that leaks later opens every letter it could read.
//
// The letter keys come from Doorway's key, so a key's backup restores its letters too.
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { keyFromPrivate, hexToBytes, bytesToHex, concat, utf8, sha256d, deserializeTx, signerOf, EPOCH_LEN, MIN_FEE_PROPOSE, MIN_SEND, buildAppTx, buildSplitTx, type Hex, type Utxo, type AppPayload } from "../../../kit/src/core";
import { connect } from "../../../kit/src/index";

export const LETTERBOX = "csd.letterbox";
export const LETTERS = "csd.letters";
// letters began here: nothing earlier is read
export const LETTERS_FROM = 149_000;
const URI_MAX = 512;
const CHUNK = 490;            // base64url characters of data per multi-part record, under 512 with its header
const NOTE_PLAIN = 343;       // bytes of plaintext per note: a note's uri is then within 512
const NOTE_HEAD = 17;         // message id 8, part 1, parts 1, time 6, flags 1
export const NOTE_TEXT = NOTE_PLAIN - NOTE_HEAD;

const b64u = (b: Uint8Array) => { let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const unb64u = (s: string) => { const t = s.replace(/-/g, "+").replace(/_/g, "/"); return Uint8Array.from(atob(t + "=".repeat((4 - t.length % 4) % 4)), c => c.charCodeAt(0)); };
const info = (s: string) => utf8(`csd.letters/v2 ${s}`);
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const low = (a: string) => a.toLowerCase() as Hex;

async function gcm(key: Uint8Array, nonce: Uint8Array, data: Uint8Array, open: boolean): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, [open ? "decrypt" : "encrypt"]);
  const out = await (open ? crypto.subtle.decrypt : crypto.subtle.encrypt).call(crypto.subtle, { name: "AES-GCM", iv: nonce as BufferSource }, k, data as BufferSource);
  return new Uint8Array(out);
}

// ── Keys ───────────────────────────────────────────────────────────────────────────────────────
export type LetterKeys = { x: { secret: Uint8Array; public: Uint8Array }; kem: { secretKey: Uint8Array; publicKey: Uint8Array }; self: Uint8Array };
export type Letterbox = { x25519: Uint8Array; mlkem: Uint8Array };

export function letterKeys(key: Hex): LetterKeys {
  const seed = hkdf(sha256, hexToBytes(key), utf8("csd.letters"), info("keys"), 128);
  const xs = seed.slice(0, 32);
  return { x: { secret: xs, public: x25519.getPublicKey(xs) }, kem: ml_kem768.keygen(seed.slice(32, 96)), self: seed.slice(96, 128) };
}

// ── Records: what goes in a uri ────────────────────────────────────────────────────────────────
// a multi-part record: <kind>.<group>.<part>.<parts>.<data>
function parts(kind: string, group: string, data: Uint8Array): string[] {
  const s = b64u(data), n = Math.ceil(s.length / CHUNK);
  return Array.from({ length: n }, (_, i) => `${kind}.${group}.${i}.${n}.${s.slice(i * CHUNK, (i + 1) * CHUNK)}`);
}
const PART = /^(lb2|lo2)\.([A-Za-z0-9_-]{11})\.(\d)\.(\d)\.([A-Za-z0-9_-]+)$/;

export type Rec = { id: string; proposer: Hex; uri: string; height: number; pos: number };

// the parts of each group, put back together, from records by one writer
function joined(recs: Rec[], kind: string): { proposer: Hex; group: string; data: Uint8Array; height: number; pos: number }[] {
  const groups = new Map<string, { proposer: Hex; group: string; n: number; got: Map<number, string>; height: number; pos: number }>();
  for (const r of recs) {
    const m = PART.exec(r.uri);
    if (!m || m[1] !== kind) continue;
    const k = `${r.proposer}|${m[2]}`, n = Number(m[4]);
    const g = groups.get(k) ?? { proposer: r.proposer, group: m[2], n, got: new Map(), height: 0, pos: 0 };
    if (g.n !== n) continue;
    if (!g.got.has(Number(m[3]))) g.got.set(Number(m[3]), m[5]);
    if (r.height > g.height || (r.height === g.height && r.pos > g.pos)) { g.height = r.height; g.pos = r.pos; }
    groups.set(k, g);
  }
  const out = [];
  for (const g of groups.values()) {
    if (g.got.size !== g.n) continue;
    try { out.push({ proposer: g.proposer, group: g.group, data: unb64u(Array.from({ length: g.n }, (_, i) => g.got.get(i)!).join("")), height: g.height, pos: g.pos }); } catch {}
  }
  return out;
}

// A letterbox: its records
export function letterboxUris(k: LetterKeys): string[] {
  return parts("lb2", b64u(rand(8)), concat(k.x.public, k.kem.publicKey));
}
// Every key's newest letterbox, from csd.letterbox records
export function letterboxes(recs: Rec[]): Map<Hex, Letterbox> {
  const out = new Map<Hex, Letterbox & { at: number }>();
  for (const g of joined(recs, "lb2")) {
    if (g.data.length !== 32 + 1184) continue;
    const at = g.height * 1e6 + g.pos, had = out.get(g.proposer);
    if (!had || had.at < at) out.set(g.proposer, { x25519: g.data.slice(0, 32), mlkem: g.data.slice(32), at });
  }
  return new Map([...out].map(([a, b]) => [a, { x25519: b.x25519, mlkem: b.mlkem }]));
}

// A conversation between two keys: who started it, who it's with, and the secret they share
export type Conversation = { id: string; a: Hex; b: Hex; secret: Uint8Array; height: number };

const secretOf = (xs: Uint8Array, ks: Uint8Array, group: string, a: Hex, b: Hex) =>
  hkdf(sha256, concat(xs, ks), utf8(group), info(`conversation ${low(a)} ${low(b)}`), 32);

// Starting a conversation with `to`: its records, and the conversation (for the notes that follow)
export async function openingUris(key: Hex, to: Hex, box: Letterbox): Promise<{ uris: string[]; conversation: Conversation }> {
  const me = low(keyFromPrivate(hexToBytes(key)).addr20), k = letterKeys(key), group = b64u(rand(8));
  const es = x25519.utils.randomPrivateKey(), eph = x25519.getPublicKey(es);
  const xs = x25519.getSharedSecret(es, box.x25519);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(box.mlkem);
  const secret = secretOf(xs, sharedSecret, group, me, low(to));
  // the secret, and who it's with, sealed for the writer: recoverable from the records with the
  // writer's key alone
  const n = rand(12), mine = concat(n, await gcm(k.self, n, concat(secret, hexToBytes(low(to))), false));
  const tag = hkdf(sha256, xs, undefined, info("opening tag"), 9);
  // eph 32 | tag 9 | sealed for the writer 80 | ML-KEM ciphertext 1088
  return { uris: parts("lo2", group, concat(eph, tag, mine, cipherText)), conversation: { id: group, a: me, b: low(to), secret, height: 0 } };
}

// The conversations this key is in, from csd.letters records: those it started (its own sealed
// copy of the secret) and those started with it (its tag, then its keys)
export async function conversations(key: Hex, recs: Rec[]): Promise<Conversation[]> {
  const me = low(keyFromPrivate(hexToBytes(key)).addr20), k = letterKeys(key), out: Conversation[] = [];
  for (const g of joined(recs, "lo2")) {
    if (g.data.length !== 32 + 9 + 80 + 1088) continue;
    const eph = g.data.slice(0, 32), tag = g.data.slice(32, 41), mine = g.data.slice(41, 121), ct = g.data.slice(121);
    try {
      if (g.proposer === me) {
        const opened = await gcm(k.self, mine.slice(0, 12), mine.slice(12), true);
        out.push({ id: g.group, a: me, b: low(bytesToHex(opened.slice(32, 52))), secret: opened.slice(0, 32), height: g.height });
        continue;
      }
      const xs = x25519.getSharedSecret(k.x.secret, eph);
      if (!eq(hkdf(sha256, xs, undefined, info("opening tag"), 9), tag)) continue;
      const ks = ml_kem768.decapsulate(ct, k.kem.secretKey);
      out.push({ id: g.group, a: g.proposer, b: me, secret: secretOf(xs, ks, g.group, g.proposer, me), height: g.height });
    } catch {}
  }
  return out;
}

// ── Notes ──────────────────────────────────────────────────────────────────────────────────────
export type Letter = { id: string; conversation: string; from: Hex; to: Hex; at: number; subject: string; body: string; re?: string; height: number };

const noteKey = (c: Conversation) => hkdf(sha256, c.secret, undefined, info("note"), 32);
const noteTag = (c: Conversation, nonce: Uint8Array) => hkdf(sha256, c.secret, nonce, info("note tag"), 9);
const NOTE = /^ln2\.([A-Za-z0-9_-]{12})\.([A-Za-z0-9_-]+)$/;

// A letter in a conversation: one record per ~330 characters
export async function noteUris(c: Conversation, letter: { subject: string; body: string; re?: string }): Promise<string[]> {
  const re = letter.re && /^[0-9a-f]{16}$/.test(letter.re) ? hexToBytes(`0x${letter.re}`) : null;
  const clean = (t: string) => t.replace(/[\u0000\u001f]/g, " ");
  const text = utf8(`${clean(letter.subject)}\u001f${letter.body.replace(/\u0000/g, "")}`);
  const room0 = NOTE_TEXT - (re ? 8 : 0);
  const chunks: Uint8Array[] = [text.slice(0, room0)];
  for (let o = room0; o < text.length; o += NOTE_TEXT) chunks.push(text.slice(o, o + NOTE_TEXT));
  if (chunks.length > 99) throw new Error("That letter is too long.");
  const id = rand(8), at = Date.now(), k = noteKey(c), out: string[] = [];
  for (let i = 0; i < chunks.length; i++) {
    const plain = new Uint8Array(NOTE_PLAIN);
    plain.set(id, 0); plain[8] = i; plain[9] = chunks.length;
    for (let j = 0, t = at; j < 6; j++, t = Math.floor(t / 256)) plain[10 + j] = t % 256;
    plain[16] = i === 0 && re ? 1 : 0;
    let o = NOTE_HEAD;
    if (i === 0 && re) { plain.set(re, o); o += 8; }
    plain.set(chunks[i], o);
    const nonce = rand(12);
    const sealed = concat(nonce, await gcm(k, nonce, plain, false));
    out.push(`ln2.${b64u(noteTag(c, nonce))}.${b64u(sealed)}`);
  }
  return out;
}

// The letters in these conversations, from csd.letters records, put together from their parts.
// A note counts only when its writer is one of the conversation's two keys.
export async function letters(convs: Conversation[], recs: Rec[]): Promise<Letter[]> {
  const keys = convs.map(c => ({ c, k: noteKey(c) }));
  const msgs = new Map<string, { c: Conversation; from: Hex; n: number; at: number; re?: string; got: Map<number, Uint8Array>; height: number }>();
  for (const r of recs) {
    const m = NOTE.exec(r.uri);
    if (!m) continue;
    let sealed: Uint8Array, tag: Uint8Array;
    try { sealed = unb64u(m[2]); tag = unb64u(m[1]); } catch { continue; }
    if (sealed.length < 12 + 16) continue;
    const nonce = sealed.slice(0, 12);
    for (const { c, k } of keys) {
      if (!eq(noteTag(c, nonce), tag)) continue;
      let plain: Uint8Array;
      try { plain = await gcm(k, nonce, sealed.slice(12), true); } catch { break; }
      if (r.proposer !== c.a && r.proposer !== c.b) break;
      const id = `${c.id}.${bytesToHex(plain.slice(0, 8)).slice(2)}`;
      const i = plain[8], n = plain[9];
      let at = 0; for (let j = 5; j >= 0; j--) at = at * 256 + plain[10 + j];
      const g = msgs.get(id) ?? { c, from: r.proposer, n, at, re: undefined as string | undefined, got: new Map<number, Uint8Array>(), height: r.height };
      if (g.from !== r.proposer || g.n !== n || i >= n) break;
      let o = NOTE_HEAD;
      if (i === 0 && plain[16] & 1) { g.re = bytesToHex(plain.slice(o, o + 8)).slice(2); o += 8; }
      let end = plain.length; while (end > o && plain[end - 1] === 0) end--;
      g.got.set(i, plain.slice(o, end));
      g.height = Math.max(g.height, r.height);
      msgs.set(id, g);
      break;
    }
  }
  const out: Letter[] = [];
  for (const [id, g] of msgs) {
    if (g.got.size !== g.n) continue;
    const text = new TextDecoder().decode(concat(...Array.from({ length: g.n }, (_, i) => g.got.get(i)!)));
    const cut = text.indexOf("\u001f");
    const other = g.from === g.c.a ? g.c.b : g.c.a;
    out.push({ id, conversation: g.c.id, from: g.from, to: other, at: g.at, subject: cut < 0 ? "" : text.slice(0, cut), body: cut < 0 ? text : text.slice(cut + 1), ...(g.re ? { re: g.re } : {}), height: g.height });
  }
  return out.sort((a, b) => b.at - a.at);
}
// a letter's short id, as a reply refers to it
export const shortId = (l: Letter) => l.id.split(".")[1];

// ── On the network ─────────────────────────────────────────────────────────────────────────────
async function getJson(url: string, ms = 60_000): Promise<any> {
  const r = await fetch(url, { signal: AbortSignal.timeout(ms) });
  if (!r.ok) throw new Error(`NODE_${r.status}`);
  return r.json();
}

// A topic's records from `from` to the tip, each checked: its transaction decodes, and its writer's
// signature is good (so a node or door passing them on can leave records out, but can't forge one)
export async function records(node: string, topic: string, from: number, tip: number): Promise<Rec[]> {
  const out: Rec[] = [], froms: number[] = [];
  for (let f = from; f <= tip; f += 2000) froms.push(f);
  for (let i = 0; i < froms.length; i += 6) {
    const got = await Promise.all(froms.slice(i, i + 6).map(f => getJson(`${node}/events/${encodeURIComponent(topic)}/${f}/2000`)));
    for (const j of got) {
      if (!j?.ok) throw new Error("This node can't list records (it needs a newer version).");
      for (const e of j.events ?? []) {
        try {
          const tx = deserializeTx(hexToBytes(String(e.tx_raw).replace(/^(0x)?/, "0x") as Hex));
          if (tx.app.kind !== "propose" || tx.app.domain !== topic) continue;
          const who = signerOf(tx);
          if (!who) continue;
          out.push({ id: String(e.txid).toLowerCase(), proposer: low(who), uri: tx.app.uri, height: Number(e.height), pos: Number(e.pos ?? 0) });
        } catch {}
      }
    }
  }
  return out;
}

export type Ask = { app: AppPayload; fee: bigint };
export const recordAsk = (topic: string, uri: string, tip: number): Ask => {
  if (utf8(uri).length > URI_MAX) throw new Error("RECORD_TOO_LONG");
  return { app: { kind: "propose", domain: topic, uri, payloadHash: sha256d(utf8(uri)), expiresEpoch: BigInt(Math.floor(tip / EPOCH_LEN)) + 10_000_000n }, fee: MIN_FEE_PROPOSE };
};

// What writing these records costs, in CSD (each record's fee; the coins made for them come back)
export const costOf = (n: number) => Number(BigInt(n) * MIN_FEE_PROPOSE) / 1e8;

// Several records, written as quickly as the network allows. The first also splits off a coin for
// each of the others, so they all go in the next block (a key can't spend change before it's in a
// block, so one record after another would take a block each). `step` says how it's going.
export async function writeAll(node: string, key: Hex, asks: Ask[], step: (s: string) => void = () => {}, sent?: (f: { txid: string; inputs: string[]; change: number; at: number }) => void): Promise<string[]> {
  const net = connect({ node }), k = keyFromPrivate(hexToBytes(key));
  const each = MIN_FEE_PROPOSE + MIN_SEND;
  const need = asks.reduce((s, a) => s + a.fee, 0n) + MIN_SEND * BigInt(asks.length);
  const utxos: Utxo[] = await net.api.utxos(k.addr20);
  if (utxos.reduce((s, u) => s + u.value, 0n) < need) throw new Error(`Not enough CSD at ${k.addr20}: this needs ${Number(need) / 1e8} CSD.`);
  const note = (tx: any, txid: string) => sent?.({ txid, inputs: tx.inputs.map((i: any) => `${String(i.txid).toLowerCase()}:${i.vout}`), change: Number(tx.outputs.filter((o: any) => low(o.addr20) === low(k.addr20)).reduce((s: bigint, o: any) => s + o.value, 0n)) / 1e8, at: Date.now() });
  const ids: string[] = [];
  // the first record, and a coin for each of the rest
  const first = asks.length > 1
    ? buildSplitTx(utxos, k, asks.slice(1).map(() => ({ to: k.addr20, value: each })), asks[0].fee, asks[0].app)
    : buildAppTx(utxos, k, asks[0].app, asks[0].fee);
  const firstId = (await net.api.submit(first)).toLowerCase();
  note(first, firstId); ids.push(firstId);
  if (asks.length === 1) return ids;
  step(`Sent 1 of ${asks.length}. The rest go with the next block, in a minute or two…`);
  // the coins it made, once they're in a block
  let coins: Utxo[] = [];
  for (let t = 0; t < 40; t++) {
    coins = (await net.api.utxos(k.addr20)).filter(u => u.txid.toLowerCase() === firstId && u.value === each);
    if (coins.length >= asks.length - 1) break;
    await new Promise(r => setTimeout(r, 15_000));
  }
  if (coins.length < asks.length - 1) throw new Error("The first part is sent, but the network is slow to take it. Doorway tries the rest again later.");
  for (let i = 1; i < asks.length; i++) {
    const tx = buildAppTx([coins[i - 1]], k, asks[i].app, asks[i].fee);
    const id = (await net.api.submit(tx)).toLowerCase();
    note(tx, id); ids.push(id);
    step(`Sent ${i + 1} of ${asks.length}…`);
  }
  return ids;
}
