// Doorway's key: one key, one balance, for every site opened through Doorway. Sites ask for a
// write at their own address (/.doorway/write on <name>.localhost); the window shows what's asked,
// and signs only once it's allowed. The key never reaches a site.
import { connect, claimInvite, openInvites } from "../../../kit/src/index";
import { buildAppTx, buildSplitTx, bytesToHex, concat, hexToBytes, keyFromPrivate, sha256d, utf8, EPOCH_LEN, MIN_FEE_ATTEST, MIN_FEE_PROPOSE, type AppPayload, type Hex } from "../../../kit/src/core";
import { DIRECTORY } from "./directory";
import { keepRecord, keptSites, heightToDate } from "../../../kit/src/keep";
export { keptSites, heightToDate };
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";

// the most one write may cost without the person typing it in somewhere else
export const MAX_FEE = 100_000_000n; // 1 CSD

export function newKey(): { key: Hex; address: Hex } {
  const key = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
  return { key, address: keyFromPrivate(hexToBytes(key)).addr20 };
}
export function addressOf(key: string): Hex {
  if (!/^(0x)?[0-9a-f]{64}$/i.test(key.trim())) throw new Error("That isn't a key backup: it's 64 hex characters.");
  return keyFromPrivate(hexToBytes(("0x" + key.trim().replace(/^0x/i, "")) as Hex)).addr20;
}

// What a site asked for, read strictly: a record (propose) or an attestation, and its fee
// `burn`: CSD sent to the all-zero address, which nobody can spend; only for keeping a site
// (csd.keep), a year for every 0.25 CSD
export type Ask = { app: AppPayload; fee: bigint; burn: bigint };
const BURN = ("0x" + "00".repeat(20)) as Hex;
export const isKeep = (a: Ask) => a.app.kind === "propose" && a.app.domain === "csd.keep";
export function readAsk(body: any): Ask {
  const a = body?.app, fee = BigInt(String(body?.fee ?? "0")), burn = BigInt(String(body?.burn ?? "0"));
  let app: AppPayload;
  if (a?.kind === "propose") {
    const domain = String(a.domain ?? ""), uri = String(a.uri ?? "");
    if (!domain || utf8(domain).length > 128 || !uri || utf8(uri).length > 512) throw new Error("bad record");
    const ph = hexToBytes(String(a.payloadHash ?? ""));
    if (ph.length !== 32) throw new Error("bad record");
    app = { kind: "propose", domain, uri, payloadHash: ph, expiresEpoch: BigInt(String(a.expiresEpoch ?? "0")) };
    if (fee < MIN_FEE_PROPOSE) throw new Error("fee too low");
  } else if (a?.kind === "attest") {
    const id = String(a.proposalId ?? "").toLowerCase();
    if (!/^0x[0-9a-f]{64}$/.test(id)) throw new Error("bad attestation");
    const score = Number(a.score), confidence = Number(a.confidence ?? 1);
    if (![score, confidence].every(n => Number.isInteger(n) && n >= 0 && n <= 0xffffffff)) throw new Error("bad attestation");
    app = { kind: "attest", proposalId: id as Hex, score, confidence };
    if (fee < MIN_FEE_ATTEST) throw new Error("fee too low");
  } else throw new Error("Doorway signs records and attestations only.");
  if (fee > MAX_FEE) throw new Error("That costs more than 1 CSD, which Doorway doesn't sign for a site.");
  if (burn < 0n) throw new Error("bad record");
  if (burn > 0n) {
    // only keeping a site burns, whole years of it, and never more than 1000
    if (app.kind !== "propose" || app.domain !== "csd.keep" || !/^ipfs:\/\/b[a-z2-7]{50,100}$/.test(app.uri)) throw new Error("Doorway burns CSD only to keep a site.");
    if (burn % MIN_FEE_PROPOSE !== 0n || burn / MIN_FEE_PROPOSE > 999n) throw new Error("bad keep record");
  }
  return { app, fee, burn };
}

// Sign and send, through `node`. "Not enough CSD" is worded as the kit words it, so pages show
// their ways to get some.
export async function send(node: string, key: Hex, ask: Ask): Promise<Hex> {
  const net = connect({ node });
  const k = keyFromPrivate(hexToBytes(key));
  const utxos = await net.api.utxos(k.addr20);
  const cost = ask.fee + (ask.burn ?? 0n);
  if (utxos.reduce((s, u) => s + u.value, 0n) < cost) throw new Error(`Not enough CSD at ${k.addr20}: writing this costs ${Number(cost) / 1e8} CSD.`);
  const tx = ask.burn ? buildSplitTx(utxos, k, [{ to: BURN, value: ask.burn }], ask.fee, ask.app) : buildAppTx(utxos, k, ask.app, ask.fee);
  return (await net.api.submit(tx)).toLowerCase() as Hex;
}

// That this key controls its address, for a trade on the CSD/USDC market (the kit's top-up): CSD
// can only be delivered to it, so there's nothing to approve
export function prove(key: Hex, authHash: string) {
  const h = hexToBytes(authHash as Hex);
  if (h.length !== 32) throw new Error("bad trade");
  const priv = hexToBytes(key);
  const s = secp256k1.sign(keccak_256(concat(utf8("AON CSD/USDC: I control this CSD address for trade "), h)), priv, { lowS: true });
  return { pubKey: bytesToHex(secp256k1.getPublicKey(priv, false).slice(1)), sig: bytesToHex(concat(s.toCompactRawBytes(), new Uint8Array([27 + s.recovery]))) };
}

export async function balance(node: string, address: Hex): Promise<number> {
  return connect({ node }).balance(address);
}

// A newcomer's welcome: one of the invites people left in the shared pool, onto this key
export async function welcomeKey(node: string, address: Hex): Promise<number | null> {
  const net = connect({ node });
  if ((await net.api.utxos(address)).length) return null;
  const open = await openInvites(net as any);
  while (open.length) {
    const [pick] = open.splice(Math.floor(Math.random() * open.length), 1);
    try { return (await claimInvite(net as any, pick.code, address)).csd; } catch { /* taken a moment ago */ }
  }
  return null;
}

// Words for what a site asks
export function describe(ask: Ask): string {
  const csd = `${Number(ask.fee + (ask.burn ?? 0n)) / 1e8} CSD`;
  if (isKeep(ask) && ask.app.kind === "propose") {
    const years = 1 + Number((ask.burn ?? 0n) / MIN_FEE_PROPOSE);
    return `Keep the site ${ask.app.uri.slice(7, 19)}… up for ${years} more year${years === 1 ? "" : "s"}, for ${csd}`;
  }
  if (ask.app.kind === "propose") return `Write "${ask.app.uri.length > 140 ? ask.app.uri.slice(0, 140) + "…" : ask.app.uri}" under ${ask.app.domain}, for ${csd}`;
  if (ask.app.kind === "attest") return `Attest ${ask.app.score} to record ${ask.app.proposalId.slice(0, 10)}…, for ${csd}`;
  return csd;
}

// Recommending a site in the directory: the first recommendation is a record naming it, the rest
// attest to that record (see directory.ts)
export function recommendAsk(site: { key: string; listing: string | null }, tip: number): Ask {
  if (site.listing) return { app: { kind: "attest", proposalId: site.listing as Hex, score: 1, confidence: 1 }, fee: MIN_FEE_ATTEST, burn: 0n };
  return { app: { kind: "propose", domain: DIRECTORY, uri: site.key, payloadHash: sha256d(utf8(site.key)), expiresEpoch: BigInt(Math.floor(tip / EPOCH_LEN)) + 10_000_000n }, fee: MIN_FEE_PROPOSE, burn: 0n };
}

// Keeping a site, with Doorway's own key (the kit's keepRecord)
export function keepAsk(cid: string, years: number, tip: number): Ask {
  return keepRecord(cid, years, tip);
}

// Every site someone keeps, read through `node`: its address -> the block it's kept until, the tip,
// and when that is as a date
const apis = new Map<string, any>();
export async function kept(node: string): Promise<{ tip: number; until: Map<string, number> }> {
  let api = apis.get(node);
  if (!api) apis.set(node, api = connect({ node }).api);
  return keptSites(api);
}
