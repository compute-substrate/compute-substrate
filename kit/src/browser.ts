// Starting with nothing installed: a key kept in the browser, and invite links to fill it.
//
//   const me = browserKey("guestbook");                  // made once, kept in this browser
//   await claimInvite(net, location.hash, me.address);   // an invite link's CSD, moved onto that key
//   await net.write(me.signer(net), "guestbook.example", "Hello");
//
// A key in the browser is the easiest way in: no wallet, no account. It's only as safe as the
// browser's storage, though: clearing site data loses it, and so does a new device. So keep small
// amounts on it, and offer `backup()` and `restore()`. A wallet (cairnSigner) is the upgrade for
// anyone with more to protect, and one identity across apps.

import { EPOCH_LEN, MIN_FEE_PROPOSE, SEND_FEE, buildAppTx, buildSendTx, buildSplitTx, bytesToHex, hexToBytes, keyFromPrivate, sha256d, utf8, type CsdKey, type Hex } from "./core";

type Net = { api: { utxos: (a: Hex) => Promise<{ txid: Hex; vout: number; value: bigint }[]>; submit: (tx: any) => Promise<Hex>; tip: () => Promise<{ height: number }>; proposalsIn: (d: string, limit?: number) => Promise<{ uri?: string; height: number | bigint }[]> } };
type Signer = { address: Hex; send: (app: any, fee: bigint) => Promise<Hex> };

const store = {
  get(k: string): string | null { try { return localStorage.getItem(k); } catch { return null; } },
  set(k: string, v: string): boolean { try { localStorage.setItem(k, v); return localStorage.getItem(k) === v; } catch { return false; } },
  del(k: string) { try { localStorage.removeItem(k); } catch {} },
};
const fresh = (): Hex => bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
const valid = (h: string | null): h is Hex => !!h && /^(0x)?[0-9a-f]{64}$/i.test(h.trim());

export type BrowserKey = {
  // the private key's place in this browser's storage, for keeping app state next to it
  slot: string;
  address: Hex;
  // false when the browser wouldn't keep it (a private window, storage blocked): it lasts this visit only
  kept: boolean;
  // something that can sign records with this key, for net.write and net.attest
  signer: (net: Net) => Signer;
  // the private key as hex, to save somewhere safe; whoever has it can write as this key and spend its CSD
  backup: () => Hex;
  // switch to a key from a backup (hex). Throws on anything that isn't one.
  restore: (privateKey: string) => void;
  // forget the key in this browser (and with it, unless backed up, its CSD)
  forget: () => void;
};

// The key this browser keeps for an app, made the first time. `app` names it, so different apps on
// the same site keep different keys.
export function browserKey(app = "csd"): BrowserKey {
  const slot = `${app}.key`;
  let priv: Hex = valid(store.get(slot)) ? (store.get(slot)!.trim().toLowerCase() as Hex) : fresh();
  if (!priv.startsWith("0x")) priv = ("0x" + priv) as Hex;
  let kept = store.get(slot)?.trim().toLowerCase().replace(/^(0x)?/, "0x") === priv || store.set(slot, priv);
  let key: CsdKey = keyFromPrivate(hexToBytes(priv));
  const me: BrowserKey = {
    slot,
    address: key.addr20,
    kept,
    signer: (net) => ({
      address: key.addr20,
      async send(app, fee) {
        const utxos = await net.api.utxos(key.addr20);
        if (utxos.reduce((s, u) => s + u.value, 0n) < fee) throw new Error(`Not enough CSD at ${key.addr20}: writing this costs ${Number(fee) / 1e8} CSD.`);
        return (await net.api.submit(buildAppTx(utxos, key, app, fee))).toLowerCase() as Hex;
      },
    }),
    backup: () => priv,
    restore(text) {
      if (!valid(text)) throw new Error("That isn't a key backup: it's 64 hex characters.");
      priv = ("0x" + text.trim().toLowerCase().replace(/^0x/, "")) as Hex;
      key = keyFromPrivate(hexToBytes(priv));
      me.address = key.addr20;
      me.kept = kept = store.set(slot, priv);
    },
    forget() { store.del(slot); priv = fresh(); key = keyFromPrivate(hexToBytes(priv)); me.address = key.addr20; me.kept = kept = store.set(slot, priv); },
  };
  return me;
}

// ── invites ─────────────────────────────────────────────────────────────────
// An invite link carries a key holding a little CSD, written as base64url after `#/invite/` (the
// form Commonplace makes, e.g. https://commonplace.place/#/invite/<code>). Whoever opens it first
// moves the CSD onto their own key. A bare code works too.

export function inviteKeyFrom(linkOrCode: string): CsdKey | null {
  const code = /(?:^|invite\/)([A-Za-z0-9_-]{40,48})\/?$/.exec(linkOrCode.trim())?.[1];
  if (!code) return null;
  try {
    const b = Uint8Array.from(atob(code.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    return b.length === 32 ? keyFromPrivate(b) : null;
  } catch { return null; }
}

// Move an invite's CSD onto `to`. Returns how much arrives (in whole CSD) and the transaction id;
// it can be spent once that's in a block, in about two minutes. Throws when the link holds nothing
// (already taken, or not funded yet).
export async function claimInvite(net: Net, linkOrCode: string, to: Hex): Promise<{ csd: number; txid: Hex }> {
  const k = inviteKeyFrom(linkOrCode);
  if (!k) throw new Error("That isn't an invite link.");
  const utxos = await net.api.utxos(k.addr20);
  const held = utxos.reduce((s, u) => s + u.value, 0n);
  if (held === 0n) throw new Error("This invite holds nothing: someone took it already, or it isn't in a block yet.");
  const tx = buildSendTx(utxos, k, to, "all");
  const txid = (await net.api.submit(tx)).toLowerCase() as Hex;
  return { csd: Number(tx.outputs.reduce((s, o) => s + o.value, 0n)) / 1e8, txid };
}

// ── open invites: a welcome for newcomers, paid for by whoever wants them in ─────────────────────
// Anyone with CSD (an app's owner, a regular, a friend) splits some into small invites and lists
// their codes under a topic, in the same transaction that funds them. A newcomer's page takes one of
// those onto its writing key the first time it opens, so writing just works. Nobody runs a server:
// the codes are public, first come first served, so keep each one small. The most anyone can take is
// what was listed.

const toCode = (k: Uint8Array) => btoa(String.fromCharCode(...k)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const INVITES_MAX = 10;
// The welcome pool every app shares: invites anyone leaves for newcomers to any app. Whoever fills it
// helps every app's newcomers at once. (Commonplace uses it too.)
export const WELCOME_TOPIC = "csd.welcome"; // codes per listing: they share one record's 512 bytes

// Split `each` CSD per invite, `count` times, off a key you hold, and list them under `topic`. Each
// invite also carries the fee for moving it on, so it arrives whole. Returns the invite links' codes.
export async function makeInvites(net: Net, privateKey: Hex | BrowserKey, o: { topic?: string; count: number; each: number }): Promise<string[]> {
  const n = Math.floor(o.count);
  if (n < 1 || n > INVITES_MAX) throw new Error(`From 1 to ${INVITES_MAX} invites at a time.`);
  const maker = keyFromPrivate(hexToBytes(typeof privateKey === "string" ? privateKey : privateKey.backup()));
  const keys = Array.from({ length: n }, () => crypto.getRandomValues(new Uint8Array(32)));
  const codes = keys.map(toCode);
  const value = BigInt(Math.round(o.each * 1e8)) + SEND_FEE;
  const uri = `invites:${codes.join(",")}`;
  const t = await net.api.tip();
  const app = { kind: "propose" as const, domain: o.topic ?? WELCOME_TOPIC, payloadHash: sha256d(utf8(uri)), uri, expiresEpoch: BigInt(Math.floor(t.height / EPOCH_LEN)) + 10_000_000n };
  const tx = buildSplitTx(await net.api.utxos(maker.addr20), maker, keys.map(k => ({ to: keyFromPrivate(k).addr20, value })), MIN_FEE_PROPOSE, app);
  await net.api.submit(tx);
  return codes;
}

// The invites listed under `topic` that still hold CSD, newest first. (Commonplace's own listings,
// `cp:invites:…`, read the same way.)
export async function openInvites(net: Net, topic: string = WELCOME_TOPIC): Promise<{ code: string; csd: number }[]> {
  const ps = [...(await net.api.proposalsIn(topic, 200))].sort((a, b) => Number(b.height) - Number(a.height));
  const codes = [...new Set(ps.flatMap(p => /^(?:[a-z0-9.]+:)?invites:([A-Za-z0-9_,-]+)$/.exec(p.uri ?? "")?.[1].split(",").slice(0, INVITES_MAX) ?? []))].slice(0, 100);
  const held = await Promise.all(codes.map(async code => {
    const k = inviteKeyFrom(code);
    const us = k ? await net.api.utxos(k.addr20).catch(() => []) : [];
    return { code, csd: Number(us.reduce((s, u) => s + u.value, 0n) - SEND_FEE) / 1e8 };
  }));
  return held.filter(x => x.csd > 0);
}

// A newcomer's welcome: when this writing key has never held anything, take one of the open invites
// under `topic` onto it (a random one, so newcomers arriving together don't all reach for the same).
// Once per browser. Returns what's on its way, or null when there was nothing to do or take.
export async function welcome(net: Net, me: BrowserKey, topic: string = WELCOME_TOPIC): Promise<{ csd: number; txid: Hex } | null> {
  const done = `${me.slot}.welcomed`;
  if (store.get(done) === me.address) return null;
  if ((await net.api.utxos(me.address)).length) { store.set(done, me.address); return null; }
  const open = await openInvites(net, topic);
  while (open.length) {
    const [pick] = open.splice(Math.floor(Math.random() * open.length), 1);
    try { const r = await claimInvite(net, pick.code, me.address); store.set(done, me.address); return r; }
    catch { /* someone took it a moment ago: try another */ }
  }
  return null;
}
