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

import { buildSendTx, bytesToHex, hexToBytes, keyFromPrivate, type CsdKey, type Hex } from "./core";

type Net = { api: { utxos: (a: Hex) => Promise<{ txid: Hex; vout: number; value: bigint }[]>; submit: (tx: any) => Promise<Hex> } };
type Signer = { address: Hex; send: (app: any, fee: bigint) => Promise<Hex> };

const store = {
  get(k: string): string | null { try { return localStorage.getItem(k); } catch { return null; } },
  set(k: string, v: string): boolean { try { localStorage.setItem(k, v); return localStorage.getItem(k) === v; } catch { return false; } },
  del(k: string) { try { localStorage.removeItem(k); } catch {} },
};
const fresh = (): Hex => bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
const valid = (h: string | null): h is Hex => !!h && /^(0x)?[0-9a-f]{64}$/i.test(h.trim());

export type BrowserKey = {
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
    address: key.addr20,
    kept,
    signer: (net) => ({
      address: key.addr20,
      async send(app, fee) {
        const { buildAppTx } = await import("./core");
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
