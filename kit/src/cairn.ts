// Cairn Wallet (cairn-substrate.com), a browser extension that holds Compute Substrate keys itself.
// With it, the writing key is the Cairn account: the page never sees a private key, and every entry
// and resonance is approved in Cairn's own window. It injects `window.cairn` and also announces
// itself with `csd:announceProvider`, like EIP-6963 for Ethereum wallets.
//
// What needs the private key on this page can't be done with Cairn: documents (signed as Arweave
// data items), remembering (encrypted with a key derived from it), invite links (made from it) and
// buying CSD with USDC (the market asks the key to prove it owns the address).

import { bytesToHex, type AppPayload, type Hex } from "./core";

export type CairnProvider = {
  isCairn?: boolean; version?: string;
  connect(): Promise<Envelope>;
  propose(p: Record<string, unknown>): Promise<Envelope>;
  attest(p: Record<string, unknown>): Promise<Envelope>;
  on?(ev: string, h: (...a: unknown[]) => void): void;
  removeListener?(ev: string, h: (...a: unknown[]) => void): void;
};
type Envelope = { ok: boolean; result?: any; error?: string; code?: string };
export type CairnMe = { addr20: Hex; cairn: CairnProvider };

export class CairnError extends Error { constructor(public code: string, msg: string) { super(msg); } }

// finds Cairn if it's installed; calls back each time it turns up (it may inject a little late)
export function discoverCairn(onFound: (p: CairnProvider) => void): () => void {
  const check = () => { const c = (window as any).cairn; if (c?.isCairn) onFound(c); };
  const onAnnounce = (e: any) => { if (e?.detail?.info?.rdns === "com.cairn-substrate.wallet" && e.detail.provider) onFound(e.detail.provider); };
  window.addEventListener("csd:announceProvider", onAnnounce);
  window.addEventListener("cairn#initialized", check);
  window.dispatchEvent(new Event("csd:requestProvider"));
  check();
  const t = setTimeout(() => { window.dispatchEvent(new Event("csd:requestProvider")); check(); }, 1000);
  return () => { window.removeEventListener("csd:announceProvider", onAnnounce); window.removeEventListener("cairn#initialized", check); clearTimeout(t); };
}

function unwrap(r: Envelope | undefined): any {
  if (!r) throw new CairnError("WALLET_UNAVAILABLE", "Cairn didn't answer.");
  const inner = r.ok ? r.result : r;
  if (!r.ok || (inner && typeof inner === "object" && "ok" in inner && !inner.ok)) {
    const code = String(inner?.code ?? r.code ?? "");
    const err = String(inner?.error ?? r.error ?? "");
    throw new CairnError(code || err, cairnMessage(code, err));
  }
  return inner;
}

export function cairnMessage(code: string, err: string): string {
  if (err.startsWith("WALLET_RELOADED")) return "Cairn was restarted. Reload this page.";
  switch (code) {
    case "USER_REJECTED": case "APPROVAL_CLOSED": return "You declined it in Cairn.";
    case "WALLET_LOCKED": return "Cairn is locked. Unlock it and try again.";
    case "ACCOUNT_CHANGED": return "Cairn switched to another account. Sign in again.";
    case "RATE_LIMITED": return "Cairn has too many requests waiting. Answer those first.";
    case "WALLET_TIMEOUT": return "Cairn took too long. Check your page before trying again: it may have gone through.";
    default: return `Cairn said: ${err || code || "something went wrong"}`;
  }
}

export async function cairnConnect(c: CairnProvider): Promise<Hex> {
  const r = unwrap(await c.connect());
  const addr = String(r?.addr ?? r?.address ?? "").toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(addr)) throw new CairnError("INTERNAL", "Cairn didn't give an address.");
  return addr as Hex;
}

// an entry or a resonance, approved in Cairn; returns its txid, which is also the proposal id
export async function cairnSubmit(c: CairnProvider, app: AppPayload, fee: bigint): Promise<Hex> {
  const r = app.kind === "propose"
    ? unwrap(await c.propose({ domain: app.domain, payloadHash: bytesToHex(app.payloadHash), uri: app.uri, expiresEpoch: Number(app.expiresEpoch), fee: Number(fee) }))
    : app.kind === "attest"
      ? unwrap(await c.attest({ proposalId: app.proposalId, score: app.score, confidence: app.confidence, fee: Number(fee) }))
      : (() => { throw new CairnError("UNKNOWN_KIND", "Cairn can't do that here."); })();
  const txid = String(r?.txid ?? "").toLowerCase();
  if (!/^(0x)?[0-9a-f]{64}$/.test(txid)) throw new CairnError("INTERNAL", "Cairn didn't return a transaction id.");
  return (txid.startsWith("0x") ? txid : `0x${txid}`) as Hex;
}
