// compute-substrate/topup: buy a little CSD with USDC, onto a writing key, through the open CSD/USDC
// market. Moved from Commonplace (src/market.ts) unchanged but for its settings, now constants, and
// its imports. A separate file so a page loads it only when someone needs CSD.
//
// Topping up the writing key with USDC, through the open CSD/USDC market.
//
// Anyone can make that market: market makers publish signed offers on AON (a public object
// network), and a contract on Ethereum settles each trade. This page is just one more way in.
// A top-up, start to finish:
//   1. read the makers' sell offers from AON and pick the one that gives the most CSD
//   2. the buyer's Ethereum wallet signs two messages, no transaction and no gas:
//        an authorization: "pay this maker N USDC once it has sent M CSD to my writing key"
//        a USDC permit, so the maker can lock the buyer's USDC in the contract
//   3. publish them on AON; the maker answers there, locks the USDC (paying the gas) and sends
//      the CSD straight to the writing key
//   4. the contract pays the maker only once it proves that CSD payment with enough CSD blocks
//      on top. If it never does, the USDC goes back to the buyer when the lock runs out.

// The AON SDK ships as an ES module only; loaded when first needed, so code run as CommonJS (the
// agent server under tsx) can still import this file
const aonSdk = () => import("@intervalplace/aon-sdk");
import { createPublicClient, createWalletClient, custom, getAddress, hashTypedData, recoverMessageAddress, toHex, type Address } from "viem";
import { mainnet } from "viem/chains";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, concat, hexToBytes, keyFromPrivate, utf8, type CsdKey, type Hex, type Node } from "./core";
import type { BrowserKey } from "./browser";
// An Ethereum wallet, as browsers give one (EIP-1193)
export type Provider = { request(args: { method: string; params?: unknown[] }): Promise<any> };

// ── the market (all public; any page can use the same) ─────────────────────
export const SETTLEMENT = "0x8863f0c477a30bb5a2077c813f42250d7fbefcb9" as Address;
export const USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" as Address;
const CSD_GENESIS = "0x00000052c2821f71b19c3d79dfabfb12d4076ba15d83b47d008e582aad6c0d52" as Hex;
// Ethereum mainnet
const CHAIN_ID = 1;
const CHAIN = mainnet;
const AON_NODES = ["https://explorer.aon.network", "https://node2.aon.network", "https://node3.aon.network", "https://node4.aon.network"];
const NS = "aon:csd-usdc";
const CONFIRMATIONS = 20n; // CSD blocks on top of the payment before the maker can be paid
export const USDC_UNIT = 1_000_000n;

const domain = { name: "AON CSD/USDC", version: "4", chainId: CHAIN_ID, verifyingContract: SETTLEMENT } as const;
const AUTH_TYPES = {
  CsdUsdcAuthorization: [
    { name: "buyer", type: "address" }, { name: "sellerUsdcRecipient", type: "address" }, { name: "sellerCsdScriptHash", type: "bytes32" },
    { name: "csdGenesisHash", type: "bytes32" }, { name: "tradeIntentHash", type: "bytes32" }, { name: "csdAmount", type: "uint256" },
    { name: "usdc", type: "address" }, { name: "usdcAmount", type: "uint256" }, { name: "minConfirmations", type: "uint256" },
    { name: "csdMaxTarget", type: "uint256" }, { name: "executorFeeAmount", type: "uint256" }, { name: "validAfter", type: "uint64" },
    { name: "validBefore", type: "uint64" }, { name: "nonce", type: "bytes32" },
  ],
} as const;
const PERMIT_TYPES = { Permit: [{ name: "owner", type: "address" }, { name: "spender", type: "address" }, { name: "value", type: "uint256" }, { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" }] } as const;
const settlementAbi = [
  { type: "function", name: "usdcLocked", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "lockedUntil", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "finalizedAuthorization", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "bool" }] },
  { type: "function", name: "totalLocked", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "maxTotalLocked", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "openLockForCsdAddress", stateMutability: "view", inputs: [{ type: "bytes32" }], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "refundExpiredLock", stateMutability: "nonpayable", outputs: [], inputs: [{ name: "auth", type: "tuple", components: AUTH_TYPES.CsdUsdcAuthorization }] },
] as const;
const usdcAbi = [
  { type: "function", name: "nonces", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
  { type: "function", name: "name", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
  { type: "function", name: "version", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
  { type: "function", name: "balanceOf", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "uint256" }] },
] as const;

// ── AON: read offers, publish an order, wait for the answer (any node will do) ──
async function aonFetch(path: string, init?: RequestInit): Promise<Response> {
  let last: unknown;
  for (const base of AON_NODES) {
    try { const r = await fetch(`${base}${path}`, init); if (r.status < 500) return r; last = new Error(`AON_${r.status}`); } catch (e) { last = e; }
  }
  throw last ?? new Error("AON_UNREACHABLE");
}
async function objectSigner(o: any): Promise<string | null> {
  try {
    if (o?.signature?.scheme !== "eip191-object") return null;
    const { signature, objectHash, ...unsigned } = o;
    const { hashObject } = await aonSdk();
    if (hashObject({ ...unsigned, signature }).toLowerCase() !== String(objectHash).toLowerCase()) return null;
    return (await recoverMessageAddress({ message: { raw: hashObject(unsigned) as Hex }, signature: signature.signature })).toLowerCase();
  } catch { return null; }
}

// ── pool math (the makers' published curve: constant product, plus a spread) ──
type Pool = { usdc: bigint; csd: bigint; spreadBps: bigint };
const BPS = 10_000n;
const ceilDiv = (a: bigint, b: bigint) => (a + b - 1n) / b;
function quoteBuy(p: Pool, csd: bigint): bigint {
  if (csd <= 0n || csd * 2n > p.csd) throw new Error("SIZE");
  return ceilDiv(ceilDiv(p.usdc * csd, p.csd - csd) * (BPS + p.spreadBps), BPS);
}
function csdForUsdc(p: Pool, usdc: bigint): bigint {
  const base = (usdc * BPS) / (BPS + p.spreadBps);
  let x = (p.csd * base) / (p.usdc + base);
  if (x * 2n > p.csd) x = p.csd / 2n;
  while (x > 0n && quoteBuy(p, x) > usdc) x -= 1n + x / 1_000_000n;
  return x > 0n ? x : 0n;
}

export type Quote = { maker: string; offer: any; csd: bigint; usdc: bigint; fee: bigint; total: bigint };

// Every maker's newest sell offer for this contract; then the one that gives the most CSD for `spend`
export async function quotes(spend: bigint, skip: Set<string> = new Set()): Promise<Quote[]> {
  const latest = new Map<string, any>(), now = Date.now();
  for (let page = 0; page < 3; page++) {
    const r = await aonFetch(`/v1/objects?namespace=${encodeURIComponent(NS)}&objectType=offer&limit=100&offset=${page * 100}`);
    const os: any[] = (await r.json()).objects ?? [];
    for (const o of os) {
      const p = o?.payload;
      if (p?.offerType !== "csd_usdc_sell_csd" || Number(p.validBefore) < now / 1000 || Number(o.createdAt) > now + 120_000) continue;
      if (String(p.settlementContract).toLowerCase() !== SETTLEMENT.toLowerCase() || String(p.usdc).toLowerCase() !== USDC.toLowerCase() || String(p.csdGenesisHash).toLowerCase() !== CSD_GENESIS) continue;
      const mm = String(p.marketMaker).toLowerCase();
      if (skip.has(mm) || (latest.get(mm) && Number(latest.get(mm).createdAt) >= Number(o.createdAt))) continue;
      if ((await objectSigner(o)) !== mm) continue;
      latest.set(mm, o);
    }
    if (os.length < 100) break;
  }
  const out: Quote[] = [];
  for (const [mm, o] of latest) {
    try {
      const p = o.payload, fee = BigInt(p.feeUsdc), pool = { usdc: BigInt(p.poolUsdc), csd: BigInt(p.poolCsd), spreadBps: BigInt(p.spreadBps) };
      if (spend <= fee) continue;
      const csd = csdForUsdc(pool, spend - fee); if (csd <= 0n) continue;
      const usdc = quoteBuy(pool, csd);
      if (usdc < BigInt(p.minTradeUsdc) || usdc + fee > BigInt(p.maxTradeUsdc)) continue;
      out.push({ maker: getAddress(mm), offer: o, csd, usdc, fee, total: usdc + fee });
    } catch {}
  }
  return out.sort((a, b) => (b.csd > a.csd ? 1 : b.csd < a.csd ? -1 : 0));
}

// What a little CSD costs right now: the best maker's price for a small buy, in dollars per CSD
export async function usdPerCsd(): Promise<number | null> {
  const q = (await quotes(5n * USDC_UNIT))[0];
  return q && q.csd > 0n ? (Number(q.usdc) / 1e6) / (Number(q.csd) / 1e8) : null;
}

// ── the buyer's side ────────────────────────────────────────────────────────
export type TopUp = { authHash: Hex; aonHash: string; maker: string; csd: string; total: string; at: number; auth: Record<string, string>; status: "waiting" | "locked" | "done" | "refunded" | "failed"; receipt?: string };

const ownershipDigest = (authHash: Hex) => keccak_256(concat(utf8("AON CSD/USDC: I control this CSD address for trade "), hexToBytes(authHash)));
function addressProof(key: CsdKey, authHash: Hex) {
  const s = secp256k1.sign(ownershipDigest(authHash), key.priv, { lowS: true });
  const pub64 = secp256k1.getPublicKey(key.priv, false).slice(1);
  return { pubKey: bytesToHex(pub64), sig: bytesToHex(concat(s.toCompactRawBytes(), new Uint8Array([27 + s.recovery]))) };
}
const bitsToTarget = (bits: number) => BigInt(bits & 0xffffff) * (1n << (8n * (BigInt(bits >>> 24) - 3n)));

function eth(provider: Provider) {
  const transport = custom(provider as any);
  return { read: createPublicClient({ chain: CHAIN, transport }), wallet: createWalletClient({ chain: CHAIN, transport }) };
}

export async function onMainnet(provider: Provider) {
  const id = await provider.request({ method: "eth_chainId" });
  if (Number(id) === CHAIN_ID) return;
  try { await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: `0x${CHAIN_ID.toString(16)}` }] }); }
  catch { throw new Error("Switch your wallet to Ethereum mainnet and try again."); }
}

// A read-only Ethereum provider over public RPCs, each tried in turn (for an agent, which has no wallet app)
export const PUBLIC_RPCS = ["https://ethereum-rpc.publicnode.com", "https://eth.llamarpc.com", "https://cloudflare-eth.com", "https://eth.merkle.io"];
export function rpcProvider(urls = PUBLIC_RPCS): Provider {
  let id = 0;
  return {
    async request({ method, params }) {
      let last: unknown;
      for (const u of urls) {
        try {
          const r = await fetch(u, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params: params ?? [] }) });
          const j = await r.json();
          if (j.error) { if (r.ok && j.error.code !== -32005 && j.error.code !== -32603) throw Object.assign(new Error(j.error.message), { rpc: true }); last = new Error(j.error.message); continue; }
          return j.result;
        } catch (e: any) { if (e?.rpc) throw e; last = e; }
      }
      throw last ?? new Error("ETH_RPC_UNREACHABLE");
    },
  };
}
// The most a single trade may spend right now, across makers (each caps its trades)
export async function maxTrade(): Promise<bigint> {
  const qs = await quotes(USDC_UNIT * 2n).catch(() => []);
  return qs.reduce((m, q) => { const x = BigInt(q.offer.payload.maxTradeUsdc); return x > m ? x : m; }, 0n);
}

// Whether a CSD address is receiving a trade that hasn't settled yet: the contract allows one at a
// time per address, so another buy must pay a different address meanwhile
export async function csdAddressBusy(provider: Provider, addr20: Hex): Promise<boolean> {
  const h = (await eth(provider).read.readContract({ address: SETTLEMENT, abi: settlementAbi, functionName: "openLockForCsdAddress", args: [(addr20 + "00".repeat(12)) as Hex] })) as string;
  return BigInt(h) !== 0n;
}

export async function usdcBalance(provider: Provider, owner: Address): Promise<bigint> {
  return (await eth(provider).read.readContract({ address: USDC, abi: usdcAbi, functionName: "balanceOf", args: [owner] })) as bigint;
}

// Places the order and waits for a maker to accept and lock it. Tries the next maker if one declines.
// `sign`, when given, signs the two messages instead of the wallet behind `provider` (an agent
// signing with its own key, with `provider` only reading Ethereum)
type Signer = (a: { domain: any; types: any; primaryType: string; message: any }) => Promise<Hex>;
export async function topUp(args: { provider: Provider; buyer: Address; key: CsdKey; spend: bigint; csdNode: Node; onStep: (s: string) => void; sign?: Signer }): Promise<TopUp> {
  const { provider, buyer, key, spend, csdNode, onStep } = args;
  await onMainnet(provider);
  const { read, wallet } = eth(provider);
  const sign: Signer = args.sign ?? (a => wallet.signTypedData({ account: buyer, ...a } as any) as Promise<Hex>);
  if (((await read.readContract({ address: USDC, abi: usdcAbi, functionName: "balanceOf", args: [buyer] })) as bigint) < spend) throw new Error("NOT_ENOUGH_USDC");
  // the easiest CSD difficulty a payment proof may use: the real one with 10% slack, from the
  // CSD node this page reads, not from the maker (easier would make fake CSD blocks cheap)
  const tip = await csdNode.tip();
  const bits = Number((await csdNode.header(tip.height)).bits);
  const csdMaxTarget = bitsToTarget(bits) * 11n / 10n;

  const tried = new Set<string>();
  for (let attempt = 0; attempt < 3; attempt++) {
    onStep("Finding the best offer…");
    const q = (await quotes(spend, tried))[0];
    if (!q) throw new Error(tried.size ? "NO_MAKER_ANSWERED" : "NO_OFFER");
    tried.add(q.maker.toLowerCase());
    const [locked, max] = await Promise.all([
      read.readContract({ address: SETTLEMENT, abi: settlementAbi, functionName: "totalLocked" }),
      read.readContract({ address: SETTLEMENT, abi: settlementAbi, functionName: "maxTotalLocked" }),
    ]) as [bigint, bigint];
    if (locked + q.total > max) throw new Error("MARKET_FULL");
    const t = Math.floor(Date.now() / 1000);
    const auth = {
      buyer, sellerUsdcRecipient: q.maker as Address, sellerCsdScriptHash: (key.addr20 + "00".repeat(12)) as Hex, csdGenesisHash: CSD_GENESIS,
      tradeIntentHash: q.offer.objectHash as Hex, csdAmount: q.csd, usdc: USDC, usdcAmount: q.usdc, minConfirmations: CONFIRMATIONS,
      csdMaxTarget, executorFeeAmount: q.fee, validAfter: BigInt(t - 120), validBefore: BigInt(t + 3 * 3600), nonce: toHex(crypto.getRandomValues(new Uint8Array(32))),
    };
    onStep("Sign in your wallet (1 of 2): the order");
    const signature = await sign({ domain, types: AUTH_TYPES, primaryType: "CsdUsdcAuthorization", message: auth });
    const authHash = hashTypedData({ domain, types: AUTH_TYPES, primaryType: "CsdUsdcAuthorization", message: auth }) as Hex;
    const [name, version, nonce] = await Promise.all([
      read.readContract({ address: USDC, abi: usdcAbi, functionName: "name" }),
      read.readContract({ address: USDC, abi: usdcAbi, functionName: "version" }),
      read.readContract({ address: USDC, abi: usdcAbi, functionName: "nonces", args: [buyer] }),
    ]) as [string, string, bigint];
    const deadline = BigInt(t + 300);
    onStep("Sign in your wallet (2 of 2): the USDC it may lock");
    const ps = await sign({ domain: { name, version, chainId: CHAIN_ID, verifyingContract: USDC }, types: PERMIT_TYPES, primaryType: "Permit",
      message: { owner: buyer, spender: SETTLEMENT, value: q.total, nonce, deadline } });
    const strs = (o: Record<string, unknown>) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, typeof v === "bigint" ? String(v) : v])) as Record<string, string>;
    const authorization = strs(auth);
    const { finalizeObject } = await aonSdk();
    const obj: any = finalizeObject({
      objectType: "authorization", schemaVersion: "1", namespace: NS, createdAt: Date.now(), references: [String(q.offer.objectHash).toLowerCase()],
      payload: { authorizationType: "csd_usdc_release", authorization, csdAddressProof: addressProof(key, authHash),
        usdcPermit: strs({ deadline, r: ps.slice(0, 66), s: "0x" + ps.slice(66, 130), v: parseInt(ps.slice(130, 132), 16) }) },
      signature: { scheme: "eip712", signer: getAddress(buyer), domain, types: AUTH_TYPES, primaryType: "CsdUsdcAuthorization", message: authorization, signature },
    } as any);
    onStep("Sending the order to the market…");
    const put = await aonFetch("/v1/objects", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(obj) });
    const pj = await put.json().catch(() => ({}));
    if (!pj.ok) throw new Error(pj.error?.code ?? `AON_${put.status}`);
    const record: TopUp = { authHash, aonHash: obj.objectHash, maker: q.maker, csd: String(q.csd), total: String(q.total), at: Date.now(), auth: authorization, status: "waiting" };

    onStep("Waiting for a market maker…");
    let answer: any = null;
    for (const end = Date.now() + 45_000; Date.now() < end && !answer;) {
      const r = await aonFetch(`/v1/objects/${obj.objectHash}/references`).then(x => x.json()).catch(() => ({}));
      for (const o of r.inbound ?? []) if (o.objectType === "response" && (await objectSigner(o)) === q.maker.toLowerCase()) { answer = o.payload; break; }
      if (!answer) await new Promise(r => setTimeout(r, 1500));
    }
    if (!answer || !answer.accepted) continue; // silent or declined: the next maker
    onStep("The maker is locking your USDC on Ethereum…");
    for (let i = 0; i < 60; i++) {
      if (await read.readContract({ address: SETTLEMENT, abi: settlementAbi, functionName: "usdcLocked", args: [authHash] }).catch(() => false)) return { ...record, status: "locked" };
      await new Promise(r => setTimeout(r, 2000));
    }
    return record; // accepted, lock not seen yet: followed from here
  }
  throw new Error("NO_MAKER_ANSWERED");
}

// The market maker's signed receipt for a top-up, published on AON once the trade settles
export const EXPLORER = "https://explorer.aon.network";
export const aonLink = (hash: string) => `${EXPLORER}?hash=${hash}`;
export async function findReceipt(t: TopUp): Promise<string | null> {
  const r = await aonFetch(`/v1/objects/${t.aonHash}/references`).then(x => x.json()).catch(() => ({}));
  for (const o of r.inbound ?? []) {
    if (o.objectType !== "receipt" || String(o.payload?.authHash).toLowerCase() !== t.authHash.toLowerCase()) continue;
    if ((await objectSigner(o)) === t.maker.toLowerCase()) return o.objectHash;
  }
  return null;
}

// Where a top-up stands now, from Ethereum
export async function topUpStatus(provider: Provider, t: TopUp): Promise<TopUp["status"]> {
  const { read } = eth(provider);
  const h = t.authHash;
  if (await read.readContract({ address: SETTLEMENT, abi: settlementAbi, functionName: "finalizedAuthorization", args: [h] })) return "done";
  if (await read.readContract({ address: SETTLEMENT, abi: settlementAbi, functionName: "usdcLocked", args: [h] })) return "locked";
  return t.status === "locked" ? "refunded" : Date.now() - t.at > 3600_000 ? "failed" : "waiting";
}
// A lock whose time ran out without the maker proving its payment: anyone may send the USDC back
export async function refundable(provider: Provider, t: TopUp): Promise<boolean> {
  const { read } = eth(provider);
  if (!(await read.readContract({ address: SETTLEMENT, abi: settlementAbi, functionName: "usdcLocked", args: [t.authHash] }))) return false;
  const until = (await read.readContract({ address: SETTLEMENT, abi: settlementAbi, functionName: "lockedUntil", args: [t.authHash] })) as bigint;
  return BigInt(Math.floor(Date.now() / 1000)) > until;
}
export async function refund(provider: Provider, buyer: Address, t: TopUp): Promise<Hex> {
  const { wallet } = eth(provider);
  const a = t.auth, auth = { ...a, csdAmount: BigInt(a.csdAmount), usdcAmount: BigInt(a.usdcAmount), minConfirmations: BigInt(a.minConfirmations), csdMaxTarget: BigInt(a.csdMaxTarget),
    executorFeeAmount: BigInt(a.executorFeeAmount), validAfter: BigInt(a.validAfter), validBefore: BigInt(a.validBefore) } as any;
  return wallet.writeContract({ account: buyer, address: SETTLEMENT, abi: settlementAbi, functionName: "refundExpiredLock", args: [auth] }) as Promise<Hex>;
}

// ── for a page with a writing key (browserKey) ──────────────────────────────
// The browser's Ethereum wallet, asking it to connect: EIP-6963 first (each wallet announces
// itself), then window.ethereum
export async function browserWallet(timeoutMs = 600): Promise<{ provider: Provider; account: Address }> {
  const w = globalThis as any;
  let provider: Provider | null = null;
  if (typeof w.addEventListener === "function") {
    provider = await new Promise<Provider | null>(resolve => {
      const on = (e: any) => { w.removeEventListener("eip6963:announceProvider", on); resolve(e.detail?.provider ?? null); };
      w.addEventListener("eip6963:announceProvider", on);
      w.dispatchEvent(new Event("eip6963:requestProvider"));
      setTimeout(() => { w.removeEventListener("eip6963:announceProvider", on); resolve(null); }, timeoutMs);
    });
  }
  provider ??= w.ethereum ?? null;
  if (!provider) throw new Error("NO_ETH_WALLET");
  const [account] = await provider.request({ method: "eth_requestAccounts" });
  if (!account) throw new Error("NO_ETH_ACCOUNT");
  return { provider, account: getAddress(account) };
}

// Top up a page's writing key with `usdc` dollars of USDC: the person's Ethereum wallet signs two
// messages (no transaction, no gas), a market maker sends the CSD to the key, and the contract pays
// the maker only once that payment is proven on Compute Substrate. The CSD arrives a few minutes
// after the maker locks the USDC.
export async function topUpWithUsdc(net: { api: Node }, me: BrowserKey, usdc: number, onStep: (s: string) => void = () => {}): Promise<TopUp> {
  const { provider, account } = await browserWallet();
  const spend = BigInt(Math.round(usdc * 1e6));
  return topUp({ provider, buyer: account, key: keyFromPrivate(hexToBytes(me.backup())), spend, csdNode: net.api, onStep });
}

// What its errors mean, in words for people
export function topUpError(e: unknown): string {
  const m = String((e as any)?.message ?? e);
  return ({
    NO_ETH_WALLET: "No Ethereum wallet in this browser. Install one, such as MetaMask or Rabby, with some USDC on Ethereum.",
    NO_ETH_ACCOUNT: "The wallet didn't share an account.",
    NOT_ENOUGH_USDC: "That wallet doesn't hold enough USDC on Ethereum.",
    NO_OFFER: "Nobody is selling CSD right now. Try again later.",
    NO_MAKER_ANSWERED: "No market maker answered. Try again in a little while.",
    MARKET_FULL: "The market is full for the moment. Try again in a little while.",
  } as Record<string, string>)[m] ?? (/rejected|denied/i.test(m) ? "The wallet didn't sign." : m);
}
