// Adding CSD by card, for Doorway (bundled on its own as ui/buy.js, loaded only when someone adds
// CSD). The person pays on Stripe's page; Stripe sends USDC on Ethereum to Doorway's key (the same
// key has an Ethereum address too), and Doorway trades it for CSD on the open CSD/USDC market,
// signing for itself, the way commonplace-agent does: no ETH needed (the market maker pays the
// gas), no wallet app, nobody holding the money in between.
import { privateKeyToAccount } from "viem/accounts";
import { connect } from "../../../kit/src/index";
import { keyFromPrivate, hexToBytes, type Hex } from "../../../kit/src/core";
import { topUp, rpcProvider, usdcBalance, maxTrade, csdAddressBusy, usdPerCsd, topUpError, USDC_UNIT } from "../../../kit/src/topup";

export const ethAddress = (key: Hex) => privateKeyToAccount(key).address;

// USDC the key holds on Ethereum, in dollars
export async function held(key: Hex): Promise<number> {
  return Number(await usdcBalance(rpcProvider(), ethAddress(key))) / 1e6;
}

// What a little CSD costs now (dollars per CSD), and the most one trade may spend (dollars)
export async function market(): Promise<{ price: number | null; most: number }> {
  const [price, most] = await Promise.all([usdPerCsd().catch(() => null), maxTrade().then(m => Number(m) / 1e6).catch(() => 0)]);
  return { price, most };
}

export type Bought = { state: "nothing" } | { state: "busy" } | { state: "bought"; csd: number; left: number };

// Trades the USDC the key holds for CSD: one trade, as much as a maker takes at once. A key can
// receive one trade at a time until it settles (about 40 minutes), so anything left waits for the
// next call.
export async function buy(node: string, key: Hex, onStep: (s: string) => void = () => {}): Promise<Bought> {
  const provider = rpcProvider(), account = privateKeyToAccount(key), csdKey = keyFromPrivate(hexToBytes(key));
  const have = await usdcBalance(provider, account.address);
  if (have < USDC_UNIT) return { state: "nothing" };
  if (await csdAddressBusy(provider, csdKey.addr20)) return { state: "busy" };
  const most = await maxTrade();
  if (most === 0n) throw new Error("NO_OFFER");
  const spend = have > most ? most : have;
  const t = await topUp({
    provider, buyer: account.address, key: csdKey, spend, csdNode: connect({ node }).api,
    onStep: s => onStep(/^Sign in your wallet/.test(s) ? "Placing the order…" : s),
    sign: a => account.signTypedData(a as any),
  });
  return { state: "bought", csd: Number(t.csd) / 1e8, left: Number(have - BigInt(t.total)) / 1e6 };
}

export const why = (e: unknown) => topUpError(e);
