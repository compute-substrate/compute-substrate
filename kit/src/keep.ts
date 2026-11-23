// Keeping a site up: anyone can pay to keep any site (by its address, ipfs://<CID>) on the doors,
// a year at a time, name or not. So a site lasts as long as anyone thinks it should, and can outlive
// its name and its maker.
//
// A keep record is a record under `csd.keep` whose text is the site's address. It keeps the site a
// year from where its time stands (or from its own block, once that has run out), plus a year for
// every 0.25 CSD it burns: an output to the all-zero address, which nobody can spend. Doors keep every
// site with time left (sites/, csd-sites), and anyone can add up a site's time from the records alone.
import { deserializeTx, EPOCH_LEN, MIN_FEE_PROPOSE, sha256d, utf8, type AppPayload, type Hex } from "./core";

export const KEEP_TOPIC = "csd.keep";
export const BURN: Hex = ("0x" + "00".repeat(20)) as Hex;
export const YEAR_BLOCKS = 365 * 24 * 30;
export const PER_YEAR = MIN_FEE_PROPOSE; // 0.25 CSD
export const MAX_YEARS = 1000;
const KEEP_FROM = 147_000;
const CID_RE = /^b[a-z2-7]{50,100}$/;

// What keeping `years` costs, in whole CSD: the record's fee is the first year, and every year after
// is burned
export const keepCost = (years: number) => years * Number(PER_YEAR) / 1e8;

// The record (and what it burns) that keeps `cid` for `years`
export function keepRecord(cid: string, years: number, tip: number): { app: AppPayload; fee: bigint; burn: bigint } {
  if (!CID_RE.test(cid)) throw new Error("That isn't a site's address (a CIDv1, bafy…).");
  const y = Math.floor(years);
  if (y < 1 || y > MAX_YEARS) throw new Error(`From 1 to ${MAX_YEARS} years at a time.`);
  const uri = `ipfs://${cid}`;
  return {
    app: { kind: "propose", domain: KEEP_TOPIC, payloadHash: sha256d(utf8(uri)), uri, expiresEpoch: BigInt(Math.floor(tip / EPOCH_LEN)) + 10_000_000n },
    fee: MIN_FEE_PROPOSE,
    burn: BigInt(y - 1) * PER_YEAR,
  };
}

type Api = { tip: () => Promise<{ height: number }>; events: (domain: string, from: number, count?: number) => Promise<{ to: number; tip: number; events: { height: number; tx_raw: string }[] } | null> };

// Every site someone keeps: its address -> the block it's kept until. Read from a node's keep
// records; cached per node, and extended as the tip moves.
const caches = new Map<Api, { next: number; until: Map<string, number> }>();
export async function keptSites(api: Api): Promise<{ tip: number; until: Map<string, number> }> {
  let c = caches.get(api);
  if (!c) caches.set(api, c = { next: KEEP_FROM, until: new Map() });
  let tip = (await api.tip()).height;
  while (c.next <= tip) {
    const r = await api.events(KEEP_TOPIC, c.next, 2000);
    if (!r) break; // an older node: no keep records
    for (const e of r.events) {
      let tx; try { tx = deserializeTx(Uint8Array.from((e.tx_raw.replace(/^0x/, "").match(/../g) ?? []).map(h => parseInt(h, 16)))); } catch { continue; }
      if (tx.app.kind !== "propose") continue;
      const cid = tx.app.uri.trim().replace(/^ipfs:\/\//, "");
      if (!tx.app.uri.trim().startsWith("ipfs://") || !CID_RE.test(cid)) continue;
      const burned = tx.outputs.filter(o => o.addr20.toLowerCase() === BURN).reduce((s, o) => s + o.value, 0n);
      const years = Math.min(MAX_YEARS, 1 + Number(burned / PER_YEAR));
      c.until.set(cid, Math.max(c.until.get(cid) ?? 0, e.height) + years * YEAR_BLOCKS);
    }
    if (r.to < c.next) break;
    c.next = r.to + 1;
    tip = Math.max(tip, r.tip);
  }
  return { tip, until: c.until };
}

// A block height as a date, from the tip and 2-minute blocks: when a site's kept time runs out
export function heightToDate(height: number, tip: number): Date {
  return new Date(Date.now() + (height - tip) * 120_000);
}

// When a keep runs out, as people say it: the month and year. Not the day or time: blocks come about
// every two minutes, so the block a keep ends at drifts by days over decades, and a minute would be
// a precision it doesn't have.
export const monthYear = (d: Date, short = false) => d.toLocaleString("en-US", { month: short ? "short" : "long", year: "numeric" });
