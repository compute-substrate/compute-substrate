// The coast's records, and how anyone checks them. Nothing here trusts anybody.
//
//   coast.sit    "sit <x> <y>"            you sit down at a spot. Every block after the one this
//                                         lands in, for SIT_BLOCKS blocks (about an hour), is a cast.
//                                         Your spot is fixed before any of those blocks exist, so
//                                         you can't pick the lucky spot after seeing a block.
//   coast.keep   "keep <sit id> <height>" you keep what bit at that block, written by whoever sat,
//                                         within KEEP_WITHIN blocks of the sitting ending.
//
// A catch is worked out again from the block's fingerprint, the sitting and the spot, so it can't
// be faked; kept catches are numbered per species in the order they landed ("the 3rd golden char
// ever"), and the biggest of each kind is on the boards.
import { build, castable, waterOf, type World } from "./world";
import { roll, type Catch, FISH } from "./fish";

export const SIT = "coast.sit", KEEP = "coast.keep";
export const SIT_BLOCKS = 30, KEEP_WITHIN = 90;
export const world: World = build();

export type Rec = { id: string; text: string; height: number; time: number; author?: string; pending?: boolean };
export type Block = { hash: string; time: number };

export const sitText = (x: number, y: number) => `sit ${x} ${y}`;
export const keepText = (sit: string, height: number) => `keep ${sit.toLowerCase()} ${height}`;
export function parseSit(text: string): { x: number; y: number } | null {
  const m = /^sit (\d{1,2}) (\d{1,2})$/.exec(text);
  if (!m) return null;
  const x = +m[1], y = +m[2];
  return castable(world, x, y) ? { x, y } : null;
}
export function parseKeep(text: string): { sit: string; height: number } | null {
  const m = /^keep (0x[0-9a-f]{64}) (\d{1,10})$/.exec(text);
  return m ? { sit: m[1], height: +m[2] } : null;
}

// The 32 bytes a cast is decided by
export async function castBytes(blockHash: string, sit: string, x: number, y: number): Promise<Uint8Array> {
  const data = new TextEncoder().encode(`coast|${blockHash.toLowerCase().replace(/^0x/, "")}|${sit.toLowerCase()}|${x}|${y}`);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

// What a sitting got at a block (null: nothing bit)
export async function castAt(sit: Rec & { spot: { x: number; y: number } }, height: number, block: Block): Promise<Catch | null> {
  if (height <= sit.height || height > sit.height + SIT_BLOCKS) return null;
  return roll(await castBytes(block.hash, sit.id, sit.spot.x, sit.spot.y), waterOf(world, sit.spot.x, sit.spot.y), block.time);
}

export type Kept = { id: string; by: string; sit: string; height: number; at: number; spot: { x: number; y: number }; catch: Catch; nth: number; landed: number };

// Every kept catch that checks out, numbered per species in the order they landed
export async function keptCatches(sits: Rec[], keeps: Rec[], block: (h: number) => Promise<Block>): Promise<Kept[]> {
  const sitBy = new Map<string, Rec & { spot: { x: number; y: number } }>();
  for (const s of sits) { const spot = parseSit(s.text); if (spot && s.author && !s.pending) sitBy.set(s.id.toLowerCase(), { ...s, spot }); }
  const seen = new Set<string>(), out: Kept[] = [];
  for (const k of [...keeps].filter(k => !k.pending && k.author).sort((a, b) => a.height - b.height || a.id.localeCompare(b.id))) {
    const p = parseKeep(k.text);
    const s = p && sitBy.get(p.sit);
    if (!p || !s || s.author!.toLowerCase() !== k.author!.toLowerCase()) continue;
    if (p.height <= s.height || p.height > s.height + SIT_BLOCKS || k.height > s.height + SIT_BLOCKS + KEEP_WITHIN || k.height <= p.height) continue;
    const key = `${p.sit}:${p.height}`;
    if (seen.has(key)) continue;
    const b = await block(p.height).catch(() => null);
    if (!b) continue;
    const c = await castAt(s, p.height, b);
    if (!c || c.species.junk) continue;
    seen.add(key);
    out.push({ id: k.id, by: k.author!.toLowerCase(), sit: p.sit, height: p.height, at: b.time, spot: s.spot, catch: c, nth: 0, landed: k.height });
  }
  const counts = new Map<string, number>();
  for (const k of out) { const n = (counts.get(k.catch.species.name) ?? 0) + 1; counts.set(k.catch.species.name, n); k.nth = n; }
  return out;
}

// The boards: the first of each species and the biggest of each, and the biggest of all
export function boards(kept: Kept[]) {
  const first = new Map<string, Kept>(), biggest = new Map<string, Kept>();
  for (const k of kept) {
    const n = k.catch.species.name;
    if (!first.has(n)) first.set(n, k);
    if (!biggest.has(n) || k.catch.cm > biggest.get(n)!.catch.cm) biggest.set(n, k);
  }
  const species = FISH.filter(s => !s.junk).map(s => ({ species: s, first: first.get(s.name) ?? null, biggest: biggest.get(s.name) ?? null, count: kept.filter(k => k.catch.species.name === s.name).length }));
  return { species, overall: [...kept].sort((a, b) => b.catch.cm - a.catch.cm).slice(0, 20) };
}

export const ordinal = (n: number) => `${n}${n % 100 >= 11 && n % 100 <= 13 ? "th" : ["th", "st", "nd", "rd"][n % 10] ?? "th"}`;
