// The coast's records, and how anyone checks them. Nothing here trusts anybody.
//
//   coast.sit    "sit <x> <y>" or         you sit down at a spot for an hour (or up to MAX_HOURS).
//                "sit <x> <y> <hours>"    Every block after the one this lands in is a cast, until
//                                         the time is up or you sit down somewhere else. Your spot is
//                                         fixed before any of those blocks exist, so you can't pick
//                                         the lucky spot after seeing a block.
//   coast.keep   "keep <sit id> <h>,<h>…" you keep what bit at those blocks (up to MAX_KEEP at once),
//                                         written by whoever sat, within KEEP_WITHIN blocks of the
//                                         sitting ending.
//
// Fishing level: every cast is experience, and every fish kept is more, by how rare it is. Some
// waters need a level to fish (a sitting there before you have it doesn't count). A catch is worked
// out again from the block's fingerprint, the sitting and the spot, so it can't be faked; kept fish
// are numbered per species in the order they landed ("the 3rd golden char ever").
import { build, castable, waterOf, SHALLOWS, REEDS, LEDGE, OPEN, type World } from "./world";
import { roll, rarity, type Catch, FISH } from "./fish";

export const SIT = "coast.sit", KEEP = "coast.keep";
export const SIT_BLOCKS = 30, MAX_HOURS = 8, KEEP_WITHIN = 360, MAX_KEEP = 40;
export const world: World = build();

export type Rec = { id: string; text: string; height: number; time: number; author?: string; pending?: boolean };
export type Block = { hash: string; time: number };

// ── fishing level ──
export const XP_CAST = 100;
export const XP_KEEP: Record<string, number> = { common: 250, uncommon: 600, scarce: 1500, rare: 5000, legendary: 20000, junk: 0 };
export const WATER_LEVEL: Record<number, number> = { [SHALLOWS]: 1, [REEDS]: 10, [LEDGE]: 25, [OPEN]: 40 };
// the experience a level starts at (the old familiar curve: quick at first, then very slow; 99 is 13 million)
const XP_TABLE = (() => { const t = [0, 0]; let p = 0; for (let l = 1; l < 99; l++) { p += Math.floor(l + 300 * Math.pow(2, l / 7)); t.push(Math.floor(p / 4)); } return t; })();
export const xpForLevel = (l: number) => XP_TABLE[Math.max(1, Math.min(99, l))];
export const levelFor = (xp: number) => { let l = 1; while (l < 99 && xp >= XP_TABLE[l + 1]) l++; return l; };
export const levelNeeded = (x: number, y: number) => WATER_LEVEL[waterOf(world, x, y)] ?? 1;

// ── the records' text ──
export const sitText = (x: number, y: number, hours = 1) => hours > 1 ? `sit ${x} ${y} ${hours}` : `sit ${x} ${y}`;
export const keepText = (sit: string, heights: number[]) => `keep ${sit.toLowerCase()} ${[...new Set(heights)].sort((a, b) => a - b).join(",")}`;
export function parseSit(text: string): { x: number; y: number; hours: number } | null {
  const m = /^sit (\d{1,2}) (\d{1,2})(?: ([2-8]))?$/.exec(text);
  if (!m) return null;
  const x = +m[1], y = +m[2];
  return castable(world, x, y) ? { x, y, hours: m[3] ? +m[3] : 1 } : null;
}
export function parseKeep(text: string): { sit: string; heights: number[] } | null {
  const m = /^keep (0x[0-9a-f]{64}) (\d{1,10}(?:,\d{1,10}){0,39})$/.exec(text);
  return m ? { sit: m[1], heights: [...new Set(m[2].split(",").map(Number))] } : null;
}

// The 32 bytes a cast is decided by
export async function castBytes(blockHash: string, sit: string, x: number, y: number): Promise<Uint8Array> {
  const data = new TextEncoder().encode(`coast|${blockHash.toLowerCase().replace(/^0x/, "")}|${sit.toLowerCase()}|${x}|${y}`);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export type Sitting = { id: string; by: string; height: number; spot: { x: number; y: number }; hours: number; end: number; valid: boolean; pending?: boolean };
// What a sitting got at a block (null: nothing bit)
export async function castAt(s: { id: string; height: number; spot: { x: number; y: number }; end: number }, height: number, block: Block): Promise<Catch | null> {
  if (height <= s.height || height > s.end) return null;
  return roll(await castBytes(block.hash, s.id, s.spot.x, s.spot.y), waterOf(world, s.spot.x, s.spot.y), block.time);
}

export type Kept = { id: string; by: string; sit: string; height: number; at: number; spot: { x: number; y: number }; catch: Catch; nth: number; landed: number };
export type Coast = { sittings: Sitting[]; kept: Kept[]; xpOf: (who: string, at?: number) => number; fishers: string[] };

// Every sitting and every kept fish that checks out, and everyone's experience, worked out in the
// order things landed
export async function coast(sits: Rec[], keeps: Rec[], block: (h: number) => Promise<Block>, tip: number): Promise<Coast> {
  const all: Sitting[] = [];
  for (const s of sits) { const p = !s.pending && s.author ? parseSit(s.text) : null; if (p) all.push({ id: s.id.toLowerCase(), by: s.author!.toLowerCase(), height: s.height, spot: { x: p.x, y: p.y }, hours: p.hours, end: s.height + p.hours * SIT_BLOCKS, valid: false }); }
  all.sort((a, b) => a.height - b.height || a.id.localeCompare(b.id));
  // sitting down somewhere new ends where you were
  const lastBy = new Map<string, Sitting>();
  for (const s of all) { const prev = lastBy.get(s.by); if (prev) prev.end = Math.min(prev.end, s.height); lastBy.set(s.by, s); }
  const byId = new Map(all.map(s => [s.id, s]));
  const keptXp: { by: string; height: number; xp: number }[] = [];
  const xpOf = (who: string, at = tip) => {
    let xp = 0;
    for (const s of all) if (s.valid && s.by === who) xp += Math.max(0, Math.min(s.end, at) - s.height) * XP_CAST;
    for (const k of keptXp) if (k.by === who && k.height <= at) xp += k.xp;
    return xp;
  };
  type Ev = { h: number; kind: 0 | 1; s?: Sitting; k?: Rec };
  const events: Ev[] = [...all.map(s => ({ h: s.height, kind: 0 as const, s })), ...keeps.filter(k => !k.pending && k.author).map(k => ({ h: k.height, kind: 1 as const, k }))]
    .sort((a, b) => a.h - b.h || a.kind - b.kind || (a.s?.id ?? a.k!.id).localeCompare(b.s?.id ?? b.k!.id));
  const kept: Kept[] = [], seen = new Set<string>();
  for (const e of events) {
    if (e.s) { e.s.valid = levelFor(xpOf(e.s.by, e.h)) >= levelNeeded(e.s.spot.x, e.s.spot.y); continue; }
    const k = e.k!, p = parseKeep(k.text), s = p && byId.get(p.sit);
    if (!p || !s || !s.valid || s.by !== k.author!.toLowerCase() || k.height > s.end + KEEP_WITHIN) continue;
    for (const h of p.heights) {
      if (h <= s.height || h > s.end || k.height <= h || seen.has(`${s.id}:${h}`)) continue;
      const b = await block(h).catch(() => null);
      if (!b) continue;
      const c = await castAt(s, h, b);
      if (!c || c.species.junk) continue;
      seen.add(`${s.id}:${h}`);
      kept.push({ id: k.id, by: s.by, sit: s.id, height: h, at: b.time, spot: s.spot, catch: c, nth: 0, landed: k.height });
      keptXp.push({ by: s.by, height: k.height, xp: XP_KEEP[rarity(c.species)] });
    }
  }
  const counts = new Map<string, number>();
  for (const k of kept) { const n = (counts.get(k.catch.species.name) ?? 0) + 1; counts.set(k.catch.species.name, n); k.nth = n; }
  return { sittings: all, kept, xpOf, fishers: [...new Set(all.filter(s => s.valid).map(s => s.by))] };
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
