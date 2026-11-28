// The deep's records, and how anyone checks them. Nothing here trusts anybody.
//
//   deep.go     "go" or "go <floor>"     you go down, from the top or down someone's rope. Your fights
//                                        are decided by the block after the one this lands in, so
//                                        nobody knew them in advance. A rope goes as deep as the
//                                        deepest floor anyone had climbed out of when this landed.
//   deep.up     "up <go id> <moves>"     you came back up: every move you made, packed. Anyone
//                                        replays them against the deep as it stood when you went
//                                        down; if you climb out alive, every relic you carried that
//                                        nobody brought up before you is yours, for good.
//   deep.fell   "fell <go id> <moves>"   you didn't. Your name stays where you fell, and what you
//                                        carried lies there for whoever comes next.
//
// One ending per going-down, written by whoever went down, within END_WITHIN blocks. Records count in
// the order they landed, so when two people bring up the same relic, the first one home has it.
import { play, unpack, relicName, deepestStart, LAMP, DEPTH, type State, type Grave } from "./dungeon";

export const GO = "deep.go", UP = "deep.up", FELL = "deep.fell";
export const END_WITHIN = 720; // about a day
export type Rec = { id: string; text: string; height: number; time: number; author?: string; pending?: boolean };
export type Block = { hash: string; time: number };

export const goText = (from = 1) => from > 1 ? `go ${from}` : "go";
export function goFrom(text: string): number | null { const m = /^go(?: ([1-9]\d?))?$/.exec(text); return m ? (m[1] ? Math.min(+m[1], DEPTH) : 1) : null; }
export const endText = (kind: "up" | "fell", go: string, packed: string) => `${kind} ${go.toLowerCase()} ${packed}`;
export function parseEnd(text: string): { kind: "up" | "fell"; go: string; moves: string } | null {
  const m = /^(up|fell) (0x[0-9a-f]{64}) ([0-9a-zNSEWZX]{1,450})$/.exec(text);
  const moves = m && unpack(m[3]);
  return m && moves && moves.length <= LAMP ? { kind: m[1] as "up" | "fell", go: m[2], moves } : null;
}

// A descent's seed: the block after the going-down, and the going-down itself
export async function seedOf(blockHash: string, go: string): Promise<string> {
  const data = new TextEncoder().encode(`deep|${blockHash.toLowerCase().replace(/^0x/, "")}|${go.toLowerCase()}`);
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", data))].map(b => b.toString(16).padStart(2, "0")).join("");
}
export const seedFor = async (go: Rec, block: (h: number) => Promise<Block>) => seedOf((await block(go.height + 1)).hash, go.id);

export type Return = { id: string; go: string; by: string; at: number; height: number; depth: number; turns: number; relics: string[]; beaten: string[] };
export type Fall = Grave & { id: string; go: string; at: number; height: number; turns: number };
export type History = {
  returns: Return[]; falls: Fall[];
  home: Map<string, { by: string; at: number; height: number; from: number }>; // relic id -> who brought it up, when, from which floor
  firstTo: Map<number, { by: string; at: number }>;                            // floor -> first to reach it (and live or leave a grave)
  deepest: number;
  stateAt: (height: number) => State;                                         // the deep as it stood at a height
};

// The whole history of the deep, worked out from its records
export async function history(gos: Rec[], ends: Rec[], block: (h: number) => Promise<Block>): Promise<History> {
  const goBy = new Map<string, Rec & { from: number }>();
  for (const g of gos) { const from = goFrom(g.text); if (from && g.author && !g.pending) goBy.set(g.id.toLowerCase(), { ...g, from }); }
  // what happened, in the order it landed: relics coming home, people falling
  const homeAt: { id: string; by: string; at: number; height: number; from: number }[] = [];
  const falls: Fall[] = [], returns: Return[] = [];
  const stateAt = (h: number): State => {
    const home = new Map<string, string>();
    for (const x of homeAt) if (x.height <= h && !home.has(x.id)) home.set(x.id, x.by);
    // a relic lies in the last grave it fell into (unless it's been brought home)
    const lies = new Map<string, Fall>();
    for (const f of falls) if (f.height <= h) for (const id of f.relics) lies.set(id, f);
    const graves = falls.filter(f => f.height <= h).map(f => ({ by: f.by, depth: f.depth, x: f.x, y: f.y, killedBy: f.killedBy, relics: f.relics.filter(id => lies.get(id) === f && !home.has(id)) }));
    let rope: State["rope"] = null;
    for (const r of returns) if (r.height <= h && (!rope || r.depth > rope.depth)) rope = { depth: r.depth, by: r.by };
    return { home, graves, rope };
  };
  const done = new Set<string>(), firstTo = new Map<number, { by: string; at: number }>();
  for (const e of [...ends].filter(e => !e.pending && e.author).sort((a, b) => a.height - b.height || a.id.localeCompare(b.id))) {
    const p = parseEnd(e.text), g = p && goBy.get(p.go);
    if (!p || !g || done.has(p.go) || g.author!.toLowerCase() !== e.author!.toLowerCase()) continue;
    if (e.height <= g.height + 1 || e.height > g.height + END_WITHIN) continue;
    const b = await block(g.height + 1).catch(() => null);
    if (!b) continue;
    const st = stateAt(g.height);
    if (g.from > deepestStart(st)) continue; // nobody's rope went that deep yet
    const run = play(await seedOf(b.hash, g.id), p.moves, st, g.from);
    const by = e.author!.toLowerCase();
    if (p.kind === "up" && run.over === "out") {
      done.add(p.go);
      const taken = new Set(homeAt.map(x => x.id));
      const relics = run.carried.filter(id => !taken.has(id)), beaten = run.carried.filter(id => taken.has(id));
      for (const id of relics) homeAt.push({ id, by, at: e.time, height: e.height, from: +id.split(".")[0] });
      returns.push({ id: e.id, go: p.go, by, at: e.time, height: e.height, depth: run.deepest, turns: run.turn, relics, beaten });
    } else if (p.kind === "fell" && (run.over === "dead" || run.over === "dark")) {
      done.add(p.go);
      falls.push({ id: e.id, go: p.go, by, at: e.time, height: e.height, turns: run.turn, depth: run.floor.depth, x: run.x, y: run.y, killedBy: run.killedBy, relics: run.carried.filter(id => !homeAt.some(x => x.id === id)) });
    } else continue;
    for (let d = run.from; d <= run.deepest; d++) if (!firstTo.has(d)) firstTo.set(d, { by, at: e.time });
  }
  const home = new Map<string, { by: string; at: number; height: number; from: number }>();
  for (const x of homeAt) if (!home.has(x.id)) home.set(x.id, x);
  return { returns, falls, home, firstTo, deepest: Math.max(0, ...firstTo.keys()), stateAt };
}

export { relicName };
export const ordinal = (n: number) => `${n}${n % 100 >= 11 && n % 100 <= 13 ? "th" : ["th", "st", "nd", "rd"][n % 10] ?? "th"}`;
