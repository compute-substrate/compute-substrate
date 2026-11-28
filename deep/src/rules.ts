// The deep's records, and how anyone checks them. Nothing here trusts anybody.
//
//   deep.go    "go"                       you go down. Your dungeon is drawn from the block after
//                                         the one this lands in, so nobody knew it in advance.
//   deep.out   "out <go id> <moves>"      you came back up: every move you made, packed. Anyone
//                                         replays them against the same dungeon; if the run ends
//                                         with you climbing out alive, what you carried is yours.
//                                         Written by whoever went down, within OUT_WITHIN blocks.
//
// Relics are numbered per kind in the order they were brought up ("the 2nd crown of ash ever").
import { play, unpack, relicOf, LAMP, type Run } from "./dungeon";

export const GO = "deep.go", OUT = "deep.out";
export const OUT_WITHIN = 720; // about a day
export type Rec = { id: string; text: string; height: number; time: number; author?: string; pending?: boolean };
export type Block = { hash: string; time: number };

export const outText = (go: string, packed: string) => `out ${go.toLowerCase()} ${packed}`;
export function parseOut(text: string): { go: string; moves: string } | null {
  const m = /^out (0x[0-9a-f]{64}) ([0-9a-zNSEWZX]{1,450})$/.exec(text);
  const moves = m && unpack(m[2]);
  return m && moves && moves.length <= LAMP ? { go: m[1], moves } : null;
}

// A dungeon's seed: the block after the going-down, and the going-down itself
export async function seedOf(blockHash: string, go: string): Promise<string> {
  const data = new TextEncoder().encode(`deep|${blockHash.toLowerCase().replace(/^0x/, "")}|${go.toLowerCase()}`);
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", data))].map(b => b.toString(16).padStart(2, "0")).join("");
}
export const seedFor = async (go: Rec, block: (h: number) => Promise<Block>) => seedOf((await block(go.height + 1)).hash, go.id);

export type Brought = { name: string; nth: number };
export type Return = { id: string; go: string; by: string; at: number; height: number; depth: number; turns: number; relics: Brought[] };

// Every return that checks out, with its relics numbered per kind in the order they came up
export async function returns(gos: Rec[], outs: Rec[], block: (h: number) => Promise<Block>): Promise<Return[]> {
  const goBy = new Map<string, Rec>();
  for (const g of gos) if (g.text === "go" && g.author && !g.pending) goBy.set(g.id.toLowerCase(), g);
  const done = new Set<string>(), out: Return[] = [], counts = new Map<string, number>();
  for (const o of [...outs].filter(o => !o.pending && o.author).sort((a, b) => a.height - b.height || a.id.localeCompare(b.id))) {
    const p = parseOut(o.text), g = p && goBy.get(p.go);
    if (!p || !g || done.has(p.go) || g.author!.toLowerCase() !== o.author!.toLowerCase()) continue;
    if (o.height <= g.height + 1 || o.height > g.height + OUT_WITHIN) continue;
    const b = await block(g.height + 1).catch(() => null);
    if (!b) continue;
    const run: Run = play(await seedOf(b.hash, g.id), p.moves);
    if (run.over !== "out") continue;
    done.add(p.go);
    const relics = run.carried.filter(n => relicOf(n)).map(name => { const nth = (counts.get(name) ?? 0) + 1; counts.set(name, nth); return { name, nth }; });
    out.push({ id: o.id, go: p.go, by: o.author!.toLowerCase(), at: o.time, height: o.height, depth: run.deepest, turns: run.turn, relics });
  }
  return out;
}

export const ordinal = (n: number) => `${n}${n % 100 >= 11 && n % 100 <= 13 ? "th" : ["th", "st", "nd", "rd"][n % 10] ?? "th"}`;
