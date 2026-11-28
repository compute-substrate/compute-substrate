// The deep: one dungeon for everyone, for good. Its twenty floors are drawn once, from WORLD, so
// every machine has the same rooms, the same monsters where they start, and the same chests in the
// same places. Each chest holds one relic, which can only ever be brought up once; at the bottom is
// one thing, and only one person will ever have it.
//
// What a descent changes is the fighting: every going-down has its own seed (from a block nobody
// knew in advance), which decides every swing and every step a monster takes. Plain arithmetic on the
// seed, the world as it stood when you went down, and your moves: anyone who replays them ends in
// the same place, carrying the same things (src/rules.ts).

export const WORLD = "the deep";
export const DEPTH = 20;            // the bottom
export const FW = 19, FH = 13;      // a floor, in squares
export const LAMP = 860;            // turns of oil: when it runs out, you're lost in the dark
export const MAX_HP = 12;
export const WALL = 0, FLOOR = 1;
export const BOTTOM = `${DEPTH}.eye`, BOTTOM_NAME = "eye of the deep";

// 32-bit hashing (FNV-1a, then a mix): the same numbers on every machine
export function hash32(...parts: (string | number)[]): number {
  let h = 0x811c9dc5;
  for (const ch of parts.join("|")) { h ^= ch.charCodeAt(0); h = Math.imul(h, 0x01000193) >>> 0; }
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b) >>> 0; h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35) >>> 0; h ^= h >>> 16;
  return h >>> 0;
}
const rnd = (...p: (string | number)[]) => hash32(...p) / 4294967296;

// ── what lives down there ──
export type Kind = { name: string; hp: number; dmg: [number, number]; hit: number; from: number; weight: number; erratic?: boolean };
export const KINDS: Kind[] = [
  { name: "rat", hp: 2, dmg: [1, 1], hit: 0.65, from: 1, weight: 10 },
  { name: "bat", hp: 2, dmg: [1, 2], hit: 0.55, from: 1, weight: 6, erratic: true },
  { name: "goblin", hp: 4, dmg: [1, 2], hit: 0.65, from: 2, weight: 8 },
  { name: "skeleton", hp: 6, dmg: [1, 3], hit: 0.65, from: 4, weight: 7 },
  { name: "spider", hp: 4, dmg: [2, 3], hit: 0.7, from: 6, weight: 6 },
  { name: "ogre", hp: 11, dmg: [2, 4], hit: 0.6, from: 9, weight: 4 },
  { name: "wraith", hp: 8, dmg: [2, 5], hit: 0.7, from: 12, weight: 4, erratic: true },
  { name: "warden", hp: 18, dmg: [3, 6], hit: 0.65, from: 99, weight: 0 }, // only at the bottom
];
export const kindOf = (n: string) => KINDS.find(k => k.name === n)!;

// ── relics: near the top, a few of each; deeper, fewer; the last floors, one of each ──
export type Relic = { name: string; from: number; copies: number };
export const RELICS: Relic[] = [
  { name: "bone dice", from: 1, copies: 4 }, { name: "tin whistle", from: 1, copies: 4 }, { name: "copper ring", from: 1, copies: 4 },
  { name: "cracked lens", from: 2, copies: 3 }, { name: "wax seal", from: 2, copies: 3 }, { name: "old key", from: 3, copies: 3 },
  { name: "clay owl", from: 3, copies: 3 }, { name: "brass compass", from: 4, copies: 3 },
  { name: "pewter cup", from: 4, copies: 2 }, { name: "carved spoon", from: 5, copies: 2 }, { name: "jade beetle", from: 5, copies: 2 },
  { name: "silver comb", from: 6, copies: 2 }, { name: "amber drop", from: 6, copies: 2 }, { name: "glass eye", from: 7, copies: 2 },
  { name: "bronze mask", from: 7, copies: 2 }, { name: "iron crown", from: 8, copies: 2 }, { name: "ivory chess king", from: 9, copies: 2 },
  { name: "ember ring", from: 10, copies: 2 },
  { name: "moth lantern", from: 11, copies: 1 }, { name: "salt harp", from: 11, copies: 1 }, { name: "drowned bell", from: 12, copies: 1 },
  { name: "silver hourglass", from: 12, copies: 1 }, { name: "star chart", from: 13, copies: 1 }, { name: "black pearl", from: 14, copies: 1 },
  { name: "obsidian heart", from: 15, copies: 1 }, { name: "frost crown", from: 15, copies: 1 }, { name: "crown of ash", from: 16, copies: 1 },
  { name: "pale key", from: 17, copies: 1 }, { name: "sun disc", from: 18, copies: 1 }, { name: "first feather", from: 18, copies: 1 },
  { name: "last candle", from: 19, copies: 1 },
];
export type Rarity = "common" | "uncommon" | "scarce" | "rare" | "legendary" | "one";
export const copiesOf = (name: string) => name === BOTTOM_NAME ? 1 : RELICS.find(r => r.name === name)?.copies ?? 1;
export function rarityOf(name: string): Rarity {
  if (name === BOTTOM_NAME) return "one";
  const r = RELICS.find(r => r.name === name);
  if (!r) return "common";
  return r.copies >= 4 ? "common" : r.copies === 3 ? "uncommon" : r.copies === 2 ? "scarce" : r.from < 15 ? "rare" : "legendary";
}
// which relics are on which floor: the copies of each spread over a few floors from where it starts
const stockOf = (() => { let m: Map<number, string[]> | null = null; return (depth: number) => {
  if (!m) {
    m = new Map();
    // each copy goes to the emptiest floor in its stretch, so no floor is crowded
    for (const r of RELICS) for (let k = 0; k < r.copies; k++) {
      const cost = (d: number) => (m!.get(d)?.length ?? 0) + (m!.get(d)?.includes(r.name) ? 10 : 0) + (d - r.from) * 0.3;
      let best = r.from;
      for (let d = r.from; d < Math.min(DEPTH, r.from + Math.min(8, r.copies * 2)); d++) if (cost(d) < cost(best)) best = d;
      m.set(best, [...(m.get(best) ?? []), r.name]);
    }
  }
  return m.get(depth) ?? [];
}; })();
function pick<T extends { from: number; weight: number }>(list: T[], depth: number, u: number): T {
  // deeper floors lean away from what's been there since the top
  const pool = list.filter(x => x.from <= depth).map(x => ({ x, w: x.weight * (x.from >= depth - 4 ? 1 : 0.35) }));
  const total = pool.reduce((a, p) => a + p.w, 0);
  let t = u * total;
  for (const p of pool) { if (t < p.w) return p.x; t -= p.w; }
  return pool[pool.length - 1].x;
}

// ── the world as it stands: what's been brought up, and who lies where with what ──
export type Grave = { by: string; depth: number; x: number; y: number; killedBy?: string; relics: string[] };
// home: relic id -> who brought it up. ropes: the deepest floor anyone has climbed out of, and who:
// their rope stays, so anyone can go straight down to it (and nobody further).
export type State = { home: Map<string, string>; graves: Grave[]; rope: { depth: number; by: string } | null };
export const EMPTY: State = { home: new Map(), graves: [], rope: null };
export const deepestStart = (s: State) => Math.max(1, s.rope?.depth ?? 1);

// ── a floor ──
export type Thing = { kind: "chest" | "draught" | "whetstone" | "grave"; x: number; y: number; id?: string; relic?: string; taken?: boolean; empty?: string; grave?: Grave };
export type Monster = { id: number; kind: string; x: number; y: number; hp: number; awake: boolean; guard?: boolean };
export type Floor = { depth: number; tiles: number[]; rope: { x: number; y: number }; stairs: { x: number; y: number } | null; things: Thing[]; monsters: Monster[] };
export const tileAt = (f: Floor, x: number, y: number) => (x < 0 || y < 0 || x >= FW || y >= FH ? WALL : f.tiles[y * FW + x]);

// The plan of a floor: the same for everyone, always
type Plan = { tiles: number[]; rope: { x: number; y: number }; stairs: { x: number; y: number } | null; chests: { id: string; relic: string; x: number; y: number }[]; supplies: Thing[]; monsters: Monster[] };
const plans = new Map<number, Plan>();
export function plan(depth: number): Plan {
  const had = plans.get(depth); if (had) return had;
  const R = (...p: (string | number)[]) => rnd(WORLD, "floor", depth, ...p);
  const tiles = new Array(FW * FH).fill(WALL);
  type Room = { x: number; y: number; w: number; h: number };
  const rooms: Room[] = [];
  for (let i = 0; i < 80 && rooms.length < 6; i++) {
    const w = 3 + Math.floor(R(i, "w") * 4), h = 3 + Math.floor(R(i, "h") * 3);
    const x = 1 + Math.floor(R(i, "x") * (FW - w - 1)), y = 1 + Math.floor(R(i, "y") * (FH - h - 1));
    if (rooms.some(r => x <= r.x + r.w && r.x <= x + w && y <= r.y + r.h && r.y <= y + h)) continue;
    rooms.push({ x, y, w, h });
  }
  const set = (x: number, y: number) => { if (x > 0 && y > 0 && x < FW - 1 && y < FH - 1) tiles[y * FW + x] = FLOOR; };
  for (const r of rooms) for (let y = r.y; y < r.y + r.h; y++) for (let x = r.x; x < r.x + r.w; x++) set(x, y);
  const mid = (r: Room) => ({ x: r.x + (r.w >> 1), y: r.y + (r.h >> 1) });
  for (let i = 1; i < rooms.length; i++) {
    const a = mid(rooms[i - 1]), b = mid(rooms[i]);
    if (R(i, "bend") < 0.5) { for (let x = Math.min(a.x, b.x); x <= Math.max(a.x, b.x); x++) set(x, a.y); for (let y = Math.min(a.y, b.y); y <= Math.max(a.y, b.y); y++) set(b.x, y); }
    else { for (let y = Math.min(a.y, b.y); y <= Math.max(a.y, b.y); y++) set(a.x, y); for (let x = Math.min(a.x, b.x); x <= Math.max(a.x, b.x); x++) set(x, b.y); }
  }
  const rope = mid(rooms[0]);
  const far = rooms.slice(1).sort((p, q) => (Math.abs(mid(q).x - rope.x) + Math.abs(mid(q).y - rope.y)) - (Math.abs(mid(p).x - rope.x) + Math.abs(mid(p).y - rope.y)))[0];
  const bottom = depth === DEPTH;
  const stairs = bottom ? null : mid(far);
  const r0 = rooms[0], free: { x: number; y: number }[] = [];
  for (let y = 0; y < FH; y++) for (let x = 0; x < FW; x++) {
    if (tiles[y * FW + x] !== FLOOR || (stairs && x === stairs.x && y === stairs.y) || (bottom && x === mid(far).x && y === mid(far).y)) continue;
    if (x >= r0.x - 1 && x <= r0.x + r0.w && y >= r0.y - 1 && y <= r0.y + r0.h) continue;
    free.push({ x, y });
  }
  let k = 0;
  const take = () => { if (!free.length) return null; const i = Math.floor(R("place", k++) * free.length); return free.splice(i, 1)[0]; };
  const chests: Plan["chests"] = [];
  // at the bottom, in the farthest room: the one thing
  if (bottom) chests.push({ id: BOTTOM, relic: BOTTOM_NAME, ...mid(far) });
  stockOf(depth).forEach((name, i) => { const s = take(); if (s) chests.push({ id: `${depth}.${i}`, relic: name, ...s }); });
  const supplies: Thing[] = [];
  if (R("draught") < 0.6 + depth * 0.01) { const s = take(); if (s) supplies.push({ kind: "draught", ...s }); }
  if (R("draught2") < depth * 0.02) { const s = take(); if (s) supplies.push({ kind: "draught", ...s }); }
  if (R("whetstone") < 0.22) { const s = take(); if (s) supplies.push({ kind: "whetstone", ...s }); }
  const monsters: Monster[] = [];
  const count = Math.min(7, 1 + Math.floor(depth * 0.3) + (R("more") < 0.5 ? 1 : 0));
  // the bottom is kept by a warden, asleep beside the one thing; it wakes when the thing is taken
  if (bottom) for (const [dx, dy] of [[-1, 0]]) { const e = mid(far); const i = free.findIndex(p => p.x === e.x + dx && p.y === e.y + dy); if (i >= 0) { free.splice(i, 1); monsters.push({ id: monsters.length, kind: "warden", x: e.x + dx, y: e.y + dy, hp: 18, awake: false, guard: true }); } }
  for (let i = 0; i < count; i++) {
    const s = take(); if (!s) break;
    const kind = pick(KINDS, depth, R("kind", i));
    monsters.push({ id: monsters.length, kind: kind.name, ...s, hp: kind.hp + Math.floor(depth / 7), awake: false });
  }
  const p = { tiles, rope, stairs, chests, supplies, monsters };
  plans.set(depth, p);
  return p;
}

// Every relic in the deep, where it was put
export const allRelics = () => { const out: { id: string; name: string; depth: number }[] = []; for (let d = 1; d <= DEPTH; d++) for (const c of plan(d).chests) out.push({ id: c.id, name: c.relic, depth: d }); return out; };
export const relicName = (id: string) => { const d = +id.split(".")[0]; return plan(d)?.chests.find(c => c.id === id)?.relic ?? "relic"; };

// A floor as you find it: the plan, with what others have done to it
function floorOf(depth: number, state: State): Floor {
  const p = plan(depth);
  const gone = new Set<string>([...state.home.keys(), ...state.graves.flatMap(g => g.relics)]);
  const things: Thing[] = [
    ...p.chests.map(c => ({ kind: "chest" as const, x: c.x, y: c.y, id: c.id, relic: c.relic, taken: gone.has(c.id), empty: state.home.get(c.id) ?? (gone.has(c.id) ? "-" : undefined) })),
    ...p.supplies.map(s => ({ ...s })),
    ...state.graves.filter(g => g.depth === depth).map(g => ({ kind: "grave" as const, x: g.x, y: g.y, grave: { ...g, relics: g.relics.filter(id => !state.home.has(id)) } })),
  ];
  return { depth, tiles: p.tiles, rope: p.rope, stairs: p.stairs, things, monsters: p.monsters.map(m => ({ ...m })) };
}

// ── a run ──
export type Run = {
  seed: string; state: State; from: number; turn: number; floor: Floor; x: number; y: number; hp: number; dmg: number;
  carried: string[]; deepest: number; over: null | "out" | "dead" | "dark"; killedBy?: string;
};
export const MOVES = "nsewzx"; // north, south, east, west, wait, climb out (on the rope)
const DIR: Record<string, [number, number]> = { n: [0, -1], s: [0, 1], e: [1, 0], w: [-1, 0] };

// a descent starts at the top, or down someone's rope to any floor no deeper than theirs
export function start(seed: string, state: State = EMPTY, from = 1): Run {
  const d = Math.max(1, Math.min(from, deepestStart(state)));
  const floor = floorOf(d, state);
  return { seed, state, from: d, turn: 0, floor, x: floor.rope.x, y: floor.rope.y, hp: MAX_HP, dmg: 0, carried: [], deepest: d, over: null };
}
export const onRope = (r: Run) => r.x === r.floor.rope.x && r.y === r.floor.rope.y;
const a = (n: string) => (/^[aeiou]/.test(n) ? "an " : "a ") + n;
// someone, in a line of the log: "@0x…" for the page to put a name to
const at = (who: string) => `@${who}`;

// One move. Returns what happened, as lines for a log. Changes the run in place.
export function step(run: Run, m: string): string[] {
  if (run.over || !MOVES.includes(m) || m.length !== 1) return [];
  run.turn++;
  const ev: string[] = [];
  const u = (k: string | number) => rnd(run.seed, "turn", run.turn, k);
  const f = run.floor;
  if (m === "x" && onRope(run)) { run.over = "out"; ev.push(run.carried.length ? `You climb out with ${run.carried.length} relic${run.carried.length === 1 ? "" : "s"}.` : "You climb out."); return ev; }
  if (DIR[m]) {
    const nx = run.x + DIR[m][0], ny = run.y + DIR[m][1];
    const foe = f.monsters.find(o => o.hp > 0 && o.x === nx && o.y === ny);
    if (foe) {
      foe.awake = true;
      if (u("you") < 0.8) {
        foe.hp -= 1 + Math.floor(u("yourdmg") * 3) + run.dmg;
        ev.push(foe.hp > 0 ? `You hit the ${foe.kind}.` : `You kill the ${foe.kind}.`);
      } else ev.push(`You miss the ${foe.kind}.`);
    } else if (tileAt(f, nx, ny) === FLOOR) {
      run.x = nx; run.y = ny;
      if (f.stairs && nx === f.stairs.x && ny === f.stairs.y) {
        const next = floorOf(f.depth + 1, run.state);
        run.floor = next; run.x = next.rope.x; run.y = next.rope.y; run.deepest = Math.max(run.deepest, next.depth);
        ev.push(next.depth === DEPTH ? `Floor ${next.depth}. The bottom.` : `Floor ${next.depth}.`);
        return lamp(run, ev);
      }
      for (const t of f.things.filter(t => !t.taken && t.x === nx && t.y === ny)) {
        if (t.kind === "chest") {
          t.taken = true; run.carried.push(t.id!);
          const c = copiesOf(t.relic!);
          ev.push(t.id === BOTTOM ? `In the chest: the ${BOTTOM_NAME}.` : c === 1 ? `In the chest: the ${t.relic}. There is only one.` : `In the chest: ${a(t.relic!)}, one of ${c}.`);
          if (t.id === BOTTOM) for (const o of f.monsters) if (o.guard && o.hp > 0 && !o.awake) { o.awake = true; ev.push(`The ${o.kind} wakes.`); }
        } else if (t.kind === "draught") { t.taken = true; run.hp = Math.min(MAX_HP, run.hp + 6); ev.push("You drink a draught."); }
        else if (t.kind === "whetstone") { t.taken = true; run.dmg++; ev.push("You sharpen your blade on a whetstone."); }
        else if (t.kind === "grave") {
          const g = t.grave!;
          ev.push(`Here lies ${at(g.by)}${g.killedBy ? `, killed by a ${g.killedBy}` : ", lost in the dark"}.`);
          if (g.relics.length) { run.carried.push(...g.relics); ev.push(`You take ${g.relics.map(id => a(relicName(id))).join(" and ")} from the grave.`); g.relics = []; }
        }
      }
      for (const t of f.things.filter(t => t.kind === "chest" && t.taken && t.empty && t.x === nx && t.y === ny && !run.carried.includes(t.id!)))
        ev.push(t.empty === "-" ? "The chest is empty. Someone took it down here and never came back up." : `The chest is empty. ${at(t.empty!)} got here first.`);
    }
  }
  // resting a while mends you a little
  if (run.turn % 10 === 0 && run.hp < MAX_HP) run.hp++;
  // then everything awake comes for you
  for (const o of f.monsters) {
    if (o.hp <= 0) continue;
    const k = kindOf(o.kind), dx = run.x - o.x, dy = run.y - o.y, dist = Math.abs(dx) + Math.abs(dy);
    if (!o.awake && !o.guard && dist <= 5) o.awake = true;
    if (!o.awake) continue;
    if (dist === 1) {
      if (u(`hit${o.id}`) < k.hit) {
        const d = k.dmg[0] + Math.floor(u(`dmg${o.id}`) * (k.dmg[1] - k.dmg[0] + 1));
        run.hp -= d; ev.push(`The ${o.kind} hits you.`);
        if (run.hp <= 0) { run.hp = 0; run.over = "dead"; run.killedBy = o.kind; ev.push(`The ${o.kind} kills you on floor ${f.depth}.`); return ev; }
      } else ev.push(`The ${o.kind} misses.`);
      continue;
    }
    const free = (x: number, y: number) => tileAt(f, x, y) === FLOOR && !(x === run.x && y === run.y) && !f.monsters.some(p => p !== o && p.hp > 0 && p.x === x && p.y === y);
    let tries: [number, number][] = Math.abs(dx) >= Math.abs(dy) ? [[Math.sign(dx), 0], [0, Math.sign(dy)]] : [[0, Math.sign(dy)], [Math.sign(dx), 0]];
    if (k.erratic && u(`flit${o.id}`) < 0.4) tries = [[[1, 0], [-1, 0], [0, 1], [0, -1]][Math.floor(u(`way${o.id}`) * 4)] as [number, number]];
    for (const [sx, sy] of tries) if ((sx || sy) && free(o.x + sx, o.y + sy)) { o.x += sx; o.y += sy; break; }
  }
  return lamp(run, ev);
}
function lamp(run: Run, ev: string[]) {
  if (run.turn >= LAMP && !run.over) { run.over = "dark"; ev.push(`Your lamp goes out on floor ${run.floor.depth}.`); }
  else if (run.turn === LAMP - 100) ev.push("Your lamp is getting low.");
  return ev;
}

export function play(seed: string, moves: string, state: State = EMPTY, from = 1): Run {
  const r = start(seed, state, from);
  for (const m of moves) step(r, m);
  return r;
}

// Moves packed two to a character, so a whole run fits in one record
const ALPHA = "0123456789abcdefghijklmnopqrstuvwxyz", ODD = "NSEWZX";
export function pack(moves: string): string {
  let s = "";
  for (let i = 0; i + 1 < moves.length; i += 2) s += ALPHA[MOVES.indexOf(moves[i]) * 6 + MOVES.indexOf(moves[i + 1])];
  if (moves.length % 2) s += ODD[MOVES.indexOf(moves[moves.length - 1])];
  return s;
}
export function unpack(s: string): string | null {
  let m = "";
  for (let i = 0; i < s.length; i++) {
    const j = ALPHA.indexOf(s[i]);
    if (j >= 0 && j < 36) { m += MOVES[Math.floor(j / 6)] + MOVES[j % 6]; continue; }
    const o = ODD.indexOf(s[i]);
    if (o >= 0 && i === s.length - 1) { m += MOVES[o]; continue; }
    return null;
  }
  return m;
}
