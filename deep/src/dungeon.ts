// The deep: a dungeon drawn from a seed, floor by floor, and a run through it played one move at a
// time. Everything here is plain arithmetic on the seed and the moves, so any machine that replays
// the same moves against the same seed ends in exactly the same place, carrying exactly the same
// things. That's what makes what you bring up checkable by anyone (src/rules.ts).

export const FW = 19, FH = 13;      // a floor, in squares
export const LAMP = 860;            // turns of oil: when it runs out, you're lost in the dark
export const MAX_HP = 12;
export const WALL = 0, FLOOR = 1;

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
  { name: "rat", hp: 2, dmg: [1, 1], hit: 0.7, from: 1, weight: 10 },
  { name: "bat", hp: 2, dmg: [1, 2], hit: 0.6, from: 1, weight: 6, erratic: true },
  { name: "goblin", hp: 4, dmg: [1, 2], hit: 0.7, from: 2, weight: 8 },
  { name: "skeleton", hp: 6, dmg: [1, 3], hit: 0.7, from: 3, weight: 7 },
  { name: "spider", hp: 4, dmg: [2, 3], hit: 0.75, from: 4, weight: 6 },
  { name: "ogre", hp: 11, dmg: [2, 4], hit: 0.65, from: 6, weight: 4 },
  { name: "wraith", hp: 8, dmg: [2, 5], hit: 0.75, from: 8, weight: 4, erratic: true },
  { name: "warden", hp: 18, dmg: [3, 6], hit: 0.7, from: 11, weight: 2 },
];
export const kindOf = (n: string) => KINDS.find(k => k.name === n)!;

// ── what you can bring up: relics, deeper ones rarer ──
export type Relic = { name: string; from: number; weight: number };
export const RELICS: Relic[] = [
  { name: "bone dice", from: 1, weight: 40 },
  { name: "tin whistle", from: 1, weight: 36 },
  { name: "copper ring", from: 1, weight: 34 },
  { name: "cracked lens", from: 1, weight: 30 },
  { name: "old key", from: 2, weight: 26 },
  { name: "jade beetle", from: 3, weight: 18 },
  { name: "silver comb", from: 3, weight: 16 },
  { name: "glass eye", from: 4, weight: 14 },
  { name: "iron crown", from: 4, weight: 10 },
  { name: "ember ring", from: 5, weight: 8 },
  { name: "moth lantern", from: 5, weight: 7 },
  { name: "drowned bell", from: 6, weight: 6 },
  { name: "star chart", from: 7, weight: 5 },
  { name: "obsidian heart", from: 8, weight: 3 },
  { name: "crown of ash", from: 9, weight: 2 },
  { name: "pale key", from: 10, weight: 2 },
  { name: "first feather", from: 12, weight: 1 },
  { name: "eye of the deep", from: 14, weight: 1 },
];
export const relicOf = (n: string) => RELICS.find(r => r.name === n);
export function rarity(r: Relic): "common" | "uncommon" | "scarce" | "rare" | "legendary" {
  return r.weight >= 26 ? "common" : r.weight >= 10 ? "uncommon" : r.weight >= 5 ? "scarce" : r.weight >= 2 ? "rare" : "legendary";
}
function pick<T extends { from: number; weight: number }>(list: T[], depth: number, u: number): T {
  // deeper floors lean away from what's been there since the top
  const pool = list.filter(x => x.from <= depth).map(x => ({ x, w: x.weight * (x.from >= depth - 4 ? 1 : 0.4) }));
  const total = pool.reduce((a, p) => a + p.w, 0);
  let t = u * total;
  for (const p of pool) { if (t < p.w) return p.x; t -= p.w; }
  return pool[pool.length - 1].x;
}

// ── a floor ──
export type Thing = { kind: "chest" | "draught" | "whetstone"; x: number; y: number; relic?: string; taken?: boolean };
export type Monster = { id: number; kind: string; x: number; y: number; hp: number; awake: boolean };
export type Floor = { depth: number; tiles: number[]; rope: { x: number; y: number }; stairs: { x: number; y: number }; things: Thing[]; monsters: Monster[] };
export const tileAt = (f: Floor, x: number, y: number) => (x < 0 || y < 0 || x >= FW || y >= FH ? WALL : f.tiles[y * FW + x]);

export function floorOf(seed: string, depth: number): Floor {
  const R = (...p: (string | number)[]) => rnd(seed, "floor", depth, ...p);
  const tiles = new Array(FW * FH).fill(WALL);
  type Room = { x: number; y: number; w: number; h: number };
  const rooms: Room[] = [];
  for (let i = 0; i < 60 && rooms.length < 6; i++) {
    const w = 3 + Math.floor(R(i, "w") * 4), h = 3 + Math.floor(R(i, "h") * 3);
    const x = 1 + Math.floor(R(i, "x") * (FW - w - 1)), y = 1 + Math.floor(R(i, "y") * (FH - h - 1));
    if (rooms.some(r => x <= r.x + r.w && r.x <= x + w && y <= r.y + r.h && r.y <= y + h)) continue;
    rooms.push({ x, y, w, h });
  }
  const set = (x: number, y: number) => { if (x > 0 && y > 0 && x < FW - 1 && y < FH - 1) tiles[y * FW + x] = FLOOR; };
  for (const r of rooms) for (let y = r.y; y < r.y + r.h; y++) for (let x = r.x; x < r.x + r.w; x++) set(x, y);
  const mid = (r: Room) => ({ x: r.x + (r.w >> 1), y: r.y + (r.h >> 1) });
  // rooms joined one to the next by corridors with a single bend
  for (let i = 1; i < rooms.length; i++) {
    const a = mid(rooms[i - 1]), b = mid(rooms[i]);
    if (R(i, "bend") < 0.5) { for (let x = Math.min(a.x, b.x); x <= Math.max(a.x, b.x); x++) set(x, a.y); for (let y = Math.min(a.y, b.y); y <= Math.max(a.y, b.y); y++) set(b.x, y); }
    else { for (let y = Math.min(a.y, b.y); y <= Math.max(a.y, b.y); y++) set(a.x, y); for (let x = Math.min(a.x, b.x); x <= Math.max(a.x, b.x); x++) set(x, b.y); }
  }
  const rope = mid(rooms[0]);
  const far = rooms.slice(1).sort((p, q) => (Math.abs(mid(q).x - rope.x) + Math.abs(mid(q).y - rope.y)) - (Math.abs(mid(p).x - rope.x) + Math.abs(mid(p).y - rope.y)))[0];
  const stairs = mid(far);
  // free squares, away from where you arrive
  const r0 = rooms[0], free: { x: number; y: number }[] = [];
  for (let y = 0; y < FH; y++) for (let x = 0; x < FW; x++) {
    if (tiles[y * FW + x] !== FLOOR || (x === stairs.x && y === stairs.y)) continue;
    if (x >= r0.x - 1 && x <= r0.x + r0.w && y >= r0.y - 1 && y <= r0.y + r0.h) continue;
    free.push({ x, y });
  }
  let k = 0;
  const take = () => { if (!free.length) return null; const i = Math.floor(R("place", k++) * free.length); return free.splice(i, 1)[0]; };
  const things: Thing[] = [];
  const chests = 1 + (R("chest2") < Math.min(0.5, depth * 0.05) ? 1 : 0);
  for (let i = 0; i < chests; i++) { const s = take(); if (s) things.push({ kind: "chest", ...s, relic: pick(RELICS, depth, R("relic", i)).name }); }
  if (R("draught") < 0.55) { const s = take(); if (s) things.push({ kind: "draught", ...s }); }
  if (R("whetstone") < 0.18) { const s = take(); if (s) things.push({ kind: "whetstone", ...s }); }
  const monsters: Monster[] = [];
  const n = Math.min(9, 1 + Math.floor(depth * 0.9) + (R("more") < 0.5 ? 1 : 0));
  for (let i = 0; i < n; i++) {
    const s = take(); if (!s) break;
    const kind = pick(KINDS, depth, R("kind", i));
    monsters.push({ id: i, kind: kind.name, ...s, hp: kind.hp + Math.floor(depth / 4), awake: false });
  }
  return { depth, tiles, rope, stairs, things, monsters };
}

// ── a run ──
export type Run = {
  seed: string; turn: number; floor: Floor; x: number; y: number; hp: number; dmg: number;
  carried: string[]; deepest: number; over: null | "out" | "dead" | "dark"; killedBy?: string;
};
export const MOVES = "nsewzx"; // north, south, east, west, wait, climb out (on the rope)
const DIR: Record<string, [number, number]> = { n: [0, -1], s: [0, 1], e: [1, 0], w: [-1, 0] };

export function start(seed: string): Run {
  const floor = floorOf(seed, 1);
  return { seed, turn: 0, floor, x: floor.rope.x, y: floor.rope.y, hp: MAX_HP, dmg: 0, carried: [], deepest: 1, over: null };
}
export const onRope = (r: Run) => r.x === r.floor.rope.x && r.y === r.floor.rope.y;
const a = (n: string) => (/^[aeiou]/.test(n) ? "an " : "a ") + n;

// One move. Returns what happened, as lines for a log. Changes the run in place.
export function step(run: Run, m: string): string[] {
  if (run.over || !MOVES.includes(m)) return [];
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
      if (nx === f.stairs.x && ny === f.stairs.y) {
        const next = floorOf(run.seed, f.depth + 1);
        run.floor = next; run.x = next.rope.x; run.y = next.rope.y; run.deepest = Math.max(run.deepest, next.depth);
        ev.push(`Floor ${next.depth}.`);
        return lamp(run, ev);
      }
      const t = f.things.find(t => !t.taken && t.x === nx && t.y === ny);
      if (t) {
        t.taken = true;
        if (t.kind === "chest") { run.carried.push(t.relic!); ev.push(`In the chest: ${a(t.relic!)}.`); }
        else if (t.kind === "draught") { run.hp = Math.min(MAX_HP, run.hp + 6); ev.push("You drink a draught."); }
        else { run.dmg++; ev.push("You sharpen your blade on a whetstone."); }
      }
    }
  }
  // resting a while mends you a little
  if (run.turn % 10 === 0 && run.hp < MAX_HP) run.hp++;
  // then everything awake comes for you
  for (const o of f.monsters) {
    if (o.hp <= 0) continue;
    const k = kindOf(o.kind), dx = run.x - o.x, dy = run.y - o.y, dist = Math.abs(dx) + Math.abs(dy);
    if (!o.awake && dist <= 5) o.awake = true;
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

export function play(seed: string, moves: string): Run {
  const r = start(seed);
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
