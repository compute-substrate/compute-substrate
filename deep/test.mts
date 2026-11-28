// The deep: the same dungeon everywhere, runs that replay exactly, and returns nobody can fake
import { floorOf, play, start, step, pack, unpack, tileAt, onRope, FW, FH, FLOOR, LAMP, MOVES, type Run } from "./src/dungeon.ts";
import * as R from "./src/rules.ts";
let f = 0; const ok = (c: unknown, w: string) => { console.log(`${c ? "ok  " : "FAIL"} ${w}`); if (!c) f++; };

const seed = "a".repeat(64);
const a = floorOf(seed, 3), b = floorOf(seed, 3);
ok(JSON.stringify(a) === JSON.stringify(b), "the same floor on every machine, from the seed alone");
ok(JSON.stringify(floorOf("b".repeat(64), 3)) !== JSON.stringify(a), "another seed, another dungeon");
// every floor: the stairs can be reached from the rope
let reachable = true;
for (let s = 0; s < 200; s++) for (let d = 1; d <= 12; d++) {
  const fl = floorOf(`seed${s}`, d), seen = new Set([`${fl.rope.x},${fl.rope.y}`]), q = [fl.rope];
  while (q.length) { const p = q.shift()!; for (const [dx, dy] of [[1, 0], [-1, 0], [0, 1], [0, -1]]) { const x = p.x + dx, y = p.y + dy; if (tileAt(fl, x, y) === FLOOR && !seen.has(`${x},${y}`)) { seen.add(`${x},${y}`); q.push({ x, y }); } } }
  if (!seen.has(`${fl.stairs.x},${fl.stairs.y}`) || fl.things.some(t => !seen.has(`${t.x},${t.y}`))) reachable = false;
}
ok(reachable, "on 2,400 floors, the stairs and everything in them can be reached from the rope");
console.log(Array.from({ length: FH }, (_, y) => Array.from({ length: FW }, (_, x) => x === a.rope.x && y === a.rope.y ? "<" : x === a.stairs.x && y === a.stairs.y ? ">" : a.monsters.some(m => m.x === x && m.y === y) ? "m" : a.things.some(t => t.x === x && t.y === y) ? "$" : tileAt(a, x, y) ? "." : "#").join("")).join("\n"));

// a simple player: fight what's next to you, open chests, go down, and climb out when hurt or deep enough
function bot(seed: string, leaveAt: number): string {
  const r = start(seed); let moves = "";
  const go = (m: string) => { step(r, m); moves += m; };
  while (!r.over && moves.length < LAMP) {
    const fl = r.floor;
    const foe = fl.monsters.find(o => o.hp > 0 && Math.abs(o.x - r.x) + Math.abs(o.y - r.y) === 1);
    if (foe) { go(foe.x > r.x ? "e" : foe.x < r.x ? "w" : foe.y > r.y ? "s" : "n"); continue; }
    const leaving = r.hp <= 5 || fl.depth >= leaveAt;
    if (leaving && onRope(r)) { go("x"); break; }
    const goals = leaving ? [fl.rope] : [...fl.things.filter(t => !t.taken && t.kind !== "draught" || (!t.taken && r.hp < 9)), fl.stairs];
    // breadth-first to the nearest goal
    const prev = new Map<string, string>(), start0 = `${r.x},${r.y}`, q = [[r.x, r.y]]; prev.set(start0, "");
    let found: string | null = null;
    while (q.length && !found) { const [x, y] = q.shift()!; for (const [m, dx, dy] of [["n", 0, -1], ["s", 0, 1], ["e", 1, 0], ["w", -1, 0]] as const) { const k = `${x + dx},${y + dy}`; if (prev.has(k) || tileAt(fl, x + dx, y + dy) !== FLOOR || fl.monsters.some(o => o.hp > 0 && o.x === x + dx && o.y === y + dy)) continue; if (leaving && fl.stairs.x === x + dx && fl.stairs.y === y + dy) continue; prev.set(k, `${x},${y},${m}`); q.push([x + dx, y + dy]); if (goals.some(g => g.x === x + dx && g.y === y + dy)) { found = k; break; } } }
    if (!found) { go("z"); continue; }
    let k = found, first = "z";
    while (prev.get(k)) { const [px, py, m] = prev.get(k)!.split(","); first = m; k = `${px},${py}`; }
    go(first);
  }
  return moves;
}
let outs = 0, dead = 0, deepest = 0, relics = 0;
for (let s = 0; s < 300; s++) {
  const sd = `run${s}`, m = bot(sd, 3 + (s % 6)), r = play(sd, m);
  if (r.over === "out") { outs++; relics += r.carried.length; deepest = Math.max(deepest, r.deepest); } else dead++;
}
console.log(`  a careful bot over 300 runs: ${outs} climbed out (${relics} relics, deepest floor ${deepest}), ${dead} didn't`);
ok(outs > 60 && dead > 30, "climbing out is common, dying is too");

const m = bot("pack", 4);
ok(unpack(pack(m)) === m && unpack(pack(m + "z")) === m + "z", "moves pack two to a character and back, odd or even");
ok(pack("z".repeat(LAMP)).length <= 430, "a whole lamp's worth of moves fits in one record");
const r1 = play("pack", m), r2 = play("pack", m);
ok(JSON.stringify(r1) === JSON.stringify(r2), "the same moves end in the same place, carrying the same things");

// returns
const alice = "0x" + "a".repeat(40), eve = "0x" + "e".repeat(40), t = 1764300000;
const block = async (h: number) => ({ hash: "0x" + h.toString(16).padStart(64, "0"), time: t + h * 120 });
let go: R.Rec = { id: "0x" + "1".repeat(64), text: "go", height: 1000, time: t, author: alice };
let sd = await R.seedFor(go, block), run = bot(sd, 4), res = play(sd, run);
for (let n = 2; (res.over !== "out" || !res.carried.length) && n < 60; n++) { go = { ...go, id: "0x" + n.toString(16).padStart(64, "1") }; sd = await R.seedFor(go, block); run = bot(sd, 4); res = play(sd, run); }
ok(res.over === "out" && res.carried.length, `a run that came up with ${res.carried.join(", ")} from floor ${res.deepest}`);
const out = (text: string, height = 1010, by = alice, id = "0x" + height.toString(16).padStart(64, "0")) => ({ id, text, height, time: t, author: by });
const good = out(R.outText(go.id, pack(run)));
ok(R.parseOut(good.text)?.moves === run, "the record reads back to the same moves");
const got = await R.returns([go], [good], block);
ok(got.length === 1 && got[0].relics.map(x => x.name).join() === res.carried.join() && got[0].depth === res.deepest, "a real return counts, with what was carried");
const cheat = run.slice(0, -1) + "z";
ok((await R.returns([go], [out(R.outText(go.id, pack(cheat)))], block)).length === 0, "a run that didn't end climbing out counts for nothing");
ok((await R.returns([go], [out(good.text, 1010, eve)], block)).length === 0, "someone else can't bring up your run");
ok((await R.returns([go], [out(good.text, 1001)], block)).length === 0, "not before the dungeon was drawn");
ok((await R.returns([go], [out(good.text, 1000 + R.OUT_WITHIN + 1)], block)).length === 0, "not too late");
ok((await R.returns([go], [good, out(good.text, 1020)], block)).length === 1, "one return per going-down");
const fake = { ...go, id: "0x" + "9".repeat(64) };
ok((await R.returns([go, fake], [out(R.outText(fake.id, pack(run)))], block)).length === 0 || (await R.seedFor(fake, block)) === sd, "the same moves in another dungeon don't bring up the same things");
const go2 = { ...go, id: "0x" + "2".repeat(64), height: 2000 }, sd2 = await R.seedFor(go2, block), run2 = bot(sd2, 4);
const both = await R.returns([go, go2], [good, out(R.outText(go2.id, pack(run2)), 2010)], block);
const byName: Record<string, number[]> = {}; for (const x of both) for (const rl of x.relics) (byName[rl.name] ??= []).push(rl.nth);
ok(Object.values(byName).every(ns => ns.join() === ns.map((_, i) => i + 1).join()), "each kind of relic numbered 1st, 2nd, 3rd… in the order it came up");
ok(MOVES.length === 6 && R.ordinal(2) === "2nd" && R.ordinal(13) === "13th", "and the small things");
if (f) { console.log(`${f} failed`); process.exit(1); }
console.log("all deep checks passed");
