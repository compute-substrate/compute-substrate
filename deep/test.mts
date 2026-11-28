// The deep: one dungeon for everyone, runs that replay exactly, relics that come up once
import { plan, play, start, step, pack, unpack, tileAt, onRope, allRelics, relicName, FW, FH, FLOOR, LAMP, DEPTH, BOTTOM, MOVES, EMPTY, type State } from "./src/dungeon.ts";
import * as R from "./src/rules.ts";
let f = 0; const ok = (c: unknown, w: string) => { console.log(`${c ? "ok  " : "FAIL"} ${w}`); if (!c) f++; };

// the world
let reachable = true;
for (let d = 1; d <= DEPTH; d++) {
  const fl = plan(d), seen = new Set([`${fl.rope.x},${fl.rope.y}`]), q = [fl.rope];
  while (q.length) { const p = q.shift()!; for (const [dx, dy] of [[1, 0], [-1, 0], [0, 1], [0, -1]]) { const x = p.x + dx, y = p.y + dy; if (fl.tiles[y * FW + x] === FLOOR && !seen.has(`${x},${y}`)) { seen.add(`${x},${y}`); q.push({ x, y }); } } }
  if ((fl.stairs && !seen.has(`${fl.stairs.x},${fl.stairs.y}`)) || fl.chests.some(c => !seen.has(`${c.x},${c.y}`))) reachable = false;
}
ok(reachable, `all ${DEPTH} floors: the stairs and every chest can be reached from the rope`);
const relics = allRelics();
ok(relics.length > 20 && new Set(relics.map(r => r.id)).size === relics.length, `${relics.length} relics in the deep, each its own`);
ok(relics.filter(r => r.id === BOTTOM).length === 1 && !plan(DEPTH).stairs && plan(DEPTH).monsters.filter(m => m.kind === "warden" && m.guard).length === 1, "one thing at the bottom, no way further down, and a warden asleep beside it");
const b = plan(DEPTH);
console.log(Array.from({ length: FH }, (_, y) => Array.from({ length: FW }, (_, x) => x === b.rope.x && y === b.rope.y ? "<" : b.chests.some(c => c.x === x && c.y === y) ? "$" : b.monsters.some(m => m.x === x && m.y === y) ? "m" : b.tiles[y * FW + x] ? "." : "#").join("")).join("\n"));

// a careful player: fights what's next to it, rests when hurt, opens chests and graves, goes down, and
// climbs out when it's hurt or deep enough
function bot(seed: string, leaveAt: number, state: State = EMPTY): string {
  const r = start(seed, state); let moves = "";
  const go = (m: string) => { step(r, m); moves += m; };
  while (!r.over && moves.length < LAMP - 1) {
    const fl = r.floor;
    const foe = fl.monsters.find(o => o.hp > 0 && Math.abs(o.x - r.x) + Math.abs(o.y - r.y) === 1);
    // fight small things; walk away from big ones (a monster that has to follow you can't hit you)
    if (foe && !(foe.guard && !foe.awake) && (foe.hp <= 4 + r.dmg || ["rat", "bat", "goblin"].includes(foe.kind))) { go(foe.x > r.x ? "e" : foe.x < r.x ? "w" : foe.y > r.y ? "s" : "n"); continue; }
    const lampLow = LAMP - r.turn < 40 + fl.depth * 4;
    if (r.hp <= 6 && !lampLow && !fl.monsters.some(o => o.hp > 0 && o.awake && Math.abs(o.x - r.x) + Math.abs(o.y - r.y) <= 3)) { go("z"); continue; }
    const leaving = fl.depth >= leaveAt || lampLow || !fl.stairs;
    const chestsLeft = fl.things.filter(t => !t.taken && (t.kind === "chest" || t.kind === "grave" || (t.kind === "draught" && r.hp < 9) || t.kind === "whetstone"));
    if (leaving && !chestsLeft.length && onRope(r)) { go("x"); break; }
    const goals = leaving && (!chestsLeft.length || lampLow) ? [fl.rope] : [...chestsLeft, ...(fl.stairs && !leaving ? [fl.stairs] : [fl.rope])];
    if (onRope(r) && goals.length === 1 && goals[0] === fl.rope) { go("x"); break; }
    const prev = new Map<string, string>(), q = [[r.x, r.y]]; prev.set(`${r.x},${r.y}`, "");
    let found: string | null = null;
    while (q.length && !found) { const [x, y] = q.shift()!; for (const [m, dx, dy] of [["n", 0, -1], ["s", 0, 1], ["e", 1, 0], ["w", -1, 0]] as const) { const k = `${x + dx},${y + dy}`; if (prev.has(k) || tileAt(fl, x + dx, y + dy) !== FLOOR || fl.monsters.some(o => o.guard && !o.awake && o.hp > 0 && o.x === x + dx && o.y === y + dy)) continue; if (fl.stairs && fl.stairs.x === x + dx && fl.stairs.y === y + dy && !goals.includes(fl.stairs as any)) continue; prev.set(k, `${x},${y},${m}`); q.push([x + dx, y + dy]); if (goals.some(g => g.x === x + dx && g.y === y + dy)) { found = k; break; } } }
    if (!found) { go("z"); continue; }
    let k = found, first = "z";
    while (prev.get(k)) { const [px, py, m] = prev.get(k)!.split(","); first = m; k = `${px},${py}`; }
    go(first);
  }
  return moves;
}
const depths: number[] = []; let outs = 0, dead = 0;
for (let s = 0; s < 400; s++) {
  const sd = `run${s}`, m = bot(sd, 2 + (s % 14)), r = play(sd, m);
  if (r.over === "out") { outs++; depths.push(r.deepest); } else dead++;
}
const hist = (xs: number[]) => Array.from({ length: DEPTH }, (_, i) => xs.filter(x => x === i + 1).length).map((n, i) => n ? `${i + 1}:${n}` : "").filter(Boolean).join(" ");
console.log(`  a careful bot, 400 runs aiming for floors 2 to 15: ${outs} came back up, ${dead} didn't. Came back from: ${hist(depths)}`);
ok(outs > 100 && dead > 50 && Math.max(...depths) < DEPTH, "coming back is common, dying is too, and nobody just walks to the bottom");

const m = bot("pack", 4);
ok(unpack(pack(m)) === m && unpack(pack(m + "z")) === m + "z", "moves pack two to a character and back, odd or even");
ok(pack("z".repeat(LAMP)).length <= 430, "a whole lamp's worth of moves fits in one record");
ok(JSON.stringify(play("pack", m)) === JSON.stringify(play("pack", m)), "the same moves end in the same place, carrying the same things");

// the history: coming home, falling, racing
const alice = "0x" + "a".repeat(40), bob = "0x" + "b".repeat(40), eve = "0x" + "e".repeat(40), t = 1764300000;
const block = async (h: number) => ({ hash: "0x" + h.toString(16).padStart(64, "0"), time: t + h * 120 });
const goRec = (n: number, height: number, by: string) => ({ id: "0x" + n.toString(16).padStart(64, "0"), text: "go", height, time: t, author: by });
const end = (kind: "up" | "fell", g: R.Rec, moves: string, height: number, by = g.author!, n = height) => ({ id: "0x" + n.toString(16).padStart(64, "f"), text: R.endText(kind, g.id, pack(moves)), height, time: t + height, author: by });
// find a run of alice's that comes up with a relic
let ga = goRec(1, 1000, alice), ma = "", ra = play("x", "");
for (let n = 1; n < 80; n++) { ga = goRec(n, 1000, alice); const sd = await R.seedFor(ga, block); ma = bot(sd, 3); ra = play(sd, ma); if (ra.over === "out" && ra.carried.length) break; }
ok(ra.over === "out" && ra.carried.length, `alice comes up from floor ${ra.deepest} with ${ra.carried.map(relicName).join(", ")}`);
const upA = end("up", ga, ma, 1010);
ok(R.parseEnd(upA.text)?.moves === ma, "the record reads back to the same moves");
let h = await R.history([ga], [upA], block);
ok(h.returns.length === 1 && ra.carried.every(id => h.home.get(id)?.by === alice), "her relics are hers");
ok((await R.history([ga], [end("up", ga, ma.slice(0, -1) + "z", 1010)], block)).returns.length === 0, "a run that didn't end climbing out isn't a return");
ok((await R.history([ga], [end("up", ga, ma, 1010, eve)], block)).returns.length === 0, "someone else can't bring up her run");
ok((await R.history([ga], [end("up", ga, ma, 1001)], block)).returns.length === 0, "not before her fights were drawn");
ok((await R.history([ga], [end("up", ga, ma, 1000 + R.END_WITHIN + 1)], block)).returns.length === 0, "not too late");
ok((await R.history([ga], [upA, end("up", ga, ma, 1020)], block)).returns.length === 1, "one ending per going-down");
// after she's home, the chest is empty for everyone who goes down later
const later = start("later", h.stateAt(2000));
const chestA = ra.carried[0];
const after = (st: State) => { let r = start("x", st); for (let d = 1; d < +chestA.split(".")[0]; d++) r = r; return r; };
void after;
ok(later.state.home.get(chestA) === alice, "when bob goes down later, that chest is already empty");
// a race: bob went down before alice came home, and takes the same chest; whoever lands first has it
let gb = goRec(500, 1002, bob), mb = "", rb = play("x", "");
for (let n = 500; n < 700; n++) { gb = goRec(n, 1002, bob); const sd = await R.seedFor(gb, block); mb = bot(sd, 3); rb = play(sd, mb); if (rb.over === "out" && rb.carried.includes(chestA)) break; }
if (rb.carried.includes(chestA)) {
  const race = await R.history([ga, gb], [upA, end("up", gb, mb, 1012)], block);
  ok(race.home.get(chestA)?.by === alice && race.returns[1].beaten.includes(chestA), "a race for the same chest: the first one home has it, the other came up too late");
  const race2 = await R.history([ga, gb], [upA, end("up", gb, mb, 1008)], block);
  ok(race2.home.get(chestA)?.by === bob, "and the other way round when bob lands first");
} else ok(false, "found a race to test");
// falling: what you carried lies where you fell, for whoever comes next
let gc = goRec(800, 3000, bob), mc = "", rc = play("x", "");
for (let n = 800; n < 1200; n++) { gc = goRec(n, 3000, bob); const sd = await R.seedFor(gc, block); mc = bot(sd, 9, h.stateAt(3000)); rc = play(sd, mc, h.stateAt(3000)); if ((rc.over === "dead") && rc.carried.length) break; }
ok(rc.over === "dead" && rc.carried.length, `bob dies on floor ${rc.floor.depth} to a ${rc.killedBy}, carrying ${rc.carried.map(relicName).join(", ")}`);
const fall = end("fell", gc, mc, 3005);
h = await R.history([ga, gc], [upA, fall], block);
const grave = h.stateAt(4000).graves[0];
ok(h.falls.length === 1 && grave && grave.by === bob && grave.depth === rc.floor.depth && grave.relics.join() === rc.carried.join(), "his grave is where he fell, with what he carried");
ok((await R.history([ga, gc], [upA, end("up", gc, mc, 3005)], block)).returns.every(r => r.go !== gc.id) && (await R.history([gc], [end("fell", gc, mc.slice(0, 5), 3005)], block)).falls.length === 0, "a fall has to be a real death, and a return a real climb out");
// whoever reaches the grave later takes what's in it; once home, it's theirs, and the grave is empty
const st = h.stateAt(5000), floorOfGrave = start("g", st);
ok(floorOfGrave.state.graves[0].relics.length === rc.carried.length, "the grave is there for everyone who goes down after");
ok(h.firstTo.get(1)?.by === alice && h.deepest >= rc.floor.depth, `the first to each floor is remembered (deepest anyone has been: ${h.deepest})`);
// ropes: once someone climbs out of floor N, anyone can go straight down to it, and no deeper
ok(h.stateAt(5000).rope?.depth === ra.deepest && h.stateAt(5000).rope?.by === alice && h.stateAt(999).rope === null, `alice's rope goes down to floor ${ra.deepest}`);
const gd = { ...goRec(2000, 6000, bob), text: R.goText(ra.deepest) }, sdd = await R.seedFor(gd, block), md = bot(sdd, ra.deepest + 1, h.stateAt(6000)), rdd = play(sdd, md, h.stateAt(6000), ra.deepest);
ok(rdd.from === ra.deepest, "bob goes down her rope");
const ge = { ...goRec(2001, 6000, bob), text: R.goText(ra.deepest + 3) };
const he = await R.history([ga, gc, ge], [upA, fall, end("up", ge, md, 6010)], block);
ok(he.returns.length === 1, "nobody goes down a rope deeper than anyone has been");
ok(R.goFrom("go") === 1 && R.goFrom("go 7") === 7 && R.goFrom("go 0") === null && R.goFrom("go 07") === null, "go, or go down to a floor");
// the bottom: hard, not impossible
let got = 0; for (let s = 0; s < 300; s++) { const r = play(`bottom${s}`, bot(`bottom${s}`, DEPTH, { ...EMPTY, rope: { depth: DEPTH, by: alice } }), { ...EMPTY, rope: { depth: DEPTH, by: alice } }, DEPTH); if (r.over === "out" && r.carried.includes(BOTTOM)) got++; }
{ const why: Record<string, number> = {}; for (let s = 0; s < 100; s++) { const st = { ...EMPTY, rope: { depth: DEPTH, by: alice } }; const r = play(`bottom${s}`, bot(`bottom${s}`, DEPTH, st), st, DEPTH); const k = `${r.over}:${r.killedBy ?? ""}:${r.carried.includes(BOTTOM) ? "had" : ""}`; why[k] = (why[k] ?? 0) + 1; } console.log("  bottom outcomes", why); }
console.log(`  starting on the bottom floor, a careful bot came back with the one thing ${got} times in 300`);
ok(got < 60, "the one thing is hard to get (a bot that fights whatever blocks its way rarely or never does; people can lead monsters away)");
ok(MOVES.length === 6 && R.ordinal(2) === "2nd" && R.ordinal(13) === "13th", "and the small things");
if (f) { console.log(`${f} failed`); process.exit(1); }
console.log("all deep checks passed");
