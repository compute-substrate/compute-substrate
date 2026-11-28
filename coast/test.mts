// The coast: the same world everywhere, fair casts, and kept catches nobody can fake
import { build, W, H, castable, waterOf, isWater, SHALLOWS, REEDS, LEDGE, OPEN, LAND, SAND } from "./src/world.ts";
import { roll, FISH, rarity, BITE } from "./src/fish.ts";
import * as R from "./src/rules.ts";
let f = 0; const ok = (c: unknown, w: string) => { console.log(`${c ? "ok  " : "FAIL"} ${w}`); if (!c) f++; };

const a = build(), b = build();
ok(a.tiles.join() === b.tiles.join() && a.tiles.length === W * H, "the same coast on every machine, from the seed alone");
const kinds = new Set(a.tiles);
ok([SHALLOWS, REEDS, LEDGE, OPEN].every(k => kinds.has(k as any)), "it has shallows, reeds, a rock ledge and open water");
ok([LAND, SAND].includes(a.tile(a.fire.x, a.fire.y) as any), "the fire is on dry ground");
const spots = []; for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) if (castable(a, x, y)) spots.push([x, y]);
ok(spots.length > 200, `${spots.length} places to cast`);
ok(build("another coast").tiles.join() !== a.tiles.join(), "another seed, another coast");
console.log(Array.from({ length: H }, (_, y) => Array.from({ length: W }, (_, x) => "#^.~\"=~"[a.tile(x, y)] === "~" && a.dist(x, y) > 2 ? " " : "#^.~\"=~"[a.tile(x, y)]).join("")).join("\n"));

// casts: about a third bite, rare things rarely
const rnd = (i: number) => { const r = new Uint8Array(32); let s = i * 2654435761 >>> 0; for (let k = 0; k < 32; k++) { s = (Math.imul(s ^ (s >>> 15), 2246822519) + k) >>> 0; r[k] = s & 255; } return r; };
const t = Date.parse("2026-11-28T06:30:00Z") / 1000; // a November dawn
let bites = 0; const got: Record<string, number> = {}; let specimens = 0;
for (let i = 0; i < 40000; i++) { const c = roll(rnd(i), REEDS, t); if (c) { bites++; got[c.species.name] = (got[c.species.name] ?? 0) + 1; if (c.specimen) specimens++; } }
ok(Math.abs(bites / 40000 - BITE) < 0.01, `about ${Math.round(BITE * 100)}% of casts bite (${(bites / 400).toFixed(1)}%)`);
ok(got["golden char"] > 0 && got["golden char"] < got["pike"] && got["pike"] < got["perch"], `a November dawn in the reeds: perch ${got.perch}, pike ${got.pike}, golden char ${got["golden char"]}`);
ok(!got["tench"], "nothing out of season (no tench in November)");
ok(specimens > 0 && specimens < bites / 100, `specimens are rare (${specimens} of ${bites})`);
const night = Date.parse("2026-11-28T23:00:00Z") / 1000;
let char = 0; for (let i = 0; i < 20000; i++) if (roll(rnd(i), REEDS, night)?.species.name === "golden char") char++;
ok(char === 0, "golden char only bites at dawn");
ok(rarity(FISH.find(s => s.name === "golden char")!) === "legendary" && rarity(FISH.find(s => s.name === "herring")!) === "common", "rarity from how often each comes up");

// keeping, and checking what was kept
const alice = "0x" + "a".repeat(40), eve = "0x" + "e".repeat(40);
const [sx, sy] = spots.find(([x, y]) => waterOf(a, x, y) === SHALLOWS)!;
const blocks = new Map<number, R.Block>();
const block = async (h: number) => { if (!blocks.has(h)) blocks.set(h, { hash: "0x" + h.toString(16).padStart(64, "0"), time: t + (h - 1000) * 120 }); return blocks.get(h)!; };
const sitRec = (n: number, height: number, text = R.sitText(sx, sy), by = alice) => ({ id: "0x" + n.toString(16).padStart(64, "1"), text, height, time: t, author: by });
const view = (s: R.Rec) => { const p = R.parseSit(s.text)!; return { id: s.id, height: s.height, spot: { x: p.x, y: p.y }, end: s.height + p.hours * R.SIT_BLOCKS }; };
// find a sitting where at least four fish (not junk) bit
let sit = sitRec(0, 1000), bit: number[] = [];
for (let n = 0; bit.length < 4 && n < 50; n++) {
  sit = sitRec(n, 1000); bit = [];
  for (let h = 1001; h <= 1000 + R.SIT_BLOCKS; h++) { const c = await R.castAt(view(sit), h, await block(h)); if (c && !c.species.junk) bit.push(h); }
}
ok(bit.length >= 4, `${bit.length} of ${R.SIT_BLOCKS} blocks in an hour brought a fish`);
const keep = (hs: number[], landed = Math.max(...hs) + 2, by = alice, id = "0x" + landed.toString(16).padStart(64, "0"), s = sit) => ({ id, text: R.keepText(s.id, hs), height: landed, time: t, author: by });
const TIP = 99999;
let c = await R.coast([sit], [keep([bit[0], bit[1]]), keep([bit[1]], bit[1] + 3, alice, "0x" + "f".repeat(64)), keep([bit[2]], bit[2] + 2, eve), keep([1000 + R.SIT_BLOCKS + 1]), keep([bit[3]], 1000 + R.SIT_BLOCKS + R.KEEP_WITHIN + 1)], block, TIP);
ok(c.kept.length === 2, "kept: two at once in one record; not the same cast again, not someone else's keep, not after the sitting, not too late");
ok(c.kept.every(k => k.by === alice) && c.kept[0].height === bit[0], "each credited to whoever sat");
const nothing: number[] = []; for (let h = 1001; h <= 1030; h++) if (!bit.includes(h) && !(await R.castAt(view(sit), h, await block(h)))) nothing.push(h);
ok((await R.coast([sit], [keep([nothing[0]])], block, TIP)).kept.length === 0, "keeping a cast where nothing bit counts for nothing");
ok((await R.coast([{ ...sit, text: "sit 0 0" }], [keep([bit[0]])], block, TIP)).kept.length === 0, "a sitting on dry land isn't a sitting");
ok(R.parseKeep(R.keepText(sit.id, [5, 3, 5]))!.heights.join() === "3,5" && !R.parseKeep(`keep ${sit.id} ${Array.from({ length: 41 }, (_, i) => i + 1).join(",")}`), "a keep holds up to 40 casts");
// a long sitting, and sitting down somewhere else ending the first
const longSit = sitRec(70, 2000, R.sitText(sx, sy, 8));
ok(R.parseSit(longSit.text)?.hours === 8 && !R.parseSit(`sit ${sx} ${sy} 9`), "sit for up to eight hours");
c = await R.coast([longSit], [], block, TIP);
ok(c.xpOf(alice) === 8 * R.SIT_BLOCKS * R.XP_CAST, "every cast is experience: a night by the water");
ok(c.xpOf(alice, 2010) === 10 * R.XP_CAST, "counted as the blocks come, not all at once");
c = await R.coast([longSit, sitRec(71, 2050)], [], block, TIP);
ok(c.sittings[0].end === 2050 && c.xpOf(alice) === (50 + R.SIT_BLOCKS) * R.XP_CAST, "sitting down somewhere else ends where you were");
// levels
ok(R.levelFor(0) === 1 && R.levelFor(R.xpForLevel(10)) === 10 && R.levelFor(R.xpForLevel(10) - 1) === 9 && R.xpForLevel(99) === 13034431, "levels 1 to 99, 99 at 13,034,431");
const reeds = spots.find(([x, y]) => waterOf(a, x, y) === REEDS)!, open = spots.find(([x, y]) => waterOf(a, x, y) === OPEN)!;
ok(R.levelNeeded(sx, sy) === 1 && R.levelNeeded(reeds[0], reeds[1]) === 10 && R.levelNeeded(open[0], open[1]) === 40, "the shallows for everyone, the reeds from 10, the ledge from 25, open water from 40");
const early = sitRec(80, 3000, R.sitText(reeds[0], reeds[1]));
c = await R.coast([early], [], block, TIP);
ok(!c.sittings[0].valid && c.xpOf(alice) === 0, "a sitting in the reeds at level 1 doesn't count");
const enough = Math.ceil(R.xpForLevel(10) / R.XP_CAST);
c = await R.coast([sitRec(81, 3000, R.sitText(sx, sy, 8)), sitRec(82, 3000 + enough, R.sitText(reeds[0], reeds[1]))], [], block, TIP);
ok(c.sittings[1].valid && R.levelFor(c.xpOf(alice, 3000 + enough)) === 10, `after ${enough} casts in the shallows (level 10), the reeds count`);
const k1 = (await R.coast([sit], [keep([bit[0]])], block, TIP));
ok(k1.xpOf(alice) === R.SIT_BLOCKS * R.XP_CAST + R.XP_KEEP[rarity(k1.kept[0].catch.species)], "and every fish you keep is experience too, more for rarer ones");
// numbering and boards
const sit2 = sitRec(90, 4000);
const more: number[] = []; for (let h = 4001; h <= 4030; h++) { const cc = await R.castAt(view(sit2), h, await block(h)); if (cc && !cc.species.junk) more.push(h); }
const all = (await R.coast([sit, sit2], [keep([bit[0]]), keep(more, 4035, alice, "0x" + "e".repeat(64), sit2)], block, TIP)).kept;
const byName: Record<string, number[]> = {}; for (const k of all) (byName[k.catch.species.name] ??= []).push(k.nth);
ok(Object.values(byName).every(ns => ns.join() === ns.map((_, i) => i + 1).join()), "each species numbered 1st, 2nd, 3rd… in the order they were kept");
const bd = R.boards(all);
ok(bd.overall[0].catch.cm === Math.max(...all.map(k => k.catch.cm)) && bd.species.find(s => s.count)!.biggest, "the boards: biggest of all, and biggest and first of each kind");
ok(R.ordinal(1) === "1st" && R.ordinal(2) === "2nd" && R.ordinal(3) === "3rd" && R.ordinal(11) === "11th" && R.ordinal(22) === "22nd" && R.ordinal(104) === "104th", "1st, 2nd, 3rd, 11th, 22nd, 104th");
if (f) { console.log(`${f} failed`); process.exit(1); }
console.log("all coast checks passed");
