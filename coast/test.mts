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
const [sx, sy] = spots.find(([x, y]) => waterOf(a, x, y) === REEDS)!;
let sit = { id: "0x" + "1".repeat(64), text: R.sitText(sx, sy), height: 1000, time: t, author: alice };
const blocks = new Map<number, R.Block>();
const block = async (h: number) => { if (!blocks.has(h)) blocks.set(h, { hash: "0x" + h.toString(16).padStart(64, "0"), time: t + (h - 1000) * 120 }); return blocks.get(h)!; };
// find blocks in the sitting where something (not junk) bit (an hour with at least four)
let bit: number[] = [];
for (let n = 0; bit.length < 4 && n < 50; n++) {
  sit = { ...sit, id: "0x" + n.toString(16).padStart(64, "1") };
  bit = [];
  for (let h = 1001; h <= 1000 + R.SIT_BLOCKS; h++) { const c = await R.castAt({ ...sit, spot: { x: sx, y: sy } }, h, await block(h)); if (c && !c.species.junk) bit.push(h); }
}
ok(bit.length >= 4, `${bit.length} of ${R.SIT_BLOCKS} blocks in an hour brought a fish`);
const keep = (h: number, by = alice, landed = h + 2, id = "0x" + h.toString(16).padStart(64, "0")) => ({ id, text: R.keepText(sit.id, h), height: landed, time: t, author: by });
const kept = await R.keptCatches([sit], [keep(bit[0]), keep(bit[1]), keep(bit[1], alice, bit[1] + 3, "0x" + "f".repeat(64)), keep(bit[2], eve), keep(1000 + R.SIT_BLOCKS + 1), keep(bit[3], alice, 1000 + R.SIT_BLOCKS + R.KEEP_WITHIN + 1)], block);
ok(kept.length === 2, "kept: the two real ones; not a second keep of the same cast, not someone else's keep, not after the sitting, not too late");
ok(kept.every(k => k.by === alice) && kept[0].height === bit[0], "each credited to whoever sat");
const nothing = []; for (let h = 1001; h <= 1030; h++) if (!bit.includes(h) && !(await R.castAt({ ...sit, spot: { x: sx, y: sy } }, h, await block(h)))) nothing.push(h);
ok((await R.keptCatches([sit], [keep(nothing[0])], block)).length === 0, "keeping a cast where nothing bit counts for nothing");
ok((await R.keptCatches([{ ...sit, text: "sit 0 0" }], [keep(bit[0])], block)).length === 0, "a sitting on dry land isn't a sitting");
// numbering and boards
const sit2 = { ...sit, id: "0x" + "2".repeat(64), height: 2000 };
const more: number[] = []; for (let h = 2001; h <= 2030; h++) { const c = await R.castAt({ ...sit2, spot: { x: sx, y: sy } }, h, await block(h)); if (c && !c.species.junk) more.push(h); }
const all = await R.keptCatches([sit, sit2], [keep(bit[0]), ...more.map(h => ({ ...keep(h), text: R.keepText(sit2.id, h) }))], block);
const byName: Record<string, number[]> = {}; for (const k of all) (byName[k.catch.species.name] ??= []).push(k.nth);
ok(Object.values(byName).every(ns => ns.join() === ns.map((_, i) => i + 1).join()), "each species numbered 1st, 2nd, 3rd… in the order they were kept");
const bd = R.boards(all);
ok(bd.overall[0].catch.cm === Math.max(...all.map(k => k.catch.cm)) && bd.species.find(s => s.count)!.biggest, "the boards: biggest of all, and biggest and first of each kind");
ok(R.ordinal(1) === "1st" && R.ordinal(2) === "2nd" && R.ordinal(3) === "3rd" && R.ordinal(11) === "11th" && R.ordinal(22) === "22nd" && R.ordinal(104) === "104th", "1st, 2nd, 3rd, 11th, 22nd, 104th");
if (f) { console.log(`${f} failed`); process.exit(1); }
console.log("all coast checks passed");
