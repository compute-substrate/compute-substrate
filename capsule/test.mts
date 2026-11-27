import * as S from "./src/schedule.ts";
let f = 0; const ok = (c: unknown, w: string) => { console.log(`${c ? "ok  " : "FAIL"} ${w}`); if (!c) f++; };
const t = (iso: string) => Date.parse(iso) / 1000;
ok(S.current(t("2026-11-27T20:00:00Z")).id === "2026-11-29" && !S.current(t("2026-11-27T20:00:00Z")).open, "on a Friday: this Sunday's capsule, not open yet");
ok(S.current(t("2026-11-29T19:10:00Z")).open, "Sunday 19:10 UTC: open");
ok(S.current(t("2026-11-29T19:30:00Z")).id === "2026-12-06", "the minute it closes, the next one is next week");
ok(S.current(t("2026-11-29T18:59:59Z")).open === false, "a second before: not yet");
ok(S.current(t("2026-11-01T12:00:00Z")).id === S.FIRST, "before the first one: the first one");
ok(S.past(t("2026-12-14T12:00:00Z")).join() === "2026-12-13,2026-12-06,2026-11-29", "earlier capsules, newest first, none before the first");
ok(S.past(t("2026-11-29T19:15:00Z")).length === 0, "an open capsule isn't earlier yet");
for (const [l, v] of [["https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=10", "dQw4w9WgXcQ"], ["https://youtu.be/dQw4w9WgXcQ", "dQw4w9WgXcQ"], ["https://m.youtube.com/shorts/dQw4w9WgXcQ", "dQw4w9WgXcQ"], ["https://vimeo.com/1", null], ["nope", null]] as const)
  ok(S.videoId(l) === v, `video from ${l}`);
ok(S.parsePick(S.pickText("dQw4w9WgXcQ", "  A   song ")).title === "A song", "a suggestion reads back");
const open = S.openAt("2026-11-29");
const picks = [
  { id: "0xa", text: S.pickText("aaaaaaaaaaa", "A"), time: open - 3000 },
  { id: "0xb", text: S.pickText("bbbbbbbbbbb", "B"), time: open - 2000 },
  { id: "0xc", text: S.pickText("ccccccccccc", "C"), time: open + 10 },
  { id: "0xd", text: "not a pick", time: open - 100 },
];
const cands = S.candidates("2026-11-29", [...picks, { id: "0xe", text: S.pickText("aaaaaaaaaaa", ""), time: open - 1000 }], { "0xa": 2, "0xb": 1, "0xc": 50 });
ok(cands.length === 2 && cands.find(c => c.video === "aaaaaaaaaaa")!.chances === 4 && cands.find(c => c.video === "bbbbbbbbbbb")!.chances === 2, "chances: one per suggestion and one per backer, per video; late ones and non-videos aren't in it");
const counts: Record<string, number> = {};
for (let i = 0n; i < 6000n; i++) { const c = S.draw(cands, i * 7919n)!; counts[c.video] = (counts[c.video] ?? 0) + 1; }
ok(Math.abs(counts["aaaaaaaaaaa"] / 6000 - 4 / 6) < 0.02, "a video with twice the chances is drawn about twice as often");
ok(S.draw([], 5n) === null, "nothing suggested: nothing drawn");
const r1 = await S.rollOf("0xABCD", "2026-11-29"), r2 = await S.rollOf("abcd", "2026-11-29"), r3 = await S.rollOf("abcd", "2026-12-06");
ok(r1 === r2 && r1 !== r3, "the roll is the same for everyone from the same block, and differs week to week");
// the opening block, from block times (one steps back a little after the opening)
const times = [open - 400, open - 280, open - 150, open - 20, open + 90, open + 60, open + 200, open + 330];
const blk = async (h: number) => ({ time: times[h], hash: "0x" + h });
ok((await S.openingBlock("2026-11-29", 7, blk))?.height === 4, "the opening block is the first at or after the opening time");
ok((await S.openingBlock("2026-11-29", 3, blk)) === null, "and there's none until a block reaches it");
ok(S.inWindow("2026-11-29", open + 60) && S.inWindow("2026-11-29", S.closeAt("2026-11-29") + 120) && !S.inWindow("2026-11-29", open - 1) && !S.inWindow("2026-11-29", S.closeAt("2026-11-29") + 3600), "what's said counts while open, and if it lands just after");
if (f) process.exit(1); console.log("all capsule checks passed");
