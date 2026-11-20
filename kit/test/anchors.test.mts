// Anchors a client learns for itself: kept only on top of the exact shipped anchors, and only from
// checked headers well behind the tip.
import { storedAnchors, anchorsToLearn } from "../src/light";
let failures = 0;
const ok = (c: unknown, what: string) => { console.log(`${c ? "ok  " : "FAIL"} ${what}`); if (!c) failures++; };
const H = (n: number) => "0x" + n.toString(16).padStart(64, "0");
const shipped = { every: 1000, hashes: [H(0), H(1000), H(2000)] };
// headers checked from height 1955 (the anchor 2000 minus the difficulty window) to 5300
const hs = Array.from({ length: 5300 - 1955 + 1 }, (_, i) => ({ hash: H(1955 + i) }));
const fresh = anchorsToLearn(1000, 2000, hs, 1955, 5300, 200);
ok(fresh.length === 3 && fresh[0] === H(3000) && fresh[2] === H(5000), "learns one anchor every 1000 blocks past the newest");
ok(anchorsToLearn(1000, 2000, hs, 1955, 5150, 200).at(-1) === H(4000), "but none closer than 200 blocks to the tip");
ok(anchorsToLearn(1000, 5000, hs, 1955, 5300, 200).length === 0, "and nothing it already has");
const saved = JSON.stringify({ every: 1000, base: H(2000), hashes: fresh });
ok(storedAnchors(shipped, saved).length === 3, "kept anchors are used on top of the shipped ones they extend");
ok(storedAnchors({ every: 1000, hashes: [H(0), H(1000), H(2000), H(3000)] }, saved).length === 0, "not on top of a newer release's anchors (those start over)");
ok(storedAnchors(shipped, JSON.stringify({ every: 1000, base: H(2000), hashes: ["nonsense"] })).length === 0, "malformed storage is ignored");
ok(storedAnchors(shipped, null).length === 0 && storedAnchors(shipped, "{oops").length === 0, "missing or broken storage is ignored");
console.log(failures ? `\n${failures} failed` : "\nall passed"); process.exit(failures ? 1 : 0);
