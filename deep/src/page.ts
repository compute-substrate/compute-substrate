// The deep: go down (a post), play the dungeon the next block draws, right here, at your own pace;
// climb out with what you found and post your way back up (a post). Anyone can replay the moves, so
// what you bring up is yours for good, numbered (src/rules.ts). Records are on their own page.
import { connect, writingKey, claimInvite, openInvites, welcome, friendlyName, doorwayAdd } from "../../kit/src/index";
import { start, step, pack, tileAt, onRope, rarity, relicOf, RELICS, FW, FH, FLOOR, LAMP, MAX_HP, type Run } from "./dungeon";
import { createScene, visible } from "./scene";
import * as R from "./rules";

const INVITES = "csd.welcome";
const $ = (id: string) => document.getElementById(id) as HTMLElement;
const esc = (s: string) => s.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const net = connect({ node: new URLSearchParams(location.search).get("node") ?? undefined });
const me = await writingKey("deep");
const mine = me.address.toLowerCase();
const who = (a?: string) => !a ? "someone" : a.toLowerCase() === mine ? "you" : friendlyName(a);
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);
const day = (t: number) => new Date(t * 1000).toLocaleDateString([], { day: "numeric", month: "short", year: "numeric" });
const list = (xs: string[]) => xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`;
const say = (t: string) => { $("said").textContent = t; };

// ── reading ──
const blocks = new Map<number, Promise<R.Block>>();
const block = (h: number) => {
  let b = blocks.get(h);
  if (!b) { b = fetch(`${net.node}/block/height/${h}`).then(r => r.json()).then(j => { if (!j.hash) throw new Error("no block"); return { hash: String(j.hash), time: Number(j.header.time) }; }); b.catch(() => blocks.delete(h)); blocks.set(h, b); }
  return b;
};
const proven = new Map<string, string>();
async function readChecked(topic: string, limit: number): Promise<R.Rec[]> {
  const rows = await net.read(topic, { limit, check: false });
  const todo = rows.filter(r => !r.pending && !proven.has(r.id));
  for (let i = 0; i < todo.length; i += 6) {
    const got = await Promise.all(todo.slice(i, i + 6).map(async r => ({ r, c: await net.check(r.id as any) })));
    for (const { r, c } of got) if (c.ok) proven.set(r.id, c.author);
  }
  return rows.filter(r => r.pending || proven.has(r.id)).map(r => ({ ...r, author: (r as any).author ?? proven.get(r.id) }));
}

let tip = 0, gos: R.Rec[] = [], outs: R.Rec[] = [], rets: R.Return[] = [];
async function refresh() {
  try {
    tip = (await net.api.tip()).height;
    const [g, o] = await Promise.all([readChecked(R.GO, 400), readChecked(R.OUT, 800)]);
    gos = g; outs = o;
    rets = await R.returns(g, o, block);
    await sync(); drawTab();
  } catch { say("Couldn't reach the network just now. It tries again by itself."); }
}

// ── the run you're on ──
const scene = createScene($("scene") as HTMLCanvasElement);
type Here = { go: string; run: Run; moves: string; seen: Set<string>; log: string[] };
let here: Here | null = null;
const saved = (go: string) => { try { return localStorage.getItem(`deep.moves.${go}`) ?? ""; } catch { return ""; } };
const save = () => { try { if (here) localStorage.setItem(`deep.moves.${here.go}`, here.moves); } catch {} };
const look = (h: Here) => { for (const k of visible(h.run)) h.seen.add(k); };

function load(go: string, seed: string): Here {
  const run = start(seed), h: Here = { go, run, moves: "", seen: new Set(), log: [] };
  look(h);
  for (const m of saved(go)) {
    const depth = run.floor.depth, ev = step(run, m);
    h.moves += m; h.log.push(...ev);
    if (run.floor.depth !== depth) h.seen = new Set();
    look(h);
  }
  h.log = h.log.slice(-40);
  return h;
}

function move(m: string) {
  if (!here || here.run.over || state !== "down") return;
  const r = here.run;
  const d: Record<string, [number, number]> = { n: [0, -1], s: [0, 1], e: [1, 0], w: [-1, 0] };
  if (d[m]) {
    const x = r.x + d[m][0], y = r.y + d[m][1];
    if (tileAt(r.floor, x, y) !== FLOOR && !r.floor.monsters.some(o => o.hp > 0 && o.x === x && o.y === y)) return; // no turn spent walking into a wall
  }
  if (m === "x" && !onRope(r)) return;
  const hp = r.hp, depth = r.floor.depth;
  const ev = step(r, m);
  here.moves += m; save();
  if (r.floor.depth !== depth) here.seen = new Set();
  look(here);
  here.log.push(...ev); here.log = here.log.slice(-40);
  if (r.hp < hp) scene.hurt();
  render();
}

// ── where you are: nowhere, on your way down, down there, or back up ──
type State = "none" | "going" | "opening" | "down" | "bringing" | "home" | "late";
let state: State = "none";
const myGo = () => gos.filter(g => g.author?.toLowerCase() === mine && g.text === "go").sort((a, b) => (b.pending ? 1e12 : b.height) - (a.pending ? 1e12 : a.height))[0];
const outFor = (go: string) => outs.find(o => o.author?.toLowerCase() === mine && R.parseOut(o.text)?.go === go.toLowerCase());

async function sync() {
  const g = myGo();
  if (!g) { state = "none"; here = null; }
  else if (g.pending) state = "going";
  else if (tip < g.height + 1) state = "opening";
  else {
    if (!here || here.go !== g.id) here = load(g.id, await R.seedFor(g, block));
    const o = outFor(g.id);
    state = o ? (o.pending ? "bringing" : rets.some(r => r.go === g.id.toLowerCase()) ? "home" : "down") : tip > g.height + R.OUT_WITHIN && here.run.over !== "dead" && here.run.over !== "dark" ? "late" : "down";
  }
  render();
}

// the way in, while you're not down there: the first floor of nobody's dungeon, all of it seen
const doorway = (() => { const run = start("the way down"), seen = new Set<string>(); for (let y = 0; y < FH; y++) for (let x = 0; x < FW; x++) if (tileAt(run.floor, x, y) === FLOOR || tileAt(run.floor, x, y + 1) === FLOOR) seen.add(`${x},${y}`); return { run, seen }; })();

function bar(html: string) { $("bar").innerHTML = html; }
function render() {
  const r = here?.run;
  if (r) scene.show(r, here!.seen); else scene.show(doorway.run, doorway.seen);
  $("log").innerHTML = here ? here.log.slice(-6).reverse().map((l, i) => `<li${i ? "" : ` class="new"`}>${esc(l)}</li>`).join("") : "";
  const again = `<button id="go">Go down${here ? " again" : ""}</button>`;
  if (state === "none") bar(`<div class="text"><b>The way down.</b> <span>Your dungeon is drawn from the next block, so nobody knows it in advance. A post to go down, a post to come back up.</span></div>${again}`);
  else if (state === "going" || state === "opening") bar(`<div class="text">Going down… <span>The way opens with the next block, in a minute or two.</span></div>`);
  else if (state === "bringing") bar(`<div class="text">Bringing ${r && r.carried.length ? "them" : "it"} home… <span>It's yours for good in a minute or two.</span></div>`);
  else if (state === "home") {
    const ret = rets.find(x => x.go === here!.go.toLowerCase())!;
    const got = ret.relics.map(x => `${x.name}, the ${R.ordinal(x.nth)} ever`);
    bar(`<div class="text"><b>${got.length ? "Yours for good:" : `Back up from floor ${ret.depth}.`}</b> <span>${esc(got.length ? got.join("; ") + "." : "Nothing carried this time.")}</span></div>${again}`);
  } else if (state === "late") bar(`<div class="text">This one's too old to bring home. <span>A run has a day to come back up.</span></div>${again}`);
  else if (r && (r.over === "dead" || r.over === "dark")) {
    bar(`<div class="text"><b>${r.over === "dark" ? `Your lamp went out on floor ${r.floor.depth}.` : `The ${r.killedBy} killed you on floor ${r.floor.depth}.`}</b> <span>${r.carried.length ? `${cap(list(r.carried))} stay${r.carried.length === 1 ? "s" : ""} down there.` : "Nothing lost but the lamp."}</span></div>${again}`);
  } else if (r && r.over === "out") {
    bar(`<div class="text"><b>You're out${r.carried.length ? `, with ${esc(list(r.carried))}` : ""}.</b> <span>${r.carried.length ? "Bring them home and they're yours for good, numbered." : `Floor ${r.deepest} and back. Bring it home to put it on the record.`}</span></div><button id="home">Bring ${r.carried.length ? "them" : "it"} home</button>`);
  } else if (r) {
    const lampLeft = LAMP - r.turn;
    bar(`<div class="text"><b>Floor ${r.floor.depth}.</b> <span>Strength ${r.hp} of ${MAX_HP}. Lamp ${lampLeft}.${r.carried.length ? ` Carrying ${esc(list(r.carried))}.` : ""}</span></div>
      <button class="quiet" id="wait">Wait</button>${onRope(r) ? `<button id="climb">Climb out</button>` : ""}`);
  }
  if ($("go")) $("go").onclick = goDown;
  if ($("home")) $("home").onclick = bringHome;
  if ($("wait")) $("wait").onclick = () => move("z");
  if ($("climb")) $("climb").onclick = () => move("x");
  $("help").hidden = state !== "down" || !!r?.over || (here?.moves.length ?? 0) > 12;
}

// ── moving: keys, or a tap toward where you want to go ──
addEventListener("keydown", e => {
  if (e.metaKey || e.ctrlKey || e.altKey || (e.target as HTMLElement)?.tagName === "INPUT" || !$("recordsview").hidden) return;
  const m = ({ ArrowUp: "n", ArrowDown: "s", ArrowRight: "e", ArrowLeft: "w", w: "n", s: "s", d: "e", a: "w", k: "n", j: "s", l: "e", h: "w", " ": "z", ".": "z" } as Record<string, string>)[e.key];
  if (!m) return;
  e.preventDefault(); move(m);
});
($("scene") as HTMLCanvasElement).addEventListener("click", e => {
  if (!here) return;
  const t = scene.at(e.clientX, e.clientY), r = here.run, dx = t.x - r.x, dy = t.y - r.y;
  if (!dx && !dy) return move("z"); // tapping yourself waits a turn
  move(Math.abs(dx) >= Math.abs(dy) ? (dx > 0 ? "e" : "w") : (dy > 0 ? "s" : "n"));
});

// ── writing ──
async function goDown() {
  say("Going down…");
  try { await net.write(me.signer(net as any), R.GO, "go"); say(""); await refresh(); }
  catch (e: any) { await trouble(e); }
}
async function bringHome() {
  if (!here) return;
  say("Bringing it home…");
  try { await net.write(me.signer(net as any), R.OUT, R.outText(here.go, pack(here.moves))); say(""); await refresh(); }
  catch (e: any) { await trouble(e); }
}
async function trouble(e: any) {
  const m = String(e?.message ?? e);
  if (/Declined/.test(m)) return say("");
  if (!/Not enough CSD/.test(m)) return say(m);
  if (me.doorway) { $("said").innerHTML = `You've run out for now. <button id="topUp">Top up in Doorway</button>, then try again.`; $("topUp").onclick = () => doorwayAdd(); return; }
  try {
    const open = await openInvites(net as any, INVITES);
    if (!open.length) { $("said").innerHTML = `You've run out for now. Open this in <a href="https://doorway.place">Doorway</a> to top up.`; return; }
    await claimInvite(net as any, open[Math.floor(Math.random() * open.length)].code, me.address);
    say("Someone left you a free start. Try again in a moment.");
  } catch (err: any) { say(String(err?.message ?? err)); }
}

// ── the records, on their own page (#records) ──
let tab = "deepest";
const route = () => { const rec = location.hash === "#records"; $("game").hidden = rec; $("recordsview").hidden = !rec; if (rec) drawTab(); scrollTo(0, 0); };
addEventListener("hashchange", route);
document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach(b => b.onclick = () => { tab = b.dataset.tab!; drawTab(); });
function drawTab() {
  if ($("recordsview").hidden) return;
  document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.tab === tab)));
  const relicLine = (x: R.Brought) => `<span class="${rarity(relicOf(x.name)!)}">${esc(x.name)}</span> (the ${R.ordinal(x.nth)})`;
  const line = (r: R.Return) => `<div class="row"><b>Floor ${r.depth}</b><span class="what"><span>${esc(cap(who(r.by)))}, ${esc(day(r.at))}, in ${r.turns} turns</span><span class="small">${r.relics.length ? `Brought up ${r.relics.map(relicLine).join(", ")}` : "Brought up nothing"}</span></span></div>`;
  if (tab === "deepest") {
    const best = [...rets].sort((a, b) => b.depth - a.depth || b.relics.length - a.relics.length || a.turns - b.turns).slice(0, 25);
    $("tabview").innerHTML = best.length ? best.map(line).join("") : `<p class="small">Nobody has come back up yet.</p>`;
  } else if (tab === "relics") {
    $("tabview").innerHTML = `<div class="relics">${RELICS.map(rl => {
      const all = rets.flatMap(r => r.relics.filter(x => x.name === rl.name).map(x => ({ r, x })));
      const first = all[0];
      return `<div class="relic ${rarity(rl)}${all.length ? "" : " unseen"}"><span class="dot"></span><span><b>${esc(cap(rl.name))}</b><span class="small">${all.length ? `${all.length} brought up. The first by ${esc(who(first.r.by))}, ${esc(day(first.r.at))}` : `Never brought up. Found from floor ${rl.from}`}</span></span></div>`;
    }).join("")}</div>`;
  } else if (tab === "latest") {
    const l = [...rets].reverse().slice(0, 30);
    $("tabview").innerHTML = l.length ? l.map(line).join("") : `<p class="small">Nobody has come back up yet.</p>`;
  } else {
    const l = rets.filter(r => r.by === mine), kinds = new Set(l.flatMap(r => r.relics.map(x => x.name)));
    $("tabview").innerHTML = `<p class="small">${kinds.size} of ${RELICS.length} kinds of relic brought up.</p>${l.length ? [...l].reverse().map(line).join("") : `<p class="small">What you bring up is listed here, for good.</p>`}`;
  }
}

if (me.kept && !me.doorway) welcome(net as any, me, INVITES).catch(() => {});
route(); render();
await refresh();
setInterval(refresh, 20_000);
