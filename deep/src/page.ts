// The deep: one dungeon for everyone. Go down (a post), from the top or down the deepest rope; play
// it here at your own pace; climb out with what you found and post your way back up, or fall and
// leave your name where you fell (a post). Anyone can replay the moves, so every relic belongs to
// whoever brought it up first, for good (src/rules.ts). Records are on their own page.
import { connect, writingKey, claimInvite, openInvites, welcome, friendlyName, doorwayAdd } from "../../kit/src/index";
import { start, step, pack, tileAt, onRope, plan, allRelics, relicName, rarityOf, copiesOf, RELICS, FW, FH, FLOOR, LAMP, MAX_HP, DEPTH, BOTTOM, BOTTOM_NAME, EMPTY, type Run } from "./dungeon";
import { createScene, visible } from "./scene";
import * as R from "./rules";

const INVITES = "csd.welcome";
const $ = (id: string) => document.getElementById(id) as HTMLElement;
const esc = (s: string) => s.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const net = connect({ node: new URLSearchParams(location.search).get("node") ?? undefined });
const me = await writingKey("deep");
const mine = me.address.toLowerCase();
const who = (a?: string) => !a ? "someone" : a.toLowerCase() === mine ? "you" : friendlyName(a);
const Who = (a?: string) => { const w = who(a); return w[0].toUpperCase() + w.slice(1); };
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);
const day = (t: number) => new Date(t * 1000).toLocaleDateString([], { day: "numeric", month: "short", year: "numeric" });
const list = (xs: string[]) => xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`;
const the = (id: string) => id === BOTTOM ? `the ${BOTTOM_NAME}` : relicName(id);
// which one of its kind a relic is, in the order they came up: "bone dice, the 2nd of 4"
function nthOf(id: string) {
  const name = relicName(id), same = [...(hist?.home.entries() ?? [])].filter(([i]) => relicName(i) === name).sort((a, b) => a[1].height - b[1].height || a[0].localeCompare(b[0]));
  return same.findIndex(([i]) => i === id) + 1;
}
const owned = (id: string) => { const c = copiesOf(relicName(id)); return c === 1 ? `${the(id)}, the only one` : `${the(id)}, the ${R.ordinal(nthOf(id))} of ${c}`; };
const say = (t: string) => { $("said").textContent = t; };
// lines from the game name people as "@0x…"
const named = (line: string) => line.replace(/@(0x[0-9a-fA-F]{40})/g, (_, a) => who(a));

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

let tip = 0, gos: R.Rec[] = [], ends: R.Rec[] = [], hist: R.History | null = null;
async function refresh() {
  try {
    tip = (await net.api.tip()).height;
    const [g, u, f] = await Promise.all([readChecked(R.GO, 500), readChecked(R.UP, 800), readChecked(R.FELL, 800)]);
    gos = g; ends = [...u, ...f];
    hist = await R.history(g, ends, block);
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

function load(g: R.Rec, seed: string): Here {
  const st = hist ? hist.stateAt(g.height) : EMPTY;
  const run = start(seed, st, R.goFrom(g.text) ?? 1), h: Here = { go: g.id, run, moves: "", seen: new Set(), log: [] };
  look(h);
  h.log.push(run.from > 1 ? `Down the rope to floor ${run.from}.` : "Floor 1.");
  for (const m of saved(g.id)) {
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

// ── where you are: up here, on your way down, down there, or done ──
type State = "none" | "going" | "opening" | "down" | "ending" | "home" | "grave" | "late";
let state: State = "none";
const myGo = () => gos.filter(g => g.author?.toLowerCase() === mine && R.goFrom(g.text)).sort((a, b) => (b.pending ? 1e12 : b.height) - (a.pending ? 1e12 : a.height))[0];
const endFor = (go: string) => ends.find(o => o.author?.toLowerCase() === mine && R.parseEnd(o.text)?.go === go.toLowerCase());

async function sync() {
  const g = myGo();
  if (!g) { state = "none"; here = null; }
  else if (g.pending) state = "going";
  else if (tip < g.height + 1) state = "opening";
  else {
    if (!here || here.go !== g.id) here = load(g, await R.seedFor(g, block));
    const e = endFor(g.id), id = g.id.toLowerCase();
    state = e ? (e.pending ? "ending" : hist?.returns.some(r => r.go === id) ? "home" : hist?.falls.some(f => f.go === id) ? "grave" : "down")
      : tip > g.height + R.END_WITHIN ? "late" : "down";
  }
  render();
}

// up here, before going down: the first floor, all of it seen
const doorway = (() => { const run = start("the way down"), seen = new Set<string>(); for (let y = 0; y < FH; y++) for (let x = 0; x < FW; x++) if (tileAt(run.floor, x, y) === FLOOR || tileAt(run.floor, x, y + 1) === FLOOR) seen.add(`${x},${y}`); return { run, seen }; })();

// the line about everyone: how deep, how much is still down there
function standing() {
  const h = hist, total = allRelics().length, up = h?.home.size ?? 0;
  if (!h || !h.deepest) return `Nobody has been down yet. ${total} relics are down there, and one thing at the bottom.`;
  const bottom = h.home.get(BOTTOM);
  return `Deepest anyone has been: floor ${h.deepest}. ${up} of ${total} relics brought up. ${bottom ? `${Who(bottom.by)} has the ${BOTTOM_NAME}.` : h.deepest >= DEPTH ? `Someone has seen the bottom. The ${BOTTOM_NAME} is still down there.` : "Nobody has seen the bottom."}`;
}

function bar(html: string) { $("bar").innerHTML = html; }
function render() {
  const r = here?.run;
  if (r && state !== "none") scene.show(r, here!.seen); else scene.show(doorway.run, doorway.seen);
  $("log").innerHTML = here ? here.log.slice(-6).reverse().map((l, i) => `<li${i ? "" : ` class="new"`}>${esc(named(l))}</li>`).join("") : "";
  $("standing").textContent = standing();
  const rope = hist?.stateAt(Infinity).rope;
  const downs = `<button class="quiet" id="go">Go down${here ? " again" : ""}</button>${rope && rope.depth > 1 ? `<button id="rope">Down ${who(rope.by) === "you" ? "your" : esc(who(rope.by)) + "'s"} rope to floor ${rope.depth}</button>` : ""}`;
  const downsOnly = rope && rope.depth > 1 ? downs : `<button id="go">Go down${here ? " again" : ""}</button>`;
  if (state === "none") bar(`<div class="text"><b>The way down.</b> <span>One dungeon, the same for everyone. Every relic in it can only be brought up once.</span></div>${downsOnly}`);
  else if (state === "going" || state === "opening") bar(`<div class="text">Going down… <span>Your fights are drawn from the next block, in a minute or two.</span></div>`);
  else if (state === "ending") bar(`<div class="text">${r?.over === "out" ? "Bringing it home…" : "Leaving your name…"} <span>On the record in a minute or two.</span></div>`);
  else if (state === "home") {
    const ret = hist!.returns.find(x => x.go === here!.go.toLowerCase())!;
    const got = ret.relics.map(owned), lost = ret.beaten.map(the);
    bar(`<div class="text"><b>${got.length ? `Yours for good: ${esc(got.join("; "))}.` : `Back up from floor ${ret.depth}.`}</b> <span>${lost.length ? `Someone got ${esc(list(lost))} home before you.` : hist!.stateAt(Infinity).rope?.depth === ret.depth && ret.depth > 1 ? `Your rope down to floor ${ret.depth} is the deepest.` : got.length ? "Nobody else can ever have them." : "Nothing carried this time."}</span></div>${downsOnly}`);
  } else if (state === "grave") bar(`<div class="text"><b>Your name is on floor ${r!.floor.depth}.</b> <span>${r!.carried.length ? `${esc(cap(list(r!.carried.map(the))))} lie${r!.carried.length === 1 ? "s" : ""} with you, for whoever comes next.` : "For whoever comes next."}</span></div>${downsOnly}`);
  else if (state === "late") bar(`<div class="text">This one's too old to put on the record. <span>A descent has a day to end.</span></div>${downsOnly}`);
  else if (r && (r.over === "dead" || r.over === "dark")) {
    bar(`<div class="text"><b>${r.over === "dark" ? `Your lamp went out on floor ${r.floor.depth}.` : `The ${r.killedBy} killed you on floor ${r.floor.depth}.`}</b> <span>${r.carried.length ? `Leave your name here, and ${esc(list(r.carried.map(the)))} lie${r.carried.length === 1 ? "s" : ""} with you for whoever comes next.` : "Leave your name here, for whoever comes next."}</span></div><button class="quiet" id="go">Go down again</button><button id="fell">Leave your name</button>`);
  } else if (r && r.over === "out") {
    bar(`<div class="text"><b>You're out${r.carried.length ? `, with ${esc(list(r.carried.map(the)))}` : ""}.</b> <span>${r.carried.length ? "Bring it home first and it's yours, for good. Nobody else can ever have it." : `Floor ${r.deepest} and back. Bring it home to put it on the record${r.deepest > (hist?.stateAt(Infinity).rope?.depth ?? 0) ? ", and leave your rope as the deepest" : ""}.`}</span></div><button id="home">Bring it home</button>`);
  } else if (r) {
    bar(`<div class="text"><b>Floor ${r.floor.depth}${r.floor.depth === DEPTH ? ", the bottom" : ""}.</b> <span>Strength ${r.hp} of ${MAX_HP}. Lamp ${LAMP - r.turn}.${r.carried.length ? ` Carrying ${esc(list(r.carried.map(the)))}.` : ""}</span></div>
      <button class="quiet" id="wait">Wait</button>${onRope(r) ? `<button id="climb">Climb out</button>` : ""}`);
  }
  if ($("go")) $("go").onclick = () => goDown(1);
  if ($("rope")) $("rope").onclick = () => goDown(rope!.depth);
  if ($("home")) $("home").onclick = () => end("up");
  if ($("fell")) $("fell").onclick = () => end("fell");
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
  if (!here || state !== "down") return;
  const t = scene.at(e.clientX, e.clientY), r = here.run, dx = t.x - r.x, dy = t.y - r.y;
  if (!dx && !dy) return move("z"); // tapping yourself waits a turn
  move(Math.abs(dx) >= Math.abs(dy) ? (dx > 0 ? "e" : "w") : (dy > 0 ? "s" : "n"));
});

// ── writing ──
async function goDown(from: number) {
  say("Going down…");
  try { await net.write(me.signer(net as any), R.GO, R.goText(from)); say(""); await refresh(); }
  catch (e: any) { await trouble(e); }
}
async function end(kind: "up" | "fell") {
  if (!here) return;
  say(kind === "up" ? "Bringing it home…" : "Leaving your name…");
  try { await net.write(me.signer(net as any), kind === "up" ? R.UP : R.FELL, R.endText(kind, here.go, pack(here.moves))); say(""); await refresh(); }
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
let tab = "players";
const route = () => { const rec = location.hash === "#records"; $("game").hidden = rec; $("recordsview").hidden = !rec; if (rec) drawTab(); scrollTo(0, 0); };
addEventListener("hashchange", route);
document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach(b => b.onclick = () => { tab = b.dataset.tab!; drawTab(); });
const dayShort = (t: number) => new Date(t * 1000).toLocaleDateString([], { day: "numeric", month: "short" });
function drawTab() {
  if ($("recordsview").hidden) return;
  document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.tab === tab)));
  const h = hist, now = h?.stateAt(Infinity), relics = allRelics();
  // the four numbers at the top
  const eye = h?.home.get(BOTTOM);
  $("stats").innerHTML = [
    ["Deepest", h?.deepest ? `Floor ${h.deepest}` : "None yet"],
    ["Relics up", `${h?.home.size ?? 0} of ${relics.length}`],
    ["Deaths", `${h?.falls.length ?? 0}`],
    ["The bottom", eye ? esc(Who(eye.by)) : "Unclaimed"],
  ].map(([k, v]) => `<div class="stat frame"><span>${k}</span><b>${v}</b></div>`).join("");
  const rank = (i: number) => `<td class="rank r${i + 1}">${i + 1}</td>`;
  const dot = (name: string) => `<span class="dot ${rarityOf(name)}"></span>`;
  if (tab === "players") {
    // everyone who has gone down: deepest floor, relics held, times back up, graves
    const by = new Map<string, { deepest: number; relics: number; ups: number; graves: number; at: number }>();
    const of = (a: string) => by.get(a) ?? (by.set(a, { deepest: 0, relics: 0, ups: 0, graves: 0, at: 0 }), by.get(a)!);
    for (const r of h?.returns ?? []) { const p = of(r.by); p.deepest = Math.max(p.deepest, r.depth); p.ups++; p.at = Math.max(p.at, r.height); }
    for (const f of h?.falls ?? []) { const p = of(f.by); p.deepest = Math.max(p.deepest, f.depth); p.graves++; }
    for (const [, x] of h?.home ?? []) of(x.by).relics++;
    const rows = [...by.entries()].sort((a, b) => b[1].deepest - a[1].deepest || b[1].relics - a[1].relics || b[1].ups - a[1].ups);
    $("tabview").innerHTML = rows.length ? `<table><thead><tr><th>#</th><th class="l">Name</th><th>Deepest</th><th>Relics</th><th>Runs</th><th>Deaths</th></tr></thead><tbody>${rows.map(([a, p], i) =>
      `<tr${a === mine ? ` class="me"` : ""}>${rank(i)}<td class="l name">${esc(Who(a))}</td><td>${p.deepest}</td><td>${p.relics}</td><td>${p.ups + p.graves}</td><td>${p.graves}</td></tr>`).join("")}</tbody></table>` : `<p class="empty">Nobody has gone down yet. The first name here is still free.</p>`;
  } else if (tab === "relics") {
    // every kind of relic, deepest first: how many there are, how many are up, and who has them
    const kinds = [...RELICS.map(r => r.name), BOTTOM_NAME].map(name => {
      const ids = relics.filter(r => r.name === name), floors = [...new Set(ids.map(r => r.depth))].sort((a, b) => a - b);
      const up = ids.filter(r => h?.home.has(r.id)).map(r => h!.home.get(r.id)!).sort((a, b) => a.height - b.height);
      return { name, ids, floors, up };
    }).sort((a, b) => b.floors[0] - a.floors[0]);
    $("tabview").innerHTML = `<table><thead><tr><th class="l">Relic</th><th>Floors</th><th>Up</th><th class="l">${"First up by"}</th></tr></thead><tbody>${kinds.map(k => {
      const one = k.ids.length === 1, lies = one && now?.graves.find(g => g.relics.includes(k.ids[0].id));
      const holders = one ? (k.up[0] ? esc(Who(k.up[0].by)) : lies ? `<span class="muted">In ${esc(who(lies.by))}'s grave</span>` : `<span class="muted">Still down there</span>`) : k.up[0] ? esc(Who(k.up[0].by)) : `<span class="muted">Nobody yet</span>`;
      const mineToo = k.up.some(u => u.by === mine);
      return `<tr class="${k.up.length ? "" : "unclaimed"}${mineToo ? " me" : ""}"><td class="l name">${dot(k.name)}${esc(k.name === BOTTOM_NAME ? `The ${BOTTOM_NAME}` : cap(k.name))}</td><td>${k.floors.length > 1 ? `${k.floors[0]} to ${k.floors[k.floors.length - 1]}` : k.floors[0]}</td><td>${k.up.length} of ${k.ids.length}</td><td class="l name">${holders}</td></tr>`;
    }).join("")}</tbody></table>`;
  } else {
    // floor by floor: who got there first, what's left, who lies there
    const rows: string[] = [];
    for (let d = 1; d <= DEPTH; d++) {
      const first = h?.firstTo.get(d), chests = plan(d).chests, left = chests.filter(c => !h?.home.has(c.id)).length, graves = (h?.falls ?? []).filter(f => f.depth === d).length;
      rows.push(`<tr class="${first ? "" : "unclaimed"}"><td>${d}${d === DEPTH ? ` <span class="muted">bottom</span>` : ""}</td><td class="l name">${first ? esc(Who(first.by)) : `<span class="muted">Nobody yet</span>`}${now?.rope?.depth === d ? ` <span class="tag">rope</span>` : ""}</td><td>${first ? esc(dayShort(first.at)) : ""}</td><td>${left} of ${chests.length}</td><td>${graves || ""}</td></tr>`);
    }
    $("tabview").innerHTML = `<table><thead><tr><th>Floor</th><th class="l">First there</th><th>When</th><th>Relics left</th><th>Deaths</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
  }
}

if (me.kept && !me.doorway) welcome(net as any, me, INVITES).catch(() => {});
route(); render();
await refresh();
setInterval(refresh, 20_000);
