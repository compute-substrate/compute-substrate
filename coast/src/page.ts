// The coast: sit down at a spot, and every block is a cast. Let most of it go; keep what's worth
// keeping, and it's yours for good, numbered and checked by anyone (src/rules.ts).
import { connect, writingKey, claimInvite, openInvites, welcome, friendlyName, doorwayAdd } from "../../kit/src/index";
import { W, H, castable, waterOf, WATER_NAME, LAND, ROCK, SAND, SHALLOWS, REEDS, LEDGE, OPEN } from "./world";
import { rarity, FISH, type Catch } from "./fish";
import * as R from "./rules";

const INVITES = "csd.welcome";
const $ = (id: string) => document.getElementById(id) as HTMLElement;
const esc = (s: string) => s.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const net = connect({ node: new URLSearchParams(location.search).get("node") ?? undefined });
const me = await writingKey("coast");
const mine = me.address.toLowerCase();
const who = (a?: string) => !a ? "someone" : a.toLowerCase() === mine ? "you" : friendlyName(a);
const cm = (n: number) => n >= 100 ? `${(n / 100).toFixed(2)} m` : `${n.toFixed(1)} cm`;
const a = (n: string) => n === "driftwood" ? n : (/^[aeiou]/.test(n) ? "an " : "a ") + n;
const tint = (s: string) => { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0; return `hsl(${h % 360} 55% 55%)`; };
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

let tip = 0, sits: R.Rec[] = [], kept: R.Kept[] = [], keepsMine: R.Rec[] = [];
let picked: { x: number; y: number } | null = null;
async function refresh() {
  try {
    tip = (await net.api.tip()).height;
    const [s, k] = await Promise.all([readChecked(R.SIT, 500), readChecked(R.KEEP, 1000)]);
    sits = s; keepsMine = k.filter(x => x.author?.toLowerCase() === mine);
    kept = await R.keptCatches(s, k, block);
    draw(); await drawSitting(); drawTab();
  } catch { say("Couldn't reach the network just now. It tries again by itself."); }
}

// ── the map ──
const COLORS: Record<number, string> = { [LAND]: "#7d9a5a", [ROCK]: "#8f8a80", [SAND]: "#d8c58f", [SHALLOWS]: "#5fb0bf", [REEDS]: "#5f9e78", [LEDGE]: "#3f8199", [OPEN]: "#2c607a" };
const canvas = $("map") as HTMLCanvasElement, ctx = canvas.getContext("2d")!;
const S = 20;
canvas.width = W * S; canvas.height = H * S;
let flicker = 0;
const recent = () => sits.filter(s => !s.pending && s.author && s.height > tip - R.SIT_BLOCKS).map(s => ({ s, spot: R.parseSit(s.text) })).filter(x => x.spot);
function draw() {
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const t = R.world.tile(x, y);
    const deep = t === OPEN ? Math.min(1, R.world.dist(x, y) / 10) : 0;
    ctx.fillStyle = COLORS[t];
    ctx.fillRect(x * S, y * S, S, S);
    if (deep) { ctx.fillStyle = `rgba(10,30,50,${deep * 0.45})`; ctx.fillRect(x * S, y * S, S, S); }
    if (t === REEDS) { ctx.strokeStyle = "rgba(30,70,40,.7)"; ctx.lineWidth = 1.4; for (const o of [5, 10, 15]) { ctx.beginPath(); ctx.moveTo(x * S + o, y * S + 16); ctx.lineTo(x * S + o + (o % 2 ? 1 : -1), y * S + 5); ctx.stroke(); } }
    if (t === ROCK) { ctx.fillStyle = "rgba(60,58,54,.35)"; ctx.fillRect(x * S + 4, y * S + 5, 7, 5); ctx.fillRect(x * S + 11, y * S + 11, 5, 4); }
    if (t === OPEN && (x * 7 + y * 13) % 11 === 0) { ctx.strokeStyle = "rgba(255,255,255,.12)"; ctx.beginPath(); ctx.moveTo(x * S + 4, y * S + 10); ctx.quadraticCurveTo(x * S + 10, y * S + 6, x * S + 16, y * S + 10); ctx.stroke(); }
  }
  // the fire
  const fx = R.world.fire.x * S + S / 2, fy = R.world.fire.y * S + S / 2;
  const g = ctx.createRadialGradient(fx, fy, 1, fx, fy, 26 + Math.sin(flicker) * 3);
  g.addColorStop(0, "rgba(255,190,90,.75)"); g.addColorStop(1, "rgba(255,150,60,0)");
  ctx.fillStyle = g; ctx.beginPath(); ctx.arc(fx, fy, 30, 0, 7); ctx.fill();
  ctx.fillStyle = "#f08a3c"; ctx.beginPath(); ctx.arc(fx, fy, 4.5, 0, 7); ctx.fill();
  // who's fishing (sat down in the last hour), and where you'd sit
  for (const { s, spot } of recent()) {
    const me_ = s.author!.toLowerCase() === mine;
    ctx.fillStyle = me_ ? "#e2563f" : tint(s.author!);
    ctx.beginPath(); ctx.arc(spot!.x * S + S / 2, spot!.y * S + S / 2, me_ ? 6 : 5, 0, 7); ctx.fill();
    ctx.strokeStyle = "#fff"; ctx.lineWidth = 1.5; ctx.stroke();
  }
  if (picked) { ctx.strokeStyle = "#fff"; ctx.lineWidth = 2; ctx.setLineDash([3, 3]); ctx.strokeRect(picked.x * S + 1, picked.y * S + 1, S - 2, S - 2); ctx.setLineDash([]); }
}
setInterval(() => { flicker += 0.6; draw(); }, 500);
canvas.addEventListener("click", e => {
  const r = canvas.getBoundingClientRect();
  const x = Math.floor((e.clientX - r.left) / r.width * W), y = Math.floor((e.clientY - r.top) / r.height * H);
  if (!castable(R.world, x, y)) { picked = null; draw(); drawSitting(); return; }
  picked = { x, y }; draw(); drawSitting();
});
canvas.addEventListener("mousemove", e => {
  const r = canvas.getBoundingClientRect();
  const x = Math.floor((e.clientX - r.left) / r.width * W), y = Math.floor((e.clientY - r.top) / r.height * H);
  canvas.style.cursor = castable(R.world, x, y) ? "pointer" : "default";
});

// ── sitting ──
const mySit = () => sits.filter(s => s.author?.toLowerCase() === mine && R.parseSit(s.text)).sort((a, b) => (b.pending ? 1e12 : b.height) - (a.pending ? 1e12 : a.height))[0];
const keptKey = (sit: string, h: number) => keepsMine.some(k => { const p = R.parseKeep(k.text); return p && p.sit === sit.toLowerCase() && p.height === h; });
const letGo = new Set<string>(JSON.parse(localStorage.getItem("coast.letgo") ?? "[]"));
let lastSeen = 0;
async function drawSitting() {
  const s = mySit();
  const active = s && (s.pending || s.height + R.SIT_BLOCKS >= tip);
  if (!active) {
    $("sit").innerHTML = picked ? `<h3>${esc(cap(WATER_NAME[waterOf(R.world, picked.x, picked.y)]))}</h3>
        <p class="small">${esc(waterSaid(waterOf(R.world, picked.x, picked.y)))}</p>
        <p>Sit down here for an hour: every block that lands is a cast, about one every two minutes. Let most of it go, and keep what's worth keeping.</p>
        <button id="sitdown">Sit down here</button> <span class="small">A post's worth for the hour.</span>`
      : `<h3>Find a spot</h3><p>Click the water near the shore to choose where to fish. The reeds, the rock ledge, the shallows and open water each have their own fish, and the hour and month change what bites.</p>${recent().length ? `<p class="small">By the fire now: ${recent().map(r => esc(who(r.s.author))).filter((v, i, l) => l.indexOf(v) === i).join(", ")}.</p>` : ""}`;
    if ($("sitdown")) $("sitdown").onclick = () => sitDown(picked!);
    return;
  }
  const spot = R.parseSit(s.text)!;
  const water = cap(WATER_NAME[waterOf(R.world, spot.x, spot.y)]);
  if (s.pending) { $("sit").innerHTML = `<h3>${esc(water)}</h3><p class="wait">Sitting down… Your first cast is the block after this one lands.</p>`; return; }
  const last = Math.min(tip, s.height + R.SIT_BLOCKS);
  const rows: string[] = [];
  const sitR = { ...s, spot };
  let empty = 0;
  const flush = () => { if (empty) rows.push(`<div class="cast nothing">Nothing${empty > 1 ? `, ${empty} casts` : ""}.</div>`); empty = 0; };
  for (let h = last; h > s.height; h--) {
    const c = await R.castAt(sitR, h, await block(h)).catch(() => null);
    const isNew = h > lastSeen && lastSeen > 0;
    if (!c) { empty++; continue; }
    flush(); rows.push(catchRow(s.id, h, c, isNew));
  }
  flush();
  lastSeen = Math.max(lastSeen, last);
  const left = s.height + R.SIT_BLOCKS - tip;
  $("sit").innerHTML = `<h3>${esc(water)}</h3>
    <p class="small">${left > 0 ? `Every block is a cast. ${left} more, about ${Math.round(left * 2)} minutes.` : "That's the hour. Sit down again to keep fishing."}</p>
    <div class="casts">${rows.length ? rows.join("") : `<div class="cast wait">The line is in. Waiting for the next block…</div>`}</div>`;
  $("sit").querySelectorAll<HTMLButtonElement>("[data-keep]").forEach(b => b.onclick = () => keepIt(s.id, +b.dataset.keep!));
  $("sit").querySelectorAll<HTMLButtonElement>("[data-go]").forEach(b => b.onclick = () => { letGo.add(`${s.id}:${b.dataset.go}`); localStorage.setItem("coast.letgo", JSON.stringify([...letGo].slice(-300))); drawSitting(); });
}
function catchRow(sit: string, h: number, c: Catch, isNew: boolean) {
  const k = `${sit}:${h}`, isKept = keptKey(sit, h), gone = letGo.has(k), r = rarity(c.species);
  const nth = !c.species.junk ? kept.filter(x => x.catch.species.name === c.species.name).length + 1 : 0;
  const best = kept.filter(x => x.catch.species.name === c.species.name).reduce((m, x) => Math.max(m, x.catch.cm), 0);
  const note = c.species.junk ? "" : `${c.specimen ? "A specimen. " : ""}${best && c.cm > best ? "Bigger than any kept so far. " : ""}${!best ? "Nobody has kept one yet. " : ""}`;
  return `<div class="cast ${r}${isNew ? " fresh" : ""}"><span class="dot"></span><div class="what"><b>${esc(cap(a(c.species.name)))}, ${cm(c.cm)}</b><span class="small">${cap(r)}${note ? `. ${esc(note.trim())}` : ""}</span>
    ${c.species.junk ? "" : isKept ? `<span class="small kept">Kept, for good</span>` : gone ? `<span class="small">Let go</span>` : `<span class="acts"><button data-keep="${h}">Keep it${nth ? `, the ${R.ordinal(nth)} ever` : ""}</button><button class="quiet" data-go="${h}">Let it go</button></span>`}</div></div>`;
}
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);
const waterSaid = (w: number) => w === REEDS ? "Perch and roach, pike in the shadows, eels after dark." : w === LEDGE ? "Wrasse and coalfish off the rock, conger and ling for the patient." : w === SHALLOWS ? "Flatfish over sand, bass at dawn and dusk." : "Herring and mackerel, cod in the cold months, and something very big, once in a while.";

async function sitDown(spot: { x: number; y: number }) {
  say("Sitting down…");
  try { await net.write(me.signer(net as any), R.SIT, R.sitText(spot.x, spot.y)); picked = null; lastSeen = 0; say(""); await refresh(); }
  catch (e: any) { await trouble(e); }
}
async function keepIt(sit: string, h: number) {
  say("Keeping it…");
  try { await net.write(me.signer(net as any), R.KEEP, R.keepText(sit, h)); say("Kept. It's yours for good, in a minute or two."); await refresh(); }
  catch (e: any) { await trouble(e); }
}
async function trouble(e: any) {
  const m = String(e?.message ?? e);
  if (/Declined/.test(m)) return say("");
  if (!/Not enough CSD/.test(m)) return say(m);
  if (me.doorway) { $("said").innerHTML = `You've run out for now. <button class="quiet" id="topUp">Top up in Doorway</button>, then try again.`; $("topUp").onclick = () => doorwayAdd(); return; }
  try {
    const open = await openInvites(net as any, INVITES);
    if (!open.length) { $("said").innerHTML = `You've run out for now. Open this in <a href="https://doorway.place">Doorway</a> to top up.`; return; }
    await claimInvite(net as any, open[Math.floor(Math.random() * open.length)].code, me.address);
    say("Someone left you a free start. Try again in a moment.");
  } catch (err: any) { say(String(err?.message ?? err)); }
}

// ── the coast's record ──
let tab = "recent";
document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach(b => b.onclick = () => { tab = b.dataset.tab!; drawTab(); });
function drawTab() {
  document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.tab === tab)));
  const line = (k: R.Kept, big = false) => `<div class="kept-row ${rarity(k.catch.species)}"><span class="dot"></span><span class="what"><b>${esc(cap(k.catch.species.name))}, ${cm(k.catch.cm)}</b><span class="small">the ${R.ordinal(k.nth)} ever${big ? "" : ""}, by ${esc(who(k.by))}, ${esc(new Date(k.at * 1000).toLocaleDateString([], { day: "numeric", month: "short", year: "numeric" }))}${k.catch.specimen ? ", a specimen" : ""}</span></span></div>`;
  if (tab === "recent") {
    const list = [...kept].reverse().slice(0, 40);
    $("tabview").innerHTML = list.length ? list.map(k => line(k)).join("") : `<p class="small">Nothing kept on the coast yet. The first of every kind is still out there.</p>`;
  } else if (tab === "records") {
    const b = R.boards(kept);
    $("tabview").innerHTML = `<h4>Biggest ever</h4>${b.overall.length ? b.overall.slice(0, 10).map(k => line(k, true)).join("") : `<p class="small">Nothing kept yet.</p>`}
      <h4>Every kind: the first, and the biggest</h4><div class="species">${b.species.map(s => `<div class="sp ${rarity(s.species)}${s.count ? "" : " unseen"}"><b>${esc(cap(s.species.name))}</b><span class="small">${rarity(s.species)}${s.count ? `, ${s.count} kept` : ", never kept"}</span>
        ${s.first ? `<span class="small">First: ${esc(who(s.first.by))}, ${esc(new Date(s.first.at * 1000).toLocaleDateString([], { day: "numeric", month: "short", year: "numeric" }))}</span><span class="small">Biggest: ${cm(s.biggest!.catch.cm)}, ${esc(who(s.biggest!.by))}</span>` : ""}</div>`).join("")}</div>`;
  } else {
    const list = kept.filter(k => k.by === mine);
    const kinds = new Set(list.map(k => k.catch.species.name));
    $("tabview").innerHTML = `<p class="small">${kinds.size} of ${FISH.filter(s => !s.junk).length} kinds kept.</p>${list.length ? [...list].reverse().map(k => line(k)).join("") : `<p class="small">What you keep is listed here, for good.</p>`}`;
  }
}

if (me.kept && !me.doorway) welcome(net as any, me, INVITES).catch(() => {});
draw(); drawSitting(); drawTab();
await refresh();
setInterval(refresh, 20_000);
