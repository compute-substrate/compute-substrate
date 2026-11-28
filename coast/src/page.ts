// The coast: sit down at a spot, and every block is a cast. Let most of it go; keep what's worth
// keeping, and it's yours for good, numbered and checked by anyone (src/rules.ts). Drawn as a small
// pixel scene of where you are (src/scene.ts), with the whole coast on a map to choose a spot.
import { connect, writingKey, claimInvite, openInvites, welcome, friendlyName, doorwayAdd } from "../../kit/src/index";
import { castable, waterOf, WATER_NAME, SHALLOWS, REEDS, LEDGE } from "./world";
import { rarity, FISH, type Catch } from "./fish";
import { createScene, drawMap, tintRGB, type Person } from "./scene";
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
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);
const day = (t: number) => new Date(t * 1000).toLocaleDateString([], { day: "numeric", month: "short", year: "numeric" });
const say = (t: string) => { $("said").textContent = t; };
const waterSaid = (w: number) => w === REEDS ? "Perch and roach, pike in the shadows, eels after dark." : w === LEDGE ? "Wrasse and coalfish off the rock; conger and ling for the patient." : w === SHALLOWS ? "Flatfish over the sand, bass at dawn and dusk." : "Herring and mackerel, cod in the cold months, and something very big, once in a while.";

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
const scene = createScene($("scene") as HTMLCanvasElement, R.world);

async function refresh() {
  try {
    tip = (await net.api.tip()).height;
    const [s, k] = await Promise.all([readChecked(R.SIT, 500), readChecked(R.KEEP, 1000)]);
    sits = s; keepsMine = k.filter(x => x.author?.toLowerCase() === mine);
    kept = await R.keptCatches(s, k, block);
    await update(); drawTab();
  } catch { say("Couldn't reach the network just now. It tries again by itself."); }
}

// who's on the coast: sat down in the last hour (and you, as soon as you sit, even before it lands)
const here = () => sits.filter(s => s.author && R.parseSit(s.text) && (s.pending ? s.author.toLowerCase() === mine : s.height > tip - R.SIT_BLOCKS));
const mySit = () => here().filter(s => s.author!.toLowerCase() === mine).sort((x, y) => (y.pending ? 1e12 : y.height) - (x.pending ? 1e12 : x.height))[0];
function people(): Person[] {
  const latest = new Map<string, R.Rec>();
  for (const s of here()) { const k = s.author!.toLowerCase(), had = latest.get(k); if (!had || s.pending || s.height > had.height) latest.set(k, s); }
  return [...latest.values()].map(s => ({ spot: R.parseSit(s.text)!, self: s.author!.toLowerCase() === mine, color: s.author!.toLowerCase() === mine ? [216, 72, 58] as any : tintRGB(s.author!) }));
}

// ── what's happening: one line inside the game, and what you caught under it ──
const decided = new Set<string>(JSON.parse(localStorage.getItem("coast.decided") ?? "[]"));
const decide = (k: string) => { decided.add(k); localStorage.setItem("coast.decided", JSON.stringify([...decided].slice(-500))); };
const isKept = (sit: string, h: number) => keepsMine.some(k => { const p = R.parseKeep(k.text); return p && p.sit === sit.toLowerCase() && p.height === h; });
let lastBlockSeen = 0, barKey = "";
const bar = (key: string, html: string) => {
  const el = $("bar");
  if (key !== barKey) { el.classList.remove("got"); void el.offsetWidth; if (key.startsWith("catch")) el.classList.add("got"); }
  barKey = key; el.innerHTML = html;
};

async function update() {
  scene.setPeople(people());
  const s = mySit();
  const active = s && (s.pending || s.height + R.SIT_BLOCKS >= tip);
  if (!active) {
    lastBlockSeen = 0;
    scene.pick(picked);
    if (picked) {
      scene.focus(picked.x, picked.y);
      const w = waterOf(R.world, picked.x, picked.y);
      bar("picked", `<div class="text"><b>${esc(cap(WATER_NAME[w]))}.</b> <span>${esc(waterSaid(w))}</span></div><button id="sitdown">Sit down here</button>`);
      $("sitdown").onclick = () => sitDown(picked!);
    } else if (s && R.parseSit(s.text)) {
      const spot = R.parseSit(s.text)!;
      bar("over", `<div class="text">That's the hour. <span>Sit down again to keep fishing.</span></div><button id="again">Sit down again</button>`);
      $("again").onclick = () => sitDown(spot);
    } else {
      bar("find", `<div class="text">Click the water near the shore to sit down and fish. <span>Every kind of water has its own fish.</span></div>`);
    }
    drawLog(null);
    return;
  }
  const spot = R.parseSit(s.text)!;
  scene.focus(spot.x, spot.y); scene.pick(null);
  if (s.pending) { bar("pending", `<div class="text">Sitting down… <span>Your first cast is the block after this one lands.</span></div>`); drawLog(null); return; }
  const last = Math.min(tip, s.height + R.SIT_BLOCKS), left = s.height + R.SIT_BLOCKS - tip;
  const casts: { h: number; c: Catch | null }[] = [];
  for (let h = last; h > s.height; h--) casts.push({ h, c: await R.castAt({ ...s, spot }, h, await block(h)).catch(() => null) });
  if (lastBlockSeen && last > lastBlockSeen && casts[0]?.c) scene.bite();
  lastBlockSeen = last;
  const open = casts.filter(x => x.c && !x.c.species.junk && !isKept(s.id, x.h) && !decided.has(`${s.id}:${x.h}`));
  const now = open[0];
  const leftSaid = left > 0 ? `${left} cast${left === 1 ? "" : "s"} left this hour` : "that was the last cast this hour";
  if (now) {
    const c = now.c!, same = kept.filter(x => x.catch.species.name === c.species.name);
    const best = same.reduce((m, x) => Math.max(m, x.catch.cm), 0);
    const note = c.specimen ? "A specimen." : !same.length ? "Nobody has kept one yet." : best && c.cm > best ? "Bigger than any kept so far." : `${cap(rarity(c.species))}.`;
    bar(`catch${now.h}`, `<div class="text"><b>${esc(cap(a(c.species.name)))}, ${cm(c.cm)}.</b> <span>${note}</span></div><button class="quiet" id="letgo">Let it go</button><button id="keep">Keep it, the ${R.ordinal(same.length + 1)} ever</button>`);
    $("letgo").onclick = () => { decide(`${s.id}:${now.h}`); update(); };
    $("keep").onclick = () => keepIt(s.id, now.h);
  } else {
    const latest = casts[0];
    const said = !latest ? "Your line is in." : latest.c ? `${cap(a(latest.c.species.name))} on the last cast.` : "Nothing on the last cast.";
    bar(`wait${last}`, `<div class="text">${esc(said)} <span>${cap(leftSaid)}.</span></div>`);
  }
  drawLog({ sit: s.id, casts: casts.filter(x => x !== now) });
}
function drawLog(h: { sit: string; casts: { h: number; c: Catch | null }[] } | null) {
  const got = h ? h.casts.filter(x => x.c) : [];
  $("log").innerHTML = got.slice(0, 8).map(x => {
    const c = x.c!, k = isKept(h!.sit, x.h);
    const fate = c.species.junk ? "" : k ? " <em>kept</em>" : decided.has(`${h!.sit}:${x.h}`) ? ", let go" : "";
    return `<li class="r-${rarity(c.species)}"><b>${esc(cap(a(c.species.name)))}</b>, ${cm(c.cm)}${fate}</li>`;
  }).join("");
}

// ── choosing a spot ──
($("scene") as HTMLCanvasElement).addEventListener("click", e => {
  const t = scene.at(e.clientX, e.clientY);
  if (mySit() && (mySit()!.pending || mySit()!.height + R.SIT_BLOCKS >= tip)) return;
  picked = castable(R.world, t.x, t.y) ? t : null;
  update();
});
const mapDlg = $("mapdlg") as HTMLDialogElement;
$("openmap").onclick = () => { drawMap($("map") as HTMLCanvasElement, R.world, people(), picked); mapDlg.showModal(); };
$("closemap").onclick = () => mapDlg.close();
($("map") as HTMLCanvasElement).addEventListener("click", e => {
  const c = $("map") as HTMLCanvasElement, b = c.getBoundingClientRect();
  const x = Math.floor((e.clientX - b.left) / b.width * (c.width / 6)), y = Math.floor((e.clientY - b.top) / b.height * (c.height / 6));
  if (!castable(R.world, x, y)) { scene.focus(x, y); mapDlg.close(); return; }
  if (mySit() && (mySit()!.pending || mySit()!.height + R.SIT_BLOCKS >= tip)) { scene.focus(x, y); mapDlg.close(); return; }
  picked = { x, y }; mapDlg.close(); update();
});

// ── writing ──
async function sitDown(spot: { x: number; y: number }) {
  say("Sitting down…");
  try { await net.write(me.signer(net as any), R.SIT, R.sitText(spot.x, spot.y)); picked = null; say(""); await refresh(); }
  catch (e: any) { await trouble(e); }
}
async function keepIt(sit: string, h: number) {
  say("Keeping it…");
  try { await net.write(me.signer(net as any), R.KEEP, R.keepText(sit, h)); decide(`${sit}:${h}`); say("Kept. It's yours for good, in a minute or two."); await refresh(); }
  catch (e: any) { await trouble(e); }
}
async function trouble(e: any) {
  const m = String(e?.message ?? e);
  if (/Declined/.test(m)) return say("");
  if (!/Not enough CSD/.test(m)) return say(m);
  if (me.doorway) { $("said").innerHTML = `You've run out for now. <button class="link" id="topUp">Top up in Doorway</button>, then try again.`; $("topUp").onclick = () => doorwayAdd(); return; }
  try {
    const open = await openInvites(net as any, INVITES);
    if (!open.length) { $("said").innerHTML = `You've run out for now. Open this in <a href="https://doorway.place">Doorway</a> to top up.`; return; }
    await claimInvite(net as any, open[Math.floor(Math.random() * open.length)].code, me.address);
    say("Someone left you a free start. Try again in a moment.");
  } catch (err: any) { say(String(err?.message ?? err)); }
}

// ── the records, on their own page (#records) ──
let tab = "records";
const route = () => { const rec = location.hash === "#records"; $("game").hidden = rec; $("recordsview").hidden = !rec; if (rec) drawTab(); scrollTo(0, 0); };
addEventListener("hashchange", route);
document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach(b => b.onclick = () => { tab = b.dataset.tab!; drawTab(); });
function drawTab() {
  if ($("recordsview").hidden) return;
  document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.tab === tab)));
  const line = (k: R.Kept) => `<div class="kept-row ${rarity(k.catch.species)}"><span class="dot"></span><span class="what"><b>${esc(cap(k.catch.species.name))}, ${cm(k.catch.cm)}</b><span class="small">The ${R.ordinal(k.nth)} ever, by ${esc(who(k.by))}, ${esc(day(k.at))}${k.catch.specimen ? ". A specimen" : ""}</span></span></div>`;
  const b = R.boards(kept);
  if (tab === "records") $("tabview").innerHTML = b.overall.length ? b.overall.map(line).join("") : `<p class="small">Nothing kept on the coast yet. The biggest of everything is still out there.</p>`;
  else if (tab === "kinds") $("tabview").innerHTML = `<div class="species">${b.species.map(s => `<div class="sp ${rarity(s.species)}${s.count ? "" : " unseen"}" title="${s.first ? `First: ${esc(who(s.first.by))}, ${esc(day(s.first.at))}. Biggest: ${cm(s.biggest!.catch.cm)}, ${esc(who(s.biggest!.by))}` : "Never kept"}"><span class="dot"></span><span><b>${esc(cap(s.species.name))}</b><span class="small">${s.count ? `${s.count} kept, biggest ${cm(s.biggest!.catch.cm)}` : "never kept"}</span></span></div>`).join("")}</div>`;
  else if (tab === "recent") { const list = [...kept].reverse().slice(0, 30); $("tabview").innerHTML = list.length ? list.map(line).join("") : `<p class="small">Nothing kept yet.</p>`; }
  else {
    const list = kept.filter(k => k.by === mine), kinds = new Set(list.map(k => k.catch.species.name));
    $("tabview").innerHTML = `<p class="small">${kinds.size} of ${FISH.filter(s => !s.junk).length} kinds kept.</p>${list.length ? [...list].reverse().map(line).join("") : `<p class="small">What you keep is listed here, for good.</p>`}`;
  }
}

if (me.kept && !me.doorway) welcome(net as any, me, INVITES).catch(() => {});
route(); update();
await refresh();
setInterval(refresh, 20_000);
