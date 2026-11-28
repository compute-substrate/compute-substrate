// The coast: sit down at a spot, and every block is a cast. Your fishing level grows with every one,
// whether you're watching or not. When you come back, what bit while you were away comes in as a
// haul: keep what's worth keeping, and it's yours for good, numbered and checked by anyone
// (src/rules.ts). Drawn as a small pixel scene of where you are (src/scene.ts).
import { connect, writingKey, claimInvite, openInvites, welcome, friendlyName, doorwayAdd } from "../../kit/src/index";
import { castable, waterOf, WATER_NAME, SHALLOWS, REEDS, LEDGE, OPEN } from "./world";
import { rarity, FISH, type Catch } from "./fish";
import { createScene, drawMap, tintRGB, type Person } from "./scene";
import { fishImage } from "./fishart";
import * as R from "./rules";

const INVITES = "csd.welcome";
const $ = (id: string) => document.getElementById(id) as HTMLElement;
const esc = (s: string) => s.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const net = connect({ node: new URLSearchParams(location.search).get("node") ?? undefined });
const me = await writingKey("coast");
const mine = me.address.toLowerCase();
const who = (a?: string) => !a ? "someone" : a.toLowerCase() === mine ? "you" : friendlyName(a);
const Who = (a?: string) => { const w = who(a); return w[0].toUpperCase() + w.slice(1); };
const cm = (n: number) => n >= 100 ? `${(n / 100).toFixed(2)} m` : `${n.toFixed(1)} cm`;
const a = (n: string) => n === "driftwood" ? n : (/^[aeiou]/.test(n) ? "an " : "a ") + n;
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);
const num = (n: number) => Math.round(n).toLocaleString("en-US");
const day = (t: number) => new Date(t * 1000).toLocaleDateString([], { day: "numeric", month: "short" });
const say = (t: string) => { $("said").textContent = t; };
const store = { get: (k: string) => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k: string, v: string) => { try { localStorage.setItem(k, v); } catch {} } };
const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
const waterSaid = (w: number) => w === REEDS ? "Perch and roach, pike in the shadows, eels after dark." : w === LEDGE ? "Wrasse and coalfish off the rock; conger and ling for the patient." : w === SHALLOWS ? "Flatfish over the sand, bass at dawn and dusk." : "Herring and mackerel, cod in the cold months, and something very big, once in a while.";
const sizeOf = (c: Catch) => Math.min(1.3, (c.cm - c.species.size[0]) / (c.species.size[1] - c.species.size[0]));
const RANK = { junk: 0, common: 1, uncommon: 2, scarce: 3, rare: 4, legendary: 5 } as const;
const hoursSaid = (casts: number) => { const m = casts * 2, h = Math.floor(m / 60), r = m % 60; return h ? `${h} hour${h === 1 ? "" : "s"}${r ? ` ${r} minutes` : ""}` : `${m} minutes`; };

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

let tip = 0, sitRecs: R.Rec[] = [], keepRecs: R.Rec[] = [], C: R.Coast | null = null;
let picked: { x: number; y: number } | null = null;
const scene = createScene($("scene") as HTMLCanvasElement, R.world);

async function refresh() {
  try {
    tip = (await net.api.tip()).height;
    const [s, k] = await Promise.all([readChecked(R.SIT, 800), readChecked(R.KEEP, 1500)]);
    sitRecs = s; keepRecs = k;
    C = await R.coast(s, k, block, tip);
    await update(); drawTab();
  } catch { say("Couldn't reach the network just now. It tries again by itself."); }
}

// ── you, and everyone by the water ──
const myXp = () => C?.xpOf(mine, tip) ?? 0;
const myLevel = () => R.levelFor(myXp());
const pendingSit = () => sitRecs.find(s => s.pending && s.author?.toLowerCase() === mine && R.parseSit(s.text));
const mySitting = () => C?.sittings.filter(s => s.by === mine && s.valid).sort((x, y) => y.height - x.height)[0];
const active = (s?: R.Sitting) => !!s && s.end > s.height && tip < s.end + 1 && s.end >= tip;
function people(): Person[] {
  const out: Person[] = [];
  for (const s of C?.sittings ?? []) if (s.valid && s.end >= tip && s.height < tip) {
    const latest = C!.sittings.filter(x => x.by === s.by && x.valid).sort((x, y) => y.height - x.height)[0];
    if (latest === s) out.push({ spot: s.spot, self: s.by === mine, color: s.by === mine ? [216, 72, 58] as any : tintRGB(s.by) });
  }
  const p = pendingSit(); if (p) { const sp = R.parseSit(p.text)!; out.push({ spot: { x: sp.x, y: sp.y }, self: true, color: [216, 72, 58] as any }); }
  return out;
}

// the level in the corner of the scene
function hud(xp = myXp()) {
  const l = R.levelFor(xp), lo = R.xpForLevel(l), hi = R.xpForLevel(l + 1);
  $("hudlevel").textContent = String(l);
  ($("hudbar") as HTMLElement).style.width = l >= 99 ? "100%" : `${((xp - lo) / (hi - lo)) * 100}%`;
  $("hud").title = l >= 99 ? `${num(xp)} experience` : `${num(xp)} experience. ${num(hi - xp)} to level ${l + 1}`;
}

// ── what's happening: one line inside the game, and what you caught under it ──
const decided = new Set<string>(JSON.parse(store.get("coast.decided") ?? "[]"));
const decide = (k: string) => { decided.add(k); store.set("coast.decided", JSON.stringify([...decided].slice(-2000))); };
const isKept = (sit: string, h: number) => keepRecs.some(k => k.author?.toLowerCase() === mine && (() => { const p = R.parseKeep(k.text); return p && p.sit === sit.toLowerCase() && p.heights.includes(h); })());
const seenOf = (s: R.Sitting) => Math.max(s.height, +(store.get(`coast.seen.${s.id}`) ?? 0));
const setSeen = (s: R.Sitting, h: number) => store.set(`coast.seen.${s.id}`, String(Math.max(h, seenOf(s))));
let lastBlockSeen = 0, barKey = "", haulOpen = false;
const bar = (key: string, html: string) => {
  const el = $("bar");
  if (key !== barKey) { el.classList.remove("got"); void el.offsetWidth; if (key.startsWith("catch")) el.classList.add("got"); }
  barKey = key; el.innerHTML = html;
};
async function castsOf(s: R.Sitting, from: number, to: number) {
  const out: { h: number; c: Catch | null }[] = [];
  const hs: number[] = []; for (let h = to; h > from; h--) hs.push(h);
  for (let i = 0; i < hs.length; i += 24) out.push(...await Promise.all(hs.slice(i, i + 24).map(async h => ({ h, c: await R.castAt(s, h, await block(h)).catch(() => null) }))));
  return out;
}

async function update() {
  scene.setPeople(people()); hud();
  const s = mySitting(), p = pendingSit();
  // a haul waiting: casts you haven't seen, from a sitting you can still keep from
  if (s && !haulOpen && tip > seenOf(s) + 3 && tip <= s.end + R.KEEP_WITHIN && seenOf(s) < s.end) {
    const last = Math.min(tip, s.end);
    return openHaul(s, seenOf(s), last, await castsOf(s, seenOf(s), last));
  }
  if (p) { const sp = R.parseSit(p.text)!; scene.focus(sp.x, sp.y); scene.pick(null); bar("pending", `<div class="text">Sitting down… <span>Your first cast is the block after this one lands.</span></div>`); drawLog(null); return; }
  if (!active(s)) {
    lastBlockSeen = 0;
    scene.pick(picked);
    if (picked) {
      scene.focus(picked.x, picked.y);
      const w = waterOf(R.world, picked.x, picked.y), need = R.levelNeeded(picked.x, picked.y);
      if (myLevel() < need) bar("locked", `<div class="text"><b>${esc(cap(WATER_NAME[w]))}.</b> <span>Fishing here needs level ${need}. You're level ${myLevel()}. The shallows are open to everyone.</span></div>`);
      else {
        bar("picked", `<div class="text"><b>${esc(cap(WATER_NAME[w]))}.</b> <span>${esc(waterSaid(w))}</span></div><button class="quiet" id="sithour">An hour</button><button id="sitnight">Sit for the night</button>`);
        $("sithour").onclick = () => sitDown(picked!, 1);
        $("sitnight").onclick = () => sitDown(picked!, R.MAX_HOURS);
      }
    } else bar("find", `<div class="text">Click the water near the shore to sit down and fish. <span>Every cast is experience, even while you're away.</span></div>`);
    drawLog(null);
    return;
  }
  scene.focus(s!.spot.x, s!.spot.y); scene.pick(null);
  const last = Math.min(tip, s!.end), left = s!.end - tip;
  const casts = await castsOf(s!, Math.max(s!.height, last - 30), last);
  setSeen(s!, last); // you're watching
  if (lastBlockSeen && last > lastBlockSeen && casts[0]?.c) scene.bite();
  lastBlockSeen = last;
  const open = casts.filter(x => x.c && !x.c.species.junk && !isKept(s!.id, x.h) && !decided.has(`${s!.id}:${x.h}`));
  const now = open[0];
  const leftSaid = left > 0 ? `${left} cast${left === 1 ? "" : "s"} left, about ${hoursSaid(left)}` : "that was the last cast";
  if (now) {
    const c = now.c!, same = C!.kept.filter(x => x.catch.species.name === c.species.name);
    const best = same.reduce((m, x) => Math.max(m, x.catch.cm), 0);
    const note = c.specimen ? "A specimen." : !same.length ? "Nobody has kept one yet." : best && c.cm > best ? "Bigger than any kept so far." : `${cap(rarity(c.species))}.`;
    bar(`catch${now.h}`, `<img class="fishpic" src="${fishImage(c.species.name, sizeOf(c))}" alt=""><div class="text"><b>${esc(cap(a(c.species.name)))}, ${cm(c.cm)}.</b> <span>${note}</span></div><button class="quiet" id="letgo">Let it go</button><button id="keep">Keep it, the ${R.ordinal(same.length + 1)} ever</button>`);
    $("letgo").onclick = () => { decide(`${s!.id}:${now.h}`); update(); };
    $("keep").onclick = () => keep(s!, [now.h]);
  } else {
    const latest = casts[0];
    const said = !latest ? "Your line is in." : latest.c ? `${cap(a(latest.c.species.name))} on the last cast.` : "Nothing on the last cast.";
    bar(`wait${last}`, `<div class="text">${esc(said)} <span>${cap(leftSaid)}.</span></div>`);
  }
  drawLog({ sit: s!.id, casts: casts.filter(x => x !== now) });
}
function drawLog(h: { sit: string; casts: { h: number; c: Catch | null }[] } | null) {
  const got = h ? h.casts.filter(x => x.c) : [];
  $("log").innerHTML = got.slice(0, 8).map(x => {
    const c = x.c!, k = isKept(h!.sit, x.h);
    const fate = c.species.junk ? "" : k ? " <em>kept</em>" : decided.has(`${h!.sit}:${x.h}`) ? ", let go" : "";
    return `<li class="r-${rarity(c.species)}"><b>${esc(cap(a(c.species.name)))}</b>, ${cm(c.cm)}${fate}</li>`;
  }).join("");
}

// ── the haul: what came in while you were away, as an event ──
async function openHaul(s: R.Sitting, from: number, to: number, casts: { h: number; c: Catch | null }[]) {
  haulOpen = true;
  const fish = casts.filter(x => x.c && !x.c.species.junk && !isKept(s.id, x.h)), junk = casts.filter(x => x.c?.species.junk).length;
  const kept = C!.kept;
  // only the biggest of each kind in this haul can be a first or a biggest ever
  const top = new Map<string, number>(); for (const x of fish) top.set(x.c!.species.name, Math.max(top.get(x.c!.species.name) ?? 0, x.c!.cm));
  const note = (c: Catch) => {
    const same = kept.filter(k => k.catch.species.name === c.species.name), best = same.reduce((m, k) => Math.max(m, k.catch.cm), 0);
    if (c.specimen) return "Specimen";
    if (c.cm < top.get(c.species.name)!) return "";
    return !same.length ? "First ever" : c.cm > best ? "Biggest ever" : "";
  };
  const score = (c: Catch) => RANK[rarity(c.species)] * 1000 + (note(c) ? 500 : 0) + sizeOf(c) * 100;
  // the best fifteen, revealed worst first so the best comes last
  const shown = [...fish].sort((x, y) => score(y.c!) - score(x.c!)).slice(0, 15).reverse();
  const rest = fish.filter(x => !shown.includes(x));
  const pick = new Set(shown.filter(x => RANK[rarity(x.c!.species)] >= 3 || note(x.c!)).map(x => x.h));
  const before = C!.xpOf(mine, from), after = C!.xpOf(mine, tip);
  const water = cap(WATER_NAME[waterOf(R.world, s.spot.x, s.spot.y)]);
  const restSaid = (() => { const n = new Map<string, number>(); for (const x of rest) n.set(x.c!.species.name, (n.get(x.c!.species.name) ?? 0) + 1); return [...n].sort((p, q) => q[1] - p[1]).map(([k, v]) => `${v} ${k}`).join(", "); })();
  $("haul").innerHTML = `<div class="haulcard">
    <p class="kicker">${to >= s.end ? "Your time by the water is up" : "While you were away"}</p>
    <h2>${esc(water)}, ${hoursSaid(to - from)}</h2>
    <div class="tally"><div><b id="tcasts">0</b><span>casts</span></div><div><b id="tbites">0</b><span>fish</span></div><div><b id="txp">0</b><span>experience</span></div></div>
    <div class="lvl"><div class="lvlrow"><span>Fishing</span><b id="hlevel">${R.levelFor(before)}</b></div><div class="lvlbar"><i id="hbar"></i></div><p id="levelup" class="levelup" aria-live="polite"></p></div>
    <div class="catches" id="catches"></div>
    ${rest.length || junk ? `<p class="more">${rest.length ? `And ${rest.length} more: ${esc(restSaid)}.` : ""}${junk ? ` And ${junk} bit${junk === 1 ? "" : "s"} of junk.` : ""}</p>` : ""}
    <div class="haulfoot" id="haulfoot"><button class="quiet" id="letrest">${fish.length ? "Let them all go" : "Back to the water"}</button>${fish.length ? `<button id="keepsel"></button>` : ""}</div>
  </div>`;
  $("haul").hidden = false;
  requestAnimationFrame(() => $("haul").classList.add("on"));
  const keepBtn = $("keepsel") as HTMLButtonElement | null;
  const label = () => { if (keepBtn) { keepBtn.textContent = pick.size ? `Keep ${pick.size} (one post)` : "Pick what to keep"; keepBtn.disabled = !pick.size; } };
  label();
  // the numbers count up, the bar fills, a level at a time
  const fishN = fish.length, castsN = to - from, wait = still ? 0 : 450, dur = still ? 1 : 1700;
  const t0 = performance.now() + wait;
  let lv = R.levelFor(before);
  const tick = (now: number) => {
    const k = Math.max(0, Math.min(1, (now - t0) / dur)), e = 1 - Math.pow(1 - k, 3);
    $("tcasts").textContent = num(castsN * e); $("tbites").textContent = num(fishN * e); $("txp").textContent = `+${num((after - before) * e)}`;
    const xp = before + (after - before) * e, l = R.levelFor(xp), lo = R.xpForLevel(l), hi = R.xpForLevel(l + 1);
    ($("hbar") as HTMLElement).style.width = l >= 99 ? "100%" : `${((xp - lo) / (hi - lo)) * 100}%`;
    $("hlevel").textContent = String(l);
    if (l > lv) { lv = l; const el = $("levelup"); el.textContent = `Level ${l}!${unlock(l)}`; el.classList.remove("pop"); void el.offsetWidth; el.classList.add("pop"); $("hlevel").classList.remove("pop"); void $("hlevel").offsetWidth; $("hlevel").classList.add("pop"); }
    if (k < 1 && $("haul").classList.contains("on")) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
  // then the fish, one at a time
  const box = $("catches");
  shown.forEach((x, i) => {
    const c = x.c!, r = rarity(c.species), n = note(c), last = i === shown.length - 1 && RANK[r] >= 3;
    const el = document.createElement("button");
    el.className = `catch ${r}${pick.has(x.h) ? " picked" : ""}${last ? " best" : ""}`;
    el.setAttribute("aria-pressed", String(pick.has(x.h)));
    el.innerHTML = `<img src="${fishImage(c.species.name, sizeOf(c))}" alt=""><b>${esc(cap(c.species.name))}</b><span>${cm(c.cm)}</span>${n ? `<em>${n}</em>` : `<i>${cap(r)}</i>`}<s></s>`;
    el.style.animationDelay = still ? "0ms" : `${wait + dur * 0.6 + i * 110}ms`;
    el.onclick = () => { if (pick.has(x.h)) pick.delete(x.h); else if (pick.size < R.MAX_KEEP) pick.add(x.h); el.classList.toggle("picked", pick.has(x.h)); el.setAttribute("aria-pressed", String(pick.has(x.h))); label(); };
    box.appendChild(el);
  });
  $("haulfoot").style.animationDelay = still ? "0ms" : `${wait + dur * 0.6 + shown.length * 110 + 200}ms`;
  const done = () => { setSeen(s, to); for (const x of fish) decide(`${s.id}:${x.h}`); closeHaul(); };
  $("letrest").onclick = done;
  if (keepBtn) keepBtn.onclick = async () => { keepBtn.disabled = true; keepBtn.textContent = "Keeping…"; if (await keep(s, [...pick], false)) done(); else label(); };
}
const unlock = (l: number) => l === R.WATER_LEVEL[REEDS] ? " The reed bed is open to you." : l === R.WATER_LEVEL[LEDGE] ? " The rock ledge is open to you." : l === R.WATER_LEVEL[OPEN] ? " Open water is yours to fish." : l === 99 ? " The most anyone can be." : "";
function closeHaul() { $("haul").classList.remove("on"); setTimeout(() => { $("haul").hidden = true; haulOpen = false; update(); }, still ? 0 : 250); }

// ── choosing a spot ──
($("scene") as HTMLCanvasElement).addEventListener("click", e => {
  const t = scene.at(e.clientX, e.clientY);
  if (active(mySitting()) || pendingSit()) return;
  picked = castable(R.world, t.x, t.y) ? t : null;
  update();
});
const mapDlg = $("mapdlg") as HTMLDialogElement;
$("openmap").onclick = () => { drawMap($("map") as HTMLCanvasElement, R.world, people(), picked, myLevel()); mapDlg.showModal(); };
$("closemap").onclick = () => mapDlg.close();
($("map") as HTMLCanvasElement).addEventListener("click", e => {
  const c = $("map") as HTMLCanvasElement, b = c.getBoundingClientRect();
  const x = Math.floor((e.clientX - b.left) / b.width * (c.width / 6)), y = Math.floor((e.clientY - b.top) / b.height * (c.height / 6));
  if (!castable(R.world, x, y) || active(mySitting()) || pendingSit()) { scene.focus(x, y); mapDlg.close(); return; }
  picked = { x, y }; mapDlg.close(); update();
});

// ── writing ──
async function sitDown(spot: { x: number; y: number }, hours: number) {
  say("Sitting down…");
  try { await net.write(me.signer(net as any), R.SIT, R.sitText(spot.x, spot.y, hours)); picked = null; say(""); await refresh(); }
  catch (e: any) { await trouble(e); }
}
async function keep(s: R.Sitting, heights: number[], refreshAfter = true): Promise<boolean> {
  say("Keeping…");
  try {
    await net.write(me.signer(net as any), R.KEEP, R.keepText(s.id, heights.slice(0, R.MAX_KEEP)));
    for (const h of heights) decide(`${s.id}:${h}`);
    say(heights.length > 1 ? "Kept. They're yours for good, in a minute or two." : "Kept. It's yours for good, in a minute or two.");
    if (refreshAfter) await refresh();
    return true;
  } catch (e: any) { await trouble(e); return false; }
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

// ── the hiscores, on their own page (#records) ──
let tab = "fishing";
const route = () => { const rec = location.hash === "#records"; $("game").hidden = rec; $("recordsview").hidden = !rec; if (rec) drawTab(); scrollTo(0, 0); };
addEventListener("hashchange", route);
document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach(b => b.onclick = () => { tab = b.dataset.tab!; drawTab(); });
function drawTab() {
  if ($("recordsview").hidden) return;
  document.querySelectorAll<HTMLButtonElement>("[data-tab]").forEach(b => b.setAttribute("aria-pressed", String(b.dataset.tab === tab)));
  const kept = C?.kept ?? [], b = R.boards(kept), fishers = (C?.fishers ?? []).map(f => ({ f, xp: C!.xpOf(f, tip) })).sort((x, y) => y.xp - x.xp);
  const top = b.overall[0];
  $("stats").innerHTML = [
    ["Fishers", num(fishers.length)],
    ["Fish kept", num(kept.length)],
    ["Biggest ever", top ? `${cap(top.catch.species.name)}, ${cm(top.catch.cm)}` : "None yet"],
    ["Highest level", fishers[0] ? `${R.levelFor(fishers[0].xp)}` : "None yet"],
  ].map(([k, v]) => `<div class="stat"><span>${k}</span><b>${esc(v)}</b></div>`).join("");
  const rank = (i: number) => `<td class="rank r${i + 1}">${i + 1}</td>`;
  const pic = (name: string, size = 0.5) => `<img class="tpic" src="${fishImage(name, size)}" alt="">`;
  if (tab === "fishing") {
    $("tabview").innerHTML = fishers.length ? `<table><thead><tr><th>#</th><th class="l">Name</th><th>Level</th><th>Experience</th><th>Kept</th></tr></thead><tbody>${fishers.map((x, i) =>
      `<tr${x.f === mine ? ` class="me"` : ""}>${rank(i)}<td class="l name">${esc(Who(x.f))}</td><td class="lvlcell">${R.levelFor(x.xp)}</td><td>${num(x.xp)}</td><td>${kept.filter(k => k.by === x.f).length}</td></tr>`).join("")}</tbody></table>` : `<p class="empty">Nobody has fished here yet. The first name on this board is still free.</p>`;
  } else if (tab === "biggest") {
    $("tabview").innerHTML = b.overall.length ? `<table><thead><tr><th>#</th><th class="l">Fish</th><th>Size</th><th class="l">Caught by</th><th>When</th></tr></thead><tbody>${b.overall.map((k, i) =>
      `<tr${k.by === mine ? ` class="me"` : ""}>${rank(i)}<td class="l name">${pic(k.catch.species.name, sizeOf(k.catch))}${esc(cap(k.catch.species.name))}${k.catch.specimen ? ` <span class="tag">specimen</span>` : ""}</td><td>${cm(k.catch.cm)}</td><td class="l name">${esc(Who(k.by))}</td><td>${day(k.at)}</td></tr>`).join("")}</tbody></table>` : `<p class="empty">Nothing kept yet. The biggest of everything is still out there.</p>`;
  } else {
    $("tabview").innerHTML = `<table><thead><tr><th class="l">Fish</th><th>Kept</th><th>Biggest</th><th class="l">By</th><th class="l">First by</th></tr></thead><tbody>${b.species.map(s =>
      `<tr class="${s.count ? "" : "unclaimed"}"><td class="l name">${pic(s.species.name)}${esc(cap(s.species.name))} <span class="dot ${rarity(s.species)}"></span></td><td>${s.count || ""}</td><td>${s.biggest ? cm(s.biggest.catch.cm) : ""}</td><td class="l name">${s.biggest ? esc(Who(s.biggest.by)) : `<span class="muted">Never kept</span>`}</td><td class="l name">${s.first ? esc(Who(s.first.by)) : ""}</td></tr>`).join("")}</tbody></table>`;
  }
}
void FISH;

if (me.kept && !me.doorway) welcome(net as any, me, INVITES).catch(() => {});
route(); update();
await refresh();
setInterval(refresh, 20_000);
