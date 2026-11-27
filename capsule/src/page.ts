// capsule.csd: every Sunday a capsule opens for 30 minutes. Everyone there watches the same video,
// picked during the week by whoever suggests and backs one, and talks beside it; then it closes,
// and what was said stays. All of it is records (src/schedule.ts says which belong where), read and
// checked here against the network: nobody runs it, picks for it or keeps it.
import { connect, writingKey, claimInvite, openInvites, welcome, friendlyName, doorwayAdd } from "../../kit/src/index";
import * as S from "./schedule";

const INVITES = "csd.welcome";
const $ = (id: string) => document.getElementById(id) as HTMLElement;
const esc = (s: string) => s.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const net = connect({ node: new URLSearchParams(location.search).get("node") ?? undefined });
const now = () => Math.floor(Date.now() / 1000);
const say = (id: string, t: string) => { $(id).textContent = t; };
const me = await writingKey("capsule");
const who = (a?: string) => a ? (a.toLowerCase() === me.address.toLowerCase() ? "you" : friendlyName(a)) : "someone";

const local = (t: number, o: Intl.DateTimeFormatOptions) => new Date(t * 1000).toLocaleString(undefined, o);
const dayTime = (id: string) => `${local(S.openAt(id), { weekday: "long", day: "numeric", month: "long" })}, ${local(S.openAt(id), { hour: "2-digit", minute: "2-digit" })} to ${local(S.closeAt(id), { hour: "2-digit", minute: "2-digit" })}`;
const until = (s: number) => {
  if (s <= 0) return "now";
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60), x = s % 60;
  return d ? `${d} day${d === 1 ? "" : "s"}, ${h} hour${h === 1 ? "" : "s"}` : h ? `${h} hour${h === 1 ? "" : "s"}, ${m} minute${m === 1 ? "" : "s"}` : m ? `${m} minute${m === 1 ? "" : "s"}` : `${x} second${x === 1 ? "" : "s"}`;
};
// a topic's entries, each proven once (signed by its author, in a block) and remembered after that
const proven = new Map<string, string>();
async function readChecked(topic: string, limit: number) {
  const rows = await net.read(topic, { limit, check: false });
  const todo = rows.filter(r => !r.pending && !proven.has(r.id));
  for (let i = 0; i < todo.length; i += 6) {
    const got = await Promise.all(todo.slice(i, i + 6).map(async r => ({ r, c: await net.check(r.id as any) })));
    for (const { r, c } of got) if (c.ok) proven.set(r.id, c.author);
  }
  return rows.filter(r => r.pending || proven.has(r.id)).map(r => ({ ...r, author: (r as any).author ?? proven.get(r.id) }));
}
const thumb = (v: string) => `https://i.ytimg.com/vi/${v}/mqdefault.jpg`;

$("when").textContent = `Every Sunday at ${local(S.openAt(S.FIRST), { hour: "2-digit", minute: "2-digit" })}, your time`;

// ── this week ──
let shown = "";           // which capsule the page is drawn for, and in which state
let viewing: string | null = null; // an earlier capsule opened from the list
async function draw() {
  const c = S.current(now());
  const state = `${c.id}:${c.open}`;
  if (state !== shown) { shown = state; $("now").innerHTML = c.open ? openHtml() : waitingHtml(c.id); wire(c); }
  if (c.open) await drawOpen(c.id); else await drawWaiting(c.id);
}

function waitingHtml(id: string) {
  return `<section class="card next">
    <p class="kicker">The next capsule</p>
    <h2>${esc(dayTime(id))}</h2>
    <p class="count">Opens in <b id="countdown"></b></p>
  </section>
  <section class="card">
    <div class="row"><h3>What we'll watch</h3><span class="small">The most backed suggestion plays when it opens.</span></div>
    <div id="picks" class="picks"><p class="small">Reading this week's suggestions…</p></div>
    <form id="suggest" class="suggest">
      <input id="link" placeholder="Suggest a video: paste a YouTube link" autocomplete="off" spellcheck="false" aria-label="A YouTube link">
      <input id="title" placeholder="What is it? (optional)" autocomplete="off" maxlength="120" aria-label="What it is">
      <button>Suggest</button>
    </form>
    <p id="pickSaid" class="small said" aria-live="polite"></p>
  </section>`;
}
function openHtml() {
  return `<section class="live">
    <div class="screen" id="screen"><p class="small">Finding this week's video…</p></div>
    <aside class="talk card">
      <div class="row"><h3>Here now</h3><span class="small">Closes in <b id="countdown"></b></span></div>
      <div id="said" class="said-list" aria-live="polite"></div>
      <form id="sayForm" class="say"><textarea id="line" maxlength="${S.SAID_MAX}" rows="2" placeholder="Say something…" aria-label="Say something"></textarea><button>Say</button></form>
      <p id="sayNote" class="small said">Lines land with the next block, in a minute or two. What's said here stays after it closes.</p>
    </aside>
  </section>`;
}

function wire(c: { id: string; open: boolean }) {
  if (c.open) {
    $("line").addEventListener("keydown", e => { if ((e as KeyboardEvent).key === "Enter" && !(e as KeyboardEvent).shiftKey) { e.preventDefault(); ($("sayForm") as HTMLFormElement).requestSubmit(); } });
    $("sayForm").onsubmit = async e => {
      e.preventDefault();
      const line = ($("line") as HTMLTextAreaElement).value.trim();
      if (!line) return;
      if (!S.current(now()).open) return say("sayNote", "It has closed. See you next Sunday.");
      await write(S.saidTopic(c.id), line, "sayNote", () => { ($("line") as HTMLTextAreaElement).value = ""; drawOpen(c.id); });
    };
  } else {
    $("suggest").onsubmit = async e => {
      e.preventDefault();
      const v = S.videoId(($("link") as HTMLInputElement).value);
      if (!v) return say("pickSaid", "That isn't a YouTube link.");
      const text = S.pickText(v, ($("title") as HTMLInputElement).value);
      await write(S.picksTopic(c.id), text, "pickSaid", () => { ($("link") as HTMLInputElement).value = ""; ($("title") as HTMLInputElement).value = ""; say("pickSaid", "Suggested. It shows here in a minute or two, for others to back."); drawWaiting(c.id); });
    };
  }
}

async function picksOf(id: string) {
  const [ps, backing] = await Promise.all([readChecked(S.picksTopic(id), 200), net.api.resonanceIn(S.picksTopic(id)).catch(() => ({} as Record<string, number>))]);
  const list = ps.map(p => ({ ...p, pick: S.parsePick(p.text), backers: backing[p.id.toLowerCase()] ?? 0 })).filter(p => p.pick && p.time < S.openAt(id));
  // one row per video: its earliest suggestion, with everyone's backing of any of them
  const byVideo = new Map<string, typeof list[number]>();
  for (const p of list.sort((a, b) => a.time - b.time)) {
    const had = byVideo.get(p.pick!.video);
    if (had) had.backers += p.backers; else byVideo.set(p.pick!.video, { ...p });
  }
  return { rows: [...byVideo.values()].sort((a, b) => b.backers - a.backers || a.time - b.time), chosen: S.chosen(id, ps, backing) };
}

async function drawWaiting(id: string) {
  try {
    const { rows } = await picksOf(id);
    if (!$("picks")) return;
    $("picks").innerHTML = rows.length ? rows.map((p, i) => `<div class="pick${i === 0 ? " top" : ""}">
      <img src="${thumb(p.pick!.video)}" alt="" loading="lazy">
      <div class="what"><b>${esc(p.pick!.title || "A video")}</b><span class="small">${i === 0 ? "Plays on Sunday if it stays on top. " : ""}${p.backers} backer${p.backers === 1 ? "" : "s"}, suggested by ${esc(who(p.author))}${p.pending ? " (on its way)" : ""}</span></div>
      ${p.pending ? "" : `<button class="quiet" data-back="${p.id}">Back it</button>`}</div>`).join("")
      : `<p class="small">Nothing suggested yet for this Sunday. Suggest something to watch together.</p>`;
    $("picks").querySelectorAll<HTMLButtonElement>("[data-back]").forEach(b => b.onclick = async () => {
      b.disabled = true; say("pickSaid", "Backing it…");
      try { await net.attest(me.signer(net as any), b.dataset.back as any, 1); say("pickSaid", "Backed. It counts in a minute or two."); }
      catch (e: any) { await trouble(e, "pickSaid"); }
      b.disabled = false;
    });
  } catch { if ($("picks")) $("picks").innerHTML = `<p class="small">Couldn't reach the network just now. It tries again by itself.</p>`; }
}

let playing = "";
async function drawOpen(id: string) {
  try {
    const [{ chosen }, lines] = await Promise.all([picksOf(id), readChecked(S.saidTopic(id), 500)]);
    if (!$("screen")) return;
    if (chosen && playing !== `${id}:${chosen.video}`) {
      playing = `${id}:${chosen.video}`;
      // everyone at the same moment of it: started as far in as the capsule has been open
      const at = Math.max(0, now() - S.openAt(id));
      $("screen").innerHTML = `<iframe src="https://www.youtube-nocookie.com/embed/${chosen.video}?autoplay=1&start=${at}&rel=0" title="${esc(chosen.title || "This week's video")}" allow="autoplay; encrypted-media; picture-in-picture; fullscreen" allowfullscreen></iframe>
        <p class="small caption">${esc(chosen.title || "This week's video")}, chosen by ${chosen.backers} backer${chosen.backers === 1 ? "" : "s"}.</p>`;
    } else if (!chosen && playing !== `${id}:none`) {
      playing = `${id}:none`;
      $("screen").innerHTML = `<div class="empty-screen"><p>Nobody picked a video this week.</p><p class="small">Just talk, then. Suggest something for next Sunday after it closes.</p></div>`;
    }
    const said = lines.filter(l => S.inWindow(id, l.time)).sort((a, b) => a.time - b.time || a.height - b.height);
    $("said").innerHTML = said.length ? said.map(l => `<p class="line${l.pending ? " pending" : ""}"><b>${esc(who(l.author))}</b> ${esc(l.text)}</p>`).join("") : `<p class="small">Nobody has said anything yet.</p>`;
    $("said").scrollTop = $("said").scrollHeight;
  } catch { if ($("said")) $("said").innerHTML = `<p class="small">Couldn't reach the network just now. It tries again by itself.</p>`; }
}

// ── earlier capsules ──
async function drawPast() {
  const ids = S.past(now());
  if (!ids.length) { $("past").innerHTML = `<p class="small">The first capsule opens on ${esc(dayTime(S.FIRST))}. After that, every one stays here: what was watched, and what was said.</p>`; return; }
  if (viewing) return drawOne(viewing);
  const rows = await Promise.all(ids.slice(0, 20).map(async id => {
    const [{ chosen }, lines] = await Promise.all([picksOf(id).catch(() => ({ chosen: null })), net.read(S.saidTopic(id), { limit: 500, check: false }).catch(() => [])]);
    return { id, chosen, n: lines.filter(l => S.inWindow(id, l.time)).length };
  }));
  $("past").innerHTML = rows.map(r => `<button class="past" data-id="${r.id}">${r.chosen ? `<img src="${thumb(r.chosen.video)}" alt="" loading="lazy">` : `<span class="noimg"></span>`}
    <span class="what"><b>${esc(local(S.openAt(r.id), { day: "numeric", month: "long", year: "numeric" }))}</b><span class="small">${r.chosen ? esc(r.chosen.title || "A video") : "No video"}, ${r.n} line${r.n === 1 ? "" : "s"} said</span></span></button>`).join("");
  $("past").querySelectorAll<HTMLButtonElement>("[data-id]").forEach(b => b.onclick = () => { viewing = b.dataset.id!; drawOne(viewing); });
}
async function drawOne(id: string) {
  const [{ chosen }, lines] = await Promise.all([picksOf(id), readChecked(S.saidTopic(id), 500)]);
  const said = lines.filter(l => S.inWindow(id, l.time)).sort((a, b) => a.time - b.time);
  $("past").innerHTML = `<div class="one"><button class="quiet" id="back">All capsules</button>
    <h3>${esc(local(S.openAt(id), { weekday: "long", day: "numeric", month: "long", year: "numeric" }))}</h3>
    ${chosen ? `<a class="watched" href="https://www.youtube.com/watch?v=${chosen.video}" target="_blank" rel="noopener"><img src="${thumb(chosen.video)}" alt=""><span>${esc(chosen.title || "The video")}</span></a>` : `<p class="small">No video that week.</p>`}
    <div class="said-list static">${said.length ? said.map(l => `<p class="line"><b>${esc(who(l.author))}</b> ${esc(l.text)} <span class="small">${esc(local(l.time, { hour: "2-digit", minute: "2-digit" }))}</span></p>`).join("") : `<p class="small">Nothing was said.</p>`}</div></div>`;
  $("back").onclick = () => { viewing = null; drawPast(); };
}

// ── writing ──
async function write(topic: string, text: string, sayId: string, done: () => void) {
  say(sayId, "Signing…");
  try { await net.write(me.signer(net as any), topic, text); done(); }
  catch (e: any) { await trouble(e, sayId); }
}
async function trouble(e: any, sayId: string) {
  const m = String(e?.message ?? e);
  if (/Declined/.test(m)) return say(sayId, "");
  if (!/Not enough CSD/.test(m)) return say(sayId, m);
  if (me.doorway) { $(sayId).innerHTML = `You've run out for now. <button class="quiet" id="topUp">Top up in Doorway</button>, then try again.`; $("topUp").onclick = () => doorwayAdd(); return; }
  try {
    const open = await openInvites(net as any, INVITES);
    if (!open.length) { $(sayId).innerHTML = `You've run out for now. Open this in <a href="https://doorway.place">Doorway</a> to top up.`; return; }
    await claimInvite(net as any, open[Math.floor(Math.random() * open.length)].code, me.address);
    say(sayId, "Someone left you a free start. Try again in a moment.");
  } catch (err: any) { say(sayId, String(err?.message ?? err)); }
}

// ── the clock ──
function tick() {
  const c = S.current(now());
  if (`${c.id}:${c.open}` !== shown) { draw(); drawPast(); return; }
  const left = (c.open ? S.closeAt(c.id) : S.openAt(c.id)) - now();
  if ($("countdown")) $("countdown").textContent = until(left);
}
if (me.kept && !me.doorway) welcome(net as any, me, INVITES).catch(() => {});
await draw();
drawPast();
setInterval(tick, 1000);
setInterval(() => { const c = S.current(now()); c.open ? drawOpen(c.id) : drawWaiting(c.id); }, 20_000);
