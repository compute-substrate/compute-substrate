// The directory's page: the list (app/resolver/src/directory.ts), and recommending, signed by a
// key kept in this browser (the kit's browserKey), with the usual ways to get the little CSD it costs.
import { listSites, siteFace, hiddenList, listed, DIRECTORY, type Listed } from "../../app/resolver/src/directory";
import { connect, writingKey, claimInvite, openInvites, welcome, heightToDate, monthYear } from "../../kit/src/index";

// Doors: public nodes anyone runs (docs/public-node.md). The page reads through the first that
// answers, and fetches each site's title and icon from any of them; everything is checked here.
const DOORS = ["https://csd.aon.network", "https://151-240-121-186.sslip.io", "https://151-240-121-187.sslip.io"];
const $ = (id: string) => document.getElementById(id)!;
const esc = (t: string) => String(t).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const tint = (cid: string) => { let h = 0; for (const ch of cid) h = (h * 31 + ch.charCodeAt(0)) >>> 0; return `hsl(${h % 360} 45% 52%)`; };
const say = (t: string) => { $("status").textContent = t; };
const HEART = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.8l2.8 5.9 6.4.8-4.7 4.4 1.2 6.4L12 17.2l-5.7 3.1 1.2-6.4-4.7-4.4 6.4-.8z" fill="currentColor"/></svg>';

const asked = new URLSearchParams(location.search).get("node");
async function pickNode(): Promise<string> {
  for (const d of asked ? [asked, ...DOORS] : DOORS) {
    try { const r = await fetch(`${d.replace(/\/$/, "")}/tip`, { signal: AbortSignal.timeout(6000) }); if (r.ok) return d.replace(/\/$/, ""); } catch {}
  }
  throw new Error("No door answered. Check that you're online, then reload.");
}

// Opened from Doorway (this page at directory.localhost), sites open from this computer too
const viaDoorway = location.hostname.endsWith(".localhost");
// named sites open by name; a site kept with no name, by its own address (Doorway serves both)
// sites open in Doorway, at name.localhost, wherever this page was opened (gateways don't have them)
const openUrl = (s: Listed) => viaDoorway ? `${location.protocol}//${s.name || s.cid}.localhost${location.port ? ":" + location.port : ""}/` : `http://${s.name || s.cid}.localhost/`;
$("howOpen").innerHTML = viaDoorway
  ? "Sites open from this computer, through Doorway, checked."
  : 'Sites open in <a href="https://doorway.place">Doorway</a>, from your own computer at <code>name.localhost</code>, checked.';

const me = await writingKey("directory");
if (me.doorway) $("keyBtn").closest("span")!.textContent = "Each recommendation is a record on Compute Substrate, signed by your key in Doorway once you allow it there. A key counts once per site.";
let net: ReturnType<typeof connect>;
let sites: Listed[] = [];
let order: "rec" | "new" = "rec";
const mine = new Set<string>(); // recommended from here, before the next block shows it
const faces = new Map<string, { title?: string; icon?: string }>();
// how long each site is kept up (kit/src/keep.ts): its address -> the block, and the tip
let kept: { tip: number; until: Map<string, number> } = { tip: 0, until: new Map() };
const lifeOf = (cid: string) => { const u = kept.until.get(cid); return u && u > kept.tip ? heightToDate(u, kept.tip).getFullYear() : null; };
// when its keep runs out, to the month (see monthYear)
const lifeSaid = (cid: string, short = false) => { const u = kept.until.get(cid); return u && u > kept.tip ? monthYear(heightToDate(u, kept.tip), short) : null; };
let keeping: string | null = null, keepYears = 10;

function render() {
  const q = (($("q") as HTMLInputElement).value || "").trim().toLowerCase();
  const list = sites
    .filter(s => !q || s.key.includes(q) || (faces.get(s.cid)?.title ?? "").toLowerCase().includes(q))
    .sort(order === "new" ? (a, b) => b.since - a.since : () => 0);
  if (!list.length) { $("grid").innerHTML = `<p class="empty">${sites.length ? "Nothing matches." : "No name points to a site yet."}</p>`; return; }
  $("grid").innerHTML = list.map(s => {
    const f = faces.get(s.cid) ?? {};
    const title = f.title || s.name || `${s.cid.slice(0, 10)}…`;
    const done = mine.has(s.key) || s.recommenders.includes(me.address.toLowerCase());
    const n = s.recommenders.length + (mine.has(s.key) && !s.recommenders.includes(me.address.toLowerCase()) ? 1 : 0);
    return `<article class="card">
      <a class="open" href="${esc(openUrl(s))}" target="_blank" rel="noopener">
        <span class="face" style="${f.icon ? "" : `background:${tint(s.cid)}`}">${f.icon ? `<img src="${esc(f.icon)}" alt="">` : esc(title[0]?.toUpperCase() ?? "·")}</span>
        <span style="min-width:0"><b>${esc(title)}</b><small>${s.name ? esc(s.name) + ".csd" : "no name, kept up by its address"}</small></span>
      </a>
      <div class="foot">
        <span class="count" title="${n} ${n === 1 ? "person recommends" : "people recommend"} it">${n ? `${HEART}${n}` : ""}${lifeOf(s.cid) ? `<span class="life" title="Kept up on the doors until ${lifeSaid(s.cid)}, name or not">until ${lifeSaid(s.cid, true)}</span>` : ""}</span>
        <span class="acts">
          <button class="rec quiet" data-share="${esc(s.key)}" title="Share a link to it">Share</button>
          <button class="rec quiet" data-keep="${esc(s.cid)}" title="Keep it up for years, name or not">Keep</button>
          <button class="rec" data-name="${esc(s.key)}" ${done ? "disabled" : ""}>${done ? "Recommended" : "Recommend"}</button>
        </span>
      </div>
      ${keeping === s.cid ? keepPanel(s) : ""}
    </article>`;
  }).join("");
}

// A name in the address (this page, then #<name>) opens that name's site: a link anyone can share
// and open on any device, phone included, with nothing installed
const wanted = () => decodeURIComponent(location.hash.replace(/^#\/?/, "")).trim().toLowerCase().replace(/\.csd$/, "");
let opening = wanted();
if (opening) $("grid").innerHTML = `<p class="empty">Opening ${esc(opening)}.csd…</p>`;
function openWanted() {
  if (!opening || !sites.length) return;
  const s = sites.find(x => x.name === opening || x.key === opening || x.cid === opening);
  if (s) { location.replace(openUrl(s)); return; }
  say(`${opening}.csd doesn't point to a site.`);
  opening = "";
  render();
}
addEventListener("hashchange", () => { opening = wanted(); openWanted(); });
// a link to a site that works for anyone: its name on doorway.place (which looks it up, checks it
// and opens it in Doorway, or says where to get Doorway); a site with no name, by its address
async function share(s: Listed) {
  const url = s.name ? `https://doorway.place/#${s.name}` : `ipfs://${s.cid}`;
  const title = faces.get(s.cid)?.title || (s.name ? `${s.name}.csd` : "A site");
  try { if ((navigator as any).share) { await (navigator as any).share({ title, url }); return; } } catch { return; }
  try { await navigator.clipboard.writeText(url); say(`Link copied: ${url}`); } catch { say(url); }
}

// adding years to a site: anyone can, for any site (kit/src/keep.ts)
function keepPanel(s: Listed) {
  const from = lifeOf(s.cid) ?? new Date().getFullYear();
  const choices = [...new Set([1, 10, 25, Math.max(1, 2100 - from)])];
  return `<div class="keep">
    <small>${lifeOf(s.cid) ? `Kept up until ${lifeSaid(s.cid)}.` : "Nobody keeps it up yet: it stays only while its name points to it."} Anyone can add time, and the doors keep it until it runs out, name or not.</small>
    <div class="years">${choices.map(y => `<button class="rec" data-years="${y}" aria-pressed="${y === keepYears}">${from + y === 2100 ? "Until 2100" : `${y} year${y === 1 ? "" : "s"}`}</button>`).join("")}</div>
    <div class="row"><small>Until ${from + keepYears}, for ${(keepYears * 0.25).toLocaleString()} CSD. The first 0.25 pays for the record; the rest is burned.</small><button class="rec go" data-keepgo="${esc(s.cid)}">Keep it</button></div>
  </div>`;
}

async function load() {
  try {
    if (!net) { net = connect({ node: await pickNode() }); $("node").textContent = net.node; }
    const [r, k, hide] = await Promise.all([listSites(net.node), net.kept().catch(() => kept), hiddenList()]);
    // sites a name points to, less the hide list: a list chooses what it shows (see listed)
    sites = listed(hide, r.sites);
    kept = k;
    if (opening) return openWanted();
    render();
    // faces, a few at a time, each remembered once it's read
    const want = sites.filter(s => !faces.has(s.cid));
    for (let i = 0; i < want.length; i += 4) {
      await Promise.all(want.slice(i, i + 4).map(async s => { faces.set(s.cid, await siteFace(s.cid, DOORS).catch(() => ({}))); }));
      render();
    }
  } catch (e: any) {
    if (!sites.length) $("grid").innerHTML = `<p class="empty">Couldn't read the network: ${esc(String(e?.message ?? e))}</p>`;
  }
}

$("grid").addEventListener("click", async e => {
  const sh = (e.target as HTMLElement).closest("button[data-share]") as HTMLButtonElement | null;
  if (sh) { const s = sites.find(x => x.key === sh.dataset.share); if (s) share(s); return; }
  const t = e.target as HTMLElement;
  const kb = t.closest("button[data-keep]") as HTMLButtonElement | null;
  if (kb) { keeping = keeping === kb.dataset.keep ? null : kb.dataset.keep!; render(); return; }
  const yb = t.closest("button[data-years]") as HTMLButtonElement | null;
  if (yb) { keepYears = Number(yb.dataset.years); render(); return; }
  const go = t.closest("button[data-keepgo]") as HTMLButtonElement | null;
  if (go) {
    const cid = go.dataset.keepgo!, years = keepYears;
    go.disabled = true;
    say("Keeping it…");
    try {
      await net.keep(me.signer(net as any), cid, years);
      $("needCsd").hidden = true;
      say(`Done. It's kept up for ${years} more year${years === 1 ? "" : "s"}, from the next block, in about two minutes.`);
      keeping = null; render();
      setTimeout(load, 130_000);
    } catch (err: any) {
      go.disabled = false;
      if (/Not enough CSD/.test(String(err?.message))) { say(`That needs ${(years * 0.25).toLocaleString()} CSD.`); $("needCsd").hidden = false; }
      else say(String(err?.message ?? err));
    }
    return;
  }
  const b = (e.target as HTMLElement).closest("button.rec") as HTMLButtonElement | null;
  if (!b || b.disabled) return;
  const s = sites.find(x => x.key === b.dataset.name);
  if (!s) return;
  const label = s.name ? `${s.name}.csd` : (faces.get(s.cid)?.title || "this site");
  b.disabled = true;
  say(`Recommending ${label}…`);
  try {
    // the first recommendation for a site is a record naming it (its name, or its address); the
    // rest attest to that record
    if (s.listing) await net.attest(me.signer(net as any), s.listing as any, 1);
    else await net.write(me.signer(net as any), DIRECTORY, s.key);
    mine.add(s.key);
    $("needCsd").hidden = true;
    say(`Thanks. Your recommendation of ${label} counts from the next block, in about two minutes.`);
    render();
    setTimeout(load, 130_000);
  } catch (err: any) {
    b.disabled = false;
    if (/Not enough CSD/.test(String(err?.message))) { say(""); $("needCsd").hidden = false; $("needCsd").scrollIntoView({ behavior: "smooth", block: "center" }); }
    else say(String(err?.message ?? err));
  }
});

// getting CSD at the moment it's needed
$("freeInvite").onclick = async () => {
  $("freeSaid").textContent = "Looking…";
  try {
    const open = await openInvites(net as any);
    if (!open.length) { $("freeSaid").textContent = "None left right now."; return; }
    const r = await claimInvite(net as any, open[Math.floor(Math.random() * open.length)].code, me.address);
    $("freeSaid").textContent = "Taken.";
    say(`${r.csd} CSD is on its way. Recommend again in about two minutes.`);
  } catch (e: any) { $("freeSaid").textContent = String(e?.message ?? e); }
};
$("buyUsdc").onclick = async () => {
  try {
    // the top-up carries an Ethereum library, so it's loaded only now
    const { topUpWithUsdc, topUpError } = await import("../../kit/src/topup");
    try {
      await topUpWithUsdc(net as any, me, 1, (step: string) => { $("buySaid").textContent = step; });
      $("buySaid").textContent = "Bought.";
      say("The CSD arrives a few minutes after the market maker's lock. Recommend again then.");
    } catch (e) { $("buySaid").textContent = topUpError(e); }
  } catch (e: any) { $("buySaid").textContent = "Couldn't load the market: " + String(e?.message ?? e); }
};
$("copyAddr").onclick = () => navigator.clipboard?.writeText(me.address).then(() => { $("copyAddr").textContent = "copied"; }).catch(() => {});
// through Doorway there's no key here to back up (the line about it says so instead)
if (!me.doorway) $("keyBtn").onclick = () => navigator.clipboard?.writeText(me.backup()).then(() => say("Key copied. Keep it somewhere safe: whoever has it can spend its CSD.")).catch(() => {});

const setOrder = (o: "rec" | "new") => { order = o; $("byRec").setAttribute("aria-pressed", String(o === "rec")); $("byNew").setAttribute("aria-pressed", String(o === "new")); render(); };
$("byRec").onclick = () => setOrder("rec");
$("byNew").onclick = () => setOrder("new");
$("q").oninput = render;

load().then(() => {
  // someone new: take one of the invites left for newcomers, so recommending just works
  if (me.kept && net) welcome(net as any, me).catch(() => {});
});
setInterval(load, 10 * 60_000);
