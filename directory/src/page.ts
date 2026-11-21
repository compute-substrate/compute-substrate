// The directory's page: the list (app/resolver/src/directory.ts), and recommending, signed by a
// key kept in this browser (the kit's browserKey), with the usual ways to get the little CSD it costs.
import { listSites, siteFace, DIRECTORY, type Listed } from "../../app/resolver/src/directory";
import { connect, writingKey, claimInvite, openInvites, welcome } from "../../kit/src/index";

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
const openUrl = (s: Listed) => viaDoorway ? `${location.protocol}//${s.name}.localhost${location.port ? ":" + location.port : ""}/` : `https://${s.cid}.ipfs.dweb.link/`;
$("howOpen").innerHTML = viaDoorway
  ? "Sites open from this computer, through Doorway, checked."
  : 'Sites open through an IPFS gateway. With <a href="https://github.com/compute-substrate/compute-substrate/tree/main/app#readme">Doorway</a> they open from your own computer at <code>name.localhost</code>, checked.';

const me = await writingKey("directory");
if (me.doorway) $("keyBtn").closest("span")!.textContent = "Each recommendation is a record on Compute Substrate, signed by your key in Doorway once you allow it there. A key counts once per site.";
let net: ReturnType<typeof connect>;
let sites: Listed[] = [];
let order: "rec" | "new" = "rec";
const mine = new Set<string>(); // recommended from here, before the next block shows it
const faces = new Map<string, { title?: string; icon?: string }>();

function render() {
  const q = (($("q") as HTMLInputElement).value || "").trim().toLowerCase();
  const list = sites
    .filter(s => !q || s.name.includes(q) || (faces.get(s.cid)?.title ?? "").toLowerCase().includes(q))
    .sort(order === "new" ? (a, b) => b.since - a.since : () => 0);
  if (!list.length) { $("grid").innerHTML = `<p class="empty">${sites.length ? "Nothing matches." : "No name points to a site yet."}</p>`; return; }
  $("grid").innerHTML = list.map(s => {
    const f = faces.get(s.cid) ?? {};
    const title = f.title || s.name;
    const done = mine.has(s.name) || s.recommenders.includes(me.address.toLowerCase());
    const n = s.recommenders.length + (mine.has(s.name) && !s.recommenders.includes(me.address.toLowerCase()) ? 1 : 0);
    return `<article class="card">
      <a class="open" href="${esc(openUrl(s))}" target="_blank" rel="noopener">
        <span class="face" style="${f.icon ? "" : `background:${tint(s.cid)}`}">${f.icon ? `<img src="${esc(f.icon)}" alt="">` : esc(title[0]?.toUpperCase() ?? "·")}</span>
        <span style="min-width:0"><b>${esc(title)}</b><small>${esc(s.name)}.csd</small></span>
      </a>
      <div class="foot">
        <span class="count" title="${n} ${n === 1 ? "person recommends" : "people recommend"} it">${n ? `${HEART}${n}` : ""}</span>
        <button class="rec" data-name="${esc(s.name)}" ${done ? "disabled" : ""}>${done ? "Recommended" : "Recommend"}</button>
      </div>
    </article>`;
  }).join("");
}

async function load() {
  try {
    if (!net) { net = connect({ node: await pickNode() }); $("node").textContent = net.node; }
    const r = await listSites(net.node);
    sites = r.sites;
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
  const b = (e.target as HTMLElement).closest("button.rec") as HTMLButtonElement | null;
  if (!b || b.disabled) return;
  const s = sites.find(x => x.name === b.dataset.name);
  if (!s) return;
  b.disabled = true;
  say(`Recommending ${s.name}.csd…`);
  try {
    // the first recommendation for a site is a record naming it; the rest attest to that record
    if (s.listing) await net.attest(me.signer(net as any), s.listing as any, 1);
    else await net.write(me.signer(net as any), DIRECTORY, s.name);
    mine.add(s.name);
    $("needCsd").hidden = true;
    say(`Thanks. Your recommendation of ${s.name}.csd counts from the next block, in about two minutes.`);
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
$("keyBtn").onclick = () => navigator.clipboard?.writeText(me.backup()).then(() => say("Key copied. Keep it somewhere safe: whoever has it can spend its CSD.")).catch(() => {});

const setOrder = (o: "rec" | "new") => { order = o; $("byRec").setAttribute("aria-pressed", String(o === "rec")); $("byNew").setAttribute("aria-pressed", String(o === "new")); render(); };
$("byRec").onclick = () => setOrder("rec");
$("byNew").onclick = () => setOrder("new");
$("q").oninput = render;

load().then(() => {
  // someone new: take one of the invites left for newcomers, so recommending just works
  if (me.kept && net) welcome(net as any, me).catch(() => {});
});
setInterval(load, 10 * 60_000);
