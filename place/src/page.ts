// doorway.place: Doorway's download, .csd names (looked up and checked here, pointed and kept up
// with the holder's own key in Cairn Wallet), and the sites on the network. Everything is read
// through the doors and checked in this browser; the page has nothing behind it.
import { lookup, listSites, siteFace, wallet as W } from "../../app/resolver/src/main";
import { cairnSigner, friendlyName, heightToDate } from "../../kit/src/index";

const DOORS = ["https://csd.aon.network", "https://151-240-121-186.sslip.io", "https://151-240-121-187.sslip.io"];
const REPO = "compute-substrate/compute-substrate";
const $ = (id: string) => document.getElementById(id)!;
const esc = (s: string) => s.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
const CID_RE = /^b[a-z2-7]{50,100}$/;
const inDoorway = (name: string) => `http://${name}.localhost/`;

// ── download: the newest Doorway, for this computer first ─────────────────────
// The links go straight to the files (the page itself names a release that has them, so they work
// before this runs); here they follow the newest release. On a phone, there's nothing to install.
const isWin = /Windows/i.test(navigator.userAgent);
const isPhone = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
async function download() {
  const dl = $("dlMain") as HTMLAnchorElement, other = $("dlAlt") as HTMLAnchorElement;
  dl.textContent = isWin ? "Download for Windows" : "Download for Mac";
  other.textContent = isWin ? "For Mac" : "For Windows";
  if (isWin) { const h = dl.href; dl.href = other.href; other.href = h; }
  if (isPhone) $("dlSaid").textContent = "Doorway is for Mac and Windows: open doorway.place on your computer to get it. Free and open source.";
  try {
    const rs = await (await fetch(`https://api.github.com/repos/${REPO}/releases?per_page=30`, { signal: AbortSignal.timeout(8000) })).json();
    const r = (rs as any[]).find(x => /^app-v/.test(x.tag_name) && !x.draft && !x.prerelease && x.assets?.some((a: any) => a.name === "Doorway-macOS.dmg"));
    if (!r) return;
    const base = `https://github.com/${REPO}/releases/download/${r.tag_name}`;
    const mac = `${base}/Doorway-macOS.dmg`, win = `${base}/Doorway-Windows-setup.exe`;
    dl.href = isWin ? win : mac; other.href = isWin ? mac : win;
  } catch { /* the releases page, which lists them */ }
}
download();

// ── the doors ─────────────────────────────────────────────────────────────────
let door: Promise<string> | null = null;
function firstDoor(): Promise<string> {
  door ??= (async () => {
    for (const d of DOORS) {
      try { if ((await fetch(`${d}/tip`, { signal: AbortSignal.timeout(6000) })).ok) return d; } catch {}
    }
    door = null;
    throw new Error("No door answered just now. Try again in a minute.");
  })();
  return door;
}
const tipOf = async () => (await (await fetch(`${await firstDoor()}/tip`, { signal: AbortSignal.timeout(8000) })).json()).height as number;
async function keptYear(cid: string): Promise<number | null> {
  try {
    const k = await W.kept(await firstDoor());
    const u = k.until.get(cid);
    return u && u > k.tip ? heightToDate(u, k.tip).getFullYear() : null;
  } catch { return null; }
}

// ── the way in: a name typed into the door's light, and what's on the other side ──
const faceCache = new Map<string, Promise<{ title?: string; icon?: string }>>();
const faceOf = (cid: string) => { let f = faceCache.get(cid); if (!f) { f = siteFace(cid, DOORS).catch(() => ({})); faceCache.set(cid, f); } return f; };
async function peek(input: string) {
  const box = $("beyond");
  const name = input.trim().toLowerCase().replace(/\.csd$/, "");
  if (!name) return;
  box.innerHTML = `<p class="msg">Looking for ${esc(name)}…</p>`;
  try {
    const f = await lookup(name, { doors: DOORS, web: true });
    if (!f.owner) {
      const free = /^Nobody holds/.test(f.why ?? "");
      box.innerHTML = `<p class="msg">${free ? `Nothing is here yet. <b>${esc(name)}</b> is free: <a href="https://cairn-substrate.com" target="_blank" rel="noopener">make it yours</a>.` : esc(f.why ?? "Nothing is here.")}</p>`;
      return;
    }
    const cid = f.open?.startsWith("ipfs://") ? f.open.slice(7) : null;
    const [face, year] = cid ? await Promise.all([faceOf(cid), keptYear(cid)]) : [{} as { title?: string; icon?: string }, null];
    const title = face.title || `${name}.csd`;
    box.innerHTML = `
      <span class="face">${face.icon ? `<img alt="" src="${face.icon}">` : esc(name.slice(0, 1).toUpperCase())}</span>
      <b>${esc(title)}</b>
      <span class="where">${esc(name)}.csd</span>
      ${cid ? `<span class="life">${year ? `Here until ${year}` : "Here as long as its name points to it"}</span>` : ""}
      <span class="go">
        ${cid ? `<a class="in" href="${inDoorway(name)}">Step in</a>` : f.open && !f.page ? `<a class="in" href="${esc(f.open)}" target="_blank" rel="noopener">Go there</a>` : `<a class="in" href="https://commonplace.place/#/p/${esc(f.owner)}" target="_blank" rel="noopener">Its holder's page</a>`}
        ${cid ? `<a class="alt" href="#get">No Doorway yet?</a>` : ""}
      </span>`;
  } catch (e: any) { box.innerHTML = `<p class="msg">${esc(String(e?.message ?? e))}</p>`; }
}
$("doorForm").addEventListener("submit", e => { e.preventDefault(); peek(($("doorName") as HTMLInputElement).value); });
const tryName = (n: string) => { ($("doorName") as HTMLInputElement).value = n; peek(n); };
$("beyond").addEventListener("click", e => { const t = (e.target as HTMLElement).closest<HTMLElement>(".try"); if (t) tryName(t.dataset.name!); });
$("glimpse").addEventListener("click", e => { const t = (e.target as HTMLElement).closest<HTMLElement>("button[data-name]"); if (t) tryName(t.dataset.name!); });

// ── names ─────────────────────────────────────────────────────────────────────
type Found = Awaited<ReturnType<typeof lookup>>;
let shown: Found | null = null;

async function look(input: string) {
  const out = $("result");
  const name = input.trim().toLowerCase().replace(/\.csd$/, "");
  if (!name) { out.innerHTML = ""; return; }
  out.innerHTML = `<div class="card"><p class="said">Looking up ${esc(name)}.csd, and checking its records…</p></div>`;
  try {
    const f = await lookup(name, { doors: DOORS, web: true });
    shown = f;
    render(f, f.open?.startsWith("ipfs://") ? await keptYear(f.open.slice(7)) : null);
  } catch (e: any) {
    out.innerHTML = `<div class="card"><p class="said bad">${esc(String(e?.message ?? e))}</p></div>`;
  }
}

function render(f: Found, year: number | null) {
  const out = $("result");
  if (!f.owner) {
    const free = /^Nobody holds/.test(f.why ?? "");
    out.innerHTML = `<div class="card"><h3>${esc(f.name)}<span>.csd</span></h3><p class="said">${esc(f.why ?? "No one holds it.")}</p>${free ? `<div class="row"><a class="btn main" href="https://cairn-substrate.com" target="_blank" rel="noopener">Register it on Cairn</a></div>` : ""}</div>`;
    return;
  }
  const cid = f.open?.startsWith("ipfs://") ? f.open.slice(7) : null;
  const points = cid ? `a site, <code>ipfs://${esc(cid)}</code>` : f.open && !f.page ? `a link, <a href="${esc(f.open)}" target="_blank" rel="noopener">${esc(f.open)}</a>` : "its holder's page";
  out.innerHTML = `
    <div class="card">
      <h3>${esc(f.name)}<span>.csd</span></h3>
      <dl class="facts">
        <dt>Held by</dt><dd title="${esc(f.owner)}">${esc(friendlyName(f.owner))}</dd>
        <dt>Points to</dt><dd>${points}</dd>
        ${cid ? `<dt>Kept up</dt><dd>${year ? `until ${year}, whether or not a name still points to it` : "as long as a name points to it"}</dd>` : ""}
        <dt>Checked</dt><dd>every record of it, in this browser, against the network's proof-of-work</dd>
      </dl>
      <div class="row">
        ${cid ? `<a class="btn main" href="${inDoorway(f.name)}">Open in Doorway</a>` : f.open && !f.page ? `<a class="btn main" href="${esc(f.open)}" target="_blank" rel="noopener">Open</a>` : ""}
        <a class="btn" href="https://commonplace.place/#/p/${esc(f.owner)}" target="_blank" rel="noopener">Its holder's page</a>
      </div>
      <div class="act">
        <b>Point it at a site</b>
        <div class="row"><input id="pointCid" placeholder="ipfs://… the address Doorway gave you when you published" spellcheck="false" autocomplete="off"><button class="btn" id="pointBtn" type="button">Point it here</button></div>
        <p class="said" id="pointSaid">Signed in Cairn Wallet by the key that holds it, for 0.25 CSD. Its other profile fields stay as they are. A name Doorway's own key holds is pointed from Doorway, under Publish.</p>
      </div>
      ${cid ? `<div class="act">
        <b>Keep its site up</b>
        <div class="row"><button class="btn" id="keepBtn" type="button">Add a year (0.25 CSD)</button></div>
        <p class="said" id="keepSaid">Anyone can keep any site up, signed in Cairn Wallet. For many years at once, use Doorway's hourglass.</p>
      </div>` : ""}
    </div>`;
  $("pointBtn").onclick = () => point(f);
  if (cid) $("keepBtn").onclick = () => keep(cid);
}

async function point(f: Found) {
  const said = $("pointSaid"), btn = $("pointBtn") as HTMLButtonElement;
  const cid = ($("pointCid") as HTMLInputElement).value.trim().replace(/^ipfs:\/\//, "").replace(/\/+$/, "");
  if (!CID_RE.test(cid)) { said.className = "said bad"; said.textContent = "That isn't a site's address: it starts with ipfs://b…"; return; }
  btn.disabled = true; said.className = "said"; said.textContent = "Asking Cairn Wallet…";
  try {
    const s = await cairnSigner();
    if (s.address.toLowerCase() !== f.owner!.toLowerCase()) throw new Error(`Cairn Wallet's account (${friendlyName(s.address)}) doesn't hold ${f.name}.csd; ${friendlyName(f.owner!)} does.`);
    const ask = W.pointAsk(f.name, f.profile ?? {}, cid, await tipOf());
    await s.send(ask.app, ask.fee);
    said.className = "said ok"; said.textContent = `Sent. ${f.name}.csd points to it from the next block, in about two minutes, and the doors take the site once Doorway hands it to them.`;
  } catch (e: any) { said.className = "said bad"; said.textContent = String(e?.message ?? e); }
  btn.disabled = false;
}

async function keep(cid: string) {
  const said = $("keepSaid"), btn = $("keepBtn") as HTMLButtonElement;
  btn.disabled = true; said.className = "said"; said.textContent = "Asking Cairn Wallet…";
  try {
    const s = await cairnSigner();
    const ask = W.keepAsk(cid, 1, await tipOf());
    await s.send(ask.app, ask.fee);
    said.className = "said ok"; said.textContent = "Done. Another year counts from the next block, in about two minutes.";
  } catch (e: any) { said.className = "said bad"; said.textContent = String(e?.message ?? e); }
  btn.disabled = false;
}

$("lookForm").addEventListener("submit", e => { e.preventDefault(); look(($("lookName") as HTMLInputElement).value); });
const fromHash = () => { const n = decodeURIComponent(location.hash.slice(1)); if (n && !["names", "sites", "how", "get"].includes(n)) tryName(n); };
window.addEventListener("hashchange", fromHash);
fromHash();

// ── sites ─────────────────────────────────────────────────────────────────────
async function sites() {
  const box = $("siteList");
  try {
    const { tip, sites } = await listSites(await firstDoor());
    if (!sites.length) { box.innerHTML = `<p class="small">No sites yet.</p>`; return; }
    const ranked = sites.slice().sort((a, b) => b.recommenders.length - a.recommenders.length || b.since - a.since).slice(0, 60);
    box.innerHTML = ranked.map(s => {
      const until = s.keptUntil && s.keptUntil > tip ? heightToDate(s.keptUntil, tip).getFullYear() : null;
      const label = s.name || `${s.cid.slice(0, 10)}…`;
      return `<a class="site" href="${inDoorway(s.name || s.cid)}" data-cid="${esc(s.cid)}" title="Open in Doorway">
        <span class="ic">${esc(label.slice(0, 1).toUpperCase())}</span>
        <span class="tx"><b>${esc(s.name || "A site with no name")}</b><small>${s.name ? `${esc(s.name)}.csd` : "kept up by its address"}</small>${until ? `<span class="until">until ${until}</span>` : ""}</span>
      </a>`;
    }).join("");
    // a glimpse through the door: the top named sites
    const top = ranked.filter(s => s.name).slice(0, 6);
    $("glimpse").innerHTML = top.map(s => `<button type="button" data-name="${esc(s.name)}" data-cid="${esc(s.cid)}"><span>${esc(s.name.slice(0, 1).toUpperCase())}</span><em>${esc(s.name)}</em></button>`).join("");
    for (const el of [...$("glimpse").querySelectorAll<HTMLElement>("button")]) faceOf(el.dataset.cid!).then(f => {
      if (f.icon) el.querySelector("span")!.innerHTML = `<img alt="" src="${f.icon}">`;
      if (f.title) el.querySelector("em")!.textContent = f.title;
    });
    // titles and icons, from each site's own files (checked against its address)
    for (const el of [...box.querySelectorAll<HTMLElement>(".site")]) {
      faceOf(el.dataset.cid!).then(f => {
        if (f.title) { el.querySelector("b")!.textContent = f.title; if (!f.icon) el.querySelector(".ic")!.textContent = f.title.trim().slice(0, 1).toUpperCase(); }
        if (f.icon) el.querySelector(".ic")!.innerHTML = `<img alt="" src="${f.icon}">`;
      }).catch(() => {});
    }
  } catch (e: any) { box.innerHTML = `<p class="small">${esc(String(e?.message ?? e))}</p>`; }
}
sites();
