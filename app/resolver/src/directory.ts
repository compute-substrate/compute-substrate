// The directory: every site a .csd name points to, ranked by how many people recommend it.
//
// Nobody keeps the list. A site is in it because a name points to it (the name's profile's
// contenthash, ipfs://<CID>), read from the network's CairnX records and replayed through
// cairnx-core like any name. Recommending is a record of its own, under `csd.sites`: the first
// person to recommend a name writes a record whose text is the name, and everyone after attests to
// that record. Each costs its writer CSD (0.25 for the first, 0.05 after), so a ranking can't be
// bought for nothing; a key counts once per name.
//
// A site's title and icon come from the site itself: its index.html and the icon it names, fetched
// from a door one file at a time (/sites/<cid>.car?path=…) and checked against the site's address,
// so a door can't dress a site up as something else.
import { resolve } from "@inversealtruism/cairnx-core";
import { allEvents, getJson, hex, parseTx, signer } from "./main";
import { fileFromCar } from "./site";
import { connect } from "../../../kit/src/index";
import { keptSites } from "../../../kit/src/keep";

export const DIRECTORY = "csd.sites";
// no directory record is older than this block
const DIRECTORY_FROM = 146_000;
const NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;

export type Listed = {
  // what recommendations name: the .csd name, or for a site kept with no name, ipfs://<CID>
  key: string;
  // "" for a site kept with no name
  name: string;
  cid: string;
  owner: string;
  // the keys that recommend it, and the record to attest to (null: nobody has yet)
  recommenders: string[];
  listing: string | null;
  // the block its name started pointing here (newest first, for "New")
  since: number;
  // the block it's kept up until, when someone keeps it (kit/src/keep.ts)
  keptUntil: number | null;
};

// Every site a name points to, read through `node` (this computer's own node, or a door)
export async function listSites(node: string): Promise<{ tip: number; sites: Listed[] }> {
  const base = node.replace(/\/$/, "");
  const tip = Number((await getJson(`${base}/tip`))?.height);
  if (!Number.isSafeInteger(tip)) throw new Error("The node didn't say how far the network is.");
  const [names, recs, kept] = await Promise.all([allEvents(tip, base), recommendations(base, tip), keptSites(apiOf(base)).catch(() => ({ tip, until: new Map<string, number>() }))]);
  const until = (cid: string) => { const u = kept.until.get(cid); return u && u > tip ? u : null; };
  const state = resolve(names, tip).names as Record<string, any>;
  // when each name last set its profile's site, for "New"
  const setAt = new Map<string, number>();
  for (const e of names) {
    if (e.kind !== "propose" || !e.uri.includes('"nprofile"')) continue;
    try { const r = JSON.parse(e.uri); if (r?.t === "nprofile" && typeof r.name === "string" && r.p?.contenthash) setAt.set(r.name, e.height); } catch {}
  }
  const sites: Listed[] = [];
  for (const [name, st] of Object.entries(state)) {
    if (!st || st.expired || st.pending) continue;
    const cid = /^ipfs:\/\/(b[a-z2-7]{50,100})$/.exec(st.profile?.["contenthash"] ?? "")?.[1];
    if (!cid) continue;
    const r = recs.get(name);
    sites.push({ key: name, name, cid, owner: String(st.owner ?? ""), recommenders: r ? [...r.who] : [], listing: r?.listing ?? null, since: setAt.get(name) ?? Number(st.height ?? 0), keptUntil: until(cid) });
  }
  // sites someone keeps up that no name points to (any more): listed by their address
  const named = new Set(sites.map(x => x.cid));
  for (const [cid, u] of kept.until) {
    if (named.has(cid) || u <= tip) continue;
    const key = `ipfs://${cid}`, r = recs.get(key);
    sites.push({ key, name: "", cid, owner: "", recommenders: r ? [...r.who] : [], listing: r?.listing ?? null, since: 0, keptUntil: u });
  }
  sites.sort((a, b) => b.recommenders.length - a.recommenders.length || b.since - a.since || (a.name < b.name ? -1 : 1));
  return { tip, sites };
}

const apis = new Map<string, any>();
const apiOf = (base: string) => { let a = apis.get(base); if (!a) apis.set(base, a = connect({ node: base }).api); return a; };

// name -> who recommends it, and its first listing record
const recCache = new Map<string, { to: number; byId: Map<string, string>; recs: Map<string, { listing: string; who: Set<string> }> }>();
async function recommendations(base: string, tip: number) {
  let c = recCache.get(base);
  if (!c) recCache.set(base, c = { to: DIRECTORY_FROM - 1, byId: new Map(), recs: new Map() });
  for (let from = c.to + 1; from <= tip; from += 2000) {
    const j = await getJson(`${base}/events/${encodeURIComponent(DIRECTORY)}/${from}/2000`);
    if (!j?.ok) break; // an older node: no recommendations, the list still shows
    for (const e of j.events) {
      let tx; try { tx = parseTx(hex(e.tx_raw)); } catch { continue; }
      const who = signer(tx);
      if (!who) continue;
      const id = String(e.txid).toLowerCase();
      if (tx.app.kind === "propose") {
        // a .csd name, or a site's own address (for a site with no name)
        const name = String(tx.app.uri).trim().toLowerCase().replace(/\.csd$/, "");
        if (!NAME_RE.test(name) && !/^ipfs:\/\/b[a-z2-7]{50,100}$/.test(name)) continue;
        c.byId.set(id, name);
        const r = c.recs.get(name) ?? { listing: id, who: new Set<string>() };
        r.who.add(who.toLowerCase());
        c.recs.set(name, r);
      } else if (tx.app.kind === "attest" && tx.app.score > 0) {
        const name = c.byId.get(String(tx.app.proposalId).toLowerCase());
        if (name) c.recs.get(name)?.who.add(who.toLowerCase());
      }
    }
    c.to = Math.min(tip, from + 1999);
  }
  return c.recs;
}

// ── what a site calls itself ────────────────────────────────────────────────
export type Face = { title?: string; icon?: string };

async function fileFrom(doors: string[], cid: string, path: string): Promise<Uint8Array | null> {
  for (const d of doors) {
    try {
      // a door from before single files sends the whole site: a large one takes longer than 10 seconds
      const r = await fetch(`${d}/sites/${cid}.car?path=${encodeURIComponent(path)}`, { signal: AbortSignal.timeout(30_000) });
      if (!r.ok) continue;
      return await fileFromCar(new Uint8Array(await r.arrayBuffer()), cid, path);
    } catch { /* the next door */ }
  }
  return null;
}

const decode = (t: string) => t.replace(/&amp;/g, "&").replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").trim();
const MIME: Record<string, string> = { png: "image/png", svg: "image/svg+xml", ico: "image/x-icon", jpg: "image/jpeg", jpeg: "image/jpeg", webp: "image/webp", gif: "image/gif" };

// A site's <title> and icon (as a data: URL), checked; remembered, since a site never changes
export async function siteFace(cid: string, doors: string[]): Promise<Face> {
  const key = `csd.face.${cid}`;
  try { const k = localStorage.getItem(key); if (k) return JSON.parse(k); } catch {}
  const html = await fileFrom(doors, cid, "index.html");
  if (!html) return {};
  const text = new TextDecoder().decode(html.slice(0, 200_000));
  const title = decode(/<title[^>]*>([^<]{1,120})<\/title>/i.exec(text)?.[1] ?? "") || undefined;
  // apple-touch-icon first (large and square), then the icons it names, then the usual places
  const hrefs: string[] = [];
  for (const m of text.matchAll(/<link\b[^>]*>/gi)) {
    const tag = m[0];
    const rel = /rel=["']?([^"'>]+)/i.exec(tag)?.[1].toLowerCase() ?? "";
    const href = /href=["']?([^"'\s>]+)/i.exec(tag)?.[1];
    if (!href || !/(^|\s)(icon|apple-touch-icon|shortcut icon)(\s|$)/.test(rel)) continue;
    if (rel.includes("apple-touch-icon")) hrefs.unshift(href); else hrefs.push(href);
  }
  hrefs.push("apple-touch-icon.png", "icon.png", "favicon.png", "icon.svg", "favicon.svg", "favicon.ico");
  let icon: string | undefined;
  for (const h of [...new Set(hrefs)]) {
    const path = h.split(/[?#]/)[0].replace(/^\.?\//, "");
    const ext = path.split(".").pop()?.toLowerCase() ?? "";
    if (!path || path.includes("..") || /^[a-z]+:/i.test(path) || !MIME[ext]) continue;
    const b = await fileFrom(doors, cid, path);
    if (!b || !b.length || b.length > 300_000) continue;
    let s = ""; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
    icon = `data:${MIME[ext]};base64,${btoa(s)}`;
    break;
  }
  const face = { title, icon };
  // kept for good once it has its icon (a site never changes); without one it may only be that
  // no door answered in time, so it's asked again on the next visit
  if (icon) try { localStorage.setItem(key, JSON.stringify(face)); } catch {}
  return face;
}
