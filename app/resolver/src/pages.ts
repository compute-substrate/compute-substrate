// Kept pages: a copy of a page from the ordinary web, kept as a site (and kept up with an hourglass
// record, csd.keep, like any site), plus one record under `csd.pages` saying which address it's a
// copy of. So anyone can find every kept copy of an address from the records alone, with nobody
// running an index.
//
// A record's text is "<cid> <address> <title>" (the title, then the address, cut to fit the 512 bytes
// a record holds; an address in its standard form has no spaces, so the title is all after it), and
// its payload hash is the hash of the address in a standard form, which is what a lookup matches.
// A record only says that its writer kept that copy, at that time: the copy is checked against its
// own address, so nobody can change it later, but whether it matches the page as it really was rests
// on whoever kept it. Several people keeping the same page, independently, is what settles that.
import { deserializeTx, signerOf, EPOCH_LEN, MIN_FEE_PROPOSE, sha256d, utf8, type AppPayload, type Hex } from "../../../kit/src/core";

export const PAGES = "csd.pages";
export const PAGES_FROM = 150_800;
const CID_RE = /^b[a-z2-7]{50,100}$/;
const TRACKING = /^(utm_[a-z]+|fbclid|gclid|dclid|msclkid|mc_cid|mc_eid|igshid|ref_src|_hsenc|_hsmi)$/i;

// An address in the form copies are matched by: http(s) only, lower-case host, no fragment, no
// tracking parameters, no default port, and no trailing slash except on the bare host
export function pageKey(input: string): string {
  let u: URL;
  try { u = new URL(input.trim()); } catch { throw new Error("That isn't a web address."); }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("Only web pages (http and https) can be kept.");
  u.hash = "";
  u.username = ""; u.password = "";
  for (const k of [...u.searchParams.keys()]) if (TRACKING.test(k)) u.searchParams.delete(k);
  u.searchParams.sort();
  const path = u.pathname.length > 1 ? u.pathname.replace(/\/+$/, "") : u.pathname;
  return `${u.protocol}//${u.host.toLowerCase()}${path}${u.search}`;
}

// Addresses on this computer or a home network aren't pages anyone else could check
export function isPrivate(input: string): boolean {
  let h: string;
  try { h = new URL(input).hostname.toLowerCase().replace(/^\[|\]$/g, ""); } catch { return true; }
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || !h.includes(".") && !h.includes(":")) return true;
  const v4 = h.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a, b] = [+v4[1], +v4[2]];
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  return h === "::1" || /^f[cd]/.test(h) || h.startsWith("fe80");
}

const keyHash = (url: string) => sha256d(utf8(`${PAGES} ${pageKey(url)}`));

// The record saying `cid` is a copy of `url`
export function pageAsk(cid: string, url: string, tip: number, title = ""): { app: AppPayload; fee: bigint; burn: bigint } {
  if (!CID_RE.test(cid)) throw new Error("That isn't a site's address.");
  const key = pageKey(url);
  let t = Array.from(title.replace(/\s+/g, " ").trim());
  const text = () => `${cid} ${key}${t.length ? " " + t.join("") : ""}`;
  while (t.length && utf8(text()).length > 512) t.pop();
  let uri = text();
  while (utf8(uri).length > 512) uri = uri.slice(0, -1);
  return { app: { kind: "propose", domain: PAGES, payloadHash: keyHash(url), uri, expiresEpoch: BigInt(Math.floor(tip / EPOCH_LEN)) + 10_000_000n }, fee: MIN_FEE_PROPOSE, burn: 0n };
}

export type Copy = { cid: string; url: string; title: string; by: Hex; height: number };

// Every kept page's record, read from `node` (and cached, extended as the network grows)
const caches = new Map<string, { next: number; all: (Copy & { hash: string })[] }>();
export async function allCopies(node: string): Promise<(Copy & { hash: string })[]> {
  let c = caches.get(node);
  if (!c) caches.set(node, c = { next: PAGES_FROM, all: [] });
  const tip = (await (await fetch(`${node}/tip`)).json()).height as number;
  while (c.next <= tip) {
    const r = await fetch(`${node}/events/${PAGES}/${c.next}/2000`);
    if (!r.ok) break;
    const j = await r.json();
    for (const e of j.events ?? []) {
      let tx; try { tx = deserializeTx(Uint8Array.from((String(e.tx_raw).replace(/^0x/, "").match(/../g) ?? []).map(h => parseInt(h, 16)))); } catch { continue; }
      if (tx.app.kind !== "propose" || tx.app.domain !== PAGES) continue;
      const sp = tx.app.uri.indexOf(" "), sp2 = tx.app.uri.indexOf(" ", sp + 1);
      const cid = tx.app.uri.slice(0, sp), url = sp2 < 0 ? tx.app.uri.slice(sp + 1) : tx.app.uri.slice(sp + 1, sp2), title = sp2 < 0 ? "" : tx.app.uri.slice(sp2 + 1);
      const by = signerOf(tx);
      if (sp < 0 || !CID_RE.test(cid) || !by) continue;
      const hash = Array.from(tx.app.payloadHash, b => b.toString(16).padStart(2, "0")).join("");
      c.all.push({ cid, url, title, by: by.toLowerCase() as Hex, height: e.height, hash });
    }
    if (typeof j.to !== "number" || j.to < c.next) break;
    c.next = j.to + 1;
  }
  return c.all;
}

// The kept copies of `url`, newest first
export async function copiesOf(node: string, url: string): Promise<Copy[]> {
  const want = Array.from(keyHash(url), b => b.toString(16).padStart(2, "0")).join("");
  return (await allCopies(node)).filter(x => x.hash === want).sort((a, b) => b.height - a.height).map(({ hash, ...x }) => x);
}

// Kept pages matching a search: words in the title or address, or a site ("nytimes.com"), newest
// copy of each address first, with how many copies it has
export async function search(node: string, words: string): Promise<(Copy & { copies: number })[]> {
  const terms = words.toLowerCase().split(/\s+/).filter(Boolean).map(w => w.replace(/^https?:\/\//, "").replace(/^www\./, ""));
  const byUrl = new Map<string, (Copy & { hash: string })[]>();
  for (const c of await allCopies(node)) byUrl.set(c.hash, [...(byUrl.get(c.hash) ?? []), c]);
  const out: (Copy & { copies: number })[] = [];
  for (const copies of byUrl.values()) {
    copies.sort((a, b) => b.height - a.height);
    const title = copies.find(c => c.title)?.title ?? "";
    const hay = `${copies.map(c => c.title).join(" ")} ${copies[0].url.replace(/^https?:\/\/(www\.)?/, "")}`.toLowerCase();
    if (!terms.every(t => hay.includes(t))) continue;
    const { hash, ...newest } = copies[0];
    out.push({ ...newest, title, copies: copies.length });
  }
  return out.sort((a, b) => b.height - a.height);
}

// What a kept page's own files say about it (kept.json, written beside index.html)
export type KeptNote = { url: string; title: string; at: string; by?: string };
