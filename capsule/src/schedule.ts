// When capsules open, and what belongs to which one: all from the clock and the blocks' times, so
// nobody has to run anything. A capsule opens every Sunday at OPEN_HOUR (UTC) for MINUTES minutes.
// Suggestions for a week's video count when they're in a block before it opens; what's said counts
// when it's in a block while it's open, or within GRACE after (a block takes a couple of minutes).

export const OPEN_HOUR = 19;          // 19:00 UTC: 20:00 in Oslo in winter, 21:00 in summer
export const MINUTES = 30;
export const GRACE = 8 * 60;          // seconds after closing that a line written while open may land
export const FIRST = "2026-11-29";    // the first capsule
export const SAID_MAX = 280;          // characters in a line said in a capsule

const DAY = 86_400;

// A capsule's id is its Sunday's date, "2026-11-29"
export const openAt = (id: string) => Date.parse(`${id}T${String(OPEN_HOUR).padStart(2, "0")}:00:00Z`) / 1000;
export const closeAt = (id: string) => openAt(id) + MINUTES * 60;
const idOf = (t: number) => new Date(t * 1000).toISOString().slice(0, 10);

// The capsule that's open now, or the next to open (from `now`, in seconds)
export function current(now: number): { id: string; open: boolean } {
  const d = new Date(now * 1000);
  const sunday = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - d.getUTCDay()) / 1000;
  let id = idOf(sunday);
  if (now >= closeAt(id)) id = idOf(sunday + 7 * DAY);
  if (id < FIRST) id = FIRST;
  return { id, open: now >= openAt(id) && now < closeAt(id) };
}

// Capsules that have closed, newest first
export function past(now: number, n = 52): string[] {
  const out: string[] = [];
  let id = current(now).id;
  for (let t = openAt(id) - 7 * DAY; out.length < n; t -= 7 * DAY) {
    id = idOf(t);
    if (id < FIRST) break;
    if (closeAt(id) <= now) out.push(id);
  }
  return out;
}

export const saidTopic = (id: string) => `capsule.${id}`;
export const picksTopic = (id: string) => `capsule.${id}.picks`;

// A suggestion: "yt:<video id> <title>"
const YT = /^[A-Za-z0-9_-]{11}$/;
export function videoId(link: string): string | null {
  const s = link.trim();
  if (YT.test(s)) return s;
  try {
    const u = new URL(s);
    const h = u.hostname.replace(/^(www|m|music)\./, "");
    if (h === "youtu.be") return YT.test(u.pathname.slice(1, 12)) && u.pathname.length === 12 ? u.pathname.slice(1) : null;
    if (h === "youtube.com" || h === "youtube-nocookie.com") {
      const v = u.searchParams.get("v") ?? /^\/(?:embed|shorts|live)\/([A-Za-z0-9_-]{11})/.exec(u.pathname)?.[1] ?? null;
      return v && YT.test(v) ? v : null;
    }
  } catch {}
  return null;
}
export const pickText = (video: string, title: string) => `yt:${video} ${title.replace(/\s+/g, " ").trim().slice(0, 120)}`.trim();
export function parsePick(text: string): { video: string; title: string } | null {
  const m = /^yt:([A-Za-z0-9_-]{11})(?: (.*))?$/.exec(text);
  return m ? { video: m[1], title: (m[2] ?? "").trim() } : null;
}

// The week's video is drawn when the capsule opens, so nobody knows it in advance: every video
// suggested in a block before opening is in the draw, with one chance for being suggested and one
// more for each backer. The draw uses the fingerprint (hash) of the network's first block at or
// after the opening time, which doesn't exist until then; everyone computes the same draw from the
// same block, and anyone can check it afterwards.
export type Candidate = { video: string; title: string; chances: number; first: { id: string; time: number; author?: string } };
export function candidates<T extends { text: string; time: number; id: string; author?: string }>(id: string, picks: T[], backing: Record<string, number>): Candidate[] {
  const by = new Map<string, Candidate>();
  for (const p of [...picks].sort((a, b) => a.time - b.time || a.id.localeCompare(b.id))) {
    const v = parsePick(p.text);
    if (!v || !(p.time < openAt(id))) continue;
    const c = by.get(v.video);
    const more = 1 + (backing[p.id.toLowerCase()] ?? 0);
    if (c) { c.chances += more; if (!c.title && v.title) c.title = v.title; }
    else by.set(v.video, { video: v.video, title: v.title, chances: more, first: { id: p.id, time: p.time, author: p.author } });
  }
  return [...by.values()].sort((a, b) => (a.video < b.video ? -1 : a.video > b.video ? 1 : 0));
}

// The draw: `roll` is a number from the opening block's fingerprint (see rollOf), the same for everyone
export function draw(cands: Candidate[], roll: bigint): Candidate | null {
  const total = cands.reduce((s, c) => s + c.chances, 0);
  if (!total) return null;
  let r = Number(roll % BigInt(total));
  for (const c of cands) { if (r < c.chances) return c; r -= c.chances; }
  return null;
}
// a number from the opening block's hash and the capsule's id: sha256 of both, its first 8 bytes
export async function rollOf(blockHash: string, id: string): Promise<bigint> {
  const data = new TextEncoder().encode(`capsule ${id} ${blockHash.toLowerCase().replace(/^0x/, "")}`);
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return d.slice(0, 8).reduce((n, b) => (n << 8n) | BigInt(b), 0n);
}

// The opening block: the lowest height whose time is at or after the opening, given a way to read
// a block's time and hash and the tip. Null until such a block exists.
export async function openingBlock(id: string, tip: number, block: (h: number) => Promise<{ time: number; hash: string }>): Promise<{ height: number; hash: string } | null> {
  const open = openAt(id);
  if ((await block(tip)).time < open) return null;
  let lo = 0, hi = tip;
  while (lo < hi) { const mid = Math.floor((lo + hi) / 2); if ((await block(mid)).time >= open) hi = mid; else lo = mid + 1; }
  // block times can step back a little: walk back to the first block of this run at or after it
  for (let i = 0; i < 30 && lo > 0 && (await block(lo - 1)).time >= open; i++) lo--;
  return { height: lo, hash: (await block(lo)).hash };
}

// What was said in a capsule: in a block while it was open, or just after
export const inWindow = (id: string, time: number) => time >= openAt(id) && time < closeAt(id) + GRACE;
