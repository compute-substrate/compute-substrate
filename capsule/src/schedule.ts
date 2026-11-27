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

// The week's video: the most backed suggestion in a block before opening (the earliest, on a tie)
export function chosen<T extends { text: string; time: number; id: string }>(id: string, picks: T[], backing: Record<string, number>): (T & { video: string; title: string; backers: number }) | null {
  let best: (T & { video: string; title: string; backers: number }) | null = null;
  for (const p of picks) {
    const v = parsePick(p.text);
    if (!v || !(p.time < openAt(id))) continue;
    const b = backing[p.id.toLowerCase()] ?? 0;
    if (!best || b > best.backers || (b === best.backers && p.time < best.time)) best = { ...p, ...v, backers: b };
  }
  return best;
}

// What was said in a capsule: in a block while it was open, or just after
export const inWindow = (id: string, time: number) => time >= openAt(id) && time < closeAt(id) + GRACE;
