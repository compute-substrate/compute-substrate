// The deep as a small pixel scene: the floor you're on, what your lamp reaches, and what you've seen
// before by its light. Flat colours, low resolution, scaled up crisp. Drawn from the run alone.
import { FW, FH, FLOOR, tileAt, hash32 as hash, type Run } from "./dungeon";

export const T = 16, VW = 13, VH = 9; // the view: part of the floor, following you
type RGB = string;
const C = {
  void: "#0b0a0e", wall: "#3e3949", wallTop: "#575066", wallEdge: "#1b1921", floor: "#3a3541", floorLine: "#332f3a",
  rope: "#a7834f", light: "rgba(255,236,190,.10)", stairs: "#15131a", step: "#302c38",
  chest: "#8a5a32", chestDark: "#6a4224", band: "#e2b04a",
  draught: "#d0483a", glass: "#e9dccb", whet: "#8f8a92",
  hat: "#3b4a5c", skin: "#e9b58b", coat: "#d8483a", legs: "#3a3f4a", lamp: "#f3b45c",
};
// little sprites, a character per pixel
const SPRITES: Record<string, { map: string[]; pal: Record<string, RGB> }> = {
  you: { map: ["  hhhh  ", " hhhhhh ", "  ssss  ", "  ssss  ", " cccc ll", "ccccccll", " cccc   ", " cccc   ", "  g  g  ", "  g  g  "], pal: { h: C.hat, s: C.skin, c: C.coat, g: C.legs, l: C.lamp } },
  rat: { map: ["        ", "        ", "        ", "        ", "   rrr  ", "  rrrrre", "t rrrrrr", " tt r r "], pal: { r: "#8b7f74", e: "#1a1a1a", t: "#c9a5a0" } },
  bat: { map: ["        ", "w      w", "ww bb ww", "wwwbbwww", " w bb w ", "   ee   "], pal: { w: "#8c74b0", b: "#5e4a7c", e: "#ff6b6b" } },
  goblin: { map: ["   gg   ", "  gggg  ", " geggeg ", "  gggg  ", "  bbbb  ", " gbbbbg ", "  bbbb  ", "  g  g  "], pal: { g: "#6f9a3f", e: "#f1d24a", b: "#6a4a30" } },
  skeleton: { map: ["  bbbb  ", "  beeb  ", "  bbbb  ", "   bb   ", " bbbbbb ", " b bb b ", "   bb   ", "  b  b  ", "  b  b  "], pal: { b: "#e3dccb", e: "#1d1b22" } },
  spider: { map: ["        ", "l  bb  l", " l bb l ", "llbbbbll", " lbeebl ", "l bbbb l", " l    l "], pal: { b: "#4a3f55", e: "#ff5a5a", l: "#77698a" } },
  ogre: { map: ["  oooo  ", " oeoeoo ", " oooooo ", "oooooooo", "obbbbbbo", "obbbbbbo", " bbbbbb ", " oo  oo ", " oo  oo "], pal: { o: "#8f9a5a", e: "#2a2418", b: "#6b5038" } },
  wraith: { map: ["  wwww  ", " wwwwww ", " weewwe ", " wwwwww ", "wwwwwwww", "wwwwwwww", " wwwwww ", " w ww w ", "w  w  w "], pal: { w: "rgba(176,196,222,.75)", e: "#151520" } },
  warden: { map: ["  kkkk  ", " kkkkkk ", " kekkek ", " kkkkkk ", "aaaaaaaa", "aakkkkaa", " akkkka ", " kk  kk ", " kk  kk "], pal: { k: "#5b5f6b", e: "#f2a33a", a: "#8c919e" } },
  chest: { map: ["          ", " cccccccc ", "cddddddddc", "cbbbbbbbbc", "cccckkcccc", "cccccccccc", "cccccccccc"], pal: { c: C.chest, d: C.chestDark, b: C.band, k: C.band } },
  open: { map: [" dddddddd ", "dccccccccd", "d        d", "cddddddddc", "cccccccccc", "cccccccccc", "cccccccccc"], pal: { c: C.chest, d: C.chestDark } },
  eye: { map: ["  bbbbbb  ", " bbbbbbbb ", "cbbbbbbbbc", "cccckkcccc", "cccckkcccc", "cccccccccc", "cccccccccc"], pal: { c: "#3c3550", b: "#5a4f78", k: "#f6e7a8" } },
  grave: { map: ["  ssss  ", " ssssss ", " sssdss ", " ssddds ", " sssdss ", " ssssss ", "gggggggg"], pal: { s: "#9c97a3", d: "#6d6874", g: "#2a2730" } },
  draught: { map: ["  gg  ", "  gg  ", " rrrr ", "rrrrrr", "rrrrrr", " rrrr "], pal: { g: C.glass, r: C.draught } },
  whetstone: { map: ["        ", "  wwww  ", " wwwwww ", "wwwwwwww"], pal: { w: C.whet } },
};

export function visible(run: Run, radius = 5.5): Set<string> {
  const out = new Set<string>(), f = run.floor;
  for (let y = 0; y < FH; y++) for (let x = 0; x < FW; x++) {
    const dx = x - run.x, dy = y - run.y;
    if (dx * dx + dy * dy > radius * radius) continue;
    // a straight line from you to it, stopping at the first wall
    const n = Math.max(Math.abs(dx), Math.abs(dy)); let clear = true;
    for (let i = 1; i < n; i++) { const px = Math.round(run.x + dx * i / n), py = Math.round(run.y + dy * i / n); if (tileAt(f, px, py) !== FLOOR) { clear = false; break; } }
    if (clear) out.add(`${x},${y}`);
  }
  return out;
}

export function createScene(canvas: HTMLCanvasElement) {
  canvas.width = VW * T; canvas.height = VH * T;
  const ctx = canvas.getContext("2d")!;
  ctx.imageSmoothingEnabled = false;
  const rect = (x: number, y: number, w: number, h: number, c: string) => { ctx.fillStyle = c; ctx.fillRect(Math.round(x), Math.round(y), w, h); };
  const sprite = (name: string, tx: number, ty: number, dy = 0) => {
    const s = SPRITES[name]; if (!s) return;
    const w = s.map[0].length, h = s.map.length, ox = tx * T + ((T - w) >> 1), oy = ty * T + T - 2 - h + dy;
    rect(ox + 1, ty * T + T - 2, w - 2, 1, "rgba(0,0,0,.35)");
    s.map.forEach((row, y) => [...row].forEach((ch, x) => { if (ch !== " ") rect(ox + x, oy + y, 1, 1, s.pal[ch]); }));
  };
  let run: Run | null = null, seen = new Set<string>(), hurtAt = 0, raf = 0;
  let cam: { x: number; y: number } | null = null;
  const view = () => ({ x: Math.round(Math.max(0, Math.min(FW * T - VW * T, cam!.x - (VW * T) / 2 + T / 2))), y: Math.round(Math.max(0, Math.min(FH * T - VH * T, cam!.y - (VH * T) / 2 + T / 2))) });

  function draw(now: number) {
    rect(0, 0, canvas.width, canvas.height, C.void);
    if (!run) { raf = requestAnimationFrame(draw); return; }
    const f = run.floor, vis = visible(run);
    const want = { x: run.x * T, y: run.y * T };
    if (!cam || Math.abs(cam.x - want.x) + Math.abs(cam.y - want.y) > 8 * T) cam = { ...want };
    cam.x += (want.x - cam.x) * 0.2; cam.y += (want.y - cam.y) * 0.2;
    const o = view();
    ctx.save(); ctx.translate(-o.x, -o.y);
    // each square lit by the lamp by how far it is from you; what's out of reach only remembered, dim
    const lit = (x: number, y: number) => vis.has(`${x},${y}`) ? Math.max(0.42, 1 - Math.hypot(x - run!.x, y - run!.y) / 7) : 0.2;
    const shade = (c: number[], b: number) => `rgb(${Math.round(c[0] * b + 26 * b * b)},${Math.round(c[1] * b + 14 * b * b)},${Math.round(c[2] * b)})`;
    for (let y = 0; y < FH; y++) for (let x = 0; x < FW; x++) {
      if (!seen.has(`${x},${y}`)) continue;
      const px = x * T, py = y * T, b = lit(x, y);
      if (tileAt(f, x, y) === FLOOR) {
        const v = (hash(x, y) % 3) * 4;
        rect(px, py, T, T, shade([92 + v, 84 + v, 96 + v], b));
        rect(px, py + T - 1, T, 1, shade([74, 67, 80], b)); rect(px + T - 1, py, 1, T, shade([74, 67, 80], b));
      } else if (tileAt(f, x, y + 1) === FLOOR) {
        // a wall face, seen from the room: a lit top edge, courses of stone, a dark foot
        rect(px, py, T, T, shade([70, 63, 80], b)); rect(px, py, T, 3, shade([118, 108, 130], b));
        rect(px, py + 8, T, 1, shade([56, 50, 64], b)); rect(px + ((x & 1) ? 4 : 11), py + 3, 1, 5, shade([56, 50, 64], b)); rect(px + ((x & 1) ? 10 : 5), py + 9, 1, 5, shade([56, 50, 64], b));
        rect(px, py + T - 2, T, 2, shade([30, 27, 36], b));
      } else rect(px, py, T, T, shade([24, 22, 29], b));
    }
    // the rope down from daylight, and the stairs on
    const rp = f.rope, sp = f.stairs;
    if (seen.has(`${rp.x},${rp.y}`)) { rect(rp.x * T + 2, rp.y * T + 2, T - 4, T - 4, C.light); rect(rp.x * T + 7, rp.y * T - 6, 2, T + 2, C.rope); rect(rp.x * T + 6, rp.y * T + 9, 4, 2, C.rope); }
    if (seen.has(`${sp.x},${sp.y}`)) { const b = lit(sp.x, sp.y); rect(sp.x * T + 2, sp.y * T + 2, T - 4, T - 3, "#0c0b10"); for (let i = 0; i < 3; i++) { rect(sp.x * T + 2, sp.y * T + 3 + i * 4, T - 4 - i * 3, 3, shade([70, 63, 80], b * (1 - i * 0.25))); rect(sp.x * T + 2, sp.y * T + 3 + i * 4, T - 4 - i * 3, 1, shade([120, 110, 132], b * (1 - i * 0.25))); } }
    for (const t of f.things) {
      if (!seen.has(`${t.x},${t.y}`)) continue;
      // graves and opened chests stay where they are; other things only while they're there
      if (t.kind === "grave") sprite("grave", t.x, t.y);
      else if (t.kind === "chest") sprite(t.taken ? "open" : t.id?.endsWith(".eye") ? "eye" : "chest", t.x, t.y);
      else if (!t.taken && vis.has(`${t.x},${t.y}`)) sprite(t.kind, t.x, t.y);
      if (t.kind === "chest" && t.id?.endsWith(".eye") && !t.taken) { const g = ctx.createRadialGradient(t.x * T + 8, t.y * T + 9, 1, t.x * T + 8, t.y * T + 9, 14 + Math.sin(now / 400) * 2); g.addColorStop(0, "rgba(246,231,168,.35)"); g.addColorStop(1, "rgba(246,231,168,0)"); ctx.fillStyle = g; ctx.fillRect(t.x * T - 8, t.y * T - 8, 32, 32); }
    }
    for (const m of f.monsters) if (m.hp > 0 && vis.has(`${m.x},${m.y}`)) {
      sprite(m.kind, m.x, m.y, m.awake ? Math.round(Math.sin(now / 180 + m.id) * 0.6) : 0);
      if (!m.awake && m.guard) { const k = Math.floor(now / 600) % 3; ctx.fillStyle = "rgba(220,220,235,.8)"; ctx.font = "6px monospace"; ctx.fillText("z", m.x * T + 12 + k, m.y * T + 2 - k * 2); }
    }
    sprite("you", run.x, run.y);
    // the lamp's warm light, flickering a little
    const cx = run.x * T + 8, cy = run.y * T + 8, rad = 74 + Math.sin(now / 130) * 2 + Math.sin(now / 47) * 1.5;
    const g = ctx.createRadialGradient(cx, cy, 4, cx, cy, rad);
    g.addColorStop(0, "rgba(255,196,120,.12)"); g.addColorStop(1, "rgba(255,170,90,0)");
    ctx.fillStyle = g; ctx.fillRect(cx - rad, cy - rad, rad * 2, rad * 2);
    ctx.restore();
    if (now - hurtAt < 320) { ctx.fillStyle = `rgba(200,40,40,${0.28 * (1 - (now - hurtAt) / 320)})`; ctx.fillRect(0, 0, canvas.width, canvas.height); }
    raf = requestAnimationFrame(draw);
  }
  raf = requestAnimationFrame(draw);

  return {
    // show a run; `seen` is everything the lamp has reached on this floor
    show(r: Run | null, s: Set<string>) { run = r; seen = s; },
    hurt() { hurtAt = performance.now(); },
    // the square under a point on the canvas (in CSS pixels)
    at(clientX: number, clientY: number) {
      const b = canvas.getBoundingClientRect(), o = cam ? view() : { x: 0, y: 0 };
      return { x: Math.floor(((clientX - b.left) / b.width * VW * T + o.x) / T), y: Math.floor(((clientY - b.top) / b.height * VH * T + o.y) / T) };
    },
    stop() { cancelAnimationFrame(raf); },
  };
}
