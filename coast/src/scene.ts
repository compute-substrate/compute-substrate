// The coast as a small pixel scene: the shore around a spot, painted once from the world, with the
// moving parts drawn over it each frame (water glinting, foam on the shore, the fire, people fishing,
// the float bobbing, and dipping when something bites). Low resolution, scaled up crisp.
import { W, H, hash32, isWater, LAND, ROCK, SAND, SHALLOWS, REEDS, LEDGE, OPEN, type World } from "./world";

export const T = 16, VW = 22, VH = 13;
type RGB = [number, number, number];
const hex = (h: string): RGB => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
const P = {
  deep: hex("#1c3a52"), mid: hex("#23506a"), shallower: hex("#4b97a6"),
  foam: hex("#dcefe8"), glint: hex("#a9dbe2"),
  sand: hex("#d9c38c"), sandDark: hex("#c3a873"), wet: hex("#b39a6a"),
  grass: hex("#6d9a4c"), grassDark: hex("#5b8640"), grassLight: hex("#88b25f"),
  rock: hex("#8d877d"), rockDark: hex("#6b675f"), rockLight: hex("#aaa499"),
  reed: hex("#3e6b45"), reedTip: hex("#b0904f"),
  log: hex("#5b3e2b"), flame1: hex("#f8d35e"), flame2: hex("#f08436"), flame3: hex("#c2461f"),
  skin: hex("#e9b58b"), hat: hex("#3b4a5c"), legs: hex("#3a3f4a"), rod: hex("#6b4a30"), line: hex("#ece6d9"),
  floatR: hex("#d8483a"), floatW: hex("#f3efe6"),
};

export type Person = { spot: { x: number; y: number }; self: boolean; color: RGB };
export const tintRGB = (s: string): RGB => { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) >>> 0; const hue = h % 360; return hsl(hue, 0.5, 0.55); };
function hsl(h: number, s: number, l: number): RGB {
  const k = (n: number) => (n + h / 30) % 12, a = s * Math.min(l, 1 - l);
  const f = (n: number) => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
  return [Math.round(f(0) * 255), Math.round(f(8) * 255), Math.round(f(4) * 255)];
}

// where someone fishing a spot sits: the nearest dry square to it
export function standFor(w: World, spot: { x: number; y: number }) {
  let best = { x: spot.x, y: spot.y }, bd = 1e9;
  for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) {
    const x = spot.x + dx, y = spot.y + dy;
    if (x < 0 || y < 0 || x >= W || y >= H || isWater(w.tile(x, y))) continue;
    const d = dx * dx + dy * dy;
    if (d < bd) { bd = d; best = { x, y }; }
  }
  return best;
}

export function createScene(canvas: HTMLCanvasElement, w: World) {
  // the whole coast painted once, a pixel at a time
  const big = new ImageData(W * T, H * T);
  const put = (img: ImageData, x: number, y: number, c: RGB) => { if (x < 0 || y < 0 || x >= img.width || y >= img.height) return; const i = (y * img.width + x) * 4; img.data[i] = c[0]; img.data[i + 1] = c[1]; img.data[i + 2] = c[2]; img.data[i + 3] = 255; };
  const r = (x: number, y: number, k = 0) => hash32(x, y, k) / 4294967296;
  // the shape of the shore at pixel level: how much land there is around each point (blended
  // between squares, with a little noise), so shores are rounded and depths shade into each other
  const landAt = (tx: number, ty: number) => (tx < 0 || ty < 0 || tx >= W || ty >= H ? 0 : isWater(w.tile(tx, ty)) ? 0 : 1);
  const sandAt = (tx: number, ty: number) => (w.tile(Math.max(0, Math.min(W - 1, tx)), Math.max(0, Math.min(H - 1, ty))) === SAND ? 1 : 0);
  const distAt = (tx: number, ty: number) => Math.min(8, w.dist(Math.max(0, Math.min(W - 1, tx)), Math.max(0, Math.min(H - 1, ty))));
  const blend = (f: (x: number, y: number) => number, fx: number, fy: number) => {
    const x0 = Math.floor(fx), y0 = Math.floor(fy), u = fx - x0, v = fy - y0;
    const sm = (t: number) => t * t * (3 - 2 * t);
    const a = f(x0, y0), b = f(x0 + 1, y0), c = f(x0, y0 + 1), d = f(x0 + 1, y0 + 1);
    return (a + (b - a) * sm(u)) * (1 - sm(v)) + (c + (d - c) * sm(u)) * sm(v);
  };
  // flat colours, few of them: the shape of the shore does the work, not texture
  for (let py = 0; py < H * T; py++) for (let px = 0; px < W * T; px++) {
    const fx = px / T - 0.5, fy = py / T - 0.5;
    const lnd = blend(landAt, fx, fy) + (r(px >> 2, py >> 2, 5) - 0.5) * 0.1;
    let c: RGB;
    if (lnd > 0.5) {
      const sandy = blend(sandAt, fx, fy) + (r(px >> 2, py >> 2, 6) - 0.5) * 0.2;
      c = lnd < 0.55 ? P.wet : sandy > 0.5 ? P.sand : P.grass;
    } else {
      // water in three bands, with a fine checkered edge where two bands meet
      const d = blend(distAt, fx, fy), edge = (px + py) & 1 ? 0.12 : -0.12;
      c = d + edge < 1.5 ? P.shallower : d + edge < 3.2 ? P.mid : P.deep;
      if (lnd > 0.46) c = P.foam;
    }
    put(big, px, py, c);
  }
  for (let ty = 0; ty < H; ty++) for (let tx = 0; tx < W; tx++) {
    const t = w.tile(tx, ty);
    // now and then a tuft of grass
    if (t === LAND && r(tx, ty, 10) < 0.35) {
      const gx = tx * T + 3 + ((r(tx, ty, 11) * 10) | 0), gy = ty * T + 4 + ((r(tx, ty, 12) * 9) | 0);
      put(big, gx, gy, P.grassDark); put(big, gx + 1, gy - 1, P.grassDark); put(big, gx + 2, gy, P.grassDark);
    }
    // rocky ground: one boulder, sometimes two, lit from the top left
    if (t === ROCK) for (let k = 0; k < 2; k++) {
      if (k && r(tx, ty, 80) < 0.6) continue;
      const cx = tx * T + 4 + r(tx, ty, 81 + k) * 8, cy = ty * T + 5 + r(tx, ty, 83 + k) * 7, rx = 3 + r(tx, ty, 85 + k) * 3, ry = rx * 0.8;
      for (let y = Math.floor(cy - ry - 1); y <= cy + ry + 1; y++) for (let x = Math.floor(cx - rx - 1); x <= cx + rx + 1; x++) {
        const dx = (x - cx) / rx, dy = (y - cy) / ry;
        if (dx * dx + dy * dy > 1) continue;
        put(big, x, y, dx + dy < -0.6 ? P.rockLight : dx + dy > 0.6 ? P.rockDark : P.rock);
      }
    }
    // reeds: a few stems with brown tips
    if (t === REEDS) for (let k = 0; k < 4; k++) {
      const sx = tx * T + 2 + ((r(tx, ty, 30 + k) * 12) | 0), h = 5 + ((r(tx, ty, 40 + k) * 4) | 0), base = ty * T + 13 - ((r(tx, ty, 50 + k) * 4) | 0);
      for (let i = 0; i < h; i++) put(big, sx, base - i, i >= h - 2 ? P.reedTip : P.reed);
    }
    // the ledge: a dark rock just under the surface
    if (t === LEDGE && r(tx, ty, 60) < 0.5) { const lx = tx * T + 4 + ((r(tx, ty, 61) * 7) | 0), ly = ty * T + 5 + ((r(tx, ty, 62) * 6) | 0); for (let i = 0; i < 4; i++) for (let j = 0; j < 2; j++) put(big, lx + i, ly + j, P.mid); }
  }
  const base = document.createElement("canvas");
  base.width = big.width; base.height = big.height;
  base.getContext("2d")!.putImageData(big, 0, 0);

  canvas.width = VW * T; canvas.height = VH * T;
  const ctx = canvas.getContext("2d")!;
  ctx.imageSmoothingEnabled = false;
  const px = (x: number, y: number, c: RGB, a = 1) => { ctx.fillStyle = `rgba(${c[0]},${c[1]},${c[2]},${a})`; ctx.fillRect(Math.round(x), Math.round(y), 1, 1); };
  const rect = (x: number, y: number, ww: number, hh: number, c: RGB) => { ctx.fillStyle = `rgb(${c[0]},${c[1]},${c[2]})`; ctx.fillRect(Math.round(x), Math.round(y), ww, hh); };

  let cam = { x: w.fire.x * T, y: w.fire.y * T }, target = { ...cam };
  let people: Person[] = [], picked: { x: number; y: number } | null = null;
  let biteAt = 0, frame = 0;

  // a person sitting on the shore, facing the water, rod out over it
  function person(p: Person, now: number) {
    const s = standFor(w, p.spot), left = p.spot.x < s.x;
    const bx = s.x * T + 5, by = s.y * T + 4;
    const f = (x: number) => left ? bx + 6 - x : bx + x;
    // hat, head, body (in their colour), legs out in front
    for (let x = 1; x < 5; x++) px(f(x), by, P.hat);
    for (let x = 0; x < 6; x++) px(f(x), by + 1, P.hat);
    for (let x = 1; x < 5; x++) for (let y = 2; y < 4; y++) px(f(x), by + y, P.skin);
    for (let x = 1; x < 5; x++) for (let y = 4; y < 8; y++) px(f(x), by + y, p.color);
    for (let x = 1; x < 7; x++) px(f(x), by + 8, P.legs);
    // the rod, up and out over the water
    const hand = { x: f(5), y: by + 5 }, tip = { x: f(11), y: by - 3 };
    for (let i = 0; i <= 6; i++) px(hand.x + (tip.x - hand.x) * i / 6, hand.y + (tip.y - hand.y) * i / 6, P.rod);
    // the float on the spot, bobbing; dipping and splashing when something bites
    const bite = p.self && now - biteAt < 1800;
    const fx = p.spot.x * T + 8, fy = p.spot.y * T + 8 + (bite ? (Math.sin(now / 60) > 0 ? 2 : 0) : Math.round(Math.sin(now / 500 + p.spot.x)));
    // the line, sagging a little
    for (let i = 0; i <= 24; i++) { const t = i / 24; px(tip.x + (fx - tip.x) * t, tip.y + (fy - 2 - tip.y) * t + Math.sin(t * Math.PI) * 4, P.line, 0.75); }
    rect(fx, fy - 2, 2, 1, P.floatW); rect(fx, fy - 1, 2, 2, P.floatR);
    if (bite) { const k = ((now - biteAt) / 1800) * 8 + 2; for (let a = 0; a < 16; a++) px(fx + 1 + Math.cos(a / 16 * 6.283) * k, fy + Math.sin(a / 16 * 6.283) * k * 0.5, P.foam, 1 - (now - biteAt) / 1800); }
  }

  function fire(now: number) {
    const x = w.fire.x * T + 4, y = w.fire.y * T + 7;
    rect(x, y + 6, 8, 2, P.log); rect(x + 1, y + 5, 6, 1, P.log);
    const fl = (k: number) => hash32(Math.floor(now / 140), k) / 4294967296;
    for (let i = 0; i < 6; i++) {
      const hh = 2 + ((fl(i) * 5) | 0);
      for (let j = 0; j < hh; j++) px(x + 1 + i, y + 5 - j, j > hh - 2 ? P.flame1 : j > 1 ? P.flame2 : P.flame3);
    }
    // a warm glow
    const g = ctx.createRadialGradient(x + 4, y + 3, 1, x + 4, y + 3, 24);
    g.addColorStop(0, "rgba(255,190,90,.28)"); g.addColorStop(1, "rgba(255,170,80,0)");
    ctx.fillStyle = g; ctx.fillRect(x - 24, y - 24, 56, 56);
  }

  function draw(now: number) {
    cam.x += (target.x - cam.x) * 0.12; cam.y += (target.y - cam.y) * 0.12;
    const ox = Math.round(Math.max(0, Math.min(W * T - VW * T, cam.x - (VW * T) / 2 + T / 2)));
    const oy = Math.round(Math.max(0, Math.min(H * T - VH * T, cam.y - (VH * T) / 2 + T / 2)));
    ctx.drawImage(base, ox, oy, VW * T, VH * T, 0, 0, VW * T, VH * T);
    ctx.save(); ctx.translate(-ox, -oy);
    const t0x = Math.floor(ox / T), t0y = Math.floor(oy / T);
    for (let ty = t0y; ty <= t0y + VH; ty++) for (let tx = t0x; tx <= t0x + VW; tx++) {
      const t = w.tile(tx, ty);
      if (!isWater(t)) continue;
      // now and then a glint drifting on the water
      const ph = hash32(tx, ty, 1) / 4294967296;
      if (ph > 0.3) continue;
      const life = (now / 3200 + ph * 3) % 1;
      if (life > 0.3) continue;
      const gx = tx * T + (hash32(tx, ty, 5) % 11) + Math.floor(life * 6), gy = ty * T + (hash32(tx, ty, 9) % 14);
      px(gx, gy, P.glint, 0.8 - life * 2); px(gx + 1, gy, P.glint, 0.8 - life * 2); px(gx + 2, gy, P.glint, 0.5 - life * 1.5);
    }
    fire(now);
    for (const p of people) if (!p.self) person(p, now);
    for (const p of people) if (p.self) person(p, now);
    if (picked && !people.some(p => p.self)) {
      const blink = Math.floor(now / 500) % 2;
      ctx.strokeStyle = `rgba(255,255,255,${blink ? 0.9 : 0.5})`; ctx.lineWidth = 1;
      ctx.strokeRect(picked.x * T + 0.5, picked.y * T + 0.5, T - 1, T - 1);
    }
    ctx.restore();
    frame++;
  }
  let raf = 0;
  const loop = (now: number) => { draw(now); raf = requestAnimationFrame(loop); };
  raf = requestAnimationFrame(loop);

  return {
    // looking at a spot: the view leans out over the water, so you see what you're fishing
    focus(x: number, y: number) {
      const st = standFor(w, { x, y });
      target = { x: (x + (x - st.x) * 2.5) * T, y: (y + (y - st.y) * 2.5) * T };
    },
    setPeople(p: Person[]) { people = p; },
    pick(p: { x: number; y: number } | null) { picked = p; },
    bite() { biteAt = performance.now(); },
    // the square under a point on the canvas (in CSS pixels)
    at(clientX: number, clientY: number) {
      const b = canvas.getBoundingClientRect();
      const ox = Math.round(Math.max(0, Math.min(W * T - VW * T, cam.x - (VW * T) / 2 + T / 2)));
      const oy = Math.round(Math.max(0, Math.min(H * T - VH * T, cam.y - (VH * T) / 2 + T / 2)));
      return { x: Math.floor(((clientX - b.left) / b.width * VW * T + ox) / T), y: Math.floor(((clientY - b.top) / b.height * VH * T + oy) / T) };
    },
    stop() { cancelAnimationFrame(raf); },
  };
}

// the whole coast, small: for choosing where to go
export function drawMap(canvas: HTMLCanvasElement, w: World, people: Person[], picked: { x: number; y: number } | null) {
  const S = 6;
  canvas.width = W * S; canvas.height = H * S;
  const c = canvas.getContext("2d")!;
  const col: Record<number, string> = { [LAND]: "#6d9a4c", [ROCK]: "#8d877d", [SAND]: "#d9c38c", [SHALLOWS]: "#4b97a6", [REEDS]: "#4f8a6c", [LEDGE]: "#337a90", [OPEN]: "#23506a" };
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) { const t = w.tile(x, y); c.fillStyle = t === OPEN && w.dist(x, y) > 5 ? "#1c3a52" : col[t]; c.fillRect(x * S, y * S, S, S); }
  c.fillStyle = "#f08436"; c.beginPath(); c.arc(w.fire.x * S + 3, w.fire.y * S + 3, 3, 0, 7); c.fill();
  for (const p of people) { c.fillStyle = p.self ? "#d8483a" : `rgb(${p.color.join(",")})`; c.beginPath(); c.arc(p.spot.x * S + 3, p.spot.y * S + 3, p.self ? 3.5 : 2.6, 0, 7); c.fill(); c.strokeStyle = "#fff"; c.lineWidth = 1; c.stroke(); }
  if (picked) { c.strokeStyle = "#fff"; c.lineWidth = 1.5; c.strokeRect(picked.x * S - 1, picked.y * S - 1, S + 2, S + 2); }
}
