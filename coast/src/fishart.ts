// A little pixel picture of each fish, drawn from a few numbers: its colours and its shape. Bigger
// fish of a kind are drawn a little longer. Made once per kind and size, as an image.

type Shape = "round" | "long" | "flat" | "boot" | "wood";
const LOOK: Record<string, [string, string, Shape]> = {
  herring: ["#7fa6c0", "#e6eef1", "round"], mackerel: ["#2f7f86", "#dbe7e4", "round"], whiting: ["#b4ad9d", "#efe9dd", "round"],
  pollack: ["#857a4c", "#dcd6bb", "round"], cod: ["#957f52", "#ebe2c6", "round"], garfish: ["#3f8a74", "#dfeae2", "long"],
  tope: ["#717c86", "#d7dbde", "long"], halibut: ["#6a6556", "#ebe6d8", "flat"], "bluefin tuna": ["#284a7c", "#cdd6e1", "round"],
  flounder: ["#9c8460", "#f0e7d3", "flat"], "sand eel": ["#bfc3ae", "#f2f2e7", "long"], dab: ["#ad9068", "#f1e7d0", "flat"],
  bass: ["#87959e", "#e4e9eb", "round"], "red mullet": ["#d25a52", "#f3d8ca", "round"], turbot: ["#76664c", "#e7ddc5", "flat"],
  "sea trout": ["#a1a9ac", "#eff1f0", "round"], perch: ["#7c983a", "#eae2ae", "round"], roach: ["#a4b0b5", "#f2d6c4", "round"],
  eel: ["#585838", "#cbc9a9", "long"], tench: ["#5a6b2b", "#ccb965", "round"], pike: ["#5a773a", "#dad7a1", "long"],
  "golden char": ["#e3a234", "#f8e5a6", "round"], wrasse: ["#c6653a", "#f2caa0", "round"], rockling: ["#86664e", "#e1ceb9", "long"],
  coalfish: ["#3a454e", "#c8cdd1", "round"], "conger eel": ["#464b52", "#cacdd1", "long"], ling: ["#76694a", "#dad1b5", "long"],
  lumpsucker: ["#76884a", "#e9b14a", "round"], anglerfish: ["#66574a", "#cab9a1", "round"],
  "old boot": ["#5a4535", "#7a5f48", "boot"], driftwood: ["#8a7558", "#a99273", "wood"],
};
const dark = (h: string, k = 0.62) => { const n = parseInt(h.slice(1), 16); const c = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map(v => Math.round(v * k)); return `rgb(${c.join(",")})`; };
const cache = new Map<string, string>();

// `size` from 0 (smallest of its kind) to 1 (largest), more for a specimen
export function fishImage(name: string, size = 0.5): string {
  const key = `${name}|${Math.round(size * 4)}`;
  const had = cache.get(key); if (had) return had;
  const [body, belly, shape] = LOOK[name] ?? ["#8a9aa3", "#e6eaec", "round"];
  const W = 28, H = 14, cv = document.createElement("canvas");
  cv.width = W; cv.height = H;
  const g = cv.getContext("2d")!;
  const px = (x: number, y: number, c: string) => { g.fillStyle = c; g.fillRect(x, y, 1, 1); };
  const len = Math.round(shape === "long" ? 22 + size * 4 : 16 + size * 6), cy = H >> 1;
  const rx = len / 2, ry = shape === "long" ? 1.9 : shape === "flat" ? 4.6 : 3.4 + size * 0.6, cx = W - 3 - rx;
  if (shape === "boot") {
    for (let y = 2; y < 12; y++) for (let x = 8; x < 14; x++) px(x, y, y < 4 ? dark(body, 0.8) : body);
    for (let y = 9; y < 12; y++) for (let x = 14; x < 22; x++) px(x, y, body);
    for (let x = 8; x < 22; x++) px(x, 12, dark(body, 0.5));
    for (const y of [4, 6, 8]) { px(10, y, belly); px(12, y, belly); }
  } else if (shape === "wood") {
    for (let x = 3; x < 25; x++) for (let y = 5; y < 9; y++) px(x, y + (x > 14 ? 0 : 0), (x + y) % 5 === 0 ? dark(body) : y === 5 ? belly : body);
    px(9, 4, body); px(10, 3, body);
  } else {
    // the body: an oval, darker along the back, pale underneath, a darker edge
    for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
      const dx = (x + 0.5 - cx) / rx, dy = (y + 0.5 - cy) / ry, d = dx * dx + dy * dy;
      if (d > 1) continue;
      const edge = d > 0.72;
      px(x, y, edge ? dark(body, 0.55) : dy > 0.25 ? belly : dy < -0.45 ? dark(body, 0.85) : body);
    }
    // the tail
    const tx = Math.round(cx - rx);
    const spread = shape === "long" ? 2 : 4;
    for (let i = 0; i < 4; i++) for (let j = -Math.min(i + 1, spread); j <= Math.min(i + 1, spread); j++) px(tx - i, cy + j, i === 3 || Math.abs(j) === Math.min(i + 1, spread) ? dark(body, 0.55) : body);
    // a fin on the back, an eye, a mouth
    if (shape !== "long") for (let i = 0; i < 4; i++) px(Math.round(cx) - 2 + i, Math.round(cy - ry) - (i === 1 || i === 2 ? 1 : 0), dark(body, 0.7));
    const ex = Math.round(cx + rx * 0.62), ey = Math.round(cy - ry * 0.3);
    px(ex, ey, "#f6f1e6"); px(ex, ey, "#111"); px(ex - 1, ey, "#f6f1e6");
    px(Math.round(cx + rx) - 1, cy + 1, dark(body, 0.4));
    // stripes and spots, for the ones that have them
    if (name === "mackerel" || name === "perch") for (let x = Math.round(cx - rx * 0.5); x < cx + rx * 0.4; x += 3) for (let y = cy - 2; y < cy; y++) px(x, y, dark(body, 0.5));
    if (name === "golden char" || name === "sea trout" || name === "pike") for (let k = 0; k < 6; k++) px(Math.round(cx - rx * 0.6 + k * 2.3), cy - 1 + (k % 2), name === "golden char" ? "#fff2c4" : "#e9e4c8");
  }
  const url = cv.toDataURL();
  cache.set(key, url);
  return url;
}
