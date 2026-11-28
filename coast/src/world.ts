// The coast: one shore everyone fishes, made from a seed so it's never sent or stored anywhere.
// Every machine that knows the seed draws the same bays, reeds, rocks and islands.

export const W = 44, H = 26;
export const SEED = "the first coast";

export const LAND = 0, ROCK = 1, SAND = 2, SHALLOWS = 3, REEDS = 4, LEDGE = 5, OPEN = 6;
export type Tile = typeof LAND | typeof ROCK | typeof SAND | typeof SHALLOWS | typeof REEDS | typeof LEDGE | typeof OPEN;
export const isWater = (t: Tile) => t >= SHALLOWS;

// 32-bit hashing (FNV-1a, then a mix): the same numbers on every machine
export function hash32(...parts: (string | number)[]): number {
  let h = 0x811c9dc5;
  for (const ch of parts.join("|")) { h ^= ch.charCodeAt(0); h = Math.imul(h, 0x01000193) >>> 0; }
  h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b) >>> 0; h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35) >>> 0; h ^= h >>> 16;
  return h >>> 0;
}
const at = (seed: number, x: number, y: number) => hash32(seed, x, y) / 4294967296;
function smooth(seed: number, x: number, y: number, scale: number) {
  const fx = x / scale, fy = y / scale, x0 = Math.floor(fx), y0 = Math.floor(fy), tx = fx - x0, ty = fy - y0;
  const s = (t: number) => t * t * (3 - 2 * t);
  const a = at(seed, x0, y0), b = at(seed, x0 + 1, y0), c = at(seed, x0, y0 + 1), d = at(seed, x0 + 1, y0 + 1);
  return (a + (b - a) * s(tx)) * (1 - s(ty)) + (c + (d - c) * s(tx)) * s(ty);
}
const fbm = (seed: number, x: number, y: number) => 0.55 * smooth(seed, x, y, 9) + 0.3 * smooth(seed + 1, x, y, 4.5) + 0.15 * smooth(seed + 2, x, y, 2.2);

export type World = { tiles: Tile[]; fire: { x: number; y: number }; tile: (x: number, y: number) => Tile; dist: (x: number, y: number) => number };

export function build(seed = SEED): World {
  const s = hash32(seed);
  const tiles: Tile[] = [];
  // land to the left, sea to the right, a ragged shore between: bays, headlands, an island or two
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    // ragged shore (strong noise against a gentle slope), plus an island or two out at sea
    const h = (fbm(s, x, y) - 0.5) * 1.9 + (0.46 - x / W) * 1.15;
    const isle = smooth(s + 5, x, y, 3.2) - 0.83 - Math.max(0, 0.55 - x / W);
    tiles.push(h > 0 || isle > 0 ? (smooth(s + 7, x, y, 2.6) > 0.7 ? ROCK : LAND) : OPEN);
  }
  const tile = (x: number, y: number) => (x < 0 || y < 0 || x >= W || y >= H ? OPEN : tiles[y * W + x]);
  // how far each square of water is from land (in steps), for shallows and where you can cast
  const dist = new Array(W * H).fill(99);
  const q: number[] = [];
  for (let i = 0; i < W * H; i++) if (!isWater(tiles[i])) { dist[i] = 0; q.push(i); }
  for (let k = 0; k < q.length; k++) {
    const i = q[k], x = i % W, y = (i / W) | 0;
    for (const [dx, dy] of [[1, 0], [-1, 0], [0, 1], [0, -1]]) {
      const nx = x + dx, ny = y + dy, j = ny * W + nx;
      if (nx < 0 || ny < 0 || nx >= W || ny >= H || dist[j] <= dist[i] + 1) continue;
      dist[j] = dist[i] + 1; q.push(j);
    }
  }
  const near = (x: number, y: number, t: Tile) => [[1, 0], [-1, 0], [0, 1], [0, -1]].some(([dx, dy]) => tile(x + dx, y + dy) === t);
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const i = y * W + x;
    if (tiles[i] === LAND && [[1, 0], [-1, 0], [0, 1], [0, -1]].some(([dx, dy]) => isWater(tile(x + dx, y + dy))) && smooth(s + 9, x, y, 3) > 0.45) tiles[i] = SAND;
  }
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const i = y * W + x;
    if (!isWater(tiles[i])) continue;
    if (dist[i] <= 2 && near(x, y, ROCK)) tiles[i] = LEDGE;
    else if (dist[i] <= 1 && smooth(s + 11, x, y, 4) > 0.6) tiles[i] = REEDS;
    else if (dist[i] <= 2) tiles[i] = SHALLOWS;
  }
  // the fire: on open ground near the middle of the shore
  let fire = { x: 0, y: 0 }, best = -1;
  for (let y = 2; y < H - 2; y++) for (let x = 1; x < W - 1; x++) {
    if (tile(x, y) !== LAND && tile(x, y) !== SAND) continue;
    let shore = false;
    for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) if (isWater(tile(x + dx, y + dy))) shore = true;
    const beside = [[1, 0], [-1, 0], [0, 1], [0, -1]].some(([dx, dy]) => isWater(tile(x + dx, y + dy)));
    const score = (shore && !beside ? 10 : 0) - Math.abs(y - H / 2) * 0.5 - Math.abs(x - W * 0.42) * 0.25;
    if (score > best) { best = score; fire = { x, y }; }
  }
  return { tiles, fire, tile, dist: (x, y) => (x < 0 || y < 0 || x >= W || y >= H ? 99 : dist[y * W + x]) };
}

// Where a line can go: water no more than four squares from land
export const castable = (w: World, x: number, y: number) => isWater(w.tile(x, y)) && w.dist(x, y) <= 4;
export const WATER_NAME: Record<number, string> = { [SHALLOWS]: "the shallows", [REEDS]: "the reed bed", [LEDGE]: "the rock ledge", [OPEN]: "open water" };
export const waterOf = (w: World, x: number, y: number) => w.tile(x, y) === OPEN || w.dist(x, y) > 2 ? OPEN : w.tile(x, y);
