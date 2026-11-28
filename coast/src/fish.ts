// What bites: decided by a block nobody could know in advance. Every block after you sit down is a
// cast: the block's fingerprint, your sitting, the water you're over and the coast's hour and month
// decide whether anything bites, what it is and how big. Anyone can work it out again.
import { SHALLOWS, REEDS, LEDGE, OPEN } from "./world";

export type Hour = "dawn" | "day" | "dusk" | "night";
export type Species = { name: string; water: number[]; weight: number; hours?: Hour[]; months?: number[]; size: [number, number]; junk?: boolean };

// Common ones so something's always happening; rare ones so there's always something to say.
export const FISH: Species[] = [
  // open water
  { name: "herring", water: [OPEN], weight: 60, size: [18, 32] },
  { name: "mackerel", water: [OPEN], weight: 48, hours: ["dawn", "day"], size: [25, 45] },
  { name: "whiting", water: [OPEN], weight: 36, size: [20, 42] },
  { name: "pollack", water: [OPEN, LEDGE], weight: 28, size: [30, 75] },
  { name: "cod", water: [OPEN], weight: 20, months: [10, 11, 12, 1, 2, 3], size: [40, 110] },
  { name: "garfish", water: [OPEN], weight: 14, hours: ["day"], months: [5, 6, 7, 8], size: [45, 85] },
  { name: "tope", water: [OPEN], weight: 6, months: [6, 7, 8, 9], size: [90, 170] },
  { name: "halibut", water: [OPEN], weight: 3, hours: ["dusk", "night"], size: [70, 220] },
  { name: "bluefin tuna", water: [OPEN], weight: 1, months: [7, 8, 9], size: [120, 300] },
  // shallows
  { name: "flounder", water: [SHALLOWS], weight: 50, size: [20, 45] },
  { name: "sand eel", water: [SHALLOWS], weight: 44, size: [10, 22] },
  { name: "dab", water: [SHALLOWS], weight: 34, size: [15, 35] },
  { name: "bass", water: [SHALLOWS, LEDGE], weight: 16, hours: ["dawn", "dusk"], size: [35, 85] },
  { name: "red mullet", water: [SHALLOWS], weight: 10, months: [5, 6, 7, 8, 9], size: [20, 40] },
  { name: "turbot", water: [SHALLOWS, OPEN], weight: 4, size: [40, 100] },
  { name: "sea trout", water: [SHALLOWS, REEDS], weight: 4, hours: ["dusk", "night"], months: [3, 4, 5, 6, 7, 8, 9, 10], size: [35, 90] },
  // reeds
  { name: "perch", water: [REEDS], weight: 50, size: [15, 40] },
  { name: "roach", water: [REEDS], weight: 46, size: [12, 35] },
  { name: "eel", water: [REEDS], weight: 24, hours: ["dusk", "night"], size: [40, 120] },
  { name: "tench", water: [REEDS], weight: 14, months: [5, 6, 7, 8, 9], size: [25, 60] },
  { name: "pike", water: [REEDS], weight: 9, size: [45, 130] },
  { name: "golden char", water: [REEDS], weight: 1, hours: ["dawn"], months: [10, 11, 12, 1, 2], size: [30, 75] },
  // rock ledge
  { name: "wrasse", water: [LEDGE], weight: 48, size: [15, 40] },
  { name: "rockling", water: [LEDGE], weight: 34, hours: ["night", "dusk"], size: [15, 35] },
  { name: "coalfish", water: [LEDGE, OPEN], weight: 26, size: [25, 80] },
  { name: "conger eel", water: [LEDGE], weight: 8, hours: ["night"], size: [80, 230] },
  { name: "ling", water: [LEDGE], weight: 5, months: [11, 12, 1, 2, 3], size: [60, 160] },
  { name: "lumpsucker", water: [LEDGE], weight: 3, months: [2, 3, 4], size: [25, 55] },
  { name: "anglerfish", water: [LEDGE, OPEN], weight: 1, hours: ["night"], size: [50, 160] },
  // what you catch when you catch nothing
  { name: "old boot", water: [SHALLOWS, REEDS, LEDGE, OPEN], weight: 10, size: [24, 46], junk: true },
  { name: "driftwood", water: [SHALLOWS, REEDS, LEDGE, OPEN], weight: 14, size: [20, 120], junk: true },
];

export function rarity(s: Species): "junk" | "common" | "uncommon" | "scarce" | "rare" | "legendary" {
  if (s.junk) return "junk";
  return s.weight >= 34 ? "common" : s.weight >= 14 ? "uncommon" : s.weight >= 4 ? "scarce" : s.weight >= 2 ? "rare" : "legendary";
}

// The coast's clock is UTC: dawn 5–8, day 8–17, dusk 17–20, night otherwise
export function hourOf(t: number): Hour {
  const h = new Date(t * 1000).getUTCHours();
  return h >= 5 && h < 8 ? "dawn" : h < 17 && h >= 8 ? "day" : h >= 17 && h < 20 ? "dusk" : "night";
}
export const monthOf = (t: number) => new Date(t * 1000).getUTCMonth() + 1;

// About one block in three brings a bite
export const BITE = 0.36;

// A cast's outcome from 32 random bytes (the hash of the block, the sitting, and the spot)
export type Catch = { species: Species; cm: number; specimen: boolean };
export function roll(r: Uint8Array, water: number, t: number): Catch | null {
  const u = (i: number) => ((r[i] << 24) | (r[i + 1] << 16) | (r[i + 2] << 8) | r[i + 3]) >>> 0;
  const f = (i: number) => u(i) / 4294967296;
  if (f(0) >= BITE) return null;
  const hour = hourOf(t), month = monthOf(t);
  const pool = FISH.filter(s => s.water.includes(water) && (!s.hours || s.hours.includes(hour)) && (!s.months || s.months.includes(month)));
  const total = pool.reduce((a, s) => a + s.weight, 0);
  let pick = u(4) % total, species = pool[0];
  for (const s of pool) { if (pick < s.weight) { species = s; break; } pick -= s.weight; }
  // size: most near the small end, a long tail toward the big; one in 250 is a specimen, up to a
  // third again beyond the usual largest
  const [lo, hi] = species.size;
  const specimen = !species.junk && f(8) < 1 / 250;
  const g = Math.pow(f(12), 1.7);
  const cm = specimen ? hi + (hi * 0.34) * f(16) : lo + (hi - lo) * g;
  return { species, cm: Math.round(cm * 10) / 10, specimen };
}
