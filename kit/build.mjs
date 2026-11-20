// dist/index.js for npm (its two dependencies stay external), and dist/compute-substrate.js: one
// file with everything in it, for a page that loads it straight from its own folder
import { build } from "esbuild";
await build({ entryPoints: ["src/index.ts"], outfile: "dist/index.js", bundle: true, format: "esm", platform: "neutral", target: "es2020", external: ["@noble/*"], logLevel: "warning" });
await build({ entryPoints: ["src/index.ts"], outfile: "dist/compute-substrate.js", bundle: true, format: "esm", platform: "browser", target: "es2020", minify: true, logLevel: "warning" });
console.log("built dist/index.js and dist/compute-substrate.js");
