// dist/index.js for npm (its two dependencies stay external), and dist/compute-substrate.js: one
// file with everything in it, for a page that loads it straight from its own folder
import { build } from "esbuild";
await build({ entryPoints: ["src/index.ts"], outfile: "dist/index.js", bundle: true, format: "esm", platform: "neutral", target: "es2020", external: ["@noble/*"], logLevel: "warning" });
await build({ entryPoints: ["src/index.ts"], outfile: "dist/compute-substrate.js", bundle: true, format: "esm", platform: "browser", target: "es2020", minify: true, logLevel: "warning" });
// the USDC top-up, apart: it carries an Ethereum library, so a page loads it only when someone needs CSD
await build({ entryPoints: ["src/topup.ts"], outfile: "dist/topup.js", bundle: true, format: "esm", platform: "neutral", target: "es2020", external: ["@noble/*", "viem", "viem/*", "@intervalplace/aon-sdk"], logLevel: "warning" });
await build({ entryPoints: ["src/topup.ts"], outfile: "dist/compute-substrate-topup.js", bundle: true, format: "esm", platform: "browser", target: "es2020", minify: true, logLevel: "warning" });
console.log("built dist/index.js, dist/compute-substrate.js, dist/topup.js and dist/compute-substrate-topup.js");
