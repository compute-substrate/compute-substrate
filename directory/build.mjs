// Builds the directory into out/: index.html and its script (the top-up, which carries an Ethereum
// library, in a chunk of its own that loads only when someone buys CSD)
import { build } from "../app/resolver/node_modules/esbuild/lib/main.js";
import { cpSync, mkdirSync, rmSync } from "node:fs";
rmSync("out", { recursive: true, force: true });
mkdirSync("out");
await build({
  entryPoints: ["src/page.ts"], bundle: true, format: "esm", splitting: true, minify: true, target: "es2022",
  outdir: "out", entryNames: "page", chunkNames: "[name]-[hash]",
  nodePaths: ["../app/resolver/node_modules", "../kit/node_modules"],
  logLevel: "warning",
});
cpSync("index.html", "out/index.html");
cpSync("doorway.json", "out/doorway.json"); // what it connects to besides the network (Doorway allows these)
cpSync("icon.svg", "out/icon.svg");
console.log("built out/");
