// Builds the coast into out/: index.html, its icon, its script and its doorway.json
import { build } from "../app/resolver/node_modules/esbuild/lib/main.js";
import { cpSync, mkdirSync, rmSync } from "node:fs";
rmSync("out", { recursive: true, force: true });
mkdirSync("out");
await build({
  entryPoints: ["src/page.ts"], bundle: true, format: "esm", minify: true, target: "es2022",
  outdir: "out", entryNames: "page",
  nodePaths: ["../app/resolver/node_modules", "../kit/node_modules"],
  logLevel: "warning",
});
cpSync("index.html", "out/index.html");
cpSync("doorway.json", "out/doorway.json"); // what it connects to besides the network (Doorway allows these)
cpSync("icon.svg", "out/icon.svg");
console.log("built out/");
