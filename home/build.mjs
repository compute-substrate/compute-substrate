// Builds the front page into out/: index.html, its icon and its script
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
console.log("built out/");
