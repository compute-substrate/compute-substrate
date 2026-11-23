// Builds doorway.place into out/: index.html, its icon and its script. A static site: upload out/
// to Cloudflare (or publish it with Doorway too).
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
cpSync("icon.svg", "out/icon.svg");
cpSync("hidden.txt", "out/hidden.txt");
cpSync("_headers", "out/_headers");
console.log("built out/");
