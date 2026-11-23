// Builds doorway.place into out/: index.html, its icon and its script. A static site: upload out/
// to Cloudflare (or publish it with Doorway too).
import { build } from "../app/resolver/node_modules/esbuild/lib/main.js";
import { cpSync, mkdirSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
rmSync("out", { recursive: true, force: true });
mkdirSync("out");
await build({
  entryPoints: ["src/page.ts"], bundle: true, format: "esm", splitting: true, minify: true, target: "es2022",
  outdir: "out", entryNames: "page", chunkNames: "[name]-[hash]",
  nodePaths: ["../app/resolver/node_modules", "../kit/node_modules"],
  logLevel: "warning",
});
// the script by its contents' hash, so a browser never runs an older copy after an update
const v = createHash("sha256").update(readFileSync("out/page.js")).digest("hex").slice(0, 10);
writeFileSync("out/index.html", readFileSync("index.html", "utf8").replace('src="page.js"', `src="page.js?v=${v}"`));
cpSync("icon.svg", "out/icon.svg");
cpSync("hidden.txt", "out/hidden.txt");
cpSync("og.png", "out/og.png");
cpSync("_headers", "out/_headers");
console.log("built out/");
