import { build } from "../../app/resolver/node_modules/esbuild/lib/main.js";
import { execFileSync } from "node:child_process";
await build({ entryPoints: ["test/game.test.ts"], bundle: true, platform: "node", format: "esm", outfile: "test/.out.mjs", logLevel: "warning" });
execFileSync("node", ["test/.out.mjs"], { stdio: "inherit" });
