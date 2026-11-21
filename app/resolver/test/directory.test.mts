// A site's title and icon, read one file at a time from a door and checked against its address.
import { packFolder } from "../src/pack";
import { fileFromCar } from "../src/site";
import { siteFace } from "../src/directory";

let failures = 0;
const ok = (c: unknown, what: string) => { console.log(`${c ? "ok  " : "FAIL"} ${what}`); if (!c) failures++; };
const enc = (s: string) => new TextEncoder().encode(s);
const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 4 4"><rect width="4" height="4" fill="#2e6b5a"/></svg>`;
const files = {
  "site/index.html": `<!doctype html><title>Tide &amp; Table</title><link rel="icon" href="/img/mark.svg" type="image/svg+xml"><p>hi`,
  "site/img/mark.svg": svg,
  "site/about.html": "<p>about",
};
const site = await packFolder(Object.entries(files).map(([path, t]) => ({ path, bytes: async () => enc(t) })));

ok(new TextDecoder().decode(await fileFromCar(site.car, site.cid, "img/mark.svg")) === svg, "a file is read from the site's .car by its path");
let why = "";
try { await fileFromCar(site.car, site.cid, "nope.html"); } catch (e: any) { why = e.message; }
ok(why === "no such file", "a file that isn't there is refused");
const bad = site.car.slice(); bad[bad.length - 3] ^= 1;
why = ""; try { await fileFromCar(bad, site.cid, "img/mark.svg"); } catch (e: any) { why = e.message; }
ok(/match its address/.test(why), "an altered block is refused");

// a door that answers every ?path= with the whole site (a real door sends just the file's blocks)
(globalThis as any).fetch = async (u: string) => String(u).includes(`/sites/${site.cid}.car?path=`) ? new Response(site.car) : new Response("", { status: 404 });
const face = await siteFace(site.cid, ["https://door.example"]);
ok(face.title === "Tide & Table", "the title comes from its index.html");
ok(face.icon === `data:image/svg+xml;base64,${btoa(svg)}`, "the icon is the one it names");
console.log(failures ? `\n${failures} failed` : "\nall passed"); process.exit(failures ? 1 : 0);
