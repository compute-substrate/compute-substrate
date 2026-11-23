// A site's title and icon, read one file at a time from a door and checked against its address.
import { packFolder } from "../src/pack";
import { fileFromCar } from "../src/site";
import { siteFace, hiddenList, listed } from "../src/directory";
import http from "node:http";

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
// the lists: sites a name points to, less the hide list (names or addresses, comments and blanks ignored)
{
  const srv = http.createServer((_q, r) => r.end("# comment\nbadsite.csd\nipfs://bafyoldversion  # an old one\n\n")).listen(0);
  await new Promise(r => srv.on("listening", r));
  const h = await hiddenList(`http://127.0.0.1:${(srv.address() as any).port}/hidden.txt`);
  srv.close();
  const sites: any[] = [{ name: "badsite", cid: "bafyA" }, { name: "good", cid: "bafyoldversion" }, { name: "fine", cid: "bafyC" }, { name: null, cid: "bafyD" }];
  ok(listed(h, sites.map(s => ({ ...s, recommenders: [], since: 0 }))).map(s => s.name).join() === "fine", "a hidden name, a hidden address and a site with no name are all left out");
  const same: any[] = [{ name: "home", cid: "bafyF", recommenders: [], since: 100 }, { name: "computesubstrate", cid: "bafyF", recommenders: [], since: 200 }, { name: "chess", cid: "bafyG", recommenders: [], since: 50 }];
  ok(listed(new Set(), same).map(s => s.name).join() === "computesubstrate,chess", "two names on one site: listed once, under the name pointed there last");
  same[0].recommenders = ["0xa"];
  ok(listed(new Set(), same).map(s => s.name).join() === "home,chess", "or under the one more people recommend");
}

(globalThis as any).fetch = async (u: string) => String(u).includes(`/sites/${site.cid}.car?path=`) ? new Response(site.car) : new Response("", { status: 404 });
const face = await siteFace(site.cid, ["https://door.example"]);
ok(face.title === "Tide & Table", "the title comes from its index.html");
ok(face.icon === `data:image/svg+xml;base64,${btoa(svg)}`, "the icon is the one it names");
console.log(failures ? `\n${failures} failed` : "\nall passed"); process.exit(failures ? 1 : 0);
