// Keeps the sites of the .csd names you list up over IPFS, from a door: a public node, which anyone
// can reach. Run it on a timer next to the node and Kubo:
//
//   node dist/keep-sites.mjs commonplace another-name
//
// For each name it reads where the name points, through this machine's own node, exactly as the
// Node app does (Cairn's resolver, every record read from the node). When that's a site
// (ipfs://<CID>), it keeps that CID pinned in Kubo, fetching it from IPFS or, failing that, as a
// checked .car from a gateway; it unpins the site the name pointed to before; and it announces the
// site's root, so anyone looking for it finds this machine at once.
//
// Settings, from the environment: CSD_NODE (the node's RPC, default http://127.0.0.1:8789),
// IPFS_BIN (default `ipfs`), and IPFS_PATH as Kubo reads it. What it kept is in
// ~/.csd-keep-sites.json.
import { execFile } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { lookup, useNode } from "./main";
import { filesFromCar } from "./site";

const IPFS = process.env.IPFS_BIN ?? "ipfs";
const STATE = join(homedir(), ".csd-keep-sites.json");
const GATEWAYS = ["https://trustless-gateway.link", "https://ipfs.io", "https://dweb.link"];

function ipfs(args: string[], timeoutMs = 15 * 60_000): Promise<string> {
  return new Promise((resolve, reject) => execFile(IPFS, args, { timeout: timeoutMs, maxBuffer: 64 << 20 }, (e, out, err) => e ? reject(new Error(String(err || e.message).trim())) : resolve(out)));
}
const pinned = async (cid: string) => (await ipfs(["pin", "ls", "--type=recursive", "--quiet"], 60_000)).split("\n").map(l => l.trim()).includes(cid);

// The site into Kubo: from IPFS if anyone reachable has it, else a .car from a gateway, checked
async function keep(cid: string): Promise<string> {
  if (await pinned(cid)) return "already kept";
  try { await ipfs(["pin", "add", "--progress=false", cid], 5 * 60_000); return "fetched over IPFS"; } catch {}
  for (const gw of GATEWAYS) {
    try {
      const r = await fetch(`${gw}/ipfs/${cid}?format=car`, { headers: { accept: "application/vnd.ipld.car" }, signal: AbortSignal.timeout(120_000) });
      if (!r.ok) continue;
      const car = new Uint8Array(await r.arrayBuffer());
      await filesFromCar(car, cid); // every block checked against the address, before Kubo gets it
      const dir = mkdtempSync(join(tmpdir(), "keep-"));
      try { writeFileSync(join(dir, "site.car"), car); await ipfs(["dag", "import", "--pin-roots=true", join(dir, "site.car")]); }
      finally { rmSync(dir, { recursive: true, force: true }); }
      return `fetched from ${new URL(gw).host}, checked`;
    } catch {}
  }
  throw new Error(`nobody has it right now. Import its .car by hand once (ipfs dag import --pin-roots=true <file>), and this keeps it from then on.`);
}

async function main() {
  const names = process.argv.slice(2).map(n => n.trim().toLowerCase().replace(/\.csd$/, "")).filter(Boolean);
  if (!names.length) { console.error("Name the .csd names to keep up: node dist/keep-sites.mjs commonplace …"); process.exit(2); }
  useNode(process.env.CSD_NODE ?? "http://127.0.0.1:8789");
  let state: Record<string, string> = {};
  try { state = JSON.parse(readFileSync(STATE, "utf8")); } catch {}
  let failed = 0;
  for (const name of names) {
    try {
      const node = process.env.CSD_NODE ?? "http://127.0.0.1:8789";
      const r = await lookup(name).catch(e => { throw new Error(`can't read names through the node at ${node} (${(e as Error).message}). Is it running, and is CSD_NODE its RPC address?`); });
      const cid = /^ipfs:\/\/(b[a-z2-7]{50,100})$/.exec(r.open ?? "")?.[1];
      if (!cid) { console.log(`${name}.csd: no site (${r.why ?? r.open ?? "nothing"})`); continue; }
      const how = await keep(cid);
      // announced now, not whenever Kubo's own round gets to it
      await ipfs(["routing", "provide", cid], 5 * 60_000).catch(e => console.log(`${name}.csd: announcing: ${e.message}`));
      const old = state[name];
      state[name] = cid;
      if (old && old !== cid && !Object.values(state).includes(old)) await ipfs(["pin", "rm", old], 60_000).catch(() => {});
      console.log(`${name}.csd: ${cid} (${how})${old && old !== cid ? `, replacing ${old}` : ""}`);
    } catch (e) { failed++; console.log(`${name}.csd: ${(e as Error).message}`); }
  }
  writeFileSync(STATE, JSON.stringify(state, null, 2) + "\n");
  process.exit(failed ? 1 : 0);
}
main();
