// A .csd name's site (its profile's contenthash, ipfs://<CIDv1>): downloaded from any IPFS gateway
// as a CAR file and checked here before the app keeps it. Every block must hash to its own address,
// and the files must hang off exactly the address the name points to. A gateway can refuse to
// answer; it can't change a byte. (The same check Commonplace uses for its own releases.)
import { CarReader } from "@ipld/car";
import * as dagPb from "@ipld/dag-pb";
import { UnixFS } from "ipfs-unixfs";
import { sha256 } from "multiformats/hashes/sha2";
import { CID } from "multiformats/cid";

const GATEWAYS = ["https://trustless-gateway.link", "https://ipfs.io", "https://dweb.link"];
const MAX_BYTES = 64 * 1024 * 1024, MAX_FILES = 5000;

export async function filesFromCar(bytes: Uint8Array, root: string): Promise<Map<string, Uint8Array>> {
  const car = await CarReader.fromBytes(bytes);
  const want = CID.parse(root).toV1().toString();
  const blocks = new Map<string, Uint8Array>();
  const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
  for await (const b of car.blocks()) {
    if (b.cid.multihash.code !== sha256.code) throw new Error("a block uses a hash the app doesn't check");
    const d = await sha256.digest(b.bytes);
    if (!same(d.digest, b.cid.multihash.digest)) throw new Error("a block doesn't match its address");
    blocks.set(b.cid.toV1().toString(), b.bytes);
  }
  const files = new Map<string, Uint8Array>();
  let total = 0;
  const block = (cid: any) => { const b = blocks.get(cid.toV1().toString()); if (!b) throw new Error("the site is incomplete"); return b; };
  const fileBytes = (cid: any): Uint8Array => {
    const b = block(cid);
    if (cid.code === 0x55) return b; // a raw leaf
    const node = dagPb.decode(b), fs = UnixFS.unmarshal(node.Data!);
    if (fs.type !== "file" && fs.type !== "raw") throw new Error("expected a file");
    const parts = [fs.data ?? new Uint8Array(), ...node.Links.map(l => fileBytes(l.Hash))];
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };
  const walk = (cid: any, path: string) => {
    const node = dagPb.decode(block(cid)), fs = UnixFS.unmarshal(node.Data!);
    if (fs.type !== "directory") throw new Error(`unsupported folder (${fs.type})`);
    for (const l of node.Links) {
      const name = l.Name ?? "";
      if (!name || name.includes("/") || name.includes("\\") || name === "." || name === "..") throw new Error("a bad file name");
      const p = path ? `${path}/${name}` : name;
      const child = l.Hash.code === 0x55 ? null : UnixFS.unmarshal(dagPb.decode(block(l.Hash)).Data!);
      if (child?.type === "directory") walk(l.Hash, p);
      else {
        const bytes = fileBytes(l.Hash);
        total += bytes.length;
        if (total > MAX_BYTES || files.size >= MAX_FILES) throw new Error("the site is larger than the app keeps (64 MB)");
        files.set(p, bytes);
      }
    }
  };
  const roots = (await car.getRoots()).map(r => r.toV1().toString());
  if (!roots.includes(want)) throw new Error("the gateway sent a different site");
  walk(CID.parse(want), "");
  if (!files.has("index.html")) throw new Error("the site has no index.html");
  return files;
}

// This app's own IPFS (Kubo, when sharing is on) asks the IPFS network directly, other Node apps
// included; the public gateways are a fallback, tried if it hasn't answered in a few seconds.
const OWN = "http://127.0.0.1:8091";
const FALLBACK_AFTER = 8_000;

async function fromGateway(gw: string, cid: string, signal: AbortSignal): Promise<{ files: Map<string, Uint8Array>; car: Uint8Array }> {
  const r = await fetch(`${gw}/ipfs/${cid}?format=car`, { headers: { accept: "application/vnd.ipld.car" }, signal });
  if (!r.ok) throw new Error(`${new URL(gw).host} answered ${r.status}`);
  const car = new Uint8Array(await r.arrayBuffer());
  return { files: await filesFromCar(car, cid), car };
}

// A site, from whichever source sends it intact first. Returns its files, checked, and the .car
// they came in, for this app to share on.
export async function fetchSite(cid: string): Promise<{ files: Map<string, Uint8Array>; car: Uint8Array }> {
  const stop = new AbortController();
  const errors: string[] = [];
  const attempt = (gw: string, delay: number) => new Promise<{ files: Map<string, Uint8Array>; car: Uint8Array }>((resolve, reject) => {
    const t = setTimeout(() => {
      const mine = new AbortController();
      const limit = setTimeout(() => mine.abort(), 120_000);
      stop.signal.addEventListener("abort", () => mine.abort());
      fromGateway(gw, cid, mine.signal).finally(() => clearTimeout(limit))
        .then(resolve, e => { errors.push(String((e as Error)?.message ?? e)); reject(e); });
    }, delay);
    stop.signal.addEventListener("abort", () => { clearTimeout(t); reject(new Error("stopped")); });
  });
  try {
    const got = await Promise.any([attempt(OWN, 0), ...GATEWAYS.map((g, i) => attempt(g, FALLBACK_AFTER + i * 2_000))]);
    return got;
  } catch {
    throw new Error(`Nobody sent this site intact (${errors.filter(e => !/stopped|fetch/i.test(e))[0] ?? "no answer"}). Whoever runs it needs to keep it pinned, or have the Node app open.`);
  } finally { stop.abort(); }
}
