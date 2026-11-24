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

// The doors first (public nodes keeping the sites names point to, /sites/<cid>.car); IPFS gateways
// as a fallback, asked if no door has answered in a few seconds. Whatever answers, every block is
// checked here against the address the name points to.
const FALLBACK_AFTER = 6_000;

async function fromUrl(url: string, cid: string, signal: AbortSignal): Promise<{ files: Map<string, Uint8Array>; car: Uint8Array }> {
  const r = await fetch(url, { headers: { accept: "application/vnd.ipld.car" }, signal });
  if (!r.ok) throw new Error(`${new URL(url).host} answered ${r.status}`);
  const car = new Uint8Array(await r.arrayBuffer());
  return { files: await filesFromCar(car, cid), car };
}

// A site, from whichever source sends it intact first. Returns its files, checked, and the .car
// they came in, for this app to keep and give to doors that don't have it.
export async function fetchSite(cid: string, doors: string[] = []): Promise<{ files: Map<string, Uint8Array>; car: Uint8Array }> {
  const stop = new AbortController();
  const errors: string[] = [];
  const attempt = (url: string, delay: number) => new Promise<{ files: Map<string, Uint8Array>; car: Uint8Array }>((resolve, reject) => {
    const t = setTimeout(() => {
      const mine = new AbortController();
      const limit = setTimeout(() => mine.abort(), 120_000);
      stop.signal.addEventListener("abort", () => mine.abort());
      fromUrl(url, cid, mine.signal).finally(() => clearTimeout(limit))
        .then(resolve, e => { errors.push(String((e as Error)?.message ?? e)); reject(e); });
    }, delay);
    stop.signal.addEventListener("abort", () => { clearTimeout(t); reject(new Error("stopped")); });
  });
  try {
    return await Promise.any([
      ...doors.map((d, i) => attempt(`${d}/sites/${cid}.car`, i * 1_500)),
      ...GATEWAYS.map((g, i) => attempt(`${g}/ipfs/${cid}?format=car`, (doors.length ? FALLBACK_AFTER : 0) + i * 2_000)),
    ]);
  } catch {
    console.warn("site not fetched:", cid, errors);
    throw new Error(errors.length && errors.filter(e => !/stopped/i.test(e)).every(e => /answered 404/.test(e))
      ? "This site isn't on the doors yet. If it was just put up, it gets there within a few minutes, from the Doorway that put it up."
      : "No door sent this site just now.");
  } finally { stop.abort(); }
}

// A .car's root: the site's address, for a .car the person picked themselves
export async function carRoot(bytes: Uint8Array): Promise<string> {
  const roots = await (await CarReader.fromBytes(bytes)).getRoots();
  if (roots.length !== 1) throw new Error("That .car doesn't have exactly one root, so it isn't one site.");
  return roots[0].toV1().toString();
}

// One file of a site from a .car that holds only it and the folders on the way to it (a door's
// /sites/<cid>.car?path=…), checked the same way: every block against its address, and the path
// from the site's own root.
export async function fileFromCar(bytes: Uint8Array, root: string, path: string): Promise<Uint8Array> {
  const car = await CarReader.fromBytes(bytes);
  const blocks = new Map<string, Uint8Array>();
  const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
  for await (const b of car.blocks()) {
    if (b.cid.multihash.code !== sha256.code) throw new Error("a block uses a hash the app doesn't check");
    const d = await sha256.digest(b.bytes);
    if (!same(d.digest, b.cid.multihash.digest)) throw new Error("a block doesn't match its address");
    blocks.set(b.cid.toV1().toString(), b.bytes);
  }
  const block = (cid: any) => { const b = blocks.get(cid.toV1().toString()); if (!b) throw new Error("incomplete"); return b; };
  let cur: any = CID.parse(root);
  for (const seg of path.split("/").filter(Boolean)) {
    const node = dagPb.decode(block(cur)), fs = UnixFS.unmarshal(node.Data!);
    if (fs.type !== "directory") throw new Error("not a folder");
    const l = node.Links.find(x => x.Name === seg);
    if (!l) throw new Error("no such file");
    cur = l.Hash;
  }
  const fileBytes = (cid: any): Uint8Array => {
    const b = block(cid);
    if (cid.code === 0x55) return b;
    const node = dagPb.decode(b), fs = UnixFS.unmarshal(node.Data!);
    if (fs.type !== "file" && fs.type !== "raw") throw new Error("expected a file");
    const parts = [fs.data ?? new Uint8Array(), ...node.Links.map(l => fileBytes(l.Hash))];
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };
  return fileBytes(cur);
}
