// A folder, packed into one site: the same .car and the same address (CID) that `npx ipfs-car pack
// <folder>` gives, so a site's address doesn't depend on which tool packed it. Hidden files (a name
// starting with ".") are left out, as ipfs-car does by default, and so is the folder's own name.
import { createDirectoryEncoderStream, CAREncoderStream } from "ipfs-car";

export type PackFile = { path: string; bytes: () => Promise<Uint8Array> };

export async function packFolder(files: PackFile[]): Promise<{ car: Uint8Array; cid: string; files: number; bytes: number }> {
  const parts = files.map(f => f.path.split("/").filter(Boolean));
  if (!parts.length) throw new Error("That folder is empty.");
  // the folder's own name, common to every path, isn't part of the site
  const common: string[] = [];
  for (let i = 0; parts.every(p => p.length > i + 1 && p[i] === parts[0][i]); i++) common.push(parts[0][i]);
  let items = files.map((f, i) => ({ name: parts[i].slice(common.length).join("/"), f }))
    .filter(x => !x.name.split("/").some(seg => seg.startsWith(".")))
    .sort((a, b) => (a.name === b.name ? 0 : a.name > b.name ? 1 : -1));
  // the site may sit one folder down (a zip unpacked into its own folder, say): then that folder is it
  if (!items.some(x => x.name === "index.html")) {
    const depth = (n: string) => n.split("/").length;
    const idx = items.filter(x => x.name.endsWith("/index.html")).sort((a, b) => depth(a.name) - depth(b.name));
    const top = idx.filter(x => depth(x.name) === depth(idx[0]?.name ?? ""));
    if (top.length !== 1) throw new Error("A site needs an index.html at the top of its folder.");
    const pre = top[0].name.slice(0, -"index.html".length);
    items = items.filter(x => x.name.startsWith(pre)).map(x => ({ ...x, name: x.name.slice(pre.length) }));
  }
  let total = 0;
  const like = await Promise.all(items.map(async x => {
    const b = await x.f.bytes();
    total += b.length;
    return { name: x.name, size: b.length, stream: () => new ReadableStream<Uint8Array>({ start(c) { c.enqueue(b); c.close(); } }) };
  }));
  if (total > 64 * 1024 * 1024) throw new Error("A site can be at most 64 MB.");
  // encode once to learn the root, then write the .car with that root in its header
  const blocks: any[] = [];
  await createDirectoryEncoderStream(like as any).pipeTo(new WritableStream({ write(b) { blocks.push(b); } }));
  const root = blocks[blocks.length - 1].cid;
  const chunks: Uint8Array[] = [];
  await new ReadableStream({ start(c) { for (const b of blocks) c.enqueue(b); c.close(); } })
    .pipeThrough(new CAREncoderStream([root])).pipeTo(new WritableStream({ write(c) { chunks.push(c); } }));
  const car = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let o = 0; for (const c of chunks) { car.set(c, o); o += c.length; }
  return { car, cid: root.toV1().toString(), files: like.length, bytes: total };
}
