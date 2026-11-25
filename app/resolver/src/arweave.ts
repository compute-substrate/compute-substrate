// Files on Arweave, for Doorway: stored for good, paid once. Uploads go through Turbo (ArDrive's
// upload service) as data items signed with Doorway's key (an Ethereum-style key too); Turbo stores
// files up to 105 KiB free, so a letter costs only its record on the network. The same code as
// Commonplace's (src/ans104.ts and src/arweave.ts there, whose tests check every item against
// arbundles, the reference implementation).
//
//   u16 signature type (3: Ethereum) | 65-byte signature | 65-byte owner (uncompressed pubkey)
//   | 0 (no target) | 0 (no anchor) | u64 tag count | u64 tag bytes | tags (Avro) | data
// The signature is EIP-191 over deepHash(["dataitem", "1", "3", owner, target, anchor, tags, data]),
// and the item's id is base64url(sha256(signature)).
import { sha256, sha384 } from "@noble/hashes/sha2";
import { secp256k1 } from "@noble/curves/secp256k1";
import { privateKeyToAccount } from "viem/accounts";
import { bytesToHex, concat, hexToBytes, sha256d, utf8, type Hex } from "../../../kit/src/core";

export const FREE_BYTES = 105 * 1024;
const UPLOADER = "https://upload.ardrive.io";
// Turbo's own gateway serves a file at once; the others once it's bundled onto Arweave
const GATEWAYS = ["https://turbo-gateway.com", "https://arweave.net", "https://ardrive.net"];
const SIG_ETHEREUM = 3;

function u16(n: number) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; }
function u64(n: number) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; }
// Avro: a long is zigzag, then base-128 little-endian
function avroLong(n: number): Uint8Array {
  let z = BigInt(n) >= 0n ? BigInt(n) << 1n : (-BigInt(n) << 1n) - 1n;
  const out: number[] = [];
  do { let b = Number(z & 0x7fn); z >>= 7n; if (z) b |= 0x80; out.push(b); } while (z);
  return new Uint8Array(out);
}
const avroBytes = (b: Uint8Array) => concat(avroLong(b.length), b);
function encodeTags(tags: { name: string; value: string }[]): Uint8Array {
  if (!tags.length) return new Uint8Array(0);
  const parts: Uint8Array[] = [avroLong(tags.length)];
  for (const t of tags) parts.push(avroBytes(utf8(t.name)), avroBytes(utf8(t.value)));
  parts.push(avroLong(0));
  return concat(...parts);
}
type Chunk = Uint8Array | Chunk[];
function deepHash(c: Chunk): Uint8Array {
  if (Array.isArray(c)) {
    let acc = sha384(concat(utf8("list"), utf8(String(c.length))));
    for (const x of c) acc = sha384(concat(acc, deepHash(x)));
    return acc;
  }
  return sha384(concat(sha384(concat(utf8("blob"), utf8(String(c.length)))), sha384(c)));
}
const b64url = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export async function dataItem(priv: Uint8Array, data: Uint8Array, tags: { name: string; value: string }[]): Promise<{ bytes: Uint8Array; id: string }> {
  const owner = secp256k1.getPublicKey(priv, false);
  const rawTags = encodeTags(tags);
  const empty = new Uint8Array(0);
  const message = deepHash([utf8("dataitem"), utf8("1"), utf8(String(SIG_ETHEREUM)), owner, empty, empty, rawTags, data]);
  const sig = hexToBytes(await privateKeyToAccount(bytesToHex(priv)).signMessage({ message: { raw: message } }));
  if (sig.length !== 65) throw new Error("BAD_SIGNATURE");
  const bytes = concat(u16(SIG_ETHEREUM), sig, owner, new Uint8Array([0]), new Uint8Array([0]), u64(tags.length), u64(rawTags.length), rawTags, data);
  return { bytes, id: b64url(sha256(sig)) };
}

// Signs `data` as a data item with the key and hands it to Turbo: its Arweave id
export async function upload(key: Hex, data: Uint8Array, tags: { name: string; value: string }[]): Promise<string> {
  if (data.length > FREE_BYTES) throw new Error("That's too long to store for free (over 105 KB).");
  const item = await dataItem(hexToBytes(key), data, tags);
  const r = await fetch(`${UPLOADER}/v1/tx/ethereum`, { method: "POST", headers: { "content-type": "application/octet-stream" }, body: new Blob([item.bytes as BlobPart]), signal: AbortSignal.timeout(60_000) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`Storing it didn't work just now (${r.status}). Try again in a minute.`);
  if (j.id && j.id !== item.id) throw new Error("Storing it didn't work: the store answered with a different file.");
  return item.id;
}

// The file's bytes from the first gateway whose copy matches the fingerprint (`payloadHash`, a
// record's sha256d of the file). Throws when none has it.
export async function readAr(id: string, payloadHash?: string): Promise<Uint8Array> {
  const want = payloadHash?.toLowerCase().replace(/^0x/, "");
  for (const g of GATEWAYS) for (const path of [`raw/${id}`, id]) {
    try {
      const r = await fetch(`${g}/${path}`, { signal: AbortSignal.timeout(20_000) });
      if (!r.ok || (r.headers.get("content-type") ?? "").toLowerCase().startsWith("multipart/")) continue;
      const buf = new Uint8Array(await r.arrayBuffer());
      if (!want || bytesToHex(sha256d(buf)).toLowerCase().replace(/^0x/, "") === want) return buf;
      break;
    } catch {}
  }
  throw new Error("It couldn't be fetched just now.");
}
