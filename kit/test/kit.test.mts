// The kit's own layer, against a stand-in node: writing builds a correctly signed transaction from
// the key's coins, reading lists newest first, and records that don't prove are left out.
import { connect, keySigner, newKey, signerOf, deserializeTx, hexToBytes, txid, MIN_FEE_PROPOSE, type Hex } from "../src/index";

let failures = 0;
const ok = (c: unknown, what: string) => { console.log(`${c ? "ok  " : "FAIL"} ${what}`); if (!c) failures++; };

let submitted: any = null, landed = false;
const key = newKey();
const fakeFetch = (async (u: string, init?: any) => {
  const url = new URL(String(u));
  const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
  if (url.pathname === "/tip") return json({ height: 145000 });
  if (url.pathname.startsWith("/utxos/")) return json({ utxos: [{ txid: "0x" + "11".repeat(32), vout: 0, value: "100000000" }] });
  if (url.pathname.startsWith("/proposals/")) return json({ proposals: [
    { proposal_id: "0x" + "aa".repeat(32), height: 10, time: 1, domain: "guestbook.example", payload_hash: "0x00", uri: "older" },
    { proposal_id: "0x" + "bb".repeat(32), height: 20, time: 2, domain: "guestbook.example", payload_hash: "0x00", uri: "newer" },
    ...(landed ? [{ proposal_id: "0x" + "cc".repeat(32), height: 30, time: 3, domain: "guestbook.example", payload_hash: "0x00", uri: "hello" }] : []) ] });
  if (url.pathname === "/tx/submit") { submitted = JSON.parse(init.body).tx; return json({ ok: true, txid: "0x" + "cc".repeat(32) }); }
  return json({ ok: false }, 404);
}) as unknown as typeof fetch;

const net = connect({ node: "http://stand-in", fetch: fakeFetch });
const unchecked = await net.read("guestbook.example", { check: false });
ok(unchecked.length === 2 && unchecked[0].text === "newer", "reads a topic, newest first");
const checked = await net.read("guestbook.example");
ok(checked.length === 0, "records the node can't prove are left out of a checked read");
const me = keySigner(net, key);
ok(/^0x[0-9a-f]{40}$/.test(me.address), "a key signer has an address");
ok((await net.balance(me.address)) === 1, "reads a balance in whole CSD");
const id = await net.write(me, "guestbook.example", "hello");
ok(id === "0x" + "cc".repeat(32), "write returns the node's txid");
ok(submitted?.app?.Propose?.domain === "guestbook.example" && submitted.app.Propose.uri === "hello", "the transaction carries the record");
const fee = submitted && BigInt(submitted.outputs.reduce((s: number, o: any) => s - Number(o.value), 100000000));
ok(fee === MIN_FEE_PROPOSE, "it pays the network's fee for a proposal, and the rest comes back as change");
// what was just written shows at once, as on its way, until it's in a block
const after = await net.read("guestbook.example", { check: false });
ok(after[0].text === "hello" && after[0].pending && after[0].id === id && after.length === 3, "a record just written is read first, as pending");
landed = true;
const later = await net.read("guestbook.example", { check: false });
ok(later.filter(e => e.id === id).length === 1 && !later.find(e => e.id === id)!.pending, "once it's in a block it's read once, from the block");
let threw = false;
try { await net.write(me, "guestbook.example", "x".repeat(600)); } catch { threw = true; }
ok(threw, "text over 512 bytes is refused before anything is sent");
console.log(failures ? `\n${failures} failed` : "\nall passed"); process.exit(failures ? 1 : 0);
