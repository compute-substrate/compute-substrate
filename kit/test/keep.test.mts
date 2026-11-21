// Keeping a site: a record under csd.keep naming it, a year for the record and a year for every
// 0.25 CSD it burns; a site's time stacks, and restarts once it has run out
import { connect, keySigner, newKey, keptSites, keepCost, BURN, YEAR_BLOCKS, PER_YEAR, serializeTx, deserializeTx, bytesToHex, type Hex } from "../src/index";

let failures = 0;
const ok = (c: unknown, what: string) => { console.log(`${c ? "ok  " : "FAIL"} ${what}`); if (!c) failures++; };
const site = "bafybeih4sszbxx3lao542tqhzwa37uk2clof5vxddvtbpqqp5nyaidsh24";
let submitted: any[] = [];
const events: { height: number; tx_raw: string }[] = [];
let tip = 150_000;
const fakeFetch = (async (u: string, init?: any) => {
  const url = new URL(String(u));
  const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
  if (url.pathname === "/tip") return json({ height: tip });
  if (url.pathname.startsWith("/utxos/")) return json({ utxos: [{ txid: "0x" + "11".repeat(32), vout: 0, value: "1000000000" }] });
  if (url.pathname === "/tx/submit") { submitted.push(JSON.parse(init.body).tx); return json({ ok: true, txid: "0x" + "cc".repeat(32) }); }
  if (url.pathname.startsWith("/events/csd.keep/")) { const from = Number(url.pathname.split("/")[3]); return json({ ok: true, to: tip, tip_height: tip, events: events.filter(e => e.height >= from) }); }
  return json({ ok: false }, 404);
}) as unknown as typeof fetch;

const net = connect({ node: "http://stand-in", fetch: fakeFetch });
const me = keySigner(net, newKey());
await net.keep(me, site, 5);
const tx = submitted[0];
ok(tx.app.Propose.domain === "csd.keep" && tx.app.Propose.uri === `ipfs://${site}`, "a keep record names the site");
const burned = tx.outputs.filter((o: any) => o.script_pubkey.every((b: number) => b === 0)).reduce((s: number, o: any) => s + Number(o.value), 0);
ok(burned === 4 * Number(PER_YEAR), "five years: the record's fee, and four burned");
ok(keepCost(5) === 1.25, "five years cost 1.25 CSD");

// the records, as a node lists them
const rec = (years: number, height: number) => {
  const t = deserializeTx(serializeTx({ version: 1, inputs: [{ txid: ("0x" + "11".repeat(32)) as Hex, vout: 0, scriptSig: new Uint8Array() }],
    outputs: [{ value: BigInt(years - 1) * PER_YEAR, addr20: BURN }, { value: 1n, addr20: ("0x" + "22".repeat(20)) as Hex }], locktime: 0,
    app: { kind: "propose", domain: "csd.keep", payloadHash: new Uint8Array(32), uri: `ipfs://${site}`, expiresEpoch: 1n } }, false));
  events.push({ height, tx_raw: bytesToHex(serializeTx(t, false)) });
};
rec(1, 148_000); rec(3, 148_010);
const k = await keptSites(net.api as any);
ok(k.until.get(site) === 148_000 + 4 * YEAR_BLOCKS, "a site's years stack");
console.log(failures ? `\n${failures} failed` : "\nall passed"); process.exit(failures ? 1 : 0);
