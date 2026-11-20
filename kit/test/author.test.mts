// A record's author is the owner of the coin it spends, not whoever signed the copy a node served:
// signatures aren't part of the txid, so a node could re-sign someone's record with its own key.
import { lightClient } from "../src/light";
import { buildAppTx, signTx, serializeTx, keyFromPrivate, hexToBytes, bytesToHex, signerOf, txid, type Hex, type Tx } from "../src/core";

let failures = 0;
const ok = (c: unknown, what: string) => { console.log(`${c ? "ok  " : "FAIL"} ${what}`); if (!c) failures++; };

const alice = keyFromPrivate(new Uint8Array(32).fill(1)), mallory = keyFromPrivate(new Uint8Array(32).fill(2));
// the coin Alice spends: an output of an earlier transaction, paying her
const funding: Tx = { version: 1, inputs: [{ txid: ("0x" + "22".repeat(32)) as Hex, vout: 0, scriptSig: new Uint8Array() }], outputs: [{ value: 0n, addr20: mallory.addr20 }, { value: 100_000_000n, addr20: alice.addr20 }], locktime: 0, app: { kind: "none" } };
const fundingId = txid(funding);
const record = buildAppTx([{ txid: fundingId, vout: 1, value: 100_000_000n }], alice, { kind: "propose", domain: "t", payloadHash: new Uint8Array(32), uri: "hello", expiresEpoch: 1n }, 25_000_000n);
const forged = signTx(record, mallory); // the same record, re-signed by Mallory
ok(txid(forged) === txid(record), "a re-signed copy has the same txid");
ok(signerOf(forged) === mallory.addr20, "and its signature checks, for Mallory");

const serve = (spent: Tx) => (async (u: string) => {
  const p = new URL(String(u)).pathname;
  if (p === `/proof/tx/${fundingId.replace(/^0x/, "")}`) return new Response(JSON.stringify({ ok: true, tx_raw: bytesToHex(serializeTx(spent, false)).replace(/^0x/, "") }));
  return new Response("{}", { status: 404 });
}) as unknown as typeof fetch;

ok(await lightClient("http://n", { fetch: serve(funding) }).authorOf(forged) === alice.addr20, "the author is Alice, the owner of the coin it spends");
// a node that also swaps the spent transaction is caught: it no longer hashes to the txid the input names
const swapped: Tx = { ...funding, outputs: [funding.outputs[0], { value: 100_000_000n, addr20: mallory.addr20 }] };
let why = "";
try { await lightClient("http://n", { fetch: serve(swapped) }).authorOf(forged); } catch (e: any) { why = String(e.message); }
ok(why.startsWith("BAD_PROOF"), "a swapped coin is refused");
console.log(failures ? `\n${failures} failed` : "\nall passed"); process.exit(failures ? 1 : 0);
