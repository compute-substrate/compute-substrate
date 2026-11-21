// A record read through a door and proven by the light client becomes the same event as the same
// record read from this computer's own node.
import { eventOf, eventOfVerified, parseTx } from "../src/main";
import { buildAppTx, serializeTx, keyFromPrivate, txid, type Hex, type Tx } from "../../../kit/src/core";

let failures = 0;
const ok = (c: unknown, what: string) => { console.log(`${c ? "ok  " : "FAIL"} ${what}`); if (!c) failures++; };
const alice = keyFromPrivate(new Uint8Array(32).fill(1));
const coin = ("0x" + "22".repeat(32)) as Hex;
for (const app of [
  { kind: "propose" as const, domain: "cairnx:v1", payloadHash: new Uint8Array(32).fill(7), uri: '{"v":1,"t":"nprofile","name":"x","p":{}}', expiresEpoch: 99n },
  { kind: "attest" as const, proposalId: ("0x" + "ab".repeat(32)) as Hex, score: 3, confidence: 9 },
]) {
  const tx: Tx = buildAppTx([{ txid: coin, vout: 0, value: 100_000_000n }], alice, app, 25_000_000n);
  const id = txid(tx);
  const own = eventOf(id, parseTx(serializeTx(tx, false)), 140_000, 3);
  const door = eventOfVerified({ txid: id, tx, author: alice.addr20, height: 140_000, index: 3, blockHash: id, depth: 5 });
  ok(JSON.stringify(own) === JSON.stringify(door), `${app.kind}: the same event either way`);
  if (JSON.stringify(own) !== JSON.stringify(door)) console.log(own, door);
}
console.log(failures ? `\n${failures} failed` : "\nall passed"); process.exit(failures ? 1 : 0);
