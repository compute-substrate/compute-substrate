// Doorway's key: what a site may ask it to sign, and the proof the CSD/USDC market checks
import { wallet } from "../src/main";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { hexToBytes, concat, utf8, keyFromPrivate } from "../../../kit/src/core";

let failures = 0;
const ok = (c: unknown, what: string) => { console.log(`${c ? "ok  " : "FAIL"} ${what}`); if (!c) failures++; };
const refused = (body: any) => { try { wallet.readAsk(body); return false; } catch { return true; } };
const rec = { kind: "propose", domain: "guestbook.example", uri: "hi", payloadHash: "0x" + "11".repeat(32), expiresEpoch: "10004900" };

ok(wallet.readAsk({ app: rec, fee: "25000000" }).fee === 25_000_000n, "a record at its fee is read");
ok(refused({ app: rec, fee: "1000" }), "below the network's fee: refused");
ok(refused({ app: rec, fee: "100000001" }), "over 1 CSD: refused");
ok(refused({ app: { kind: "send", to: "0x00" }, fee: "25000000" }), "anything but a record or an attestation: refused (no sending CSD away)");
ok(refused({ app: { ...rec, uri: "x".repeat(513) }, fee: "25000000" }), "a record over 512 bytes: refused");
ok(wallet.readAsk({ app: { kind: "attest", proposalId: "0x" + "ab".repeat(32), score: 1 }, fee: "5000000" }).app.kind === "attest", "an attestation is read");

const { key, address } = wallet.newKey();
ok(wallet.addressOf(key) === address, "a key's address");
const authHash = "0x" + "22".repeat(32);
const p = wallet.prove(key as any, authHash);
const digest = keccak_256(concat(utf8("AON CSD/USDC: I control this CSD address for trade "), hexToBytes(authHash as any)));
const sig = hexToBytes(p.sig as any);
const pub = secp256k1.Signature.fromCompact(sig.slice(0, 64)).addRecoveryBit(sig[64] - 27).recoverPublicKey(digest).toRawBytes(false).slice(1);
ok(Buffer.from(pub).toString("hex") === p.pubKey.slice(2), "the market's ownership proof recovers to the key");
ok(keyFromPrivate(hexToBytes(key as any)).addr20 === address, "and it's this address's key");
console.log(failures ? `\n${failures} failed` : "\nall passed"); process.exit(failures ? 1 : 0);
