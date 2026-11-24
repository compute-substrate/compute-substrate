// Doorway's key: what a site may ask it to sign, and the proof the CSD/USDC market checks
import { wallet } from "../src/main";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { hexToBytes, bytesToHex, concat, utf8, keyFromPrivate } from "../../../kit/src/core";
import { resolve } from "@inversealtruism/cairnx-core";

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

ok(refused({ app: { ...rec, domain: "cairnx:v1", uri: '{"v":1,"t":"nxfer","name":"alice","to":"0x' + "22".repeat(20) + '"}' }, fee: "25000000" }), "a site's Cairn record (it could give a name away): refused");

// pointing a name Doorway's key holds at a site keeps the rest of its profile
{
  const cid = "bafybeih4sszbxx3lao542tqhzwa37uk2clof5vxddvtbpqqp5nyaidsh24";
  const a = wallet.pointAsk("alice", { contenthash: "ipfs://bafybeihokgavuhapm534e7pknl3uqnfchemmvmk4fyshzdtlcb243zse4a", url: "https://example.com" }, cid, 147_600);
  const r = a.app.kind === "propose" ? JSON.parse(a.app.uri) : null;
  ok(a.app.kind === "propose" && a.app.domain === "cairnx:v1" && r?.t === "nprofile" && r?.name === "alice", "a name's site is set by its nprofile record");
  ok(r?.p?.contenthash === `ipfs://${cid}` && r?.p?.url === "https://example.com", "with the new site, and its link kept");
  ok(a.fee === 25_000_000n && a.burn === 0n, "for 0.25 CSD, nothing burned");
}

const keep = { kind: "propose", domain: "csd.keep", uri: "ipfs://bafybeih4sszbxx3lao542tqhzwa37uk2clof5vxddvtbpqqp5nyaidsh24", payloadHash: "0x" + "11".repeat(32), expiresEpoch: "1" };
ok(wallet.readAsk({ app: keep, fee: "25000000", burn: "250000000" }).burn === 250_000_000n, "keeping a site may burn whole years");
ok(refused({ app: rec, fee: "25000000", burn: "25000000" }), "nothing else may burn");
ok(refused({ app: keep, fee: "25000000", burn: "1000" }), "only whole years");
ok(refused({ app: keep, fee: "25000000", burn: String(1000n * 25_000_000n) }), "at most 1000 years");
const { key, address } = wallet.newKey();
ok(wallet.addressOf(key) === address, "a key's address");
const authHash = "0x" + "22".repeat(32);
const p = wallet.prove(key as any, authHash);
const digest = keccak_256(concat(utf8("AON CSD/USDC: I control this CSD address for trade "), hexToBytes(authHash as any)));
const sig = hexToBytes(p.sig as any);
const pub = secp256k1.Signature.fromCompact(sig.slice(0, 64)).addRecoveryBit(sig[64] - 27).recoverPublicKey(digest).toRawBytes(false).slice(1);
ok(Buffer.from(pub).toString("hex") === p.pubKey.slice(2), "the market's ownership proof recovers to the key");
ok(keyFromPrivate(hexToBytes(key as any)).addr20 === address, "and it's this address's key");
// getting a name with Doorway's key: commit, reveal, finalize, replayed by cairnx-core's own resolver
{
  const me = address.toLowerCase(), other = "0x" + "33".repeat(20);
  const ev = (a: any, height: number, pos: number, who = me) => ({ kind: "propose", id: "0x" + (height * 10 + pos).toString(16).padStart(64, "0"), proposer: who,
    uri: a.app.uri, payloadHash: bytesToHex(a.app.payloadHash), expiresEpoch: Number(a.app.expiresEpoch), height, pos,
    paidTo: a.pay ? { [a.pay.to.toLowerCase()]: String(a.pay.value) } : {} });
  const H = 148_400, salt = wallet.newSalt(), name = "doorwaytest";
  const c = wallet.commitAsk(name, salt, me as any, H), r = wallet.revealAsk(name, salt, H + 1);
  ok(!c.app.uri.includes(name), "the commit doesn't show the name");
  let st = resolve([ev(c, H, 1), ev(r, H + 1, 1)] as any, H + 2).names[name];
  ok(st?.pending && st.owner === me, "after the reveal it's a pending reservation, ours");
  let refusedEarly = false; try { wallet.finalizeAsk(name, salt, st, me as any, H, H + 5); } catch { refusedEarly = true; }
  ok(refusedEarly, "a finalize is refused before the contest is frozen");
  const T = H + wallet.FINALIZE_FROM;
  const f = wallet.finalizeAsk(name, salt, st, me as any, H, T);
  ok(f.pay && f.pay.value === 300_000_000n, "the finalize pays the year's fee (3 CSD for this name)");
  st = resolve([ev(c, H, 1), ev(r, H + 1, 1), ev(f, T + 1, 1)] as any, T + 2).names[name];
  ok(st && !st.pending && st.owner === me && typeof st.paidThroughEpoch === "number", "and the name is ours for a year");
  // an earlier rival commit wins the contest: then the finalize is refused, and no fee is sent
  const rs = wallet.newSalt();
  const rc = wallet.commitAsk(name, rs, other as any, H - 1), rr = wallet.revealAsk(name, rs, H + 2);
  st = resolve([ev(rc, H - 1, 1, other), ev(c, H, 1), ev(r, H + 1, 1), ev(rr, H + 2, 1, other)] as any, T).names[name];
  let refusedLost = false; try { wallet.finalizeAsk(name, salt, st, me as any, H, T); } catch { refusedLost = true; }
  ok(refusedLost && st.owner === other, "outbid by an earlier commit: no finalize, so no fee lost");
  const n = wallet.renewAsk(name, T + 100);
  ok(n.pay && n.pay.value === 300_000_000n && JSON.parse(n.app.kind === "propose" ? n.app.uri : "{}").t === "nrenew", "another year is a renewal with the fee");
}
console.log(failures ? `\n${failures} failed` : "\nall passed"); process.exit(failures ? 1 : 0);
