// Letters: sealed for one reader (and the writer), found by a tag only the reader can recognise,
// signed by the writer, and refused when anything about them doesn't check out
import * as L from "../src/letters";
import { keyFromPrivate, hexToBytes, bytesToHex, type Hex } from "../../../kit/src/core";

let failures = 0;
const ok = (c: unknown, what: string) => { console.log(`${c ? "ok  " : "FAIL"} ${what}`); if (!c) failures++; };
const newKey = () => bytesToHex(crypto.getRandomValues(new Uint8Array(32))) as Hex;
const addr = (k: Hex) => keyFromPrivate(hexToBytes(k)).addr20.toLowerCase() as Hex;

const alice = newKey(), bob = newKey(), eve = newKey();
const box = (k: Hex) => L.readLetterbox(L.letterboxDoc(L.letterKeys(k)));

// keys
const a1 = L.letterKeys(alice), a2 = L.letterKeys(alice);
ok(a1.x.public.every((b, i) => b === a2.x.public[i]) && a1.kem.publicKey.every((b, i) => b === a2.kem.publicKey[i]), "letter keys come from Doorway's key, the same every time");
ok(!L.letterKeys(bob).x.public.every((b, i) => b === a1.x.public[i]), "different keys, different letter keys");
ok(L.readLetterbox(L.letterboxDoc(a1)).mlkem.length === 1184, "a letterbox document reads back");
let bad = false; try { L.readLetterbox(new TextEncoder().encode('{"v":1,"x25519":"AA","mlkem768":"AA"}')); } catch { bad = true; }
ok(bad, "a malformed letterbox is refused");

// a letter from Alice to Bob
const { bytes, hint } = await L.seal(alice, addr(bob), box(bob), { subject: "Hello", body: "A letter, slowly." });
const uri = `ar://${"x".repeat(43)}#${hint}`;
ok(uri.length <= 512, `the record's uri fits a record (${uri.length} bytes)`);
ok(L.isForMe(L.letterKeys(bob), uri), "Bob recognises it from the record alone");
ok(!L.isForMe(L.letterKeys(eve), uri), "Eve doesn't");
ok(!L.isForMe(L.letterKeys(alice), uri), "the tag is the recipient's: the writer finds sent letters by their own records");
ok(!new TextDecoder().decode(bytes).includes("A letter, slowly."), "the stored letter doesn't contain its text");

const forBob = await L.openLetter(bob, bytes, addr(alice));
ok(forBob?.body === "A letter, slowly." && forBob?.subject === "Hello" && forBob?.from === addr(alice) && forBob?.to === addr(bob), "Bob reads it, from Alice");
const forAlice = await L.openLetter(alice, bytes, addr(alice));
ok(forAlice?.body === "A letter, slowly.", "Alice can read what she sent");
ok((await L.openLetter(eve, bytes)) === null, "Eve can't read it");
ok((await L.openLetter(bob, bytes, addr(eve))) === null, "a record by someone else claiming Alice's letter is refused");

// tampering
const j = JSON.parse(new TextDecoder().decode(bytes));
const flip = (s: string) => (s[5] === "A" ? s.slice(0, 5) + "B" : s.slice(0, 5) + "A") + s.slice(6);
const tampered = new TextEncoder().encode(JSON.stringify({ ...j, c: flip(j.c) }));
ok((await L.openLetter(bob, tampered)) === null, "a changed letter doesn't open");
const swapped = new TextEncoder().encode(JSON.stringify({ ...j, r: j.r.map((w: any) => ({ ...w, k: flip(w.k) })) }));
ok((await L.openLetter(bob, swapped)) === null, "a changed ML-KEM part doesn't open (both halves are needed)");
ok((await L.openLetter(bob, new TextEncoder().encode("not a letter"))) === null, "garbage is refused, not thrown");

// lengths: padded to whole kilobytes
const short = await L.seal(alice, addr(bob), box(bob), { subject: "", body: "x" });
const longer = await L.seal(alice, addr(bob), box(bob), { subject: "", body: "x".repeat(600) });
ok(JSON.parse(new TextDecoder().decode(short.bytes)).c.length === JSON.parse(new TextDecoder().decode(longer.bytes)).c.length, "a one-character letter and a 600-character one look the same size");

// a reply carries what it answers
const re = await L.seal(bob, addr(alice), box(alice), { subject: "Re: Hello", body: "Got it.", re: "0x" + "ab".repeat(32) });
ok((await L.openLetter(alice, re.bytes, addr(bob)))?.re === "0x" + "ab".repeat(32), "a reply says which letter it answers");

if (failures) { console.log(`${failures} failed`); process.exit(1); }
console.log("all letters checks passed");
