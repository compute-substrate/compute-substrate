// Letters on the network alone: letterboxes, openings and notes as records of at most 512 bytes,
// read back from the records with nothing else, by the two people in a conversation and nobody else
import * as L from "../src/letters";
import { keyFromPrivate, hexToBytes, bytesToHex, type Hex } from "../../../kit/src/core";

let failures = 0;
const ok = (c: unknown, what: string) => { console.log(`${c ? "ok  " : "FAIL"} ${what}`); if (!c) failures++; };
const newKey = () => bytesToHex(crypto.getRandomValues(new Uint8Array(32))) as Hex;
const addr = (k: Hex) => keyFromPrivate(hexToBytes(k)).addr20.toLowerCase() as Hex;
let height = 149_000, pos = 0;
const recs = (who: Hex, uris: string[]): L.Rec[] => uris.map(uri => ({ id: "0x" + Math.random().toString(16).slice(2).padEnd(64, "0"), proposer: addr(who), uri, height: ++height, pos: pos++ }));

const alice = newKey(), bob = newKey(), eve = newKey();
const fits = (uris: string[]) => uris.every(u => new TextEncoder().encode(u).length <= 512);

// letterboxes
const bobBoxUris = L.letterboxUris(L.letterKeys(bob));
ok(bobBoxUris.length === 4 && fits(bobBoxUris), `a letterbox is ${bobBoxUris.length} records, each within 512 bytes`);
const boxRecs = recs(bob, bobBoxUris);
const boxes = L.letterboxes(boxRecs);
const bobBox = boxes.get(addr(bob));
ok(bobBox && bobBox.x25519.every((b, i) => b === L.letterKeys(bob).x.public[i]), "Bob's letterbox reads back from its records");
ok(!L.letterboxes(boxRecs.slice(0, 3)).get(addr(bob)), "a letterbox with a part missing isn't used");
ok(!L.letterboxes(recs(eve, bobBoxUris)).get(addr(bob)), "copying Bob's letterbox records under another key doesn't make them Bob's");

// Alice opens a conversation with Bob and writes
const { uris: openUris } = await L.openingUris(alice, addr(bob), bobBox!);
ok(openUris.length === 4 && fits(openUris), `an opening is ${openUris.length} records, each within 512 bytes`);
const openRecs = recs(alice, openUris);
const [aliceConv] = await L.conversations(alice, openRecs);
const [bobConv] = await L.conversations(bob, openRecs);
ok(aliceConv && bobConv && aliceConv.secret.every((b, i) => b === bobConv.secret[i]), "Alice (from her own sealed copy) and Bob (from his keys) get the same secret from the records alone");
ok(aliceConv?.b === addr(bob) && bobConv?.a === addr(alice), "both know who the conversation is with, from the records");
ok((await L.conversations(eve, openRecs)).length === 0, "Eve finds no conversation in them");

const hello = await L.noteUris(aliceConv, { subject: "Hello", body: "A letter, kept by the network." });
ok(hello.length === 1 && fits(hello), "a short letter is one record");
const longBody = "Lorem ipsum æøå 🌊 ".repeat(60);
const long = await L.noteUris(aliceConv, { subject: "A long one", body: longBody });
ok(long.length > 1 && fits(long), `a ${longBody.length}-character letter is ${long.length} records`);
ok(new Set([...hello, ...long].map(u => u.length)).size === 1, "every note record is the same size, whatever it holds");
const noteRecs = recs(alice, [...hello, ...long]);

const forBob = await L.letters([bobConv], noteRecs);
const forAlice = await L.letters([aliceConv], noteRecs);
const h = forBob.find(l => l.subject === "Hello"), lg = forBob.find(l => l.subject === "A long one");
ok(h?.body === "A letter, kept by the network." && h.from === addr(alice) && h.to === addr(bob), "Bob reads the short letter, from Alice");
ok(lg?.body === longBody, "the long one comes back whole, across its records, emoji and all");
ok(forAlice.length === 2, "Alice reads what she sent");
ok((await L.letters(await L.conversations(eve, openRecs), noteRecs)).length === 0, "Eve reads nothing");
ok((await L.letters([bobConv], noteRecs.slice(0, -1))).every(l => l.subject !== "A long one"), "a letter with a part missing isn't shown half");

// Bob replies, with no letterbox of Alice's needed
const reply = await L.noteUris(bobConv, { subject: "Re: Hello", body: "Got it.", re: L.shortId(h!) });
const replyRecs = recs(bob, reply);
const back = (await L.letters([aliceConv], [...noteRecs, ...replyRecs])).find(l => l.subject === "Re: Hello");
ok(back?.from === addr(bob) && back.body === "Got it." && back.re === L.shortId(h!), "Bob's reply reaches Alice and says what it answers");

// a letter can say who wrote it, sealed with the rest
{
  const named = await L.noteUris(aliceConv, { subject: "From me", body: "Hi", name: "alice" });
  const [got] = await L.letters([bobConv], recs(alice, named));
  ok(got?.name === "alice" && got.subject === "From me" && got.body === "Hi", "the writer's name comes with the letter, inside the seal");
  ok(!named.some(u => u.includes("alice")), "and isn't readable from the record");
}

// someone else replaying the notes under their own key
const stolen = await L.letters([bobConv], recs(eve, hello));
ok(stolen.length === 0, "the same notes written by a third key are ignored");
// tampering
const t = hello[0], flipped = t.slice(0, 40) + (t[40] === "A" ? "B" : "A") + t.slice(41);
ok((await L.letters([bobConv], recs(alice, [flipped]))).length === 0, "a changed note doesn't open");

// restoring a key: everything again from the records alone
const restored = await L.conversations(alice, [...openRecs, ...noteRecs, ...replyRecs, ...boxRecs]);
ok((await L.letters(restored, [...noteRecs, ...replyRecs])).length === 3, "with only the key and the records, Alice gets all three letters back");

ok(L.costOf(4) === 1 && L.costOf(1) === 0.25, "a record costs a post (0.25)");


// groups: Alice starts one with Bob and Carol; invitations go in her two-person conversations
{
  const carol = newKey();
  const carolBox = L.letterboxes(recs(carol, L.letterboxUris(L.letterKeys(carol)))).get(addr(carol))!;
  const { uris: openC } = await L.openingUris(alice, addr(carol), carolBox);
  const openCRecs = recs(alice, openC);
  const pairsA = await L.conversations(alice, [...openRecs, ...openCRecs]);
  const toBob = pairsA.find(c => c.b === addr(bob))!, toCarol = pairsA.find(c => c.b === addr(carol))!;
  const g = L.newGroup(alice, "Sunday | club", [addr(bob), addr(carol)]);
  const inv = recs(alice, [...await L.inviteUris(toBob, g), ...await L.inviteUris(toCarol, g)]);
  ok(inv.every(r => new TextEncoder().encode(r.uri).length <= 512), `a three-person invitation is ${inv.length / 2} record(s) per member`);
  const pairsB = await L.conversations(bob, [...openRecs, ...openCRecs]);
  const pairsC = await L.conversations(carol, [...openRecs, ...openCRecs]);
  const [gA] = await L.groups(pairsA, inv), [gB] = await L.groups(pairsB, inv), [gC] = await L.groups(pairsC, inv);
  ok(gA && gB && gC && gB.id === g.id && gC.group!.members.length === 3 && gB.group!.title === "Sunday   club" || gB?.group!.title === "Sunday   club".replace(/\s+/g, " "), "Alice, Bob and Carol each find the group, its title and its three members");
  ok((await L.letters(pairsB, inv)).length === 0, "an invitation never shows as a letter");
  ok((await L.groups(await L.conversations(eve, [...openRecs, ...openCRecs]), inv)).length === 0, "Eve finds no group");
  // messages
  const hi = recs(bob, await L.noteUris(gB, { subject: "", body: "Hi both" }));
  const fromCarol = recs(carol, await L.noteUris(gC, { subject: "", body: "Hello!" }));
  const seenByA = await L.letters([gA], [...hi, ...fromCarol]);
  ok(seenByA.length === 2 && seenByA.every(l => l.group === g.id) && seenByA.some(l => l.from === addr(bob) && l.body === "Hi both"), "every member reads every member's messages");
  ok((await L.letters([gC], recs(eve, await L.noteUris(gB, { subject: "", body: "sneaky" })))).length === 0, "a message from outside the group, even sealed right, doesn't count");
  // someone else can't take over the group with their own invitation
  const pairsBE = await L.conversations(bob, [...openRecs]);
  const fake = L.newGroup(bob, "Mine now", [addr(alice), eve]);
  const takeover = recs(bob, await L.inviteUris(pairsBE[0], { ...fake, id: g.id, secret: g.secret }));
  const [gA2] = await L.groups(pairsA, [...inv, ...takeover]);
  ok(gA2.group!.by === addr(alice) && !gA2.group!.members.includes(eve) && gA2.group!.title !== "Mine now", "a member can't add people or rename the group: only its starter's invitations count");
}

// writing several records: the first makes a coin for each of the rest, which then all go at once
{
  const submitted: any[] = [];
  const me = addr(alice);
  (globalThis as any).fetch = async (url: string, init?: any) => {
    const u = String(url);
    if (u.includes("/tx/submit")) { const tx = JSON.parse(init.body).tx; submitted.push(tx); return new Response(JSON.stringify({ ok: true, txid: "0x" + String(submitted.length).padStart(64, "0") })); }
    if (u.includes("/utxos/")) {
      const first = "0x" + "1".padStart(64, "0");
      const utxos = submitted.length === 0 ? [{ txid: "0x" + "ab".repeat(32), vout: 0, value: "500000000" }]
        : submitted[0].outputs.map((o: any, i: number) => ({ txid: first, vout: i, value: String(o.value) }));
      return new Response(JSON.stringify({ ok: true, utxos }));
    }
    return new Response("{}", { status: 404 });
  };
  const asks = [...openUris, ...hello].map(u => L.recordAsk(L.LETTERS, u, 149_500));
  const steps: string[] = [];
  const ids = await L.writeAll("http://n", alice, asks, s => steps.push(s));
  const each = 25_000_000 + 1_000_000;
  const made = submitted[0].outputs.filter((o: any) => o.value === each).length;
  ok(ids.length === 5 && submitted.length === 5, "five records, five writes");
  ok(made === 4, "the first write also makes a coin for each of the other four");
  ok(submitted.slice(1).every((t: any) => t.inputs.length === 1), "each of the others spends just its own coin, so they can all go in the same block");
  ok(submitted.every((t: any) => t.app.Propose && t.app.Propose.domain === L.LETTERS), "every write is a letters record");
  ok(steps.some(s => /On its way/.test(s)), "it says it's on its way once the first is out");
  void me;
}

if (failures) { console.log(`${failures} failed`); process.exit(1); }
console.log("all letters checks passed");
