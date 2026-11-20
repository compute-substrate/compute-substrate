// A key kept in the browser, and invites claimed onto it
import { browserKey, claimInvite, inviteKeyFrom, makeInvites, openInvites, welcome, connect, keyFromPrivate, bytesToHex, deserializeTx, hexToBytes, signerOf, type Hex } from "../src/index";
let failures = 0;
const ok = (c: unknown, what: string) => { console.log(`${c ? "ok  " : "FAIL"} ${what}`); if (!c) failures++; };

const mem = new Map<string, string>();
(globalThis as any).localStorage = { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v), removeItem: (k: string) => void mem.delete(k) };

const a = browserKey("guestbook"), b = browserKey("guestbook");
ok(a.kept && a.address === b.address, "the same key comes back on the next visit");
ok(browserKey("other").address !== a.address, "another app keeps its own key");
const saved = a.backup();
a.forget();
ok(a.address !== b.address, "forget makes a new key");
a.restore(saved);
ok(a.address === b.address && browserKey("guestbook").address === b.address, "restore brings the old one back, and keeps it");
let threw = false; try { a.restore("nope"); } catch { threw = true; }
ok(threw, "a restore that isn't a key is refused");

const inv = keyFromPrivate(new Uint8Array(32).fill(9));
const code = btoa(String.fromCharCode(...new Uint8Array(32).fill(9))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
ok(inviteKeyFrom(`https://commonplace.place/#/invite/${code}`)?.addr20 === inv.addr20 && inviteKeyFrom(code)?.addr20 === inv.addr20, "reads an invite from a link or a bare code");
ok(inviteKeyFrom("https://example.org/#/hello") === null, "anything else isn't an invite");

let sent: any = null;
const f = (async (u: string, init?: any) => {
  const p = new URL(String(u)).pathname, j = (o: unknown) => new Response(JSON.stringify(o));
  if (p === `/utxos/${inv.addr20.slice(2)}`) return j({ utxos: sent ? [] : [{ txid: "0x" + "33".repeat(32), vout: 0, value: "200100000" }] });
  if (p === "/tx/submit") { sent = JSON.parse(init.body).tx; return j({ ok: true, txid: "0x" + "dd".repeat(32) }); }
  return new Response("{}", { status: 404 });
}) as unknown as typeof fetch;
const net = connect({ node: "http://n", fetch: f });
const got = await claimInvite(net, `#/invite/${code}`, a.address);
ok(got.csd === 2 && sent.outputs.length === 1 && bytesToHex(Uint8Array.from(sent.outputs[0].script_pubkey)) === a.address, "claiming moves all of it, less the fee, onto the key");
threw = false; try { await claimInvite(net, code, a.address); } catch { threw = true; }
ok(threw, "a taken invite says so");

// a welcome: a sponsor lists invites under a topic; a new writing key takes one, once
{
  const coins = new Map<string, bigint>(); const listed: { uri: string; height: number }[] = [];
  const sponsor = browserKey("sponsor");
  coins.set(sponsor.address, 10_00000000n);
  const g = (async (u: string) => {
    const p = decodeURIComponent(new URL(String(u)).pathname), j = (o: unknown) => new Response(JSON.stringify(o));
    if (p === "/tip") return j({ height: 1000 });
    if (p.startsWith("/utxos/")) { const a = "0x" + p.slice(7); const v = coins.get(a) ?? 0n; return j({ utxos: v ? [{ txid: "0x" + a.slice(2, 10).padEnd(64, "0"), vout: 0, value: String(v) }] : [] }); }
    if (p.startsWith("/proposals/guestbook.example.invites/")) return j({ proposals: listed.map((l, i) => ({ proposal_id: "0x" + String(i).padStart(64, "0"), height: l.height, time: 1, uri: l.uri })) });
    return new Response("{}", { status: 404 });
  }) as unknown as typeof fetch;
  const net2 = connect({ node: "http://n", fetch: g });
  // a stand-in for the network: what each submitted transaction spends, pays and lists
  (net2.api as any).submit = async (tx: any) => {
    for (const i of tx.inputs) for (const [a, v] of coins) if (("0x" + a.slice(2, 10).padEnd(64, "0")) === i.txid) coins.delete(a);
    for (const o of tx.outputs) coins.set(o.addr20, (coins.get(o.addr20) ?? 0n) + o.value);
    if (tx.app.kind === "propose") listed.push({ uri: tx.app.uri, height: 1001 });
    return "0x" + "ee".repeat(32);
  };
  const codes = await makeInvites(net2, sponsor, { topic: "guestbook.example.invites", count: 3, each: 1 });
  ok(codes.length === 3 && listed.length === 1 && listed[0].uri.startsWith("invites:"), "makeInvites funds them and lists them in one transaction");
  ok((await openInvites(net2, "guestbook.example.invites")).length === 3, "all three are open");
  const newcomer = browserKey("newcomer");
  const w = await welcome(net2, newcomer, "guestbook.example.invites");
  ok(w?.csd === 1, "a new writing key is welcomed with one, arriving whole");
  ok((await openInvites(net2, "guestbook.example.invites")).length === 2, "and that one is no longer open");
  ok((await welcome(net2, newcomer, "guestbook.example.invites")) === null, "only once");
  let big = false; try { await makeInvites(net2, sponsor, { topic: "t", count: 11, each: 1 }); } catch { big = true; }
  ok(big, "at most ten per listing, so they fit in one record");
}
console.log(failures ? `\n${failures} failed` : "\nall passed"); process.exit(failures ? 1 : 0);
