// A key kept in the browser, and invites claimed onto it
import { browserKey, claimInvite, inviteKeyFrom, connect, keyFromPrivate, bytesToHex, deserializeTx, hexToBytes, signerOf, type Hex } from "../src/index";
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
console.log(failures ? `\n${failures} failed` : "\nall passed"); process.exit(failures ? 1 : 0);
