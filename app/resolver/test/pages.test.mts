// Kept pages: addresses in one standard form, the record that says what a copy is of, and finding
// every copy of an address from the records alone
import * as P from "../src/pages";
import { keyFromPrivate, hexToBytes, bytesToHex, buildAppTx, serializeTx, type Hex } from "../../../kit/src/core";

let failures = 0;
const ok = (c: unknown, what: string) => { console.log(`${c ? "ok  " : "FAIL"} ${what}`); if (!c) failures++; };
const cid = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

ok(P.pageKey("https://Example.com/a/b/?utm_source=x&b=2&a=1#top") === "https://example.com/a/b?a=1&b=2", "an address in its standard form: host, tracking, order, fragment, trailing slash");
ok(P.pageKey("https://example.com") === "https://example.com/" && P.pageKey("https://example.com/") === "https://example.com/", "the bare host keeps its slash");
ok(P.pageKey("http://example.com:80/x") === "http://example.com/x", "a default port is dropped");
let threw = false; try { P.pageKey("ftp://x.org/a"); } catch { threw = true; }
ok(threw, "only web pages");
ok(P.isPrivate("http://localhost:3000/") && P.isPrivate("http://192.168.1.1/") && P.isPrivate("http://10.0.0.5/x") && P.isPrivate("http://router/") && P.isPrivate("http://[::1]/"), "pages on this computer or a home network are refused");
ok(!P.isPrivate("https://www.nytimes.com/2026/11/27/x.html"), "an ordinary page isn't");

const a = P.pageAsk(cid, "https://example.com/news?id=7&utm_medium=mail", 150_900);
ok(a.app.kind === "propose" && a.app.domain === P.PAGES && a.app.uri === `${cid} https://example.com/news?id=7` && a.fee === 25_000_000n && a.burn === 0n, "the record: the copy's address and the page's");
const titled = P.pageAsk(cid, "https://example.com/news?id=7", 150_900, "  Storm  hits\nthe coast ");
ok((titled.app as any).uri === `${cid} https://example.com/news?id=7 Storm hits the coast`, "with the page's title after the address, on one line");
const longTitle = P.pageAsk(cid, "https://example.com/a", 150_900, "Æ".repeat(400));
ok(new TextEncoder().encode((longTitle.app as any).uri).length <= 512 && (longTitle.app as any).uri.startsWith(`${cid} https://example.com/a Æ`), "a long title is cut, never the address");
const long = P.pageAsk(cid, "https://example.com/" + "x".repeat(900), 150_900);
ok(new TextEncoder().encode((long.app as any).uri).length <= 512, "a long address is cut to fit, and still found by its hash");

// finding copies, from signed records on a node
const key = keyFromPrivate(hexToBytes(bytesToHex(crypto.getRandomValues(new Uint8Array(32)))));
const coin = [{ txid: ("0x" + "ab".repeat(32)) as Hex, vout: 0, value: 100_000_000n }];
const raw = (ask: ReturnType<typeof P.pageAsk>) => bytesToHex(serializeTx(buildAppTx(coin, key, ask.app, ask.fee)));
const other = "bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
const events = [
  { height: 150_901, tx_raw: raw(P.pageAsk(cid, "https://example.com/news?id=7", 150_900, "Storm hits the coast")) },
  { height: 150_950, tx_raw: raw(P.pageAsk(other, "https://EXAMPLE.com/news?id=7#c", 150_900)) },
  { height: 150_960, tx_raw: raw(P.pageAsk(other, "https://example.com/elsewhere", 150_900)) },
  { height: 150_970, tx_raw: "0xdeadbeef" },
];
(globalThis as any).fetch = async (url: string) => {
  const u = String(url);
  if (u.endsWith("/tip")) return new Response(JSON.stringify({ height: 151_000 }));
  if (u.includes(`/events/${P.PAGES}/`)) return new Response(JSON.stringify({ to: 151_000, tip: 151_000, events }));
  return new Response("{}", { status: 404 });
};
const found = await P.copiesOf("http://n", "https://example.com/news?id=7");
ok(found.length === 2 && found[0].cid === other && found[1].cid === cid, "both copies of the page, newest first, written any way the address was");
ok(found.every(f => f.by === key.addr20.toLowerCase()), "each with who kept it, from the record's signature");
ok((await P.copiesOf("http://n", "https://example.com/nothing")).length === 0, "an address nobody kept has none");
ok(found[1].title === "Storm hits the coast" && found[0].title === "", "titles read back, and older records without one still read");
const hits = await P.search("http://n", "storm coast");
ok(hits.length === 1 && hits[0].url === "https://example.com/news?id=7" && hits[0].copies === 2, "search by words in the title: the page once, with how many copies it has");
ok((await P.search("http://n", "www.example.com")).length === 2, "search by site: each page kept from it");
ok((await P.search("http://n", "elsewhere")).length === 1 && (await P.search("http://n", "nothing here")).length === 0, "or words in the address");

if (failures) { console.log(`${failures} failed`); process.exit(1); }
console.log("all pages checks passed");
