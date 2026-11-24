// guestbook.csd: the kit's guestbook (kit/template), for everyone. Entries are records under
// TOPIC, signed by whoever wrote them, read and checked here against the network.
import { connect, writingKey, claimInvite, openInvites, welcome, friendlyName, doorwayAdd } from "../../kit/src/index";

const TOPIC = "csd.guestbook";
const INVITES = "csd.welcome"; // the welcome pool every app on the network shares

const $ = (id: string) => document.getElementById(id) as HTMLElement;
const say = (t: string) => { $("status").textContent = t; };
const esc = (s: string) => s.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const net = connect({ node: new URLSearchParams(location.search).get("node") ?? undefined });

const me = await writingKey("guestbook");
$("who").textContent = `Signing as ${friendlyName(me.address)}`;
$("who").title = me.address;
if (!me.doorway && me.kept) $("keyLine").hidden = false;
$("backup").onclick = () => navigator.clipboard?.writeText(me.backup()).then(() => say("Key copied. Keep it somewhere safe: whoever has it can sign as you.")).catch(() => {});

const when = (t: number) => new Date(t * 1000).toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" });
async function load() {
  try {
    const entries = await net.read(TOPIC, { limit: 200 }); // each one checked; anything that doesn't prove is left out
    $("list").innerHTML = entries.length ? entries.map(e => `
      <article class="entry${e.pending ? " pending" : ""}">
        <p>${esc(e.text)}</p>
        <div class="meta sans"><b title="${esc(e.author ?? "")}">${esc(e.author ? friendlyName(e.author) : "someone")}</b>${e.pending
          ? `<span>Saving…</span>`
          : `<span>${when(e.time)}</span><span class="ok" title="Signed by its author and checked on this computer">✓</span>`}</div>
      </article>`).join("") : `<p class="lede">Nobody has signed yet. Be the first.</p>`;
  } catch { $("list").innerHTML = `<p class="lede">Couldn't reach the network just now. It tries again by itself.</p>`; }
}

// out of CSD: Doorway tops up by card; elsewhere, one of the invites people left for newcomers
async function short() {
  if (me.doorway) {
    $("status").innerHTML = `You've run out for now. <button class="quiet" id="topUp">Top up in Doorway</button>, then sign again.`;
    $("topUp").onclick = () => doorwayAdd();
    return;
  }
  say("Looking for a free start someone left for newcomers…");
  try {
    const open = await openInvites(net as any, INVITES);
    if (!open.length) { $("status").innerHTML = `You've run out for now. Open this in <a href="https://doorway.place">Doorway</a> to top up by card.`; return; }
    await claimInvite(net as any, open[Math.floor(Math.random() * open.length)].code, me.address);
    say("Someone left you a free start. Sign again in a moment.");
  } catch (e: any) { say(String(e?.message ?? e)); }
}

$("sign").onclick = async () => {
  const text = ($("text") as HTMLTextAreaElement).value.trim();
  if (!text) return;
  ($("sign") as HTMLButtonElement).disabled = true;
  say("Signing…");
  try {
    await net.write(me.signer(net as any), TOPIC, text);
    ($("text") as HTMLTextAreaElement).value = "";
    say("Thank you for signing.");
    load(); // shown at once, as saving
    setTimeout(load, 130_000);
  } catch (e: any) {
    if (/Not enough CSD/.test(String(e?.message))) await short();
    else if (/Declined/.test(String(e?.message))) say("");
    else say(String(e?.message ?? e));
  }
  ($("sign") as HTMLButtonElement).disabled = false;
};

// someone new, with nothing on their key, gets one of the invites left for newcomers
if (me.kept && !me.doorway) welcome(net as any, me, INVITES).catch(() => {});
load();
setInterval(load, 120_000);
