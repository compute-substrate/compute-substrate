// The front page's live parts: the network's height (its headers checked here, by proof-of-work),
// the doors that answer, the sites on the network, and how long this page is kept up, with a way for
// anyone to add a year.
import { listSites, type Listed } from "../../app/resolver/src/directory";
import { newestDoorway } from "../../app/resolver/src/release";
import { connect, lightClient, writingKey, doorwayAdd, claimInvite, openInvites, heightToDate, monthYear } from "../../kit/src/index";

// this page's own .csd name, and the doors it starts from (it finds the rest on the network)
const NAME = "computesubstrate";
const DOORS = ["https://csd.aon.network", "https://151-240-121-186.sslip.io", "https://151-240-121-187.sslip.io"];
const $ = (id: string) => document.getElementById(id)!;
const fmt = (n: number) => n.toLocaleString("en-US");
const CID_RE = /^b[a-z2-7]{50,61}$/;

// Opened through Doorway, links to other sites open on this computer too
const viaDoorway = location.hostname.endsWith(".localhost");
const here = (name: string) => `${location.protocol}//${name}.localhost${location.port ? ":" + location.port : ""}/`;
if (viaDoorway) {
  ($("browse") as HTMLAnchorElement).href = here("directory");
  ($("commonplace") as HTMLAnchorElement).href = here("commonplace");
  $("getDoorway").textContent = "You're in Doorway";
  ($("getDoorway") as HTMLAnchorElement).href = "#open";
}

// This page never changes once it's published, so its download links follow Doorway's newest
// release, read from GitHub as the page opens (else they go to Doorway's page, which lists them)
const REPO = "compute-substrate/compute-substrate";
// the newest Doorway's files, by version (release.ts)
newestDoorway().then(r => {
  if (!r) return;
  ($("dlMac") as HTMLAnchorElement).href = r.mac;
  ($("dlWin") as HTMLAnchorElement).href = r.win;
  if (r.doorSh) $("doorCmd").textContent = `curl -fsSL ${r.doorSh} | bash`;
});

async function firstDoor(): Promise<string> {
  const asked = new URLSearchParams(location.search).get("node");
  for (const d of asked ? [asked, ...DOORS] : DOORS) {
    try { const r = await fetch(`${d.replace(/\/$/, "")}/tip`, { signal: AbortSignal.timeout(6000) }); if (r.ok) return d.replace(/\/$/, ""); } catch {}
  }
  throw new Error("no door answered");
}

// the doors announced on the network that answer right now
async function openDoors(node: string): Promise<number> {
  let list = [...DOORS];
  try {
    const j = await (await fetch(`${node}/proposals/csd.doors/200`, { signal: AbortSignal.timeout(10_000) })).json();
    for (const p of j.proposals ?? []) {
      const u = String(p.uri ?? "").trim().replace(/\/+$/, "");
      try { const x = new URL(u); if (x.protocol === "https:" && x.pathname === "/" && !x.search) list.push(u); } catch {}
    }
  } catch {}
  list = [...new Set(list)].slice(0, 40);
  const up = await Promise.all(list.map(async d => { try { return (await fetch(`${d}/tip`, { signal: AbortSignal.timeout(6000) })).ok; } catch { return false; } }));
  return up.filter(Boolean).length;
}

let net: ReturnType<typeof connect>;
let me: Awaited<ReturnType<typeof writingKey>> | null = null;
let myCid: string | null = CID_RE.test(location.hostname.split(".")[0]) ? location.hostname.split(".")[0] : null;
let sites: Listed[] = [];

async function heartbeat(light: ReturnType<typeof lightClient>) {
  try {
    await light.syncTail(); // every header since the release's anchors: linked, at the right difficulty, with valid proof-of-work
  } catch {}
}

async function showKept() {
  const k = await net.kept().catch(() => null);
  if (!k) return;
  if (!myCid) myCid = sites.find(s => s.name === NAME)?.cid ?? null;
  $("addYear").hidden = !myCid;
  const u = myCid ? k.until.get(myCid) : undefined;
  if (u && u > k.tip) {
    const d = heightToDate(u, k.tip);
    $("until").textContent = monthYear(d, true);
    $("keptLine").textContent = `This page has no server. It's kept up until ${monthYear(d)}.`;
  } else {
    $("until").textContent = "—";
    $("untilSaid").textContent = myCid ? "nobody keeps this page up yet" : "this page isn't on the network yet";
    $("keptLine").textContent = myCid ? "This page has no server. Nobody keeps it up yet." : "This page has no server.";
  }
}

async function start() {
  let node: string;
  try { node = await firstDoor(); } catch { $("doors").textContent = "—"; return; }
  net = connect({ node });
  $("node").textContent = node.replace(/^https:\/\//, "");
  const light = lightClient(node);
  heartbeat(light);
  setInterval(() => heartbeat(light), 120_000);
  openDoors(node).then(n => { $("doors").textContent = fmt(n); });
  try { sites = (await listSites(node)).sites; $("sites").textContent = fmt(sites.length); } catch { $("sites").textContent = "?"; }
  await showKept();
}

// Add a year to this page: anyone can (kit/src/keep.ts)
$("addYear").onclick = async () => {
  if (!myCid) return;
  const b = $("addYear") as HTMLButtonElement;
  b.disabled = true;
  $("keepSaid").textContent = "Adding a year…";
  try {
    me ??= await writingKey(NAME);
    await net.keep(me.signer(net as any), myCid, 1);
    $("keepSaid").textContent = "Thank you. Your year counts in about two minutes.";
    setTimeout(showKept, 130_000);
  } catch (e: any) {
    const m = String(e?.message ?? e);
    if (/Not enough CSD/.test(m) && me!.doorway) {
      $("keepSaid").innerHTML = `You've run out for now. <button id="addInDoorway">Top up in Doorway</button>`;
      $("addInDoorway").onclick = () => doorwayAdd();
    } else if (/Not enough CSD/.test(m)) {
      $("keepSaid").innerHTML = `A year costs 0.25 CSD, and your key here has less. <button id="takeInvite">Take a free invite</button> someone left for newcomers, or send CSD to <code>${me!.address}</code>.`;
      $("takeInvite").onclick = async () => {
        $("keepSaid").textContent = "Looking for one…";
        try {
          const open = await openInvites(net as any);
          if (!open.length) { $("keepSaid").textContent = "None are left right now. Try again later."; return; }
          const r = await claimInvite(net as any, open[Math.floor(Math.random() * open.length)].code, me!.address);
          $("keepSaid").textContent = `${r.csd} CSD is on its way. Add the year again in about two minutes.`;
        } catch (err: any) { $("keepSaid").textContent = String(err?.message ?? err); }
      };
    } else $("keepSaid").textContent = m;
  }
  b.disabled = false;
};

$("copyDoor").onclick = () => navigator.clipboard?.writeText($("doorCmd").textContent ?? "").then(() => { $("copyDoor").textContent = "Copied"; setTimeout(() => $("copyDoor").textContent = "Copy", 1500); }).catch(() => {});

start();
