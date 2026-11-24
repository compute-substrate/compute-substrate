import { friendlyName } from "../../kit/src/friendly";
import { chessNet, pickNode } from "./net";
import { replay, ratings, encodeMove, RESIGN, OFFER_DRAW, ACCEPT_DRAW, type GameRecord, type Attest, type State } from "./game";

const $ = (id: string) => document.getElementById(id)!;
const esc = (t: string) => String(t).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const say = (t: string) => { $("status").textContent = t; };
// text presentation, so the pieces never turn into emoji
const GLYPH: Record<string, string> = { k: "♚", q: "♛", r: "♜", b: "♝", n: "♞", p: "♟" };

let c: ReturnType<typeof chessNet>;
let door = "", inDoorway = false;
// what to do when the key is short of CSD: Doorway adds it by card; elsewhere, get Doorway
const short = () => inDoorway ? "Top up in Doorway, then try again." : "Open this in Doorway (doorway.place) to top up by card.";
let meAddr = "";
let games: GameRecord[] = [], attests: Attest[] = [], checked = new Set<string>();
const states = new Map<string, State>();

function ago(height: number) {
  const m = Math.max(0, (c.tip() - height) * 2);
  const n = (x: number, unit: string) => `${x} ${unit}${x === 1 ? "" : "s"} ago`;
  return m < 2 ? "just now" : m < 60 ? n(m, "minute") : m < 48 * 60 ? n(Math.round(m / 60), "hour") : n(Math.round(m / 1440), "day");
}
// a player as people read them: you, or the two words made from their address (the address
// itself in the tooltip, and on the game's own record)
const name = (a: string | null) => a === meAddr ? "You" : a ? friendlyName(a) : "anyone";
const who = (a: string | null) => `<span title="${esc(a ?? "")}">${esc(name(a))}</span>`;

function rebuild() {
  const r = c.records();
  games = r.games; attests = r.attests; checked = r.checked;
  states.clear();
  for (const g of games) states.set(g.id, replay(g, attests));
}

// ── the lists ──────────────────────────────────────────────────────────────
function card(g: GameRecord) {
  const s = states.get(g.id)!;
  const mine = s.white === meAddr || s.black === meAddr;
  const myTurn = mine && s.result === "playing" && (s.turn === "w" ? s.white : s.black) === meAddr;
  const last = s.moves.at(-1)?.height ?? g.height;
  const line = s.result !== "playing" ? `${s.result.replace("1/2-1/2", "½–½")}, ${s.how.toLowerCase()}` : myTurn ? "" : s.how;
  return `<a class="g" href="#g/${g.id}">
    <b>${esc(name(s.white))} vs ${esc(name(s.black))}</b>
    ${myTurn ? `<span class="yours">Your move</span>` : `<span>${esc(line)}</span>`}
    <small>${s.moves.length} ${s.moves.length === 1 ? "move" : "moves"}, ${(g as any).pending ? "on its way" : ago(last)}</small>
  </a>`;
}
function renderHome() {
  const all = [...games].sort((a, b) => (states.get(b.id)!.moves.at(-1)?.height ?? b.height) - (states.get(a.id)!.moves.at(-1)?.height ?? a.height));
  const mine = all.filter(g => { const s = states.get(g.id)!; return s.white === meAddr || s.black === meAddr; });
  // yours first: your move, then theirs, then finished
  const rank = (g: GameRecord) => { const s = states.get(g.id)!; return s.result !== "playing" ? 2 : (s.turn === "w" ? s.white : s.black) === meAddr ? 0 : 1; };
  mine.sort((a, b) => rank(a) - rank(b));
  $("mine").innerHTML = mine.length ? mine.map(card).join("") : `<p class="muted">No games yet. Start one below, or take an open one.</p>`;
  const open = all.filter(g => { const s = states.get(g.id)!; return s.result === "playing" && (!s.white || !s.black) && s.white !== meAddr && s.black !== meAddr; });
  $("open").innerHTML = open.length ? open.map(card).join("") : `<p class="muted">None right now. Start one and leave the opponent empty.</p>`;
  const recent = all.filter(g => !mine.includes(g) && !open.includes(g)).slice(0, 12);
  $("recent").innerHTML = recent.length ? recent.map(card).join("") : `<p class="muted">None yet.</p>`;
  const finished = [...states.values()].filter(s => s.result !== "playing" && s.white && s.black && s.endedAt !== null && !s.moves.some(m => m.pending))
    .map(s => ({ white: s.white!, black: s.black!, result: s.result as "1-0" | "0-1" | "1/2-1/2", endedAt: s.endedAt! }));
  const r = ratings(finished);
  $("ratings").innerHTML = r.length ? r.slice(0, 20).map((x, i) => `<tr><td>${i + 1}</td><td>${who(x.who)}</td><td class="n">${x.rating}</td><td class="n muted">${x.wins}–${x.losses}–${x.draws}</td></tr>`).join("") : `<tr><td></td><td class="muted">No finished games yet.</td></tr>`;
}

// ── a game ─────────────────────────────────────────────────────────────────
let viewing: string | null = null, at: number | null = null; // at: the move shown, null for now
let pick: string | null = null, promoFor: { from: string; to: string } | null = null, sending = false, canMoveNow = false;

function renderGame() {
  const g = games.find(x => x.id === viewing);
  if (!g) { $("state").textContent = "Looking for this game…"; $("board").innerHTML = ""; return; }
  const s = states.get(g.id)!;
  const n = at ?? s.moves.length;
  const fen = n === 0 ? "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1" : s.moves[n - 1].fen;
  const flip = s.black === meAddr && s.white !== meAddr;
  const myColor = s.white === meAddr ? "w" : s.black === meAddr ? "b" : null;
  // you can move when it's your turn, or the side to move is an open seat you can take
  const seat = s.turn === "w" ? s.white : s.black, other = s.turn === "w" ? s.black : s.white;
  const canMove = s.result === "playing" && at === null && !sending && !s.moves.some(m => m.pending) && (seat === meAddr || (!seat && other !== meAddr));
  canMoveNow = canMove;
  const board = fen.split(" ")[0].split("/").map(row => row.replace(/\d/g, d => ".".repeat(+d)).split(""));
  const last = n > 0 ? s.moves[n - 1] : null;
  const targets = pick && canMove ? s.chess.moves({ square: pick as any, verbose: true }) : [];
  let html = "";
  for (let rr = 0; rr < 8; rr++) for (let ff = 0; ff < 8; ff++) {
    const r = flip ? 7 - rr : rr, f = flip ? 7 - ff : ff;
    const sq = "abcdefgh"[f] + (8 - r);
    const p = board[r][f];
    const isW = p !== "." && p === p.toUpperCase();
    const mineHere = p !== "." && canMove && (isW ? "w" : "b") === s.turn;
    const t = targets.find(m => m.to === sq);
    const cls = ["sq", (r + f) % 2 ? "d" : "l", last && (last.from === sq || last.to === sq) ? "last" : "", pick === sq ? "pick" : "", mineHere || t ? "can" : "", t ? "to" : "", t && p !== "." ? "take" : ""].filter(Boolean).join(" ");
    const coords = (rr === 7 ? `<span class="coord f">${"abcdefgh"[f]}</span>` : "") + (ff === 0 ? `<span class="coord r">${8 - r}</span>` : "");
    html += `<button class="${cls}" data-sq="${sq}" aria-label="${sq}">${coords}${p !== "." ? `<span class="pc ${isW ? "w" : "b"}">${GLYPH[p.toLowerCase()]}︎</span>` : ""}</button>`;
  }
  $("board").innerHTML = html;
  const player = (color: "w" | "b") => {
    const who = color === "w" ? s.white : s.black;
    const turnHere = s.result === "playing" && s.turn === color;
    return `<span class="dot ${color}"></span><span>${who ? `<b>${esc(name(who))}</b>` : `<span class="muted">Open: anyone can take ${color === "w" ? "white" : "black"}</span>`}</span>${turnHere ? `<span class="turn">to move</span>` : ""}`;
  };
  $("pTop").innerHTML = player(flip ? "w" : "b");
  $("pBottom").innerHTML = player(flip ? "b" : "w");
  const pendingMove = s.moves.some(m => m.pending);
  $("state").textContent = s.result !== "playing" ? `${s.result.replace("1/2-1/2", "½–½")}. ${s.how}.`
    : pendingMove ? "Your move is on its way: it shows within about two minutes."
    : canMove ? (seat ? "Your move." : `Your move, if you take ${s.turn === "w" ? "white" : "black"}.`)
    : s.drawOffer && myColor && s.drawOffer !== meAddr ? "Your opponent offers a draw." : s.how + ".";
  // the moves, in pairs
  let mv = "";
  for (let i = 0; i < s.moves.length; i += 2) {
    const cell = (k: number) => s.moves[k] ? `<span class="${[s.moves[k].pending ? "pend" : "", k + 1 === n ? "cur" : ""].join(" ")}" data-at="${k + 1}" title="block ${s.moves[k].height}${checked.has(s.moves[k].txid) ? ", checked" : ""}">${esc(s.moves[k].san)}</span>` : "<span></span>";
    mv += `<span class="n">${i / 2 + 1}.</span>${cell(i)}${cell(i + 1)}`;
  }
  $("moves").innerHTML = mv || `<span class="muted" style="grid-column:1/-1">No moves yet.</span>`;
  // what a player can do
  const acts: string[] = [];
  if (myColor && s.result === "playing" && s.white && s.black) {
    acts.push(`<button data-act="resign">Resign</button>`);
    if (s.drawOffer && s.drawOffer !== meAddr) acts.push(`<button data-act="accept">Accept the draw</button>`);
    else if (!s.drawOffer) acts.push(`<button data-act="offer">Offer a draw</button>`);
    else acts.push(`<span class="muted">You offered a draw.</span>`);
  }
  $("acts").innerHTML = acts.join("");
  // how it's checked
  const proven = s.moves.filter(m => checked.has(m.txid)).length + (checked.has(g.id) ? 1 : 0);
  const total = s.moves.filter(m => !m.pending).length + 1;
  $("check").innerHTML = `<b>${proven === total ? "✓ Every record checked" : `Checking: ${proven} of ${total}`}</b> in your browser: each move is signed by its player, in a block on the network, and replayed by the rules here. Started ${ago(g.height)}.`;
}

async function send(score: number, nth: number, what: string) {
  if (!viewing) return;
  sending = true; renderGame();
  say(what);
  try {
    await c.act(viewing, score, nth);
    say("");
    rebuild();
  } catch (e: any) {
    say(/Not enough CSD/.test(String(e?.message)) ? `You've run out for now. ${short()}` : String(e?.message ?? e));
  }
  sending = false; pick = null; renderGame();
}

$("board").addEventListener("click", e => {
  const b = (e.target as HTMLElement).closest("[data-sq]") as HTMLElement | null;
  if (!b || !viewing || !canMoveNow) return;
  const s = states.get(viewing)!;
  const sq = b.dataset.sq!;
  if (pick) {
    const m = s.chess.moves({ square: pick as any, verbose: true }).find(x => x.to === sq);
    if (m) {
      if (m.promotion) { promoFor = { from: pick, to: sq }; showPromo(s.turn); return; }
      send(encodeMove(pick, sq), s.moves.length + 1, `Moving ${m.san}…`);
      return;
    }
  }
  const piece = s.chess.get(sq as any);
  pick = piece && piece.color === s.turn && pick !== sq ? sq : null;
  renderGame();
});
function showPromo(turn: "w" | "b") {
  $("promo").hidden = false;
  $("promo").innerHTML = ["q", "r", "b", "n"].map(p => `<button data-promo="${p}"><span class="pc ${turn}">${GLYPH[p]}︎</span></button>`).join("");
}
$("promo").addEventListener("click", e => {
  const b = (e.target as HTMLElement).closest("[data-promo]") as HTMLElement | null;
  if (!b || !promoFor || !viewing) return;
  const s = states.get(viewing)!;
  $("promo").hidden = true;
  send(encodeMove(promoFor.from, promoFor.to, b.dataset.promo), s.moves.length + 1, "Promoting…");
  promoFor = null;
});
$("acts").addEventListener("click", e => {
  const b = (e.target as HTMLElement).closest("[data-act]") as HTMLElement | null;
  if (!b || !viewing) return;
  const n = states.get(viewing)!.moves.length + 1;
  const a = b.dataset.act;
  if (a === "resign") { if (b.dataset.sure !== "1") { b.dataset.sure = "1"; b.textContent = "Sure? Resign"; return; } send(RESIGN, n, "Resigning…"); }
  if (a === "offer") send(OFFER_DRAW, n, "Offering a draw…");
  if (a === "accept") send(ACCEPT_DRAW, n, "Accepting the draw…");
});
$("moves").addEventListener("click", e => { const x = (e.target as HTMLElement).closest("[data-at]") as HTMLElement | null; if (x) { at = +x.dataset.at!; pick = null; renderGame(); } });
$("back").onclick = () => { const s = viewing && states.get(viewing); if (!s) return; at = Math.max(0, (at ?? s.moves.length) - 1); renderGame(); };
$("fwd").onclick = () => { const s = viewing && states.get(viewing); if (!s) return; const n = (at ?? s.moves.length) + 1; at = n >= s.moves.length ? null : n; renderGame(); };
$("live").onclick = () => { at = null; renderGame(); };
$("share").onclick = () => {
  const url = location.href;
  navigator.clipboard?.writeText(url).then(() => { $("share").textContent = "Link copied"; setTimeout(() => $("share").textContent = "Share this game", 1500); }).catch(() => say(url));
};

// ── starting a game ────────────────────────────────────────────────────────
let asWhite = true;
$("asW").onclick = () => { asWhite = true; $("asW").setAttribute("aria-pressed", "true"); $("asB").setAttribute("aria-pressed", "false"); };
$("asB").onclick = () => { asWhite = false; $("asW").setAttribute("aria-pressed", "false"); $("asB").setAttribute("aria-pressed", "true"); };
$("start").onclick = async () => {
  let opp = ($("against") as HTMLInputElement).value.trim().toLowerCase().replace(/^@/, "") || null;
  // a .csd name: whoever holds it plays (an address works too)
  if (opp && !/^0x[0-9a-f]{40}$/.test(opp)) {
    say(`Looking up ${opp.replace(/\.csd$/, "")}.csd…`);
    try {
      const { lookup } = await import("../../app/resolver/src/main");
      const o = await lookup(opp, { web: true, doors: [door] });
      if (!o.owner) { say(o.why ?? `Nobody holds ${o.name}.csd yet.`); return; }
      opp = o.owner.toLowerCase();
    } catch (e: any) { say(String(e?.message ?? e)); return; }
  }
  if (opp === meAddr) { say("That's you. Leave it empty to let anyone play."); return; }
  ($("start") as HTMLButtonElement).disabled = true;
  say("Starting the game…");
  try {
    const id = await c.newGame(asWhite ? meAddr : opp, asWhite ? opp : meAddr);
    say("");
    rebuild();
    location.hash = `g/${id}`;
  } catch (e: any) {
    say(/Not enough CSD/.test(String(e?.message)) ? `You've run out for now. ${short()}` : String(e?.message ?? e));
  }
  ($("start") as HTMLButtonElement).disabled = false;
};

// ── the route, and keeping up with the network ─────────────────────────────
function route() {
  const m = /^#g\/(0x[0-9a-f]{64})$/.exec(location.hash);
  viewing = m ? m[1] : null; at = null; pick = null; promoFor = null; $("promo").hidden = true;
  $("home").hidden = !!viewing; $("view").hidden = !viewing;
  viewing ? renderGame() : renderHome();
}
addEventListener("hashchange", route);

async function tick() {
  try {
    await c.sync();
    rebuild(); route();
    c.prove(() => { rebuild(); viewing ? renderGame() : renderHome(); });
  } catch (e: any) { if (!games.length) say(`Couldn't read the network: ${e?.message ?? e}`); }
}

(async () => {
  try {
    const node = await pickNode();
    c = chessNet(node); door = node;
    const k = await c.key();
    meAddr = k.address.toLowerCase(); inDoorway = !!k.doorway;
    $("me").innerHTML = `<span title="${esc(meAddr ?? "")}">Playing as ${esc(meAddr ? friendlyName(meAddr) : "you")}</span>`;
    if (k.doorway) { $("keyWhose").textContent = "your key in Doorway, once you allow each one there"; $("backup").hidden = true; }
    $("backup").onclick = () => navigator.clipboard?.writeText(k.backup()).then(() => say("Key copied. Keep it somewhere safe: whoever has it can play as you and use your balance.")).catch(() => {});
    await tick();
    setInterval(tick, 30_000);
  } catch (e: any) { say(String(e?.message ?? e)); }
})();
