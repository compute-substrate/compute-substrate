// Correspondence chess on Compute Substrate. The network is the referee: a game is a record, every
// move is an attestation to it, signed by its player and kept in order by the network, and anyone
// replays the same records to the same position. Nobody runs the game, so nobody can change it.
//
// The records, under the topic `chess.v1`:
//   a game     a record whose text is {"t":"game","white":<address|null>,"black":<address|null>}.
//              Its writer is one of the two; an empty seat is open: the first other key to move
//              for that side takes it.
//   a move     an attestation to the game: score = from + 64*to + 4096*promotion (squares a1=0 to
//              h8=63; promotion 0 none, 1 queen, 2 rook, 3 bishop, 4 knight), confidence = the move's
//              number in the game (1 for white's first). A move counts only if it's by the player
//              whose turn it is, has the next number, and is legal.
//   resign     score RESIGN, by either player: the other wins
//   draw       score OFFER_DRAW by one player, then ACCEPT_DRAW by the other before either moves again
// Anything else is ignored, so a broken or hostile record can't change a game.
import { Chess, type Square } from "chess.js";

export const TOPIC = "chess.v1";
export const RESIGN = 900_000, OFFER_DRAW = 900_001, ACCEPT_DRAW = 900_002;
const PROMO = ["", "q", "r", "b", "n"];
const FILES = "abcdefgh";

export const square = (i: number) => `${FILES[i % 8]}${Math.floor(i / 8) + 1}` as Square;
export const index = (sq: string) => FILES.indexOf(sq[0]) + 8 * (Number(sq[1]) - 1);
export function encodeMove(from: string, to: string, promotion?: string): number {
  return index(from) + 64 * index(to) + 4096 * Math.max(0, PROMO.indexOf(promotion ?? ""));
}
export function decodeMove(score: number): { from: Square; to: Square; promotion?: string } | null {
  if (!Number.isInteger(score) || score < 0 || score >= 4096 * 5) return null;
  const p = Math.floor(score / 4096), rest = score % 4096;
  return { from: square(rest % 64), to: square(Math.floor(rest / 64)), ...(p ? { promotion: PROMO[p] } : {}) };
}

export type GameRecord = { id: string; author: string; white: string | null; black: string | null; height: number; pos: number; time?: number };
export type Attest = { txid: string; game: string; author: string; score: number; confidence: number; height: number; pos: number; pending?: boolean };

// What a game record says, or null if it isn't one; its writer must sit in one of the seats
export function readGame(uri: string, author: string): { white: string | null; black: string | null } | null {
  try {
    const j = JSON.parse(uri);
    if (j?.t !== "game") return null;
    const seat = (x: unknown) => x === null || x === undefined ? null : typeof x === "string" && /^0x[0-9a-f]{40}$/i.test(x) ? x.toLowerCase() : undefined;
    const white = seat(j.white), black = seat(j.black);
    if (white === undefined || black === undefined) return null;
    const a = author.toLowerCase();
    if (white !== a && black !== a) return null;
    if (white && white === black) return null;
    return { white, black };
  } catch { return null; }
}
export const gameText = (white: string | null, black: string | null) => JSON.stringify({ t: "game", white: white?.toLowerCase() ?? null, black: black?.toLowerCase() ?? null });

export type Played = {
  san: string; from: string; to: string; by: string; txid: string; height: number; pending?: boolean;
  fen: string; // the position after it
};
export type State = {
  chess: Chess;
  white: string | null;
  black: string | null;
  moves: Played[];
  turn: "w" | "b";
  // "playing", or how it ended
  result: "playing" | "1-0" | "0-1" | "1/2-1/2";
  how: string;            // in words: "White to move", "Checkmate", "Black resigned", …
  drawOffer: string | null; // who offered a draw that still stands
  endedAt: number | null;   // the block the game ended in
};

// Replay a game from its attestations, in the network's order (block, then position in the block).
// Pending moves (sent from this browser, not in a block yet) come last.
export function replay(g: GameRecord, attests: Attest[]): State {
  const chess = new Chess();
  let white = g.white, black = g.black;
  const moves: Played[] = [];
  let result: State["result"] = "playing", how = "", drawOffer: string | null = null, endedAt: number | null = null;
  const order = [...attests].filter(a => a.game === g.id).sort((a, b) => Number(!!a.pending) - Number(!!b.pending) || a.height - b.height || a.pos - b.pos);
  for (const a of order) {
    if (result !== "playing") break;
    const who = a.author.toLowerCase();
    const isPlayer = who === white || who === black;
    if (a.score === RESIGN) {
      if (!isPlayer) continue;
      result = who === white ? "0-1" : "1-0"; how = who === white ? "White resigned" : "Black resigned"; endedAt = a.height;
      continue;
    }
    if (a.score === OFFER_DRAW) { if (isPlayer && white && black) drawOffer = who; continue; }
    if (a.score === ACCEPT_DRAW) {
      if (isPlayer && drawOffer && drawOffer !== who) { result = "1/2-1/2"; how = "Drawn by agreement"; endedAt = a.height; }
      continue;
    }
    const m = decodeMove(a.score);
    if (!m || a.confidence !== moves.length + 1) continue;
    const side = chess.turn();
    // an open seat is taken by the first other key to move for it
    if (side === "w" && !white && who !== black) white = who;
    if (side === "b" && !black && who !== white) black = who;
    if (who !== (side === "w" ? white : black)) continue;
    let mv;
    try { mv = chess.move(m); } catch { continue; }
    if (!mv) continue;
    moves.push({ san: mv.san, from: mv.from, to: mv.to, by: who, txid: a.txid, height: a.height, pending: a.pending, fen: chess.fen() });
    drawOffer = null; // a move answers any offer
    if (chess.isGameOver()) {
      endedAt = a.height;
      if (chess.isCheckmate()) { result = side === "w" ? "1-0" : "0-1"; how = "Checkmate"; }
      else { result = "1/2-1/2"; how = chess.isStalemate() ? "Stalemate" : chess.isInsufficientMaterial() ? "Draw: not enough pieces to mate" : chess.isThreefoldRepetition() ? "Draw by repetition" : "Draw by the fifty-move rule"; }
    }
  }
  const turn = chess.turn();
  if (result === "playing") how = `${turn === "w" ? "White" : "Black"} to move${chess.inCheck() ? ", in check" : ""}`;
  return { chess, white, black, moves, turn, result, how, drawOffer, endedAt };
}

// Ratings everyone can work out for themselves, from every finished game in the order they ended:
// Elo, starting at 1200, K = 32. Nobody keeps them, so nobody can change them.
export function ratings(finished: { white: string; black: string; result: "1-0" | "0-1" | "1/2-1/2"; endedAt: number }[]) {
  const r = new Map<string, { rating: number; games: number; wins: number; losses: number; draws: number }>();
  const get = (k: string) => { let x = r.get(k); if (!x) r.set(k, x = { rating: 1200, games: 0, wins: 0, losses: 0, draws: 0 }); return x; };
  for (const g of [...finished].sort((a, b) => a.endedAt - b.endedAt)) {
    const w = get(g.white), b = get(g.black);
    const sw = g.result === "1-0" ? 1 : g.result === "0-1" ? 0 : 0.5;
    const ew = 1 / (1 + 10 ** ((b.rating - w.rating) / 400));
    w.rating += 32 * (sw - ew); b.rating += 32 * ((1 - sw) - (1 - ew));
    w.games++; b.games++;
    if (sw === 1) { w.wins++; b.losses++; } else if (sw === 0) { b.wins++; w.losses++; } else { w.draws++; b.draws++; }
  }
  return [...r.entries()].map(([who, x]) => ({ who, ...x, rating: Math.round(x.rating) })).sort((a, b) => b.rating - a.rating);
}
