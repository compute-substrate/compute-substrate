// The rules the network's records are replayed by: anyone replaying the same records gets the same game
import { replay, encodeMove, decodeMove, readGame, gameText, ratings, RESIGN, OFFER_DRAW, ACCEPT_DRAW, type Attest, type GameRecord } from "../src/game";

let failures = 0;
const ok = (c: unknown, what: string) => { console.log(`${c ? "ok  " : "FAIL"} ${what}`); if (!c) failures++; };
const W = "0x" + "aa".repeat(20), B = "0x" + "bb".repeat(20), X = "0x" + "cc".repeat(20);
const game: GameRecord = { id: "g", author: W, white: W, black: B, height: 100, pos: 1 };
let h = 101;
const mv = (by: string, from: string, to: string, n: number, promo?: string): Attest => ({ txid: `t${h}`, game: "g", author: by, score: encodeMove(from, to, promo), confidence: n, height: h++, pos: 1 });
const act = (by: string, score: number, n: number): Attest => ({ txid: `t${h}`, game: "g", author: by, score, confidence: n, height: h++, pos: 1 });

ok(JSON.stringify(decodeMove(encodeMove("e7", "e8", "q"))) === JSON.stringify({ from: "e7", to: "e8", promotion: "q" }), "a move encodes and decodes, promotion included");
ok(readGame(gameText(W, null), W)?.black === null, "a game with an open seat");
ok(readGame(gameText(W, B), X) === null, "a game written by someone not in it isn't one");

// fool's mate
const fools = [mv(W, "f2", "f3", 1), mv(B, "e7", "e5", 2), mv(W, "g2", "g4", 3), mv(B, "d8", "h4", 4)];
let s = replay(game, fools);
ok(s.result === "0-1" && s.how === "Checkmate" && s.moves.length === 4, "fool's mate: black mates in two");

// moves that don't count
h = 200;
s = replay(game, [mv(B, "e7", "e5", 1), mv(X, "e2", "e4", 1), mv(W, "e2", "e5", 1), mv(W, "e2", "e4", 2), mv(W, "e2", "e4", 1)]);
ok(s.moves.length === 1 && s.moves[0].san === "e4", "out of turn, by a stranger, illegal, or out of number: ignored");
s = replay(game, [mv(W, "e2", "e4", 1), mv(W, "e2", "e4", 1)]);
ok(s.moves.length === 1, "the same move twice counts once");

// an open seat is taken by the first other key to move for it
const open: GameRecord = { ...game, black: null };
s = replay(open, [mv(W, "e2", "e4", 1), mv(W, "e7", "e5", 2), mv(X, "e7", "e5", 2), mv(B, "d7", "d5", 3)]);
ok(s.black === X && s.moves.length === 2, "the open seat goes to the first other key to move, and then it's theirs");

// resigning and draws
s = replay(game, [mv(W, "e2", "e4", 1), act(X, RESIGN, 2), act(B, RESIGN, 2)]);
ok(s.result === "1-0" && s.how === "Black resigned", "only a player can resign");
s = replay(game, [mv(W, "e2", "e4", 1), act(W, OFFER_DRAW, 2), act(W, ACCEPT_DRAW, 2)]);
ok(s.result === "playing", "you can't accept your own draw offer");
s = replay(game, [mv(W, "e2", "e4", 1), act(W, OFFER_DRAW, 2), mv(B, "e7", "e5", 2), act(B, ACCEPT_DRAW, 3)]);
ok(s.result === "playing", "a move answers a draw offer");
s = replay(game, [mv(W, "e2", "e4", 1), act(W, OFFER_DRAW, 2), act(B, ACCEPT_DRAW, 2)]);
ok(s.result === "1/2-1/2", "an offer accepted is a draw");

// the network's order decides, whatever order the records arrive in
const shuffled = [fools[3], fools[1], fools[0], fools[2]];
ok(replay(game, shuffled).result === "0-1", "records replay in the network's order, however they arrive");

const r = ratings([{ white: W, black: B, result: "1-0", endedAt: 1 }, { white: B, black: W, result: "1-0", endedAt: 2 }]);
ok(r.length === 2 && r.every(x => x.games === 2) && Math.abs(r[0].rating + r[1].rating - 2400) <= 1, "ratings: Elo from every finished game, in order");
console.log(failures ? `\n${failures} failed` : "\nall passed"); process.exit(failures ? 1 : 0);
