// Reading and writing chess records on the network, through any door. Every record is shown at
// once, attributed by its signature, and then proven in the background the way a light client
// proves it (kit/src/light.ts): it's in a block on the network's heaviest chain, and its author
// is the owner of the coin it spends. A record that doesn't prove is dropped.
import { connect, lightClient, writingKey, deserializeTx, signerOf, hexToBytes, type Hex } from "../../kit/src/index";
import { TOPIC, readGame, gameText, type GameRecord, type Attest } from "./game";

// no chess record is older than this block
const FROM = 147_000;
export const DOORS = ["https://csd.aon.network", "https://151-240-121-186.sslip.io", "https://151-240-121-187.sslip.io"];

const store = {
  get<T>(k: string, d: T): T { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : d; } catch { return d; } },
  set(k: string, v: unknown) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
};

export async function pickNode(): Promise<string> {
  const asked = new URLSearchParams(location.search).get("node");
  for (const d of asked ? [asked, ...DOORS] : DOORS) {
    try { const r = await fetch(`${d.replace(/\/$/, "")}/tip`, { signal: AbortSignal.timeout(6000) }); if (r.ok) return d.replace(/\/$/, ""); } catch {}
  }
  throw new Error("No door answered. Check that you're online, then reload.");
}

type Raw = { txid: string; height: number; pos: number; tx_raw: string };
type Proven = { author: string; height: number; pos: number } | "bad";

export function chessNet(node: string) {
  const net = connect({ node });
  const light = lightClient(node);
  let next = FROM, tip = 0;
  const raws = new Map<string, Raw>();
  const proven: Record<string, Proven> = store.get("chess.proven1", {});
  const proving = new Set<string>();

  // everything under the topic, from where we left off
  async function sync(): Promise<number> {
    tip = (await net.api.tip()).height;
    while (next <= tip) {
      const r = await net.api.events(TOPIC, next, 2000);
      if (!r) break;
      for (const e of r.events as Raw[]) raws.set(e.txid.toLowerCase(), { ...e, txid: e.txid.toLowerCase() });
      if (r.to < next) break;
      next = r.to + 1;
    }
    return tip;
  }

  // prove what isn't proven yet, a few at a time; calls back as each one settles
  async function prove(onChange: () => void) {
    const todo = [...raws.keys()].filter(id => !proven[id] && !proving.has(id));
    for (let i = 0; i < todo.length; i += 4) {
      await Promise.all(todo.slice(i, i + 4).map(async id => {
        proving.add(id);
        try {
          const v = await light.checkTx(id as Hex);
          proven[id] = v.author ? { author: v.author.toLowerCase(), height: v.height, pos: v.index } : "bad";
        } catch (e: any) {
          if (/BAD_PROOF|BAD_CHAIN/.test(String(e?.message))) proven[id] = "bad";
        } finally { proving.delete(id); }
      }));
      store.set("chess.proven1", proven);
      onChange();
    }
  }

  // The games and moves as they stand: proven ones by their proven author, the rest by their
  // signature until they're proven, and none that failed
  function records(): { games: GameRecord[]; attests: Attest[]; checked: Set<string> } {
    const games: GameRecord[] = [], attests: Attest[] = [], checked = new Set<string>();
    for (const e of raws.values()) {
      const p = proven[e.txid];
      if (p === "bad") continue;
      let tx; try { tx = deserializeTx(hexToBytes(e.tx_raw as Hex)); } catch { continue; }
      const author = p ? p.author : (signerOf(tx) ?? "").toLowerCase();
      if (!author) continue;
      if (p) checked.add(e.txid);
      if (tx.app.kind === "propose") {
        const g = readGame(tx.app.uri, author);
        if (g) games.push({ id: e.txid, author, ...g, height: e.height, pos: e.pos });
      } else if (tx.app.kind === "attest") {
        attests.push({ txid: e.txid, game: tx.app.proposalId.toLowerCase(), author, score: tx.app.score, confidence: tx.app.confidence, height: e.height, pos: e.pos });
      }
    }
    // and what this browser sent that isn't in a block yet
    const sent = store.get<{ games: GameRecord[]; attests: Attest[] }>("chess.sent1", { games: [], attests: [] });
    const live = (x: { id?: string; txid?: string; at?: number }) => !raws.has((x.id ?? x.txid)!) && Date.now() - ((x as any).at ?? 0) < 86_400_000;
    sent.games = sent.games.filter(live); sent.attests = sent.attests.filter(live);
    store.set("chess.sent1", sent);
    return { games: [...games, ...sent.games], attests: [...attests, ...sent.attests], checked };
  }

  let me: Awaited<ReturnType<typeof writingKey>> | null = null;
  const key = async () => (me ??= await writingKey("chess"));

  return {
    net, node, sync, prove, records,
    tip: () => tip,
    key,
    async newGame(white: string | null, black: string | null): Promise<string> {
      const k = await key();
      const id = (await net.write(k.signer(net as any), TOPIC, gameText(white, black))).toLowerCase();
      const sent = store.get<{ games: any[]; attests: any[] }>("chess.sent1", { games: [], attests: [] });
      sent.games.push({ id, author: k.address.toLowerCase(), white, black, height: tip + 1, pos: 0, pending: true, at: Date.now() });
      store.set("chess.sent1", sent);
      return id;
    },
    async act(game: string, score: number, n: number): Promise<string> {
      const k = await key();
      const id = (await net.attest(k.signer(net as any), game as Hex, score, { confidence: n })).toLowerCase();
      const sent = store.get<{ games: any[]; attests: any[] }>("chess.sent1", { games: [], attests: [] });
      sent.attests.push({ txid: id, game, author: k.address.toLowerCase(), score, confidence: n, height: tip + 1, pos: 0, pending: true, at: Date.now() });
      store.set("chess.sent1", sent);
      return id;
    },
  };
}
