# Chess

Correspondence chess with no server: the network is the referee. Every move is signed by its
player and kept by the network, in order, and anyone's browser replays the same records to the same
game. Nobody, not even whoever hosts the page, can take a move back or change a result. Ratings
(Elo) are worked out in each browser from every finished game, so nobody keeps them and anyone can
recompute them.

## The records

Under the topic `chess.v1` (see `src/game.ts`):

- **A game** is a record whose text is `{"t":"game","white":<address|null>,"black":<address|null>}`
  (0.25 CSD), written by one of the two players. An empty seat is open: the first other key to move
  for that side takes it.
- **A move** is an attestation to the game (0.05 CSD): score `from + 64*to + 4096*promotion`
  (squares a1 = 0 to h8 = 63; promotion 1 queen, 2 rook, 3 bishop, 4 knight), confidence the move's
  number (1 for white's first). It counts only if it's by the player to move, has the next number,
  and is legal.
- **Resigning** is score 900000 by either player; **a draw** is 900001 (offer) by one player, then
  900002 (accept) by the other before either moves again.

Anything else is ignored, so a broken or hostile record can't change a game. Each record is shown at
once and proven in the background, as the kit's light client proves it: in a block on the heaviest
chain, its author the owner of the coin it spends.

Moves are signed with Doorway's key when the page is opened through Doorway (each one approved
there), else with a key kept in the browser. Rules by [chess.js](https://github.com/jhlywa/chess.js)
(BSD 2-Clause).

## Build and publish

```bash
cd kit && npm ci && cd ../app/resolver && npm ci && cd ../../chess && npm ci
npm test
npm run build        # out/
```

The release attaches it packed, as `chess.car`: in Doorway, *Publish*, choose that file, and point
a name (`chess`) to it.
