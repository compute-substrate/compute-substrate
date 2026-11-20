# compute-substrate

A shared record that nobody owns: every node keeps the same copy and checks every block by the same
rules. See [computesubstrate.org](https://computesubstrate.org).

- **Open .csd sites, and publish your own:** [Doorway](app/README.md), for macOS and Windows. It runs a node
  too, with no terminal.
  Or build `csd` from this repository (`cargo build --release --locked`).
- **Build an app on it**, with no server: [the kit](kit/README.md) (`npm install compute-substrate`),
  and a whole app in one static page to start from ([`kit/template`](kit/template)).
- **Run a door**, one command on any server: it lets anyone use the network from a browser and
  keeps every named site up. [Running a door](docs/public-node.md).
