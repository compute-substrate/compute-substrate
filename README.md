# compute-substrate

A shared record that nobody owns: every node keeps the same copy and checks every block by the same
rules. See [computesubstrate.org](https://computesubstrate.org).

- **Run a node** without a terminal: [Compute Substrate Node](app/README.md), for macOS and Windows.
  Or build `csd` from this repository (`cargo build --release --locked`).
- **Build an app on it**, with no server: [the kit](kit/README.md) (`npm install compute-substrate`),
  and a whole app in one static page to start from ([`kit/template`](kit/template)).
- **Open a public door**, so anyone's browser can use the network through your node:
  [running a public door](docs/public-node.md).
