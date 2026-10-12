# csd-anchor

Anchor the contents of a git repository on Compute Substrate.

The first target is [`openai/math`](https://github.com/openai/math): 719 AI-generated
manuscripts (722 in the first release), published on GitHub, where the repository
owner controls the history and the feedback channels. Anchoring them records, at a
chain height nobody can backdate, exactly which bytes were published. That gives
anyone a fixed point to:

- check OpenAI's own promise that "previously released versions remain accessible"
- support a specific manuscript by attesting to its proposal, or answer it with a review recorded as its own proposal
- prove later which edition of a paper a citation, review or formalization referred to

The substrate asserts nothing about whether any manuscript is correct. It records
which bytes existed, and when.

## What gets recorded

| Record | `payload_hash` | `uri` |
|---|---|---|
| `@root` (one) | `sha256d(manifest.json bytes)` | where you publish `manifest.json` |
| one per unit | the unit's tree hash | GitHub permalink pinned to the commit |

A *unit* is each `preprints/<manuscript>/` directory, plus each top-level file or
directory (`lean/`, `README.md`, `history.md`, ...). Units cover every tracked file,
so the root record commits to the whole commit and the unit records let people
attest to a single manuscript.

All proposals go into the domain `math/openai-math` (configurable) with
`expires_epoch` about ten years out, so attestations stay open.

## Hash spec (`csd-anchor/v1`)

```
leaf(file)       = sha256d(blob bytes)
tree(files)      = sha256d("csd-anchor/tree/v1\0" || Σ (path || 0x00 || leaf))
                   over repo-relative paths in ascending byte order
unit tree_hash   = tree(files under that unit)
commit_tree_hash = tree(all tracked files)
root payload     = sha256d(exact bytes of manifest.json)
```

`sha256d` is the same double-SHA256 that `csd propose --payload` uses. Files are
read from git objects at the pinned commit, never from the working tree, so local
edits or ignored files can't leak in.

`verify_manifest.py` re-implements this spec in about 100 lines of standard-library Python.
Run it to check a manifest without trusting the Rust tool.

## One command (openai/math)

After the manifests are published (see the steps in the anchors repo):

```bash
cargo build --release --bin csd_anchor
RPC=http://127.0.0.1:8789 KEY=key.hex GITHUB_OWNER=<you> \
URI_1007='<raw address of manifest-2026-10-07.json>' \
URI_1006='<raw address of manifest-2026-10-06.json>' \
bash anchor/run-openai-math.sh
```

It checks that the published manifests match byte-for-byte, shows the cost and asks
once, then fans out, submits, waits for blocks, verifies and writes
`publish-out/` (a finished README plus state files) ready to upload. Re-running it
is safe.

## Usage (individual steps)

```bash
cargo build --release --bin csd_anchor
A=target/release/csd_anchor

# 1. Hash a pinned commit (≈12 s for openai/math's 134k files)
git clone https://github.com/openai/math.git
$A manifest --repo math --commit fd4aeeb2ee4fc729c18d98444fed42fd0529eeeb \
            --out manifest-2026-10-07.json

# 2. Independent check of the manifest (optional, recommended)
python3 anchor/verify_manifest.py --repo math --manifest manifest-2026-10-07.json

# 3. Cost
$A plan --manifest manifest-2026-10-07.json            # all units: 758 × 0.25 CSD
$A plan --manifest manifest-2026-10-07.json --mode root # 1 × 0.25 CSD

# 4. Publish manifest-2026-10-07.json somewhere stable first (it is the root URI)

# 5. Fund: split coins into one confirmed fee-sized UTXO per proposal.
#    Needed because the mempool only accepts spends of confirmed outputs.
export CSD_PRIVKEY=...            # or --privkey-file key.hex
$A fanout --rpc http://127.0.0.1:8789 --manifest manifest-2026-10-07.json          # dry run
$A fanout --rpc http://127.0.0.1:8789 --manifest manifest-2026-10-07.json --send
#    ...wait one block...

# 6. Submit (dry run first; --limit 5 is a good first real run)
$A submit --rpc http://127.0.0.1:8789 --manifest manifest-2026-10-07.json \
          --manifest-uri https://<your-host>/manifest-2026-10-07.json
$A submit ... --send

# 7. Verify (anyone with the manifest + state file and a node can run this)
$A verify --rpc http://127.0.0.1:8789 --manifest manifest-2026-10-07.json

# Compare releases: what changed, was added, removed or withdrawn
$A diff manifest-2026-10-06.json manifest-2026-10-07.json
```

`submit` keeps `anchor-state.json` (txids and signed transactions). It is safe to
re-run: confirmed records are skipped and signed-but-unmined ones are resubmitted
unchanged. Publish the state file next to the manifest. It maps each unit to its
proposal txid, which is what attesters need.

## Responding to a manuscript

Attestations carry no text: an attestation is a support signal (score, confidence),
weighted by its fee.

```bash
csd attest --proposal-id <txid from anchor-state.json> --score <n> --confidence <n> --fee 5000000 ...
```

A review, critique or Lean result is a new PROPOSE (for example in the domain
`math/openai-math/review`) whose payload is the write-up's hash and whose URI points
to it. The write-up names the manuscript proposal ID it responds to.

## Results so far (openai/math)

| | 2026-10-06 `adc7f12` | 2026-10-07 `fd4aeeb` |
|---|---|---|
| tracked files | 132,851 | 133,955 |
| manuscripts in catalogue | 722 | 719 |
| manuscript directories | 722 | 749 |
| labelled withdrawn | 0 | 3 |
| commit tree hash | `0xbbb1c52c…1503be` | `0xaf0d3a2d…fa57bc` |
| root payload hash | `0x75d204dd…ac45fb` | `0x19d9f794…a1bb` |

`diff` between them: 721 units byte-identical (719 of the 722 original
manuscripts, plus `LICENSE` and `reasoning_traces`); 8 changed (the 3 withdrawn
manuscripts plus `README.md`, `CONTENTS.md`, `overview.*` and `lean/`); 28 added
(`history.md` and 27 revised editions); no directories removed. The withdrawn
manuscripts' directories now contain only a notice, with their original files
deleted from the current version and linked from the October 6 commit. Anchoring
the October 6 manifest is what keeps those originals provable.

Anchoring today can't prove when these commits were *created*, only that their
exact contents existed by the anchoring height. From that height onward, any
rewrite, deletion or silent edit is detectable.
