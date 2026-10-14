# openai/math: a mechanical audit

**Release audited:** [`openai/math` at `fd4aeeb2ee4f`](https://github.com/openai/math/tree/fd4aeeb2ee4fc729c18d98444fed42fd0529eeeb) (2026-10-07), the release anchored on Compute Substrate in domain `math/openai-math` (root payload hash `0x19d9f7945074ac0e71b4864b4a00fb5e097b952677e52586bd37db121479a1bb`).
**Audit date:** 2026-10-14
**Recorded in:** domain `math/openai-math/review`

This is not a mathematical review. It does not say whether any theorem is true. It reports
only checks that a machine can perform and anyone can repeat, with the scripts in
[`tools/`](tools/) and their raw output in [`results/`](results/). Every number below can be
recomputed from a clone of the repository at the commit above.

It was prepared with Claude (Anthropic) for compute-substrate-anchors.

## Summary

| Check | Scope | Result |
|---|---|---|
| Unresolved citations in the published PDFs | 749 PDFs, 36,667 pages | **1**, already corrected by OpenAI in a later edition |
| Broken cross-references in the published PDFs | same | **0** |
| `sorry`, `admit`, new `axiom`, `native_decide` in the Lean library | 122,458 files, 26,060,031 lines | **0** |
| The same, in lines added by the dependency patches | 25 patches | **0** added (some removed) |
| Declared main theorems present where the catalogue says | 200 declarations, 173 manuscripts | **200 of 200** |
| Live manuscripts citing a withdrawn manuscript | 746 live manuscripts | **0** |
| Live manuscripts using the withdrawn proof technique | same | **0** |
| Manuscripts changed since the anchor | to `1581d4cbdd69` (2026-10-12) | **0** |
| Formal verification of the statements (Comparator) | 416 challenges | **not yet run** |
| Existence of every cited work | 19,233 references | in the companion [reference audit](../2026-10-14-reference-audit/) |

By these measures the release is mechanically clean. The one defect found had already been
fixed by its authors.

## Findings

### 1. One unresolved citation, already corrected

*Exact Birch–Swinnerton-Dyer Formula from Low Selmer Corank*, edition of 2026-10-03
(proposal `0xb6b30831c5179af0eeb709c3d582baa5e3cbd24ffa292c3d7bfe0e812e36e49b`), page 4:

> The finite-model, switching, and theta methods of [24, 23, ?] provide the starting constructions.

The source cites `\cite{B,C,Dv}` (`sections/01-introduction.tex`, line 134) and no
bibliography entry has the key `Dv`. The revised edition of 2026-10-07
(proposal `0xf4b9edcbdbd284a8d0c7893d56fe88f03aabe6d1ef0abdc61914157fd3634c24`) cites
`\cite{B,C}`; its version note says it "removes an obsolete supporting citation".

Across all 749 published PDFs this is the only unresolved citation, and no cross-reference
renders as `??`.

### 2. The Lean library contains no proof gaps

[`tools/lean_scan.py`](tools/lean_scan.py) removes comments and strings, then searches every
file under `lean/OAI/` for the four ways a Lean proof can be incomplete or rest on unchecked
trust: `sorry`, `admit`, an `axiom` declaration, and `native_decide`. It finds none in
122,458 files. (The scanner was tested against a file containing each of the four, and
flags all of them.)

The project applies 25 patches to its third-party dependencies, some over a megabyte. No
added line introduces any of the four. Three patches remove occurrences from their
dependencies (AINTLIB, AbsorptionCutoff, PrimeNumberTheoremAnd).

### 3. The formalization catalogue is consistent with the code

`lean/formalization.yaml` lists 173 manuscripts with formalized main results and 200 main
result declarations. Every manuscript path, Lean file and Comparator configuration it names
exists, and each of the 200 declarations is defined in the file it names.

The catalogue describes its own scope as "Partial progress", and its `review.status` is
`unchecked`. The static checks here do not change that: they show the library has no
admitted gaps, not that each formal statement matches its paper. That is what the
Comparator challenges check (below).

### 4. The withdrawals were contained

Three manuscripts were withdrawn on 2026-10-06, all traced to one sign error in a
stabilization-trace argument (*Algebraicity of Weil classes on split abelian eightfolds*,
and two papers adapting its construction). No live manuscript cites any of the three by
title or path, and none uses the technique (no live source mentions stabilization traces,
the Eliashberg–Murphy cancellation theorem, signed double points or embedded branes).

The original texts of the three are recorded by hash in the 2026-10-06 anchor.

### 5. Nothing has changed since the anchor

The one later commit, `1581d4cbdd69` (2026-10-12), adds `.github/workflows/lock-prs.yml`,
which locks the conversation on every pull request as it is opened. No manuscript or Lean
file changed. Public discussion on the repository is therefore closed, which leaves records
like this one as a place where responses can be attached to specific manuscripts.

## Not covered here

**Reference existence.** [`results/references.json`](results/references.json) holds all
19,233 references extracted from the sources (13,700 with a DOI, 5,935 with an arXiv
identifier, 3,550 with neither). Whether each identifier leads to the work it names is
checked in the companion [reference audit](../2026-10-14-reference-audit/), recorded
separately in this domain.

**Formal statements.** The Comparator challenges compare each formal statement with an
independently written reference statement and report the axioms each proof depends on. The
repository documents the procedure in `lean/ComparatorChallenges/README.md`; it requires a
full Mathlib build.

## Reproduce

From this folder (`T` is its `tools/` directory):

```bash
T=$PWD/tools
git clone https://github.com/openai/math.git && cd math && git checkout fd4aeeb2ee4f
python3 $T/lean_scan.py lean/OAI                    # prints {} : no gaps
python3 $T/pdf_scan.py preprints pdf-scan.json      # needs pdftotext (poppler)
python3 $T/refs_extract.py preprints references.json
```

(`refs_extract.py` also runs offline identifier checks; on this release they flagged only
LaTeX escaping artefacts, so no finding here relies on them.)

## Files

The SHA-256 of each supporting file, so that this document commits to them:

| File | SHA-256 |
|---|---|
| `results/lean-scan.json` | `44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a` |
| `results/pdf-scan.json` | `2ef1e3ea06ad12c85719e9d67d780b5b63787bae6b03ae744729ed9ff963aa90` |
| `results/references.json` | `a49ae3592a4ce745c33f1a2617a01d00d3bddfc1ab14b7a0a39979beb3a00eb7` |
| `tools/lean_scan.py` | `1696004b9c3de732ff76dd7d917993466d7ef55183dcee6191b39cdcff861c84` |
| `tools/pdf_scan.py` | `5be7678e73ed3ce5cdac8098a17147851b45da881b8b701a6124a9e573ba62e3` |
| `tools/ref_check.py` | `74dc7fdfc13e553864f260d9d2f8ca4118d9be9b1011e0d5fe81d3e43aa0cb64` |
| `tools/refs_extract.py` | `479487d054209e3a45cf1f39c872d1a1b51679304a8b14ba80d4329d5125c793` |
