# openai/math: a reference audit

**Release audited:** [`openai/math` at `fd4aeeb2ee4f`](https://github.com/openai/math/tree/fd4aeeb2ee4fc729c18d98444fed42fd0529eeeb) (2026-10-07), anchored on Compute Substrate in domain `math/openai-math` (root payload hash `0x19d9f7945074ac0e71b4864b4a00fb5e097b952677e52586bd37db121479a1bb`).
**Lookups run:** 2026-10-14, against Crossref, arXiv and the DOI registry (doi.org)
**Recorded in:** domain `math/openai-math/review`
**Follows:** [the mechanical audit](../2026-10-14-mechanical-audit/) of the same release, which extracted the references checked here.

This review asks one question of every reference in the release: does the identifier it
gives lead to the work it names? It does not judge whether a reference is relevant, or
whether any theorem is true. Every result can be repeated with the scripts in
[`tools/`](tools/); the raw lookups are in [`results/`](results/).

It was prepared with Claude (Anthropic) for compute-substrate-anchors.

## Summary

| | References |
|---|---|
| Extracted from the 746 live manuscripts | 19,233 |
| with a DOI | 13,700 |
| with an arXiv identifier and no DOI | 1,983 |
| with neither (**not assessed**, see below) | 3,550 |
| DOIs that resolve | 13,673 (13,221 in Crossref, 452 through other registries) |
| **DOIs registered nowhere** | **27 references, 16 distinct DOIs, 23 manuscript editions (20 distinct manuscripts)** |
| arXiv identifiers that exist | 1,983 of 1,983 |
| Identifiers whose work could be compared by title | about 15,100 |
| **Identifiers that resolve to a different work** | **4** |

The bibliographies are overwhelmingly accurate. Every arXiv identifier exists and carries
the cited title. Of roughly 15,100 references whose identifier and title could be
compared, four disagree. Separately, 16 DOIs are not registered anywhere. In each of those
cases the cited work itself appears to be real; it is the identifier that leads nowhere.

## Findings

### 1. Sixteen DOIs that are registered nowhere

For each DOI below, as of 2026-10-14 both Crossref (`api.crossref.org/works/<doi>`) and the
DOI registry itself (`doi.org/api/handles/<doi>`) answer 404: there is no such DOI. Most
follow the publisher's real numbering pattern. The proposal ID of each manuscript is in
[`results/findings.json`](results/findings.json).

| DOI | Cited work | Cited in |
|---|---|---|
| `10.24033/ast.198` | J. Kollár (ed.), *Flips and abundance for algebraic threefolds*, Astérisque 211 (1992) | Conditional good minimal models for compact Kähler fourfolds (both editions); Termination for projective log canonical fourfolds with rational boundary; Uniform effective log Iitaka fibrations for fourfolds |
| `10.1090/pspum/094/01620` | J. Blanc, *Algebraic structures of groups of birational transformations* (2017) | Conditional good minimal models for compact Kähler fourfolds (both editions); Log abundance in characteristic zero; Logarithmic Kodaira dimension and whole-fiber variation |
| `10.19086/da.144978` | D. P. Hardin and N. J. Tenpas, *Universally optimal periodic configurations in the plane*, Discrete Analysis (2025) | An atomic certificate for triangular-lattice universal optimality; Universal optimality of the triangular lattice |
| `10.1515/9781400882498` | J. Arthur and L. Clozel, *Simple Algebras, Base Change, and the Advanced Theory of the Trace Formula* (1989) | The Selmer converse for elliptic curves at every prime (both editions) |
| `10.4007/annals.2003.157.891` | E. Lapid and S. Rallis, *On the nonnegativity of L(1/2, π) for SO(2n+1)*, Ann. of Math. 157 (2003) | The two-primary Birch–Swinnerton-Dyer formula in Selmer corank at most one (both editions) |
| `10.1090/S0002-9939-1956-0075933-9` | A. S. Amitsur, *Algebras over infinite fields*, Proc. AMS (1956) | A counterexample to Kurosh's division ring problem |
| `10.1090/pspum/102/01809` | J. Pardon, *Totally disconnected groups (not) acting on two-manifolds* (2019) | The Hilbert–Smith conjecture in every finite dimension |
| `10.1093/oso/9780198511762.001.0001` | N. Higson and J. Roe, *Analytic K-Homology* (2000) | Failure of rational injectivity for maximal coarse assembly |
| `10.1145/1347082.1347125` | T. Holenstein, M. Mitzenmacher, R. Panigrahy and U. Wieder, *Trace reconstruction with constant deletion probability and related results*, SODA (2008) | Uniform quasipolynomial-time trace reconstruction |
| `10.11606/resimeusp.v2i2.74798` | P. Erdős, *Some of my favourite problems in number theory, combinatorics, and geometry* (1995) | An asymptotic formula for the number of totients |
| `10.19086/da.117575` | R. Alweiss, *Monochromatic sums and products of polynomials*, Discrete Analysis (2024) | Monochromatic finite sums and products in the positive integers |
| `10.19086/da.57741` | J. Wellens, *Relationships between the number of inputs and other complexity measures of Boolean functions*, Discrete Analysis (2022) | A superquadratic separation between sensitivity and block sensitivity |
| `10.24033/ast.245` | D. Eisenbud, M. Green and J. Harris, *Some conjectures extending Castelnuovo theory*, Astérisque 218 (1993) | Commuting division coefficient forms and the Artinian Eisenbud–Green–Harris conjecture |
| `10.24033/ast.534` | T. Zink, *The display of a formal p-divisible group*, Astérisque (2002) | Filtered chromatic splitting at generic primes |
| `10.24033/ast.93` | M. Laurent, *Sur quelques résultats récents de transcendance*, Astérisque 198–200 (1991) | Open homomorphisms of global solvably closed Galois groups |
| `10.47013/16.4.6` | A. Baniabedalruhman, *The cycle-complete graph Ramsey numbers R(Cₙ, K₈) for 10 ≤ n ≤ 15* (2023) | Cycle–clique Ramsey numbers |

### 2. Four identifiers that resolve to a different work

| Manuscript | Cited as | DOI given | The DOI actually resolves to |
|---|---|---|---|
| Positive scalar curvature forces rational inessentiality… | M. Gromov, *Volume and bounded cohomology* (1982) | `10.1007/BF02698699` | *Stability of a surface-charged viscous jet in an electric field* (1998) |
| Global quantum geometric Langlands at irrational level… | D. Gaitsgory, *A "strange" functional equation for Eisenstein series and miraculous duality on the moduli stack of bundles* | `10.24033/asens.2641` | *Algebraization Techniques and Rigid-Analytic Artin–Grothendieck Vanishing* (2026) |
| Bounded recovery for modular spectral averages | A. Ioana and S. Vaes, *Spectral gap for inclusions of von Neumann algebras* (2015) | `10.24033/asens.2239` | *Cartan subalgebras of amalgamated free product II₁ factors* (2015) |
| Virtual compact specialness of hyperbolic one-relator… | R. Coulon, *Small cancellation theory and Burnside problem*, IJAC 24 (2014) | `10.1142/S0218196714500143` | *On the geometry of Burnside quotients of torsion free hyperbolic groups* (2014) |

The first two lead to unrelated papers. The last two lead to papers in the same area, so
either the DOI or the cited title is wrong; this review does not say which.

## Method

1. **Lookup** ([`tools/ref_check.py`](tools/ref_check.py)). Each DOI was looked up at
   Crossref; each arXiv identifier (for references without a DOI) at the arXiv API.
   Results: [`results/ref_results.jsonl`](results/ref_results.jsonl).
2. **Recheck** ([`tools/recheck.py`](tools/recheck.py)). Every DOI that did not resolve
   was looked up again at Crossref and at the DOI registry, slowly, after removing
   trailing characters picked up from URLs (`.pdf`, `;`). "Registered nowhere" means both
   answered 404; a rate limit or timeout is never counted as absence. Eight first-pass
   failures turned out to be such artefacts and resolve correctly. Results:
   [`results/recheck_results.json`](results/recheck_results.json).
3. **Title comparison** ([`tools/title_compare.py`](tools/title_compare.py)). For every
   resolved identifier, the title it resolves to was compared with the cited title, after
   removing MathML and LaTeX markup. Disagreements were read by hand. Most were
   translations (a French or Russian original, an English DOI title), Oberwolfach Reports
   that collect many talks under one DOI, appendices inside a larger arXiv paper, or
   arXiv papers retitled between versions. Those are not reported. The four above remain.

## Not assessed

**3,550 references carry no identifier.** Matching them requires searching by title, and
title search returns near misses often enough that a non-match proves nothing. Including
them would mean accusing papers on weak evidence, so this review makes no claim about
them.

**Relevance and accuracy of use.** A reference can exist, carry a correct DOI, and still
not say what the manuscript says it says. Checking that requires reading, which is the
work of mathematical review rather than of this audit.

## Files

The SHA-256 of each supporting file, so that this document commits to them:

| File | SHA-256 |
|---|---|
| `results/findings.json` | `a270458cdf492af8c2ffd043f7fde57ee41bdc23e07f89f496fac5b17309db35` |
| `results/recheck_results.json` | `be0bb08b2c75dfecb37a78132d55c99a41fa99a39f67f6f756fc03cbe0812125` |
| `results/ref_results.jsonl` | `fc7ec5b3903b78cb836c3d5703ef4beafef2aa47190fc42b48219c83c6a1ba17` |
| `tools/recheck.py` | `d7f8acf68e20c069e8ce25498b681928968c6eb1526244477d94b7b24509e57d` |
| `tools/ref_check.py` | `74dc7fdfc13e553864f260d9d2f8ca4118d9be9b1011e0d5fe81d3e43aa0cb64` |
| `tools/title_compare.py` | `87865a386c8ad74c34775f8aa8e4ea3ee8f7ac73a05afecf24caea9d44f5cce3` |
