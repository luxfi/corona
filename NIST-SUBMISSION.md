# NIST MPTC Submission — Corona (one-page executive summary)

> **Executive summary** of the Corona package for the NIST Multi-Party
> Threshold Cryptography (MPTC) project. The full cover sheet is in
> `SUBMISSION.md`; the package contents map is below.

## Submission metadata

| Field | Value |
|---|---|
| Submission name | **Corona** |
| Submitting organisation | Lux Industries, Inc. |
| Algorithm | Threshold Ring-LWE 2-round signing + Pedersen DKG + proactive resharing |
| MPTC classes | **N1** (construction-level threshold signing) + **N4** (multi-party key generation with public-key preservation across resharing) |
| Underlying construction | Boschini, Kaviani, Lai, Malavolta, Takahashi, Tibouchi. *Practical two-round threshold signatures from learning with errors.* IACR ePrint **2024/1113**, IEEE S&P 2025 |
| Lattice family | Ring-LWE over `R_q = Z_q[X]/(X^N + 1)`, `N = 256`, `q = 0x1000000004A01` (48-bit NTT-friendly prime) |
| Round count | 2 rounds per signature |
| Hash suite | Corona-SHA3 (cSHAKE256 / KMAC256 / TupleHash256, FIPS 202 + SP 800-185) |
| Repository | <https://github.com/luxfi/corona> |
| Submission tag | `submission-2026-11-16` (planned) |
| Latest tagged release | `v0.4.1` (next: `v0.5.0` accompanying the submission package) |
| License | Apache-2.0 (code) + CC-BY-4.0 (PATENTS.md) |

## Headline claim

> Every signature produced by a Corona threshold ceremony (DKG →
> Round-1 → Round-2 → Combine) verifies under the Corona verifier
> (`sign.Verify`) on the same message and group public key `(A, bTilde)`
> as a single-party Corona run would. The group public key is
> preserved bit-identically across proactive resharing events within
> a key era (Class N4 invariant).

**Theorem framing**: construction-level interchangeability. Corona
implements the published Boschini et al. 2-round R-LWE threshold
signature scheme (IACR ePrint 2024/1113) on a fixed parameter set;
Corona's contribution beyond the academic paper is the production
lifecycle (Pedersen DKG over `R_q`, proactive resharing, identifiable
abort, activation certs, KAT-deterministic Corona-SHA3 hash suite).

**Verifier-side reality.** R-LWE threshold signatures have no NIST
standard at submission time. The Boschini et al. construction
verifier is the spec. Corona's `sign.Verify` is the canonical
implementation of that verifier; there is no third-party
FIPS-validated R-LWE verifier to cross-check against. This is the
honest framing distinction from Pulsar (M-LWE / FIPS 204), which
DOES cross-check against BoringSSL FIPS / AWS-LC / OpenSSL 3.0 PQ.

## Package contents (mapped to NIST IR 8214C requirements)

| NIST requirement | Corona artifact |
|---|---|
| Technical specification | `SPEC.md` + `papers/lp-073-pulsar/` LaTeX sections + `DESIGN.md` |
| Open-source reference implementation | `sign/` + `threshold/` + `dkg2/` + `reshare/` + `primitives/` + `hash/` (Apache-2.0) |
| Experimental evaluation report | `docs/evaluation.md` |
| Test vectors | `cmd/{reshare,dkg2,activation,cross_runtime}_oracle*/`, manifest at `scripts/regen-kats.manifest.sha256` |
| Security analysis | `SPEC.md` §15 + Boschini et al. ePrint 2024/1113 §§3–4 |
| Patent / IP statement | `PATENTS.md` (royalty-free grant) + `docs/patent-claims.md` (attorney prep) |
| Known limitations | `SUBMISSION.md` §"Does NOT claim" + `DESIGN.md` §"What this isn't" |
| Contact / maintainers | `SUBMISSION.md` §Contact |

## What makes this submission different

1. **Production-hardened R-LWE threshold** — beyond the Boschini et al.
   academic construction, Corona adds Pedersen DKG over `R_q`
   (`dkg2/`), proactive resharing with two distinct primitives
   (`Refresh` for same-set; `ReshareToNewSet` for set rotation),
   identifiable-abort evidence pipeline, and activation certificates
   (the circuit-breaker that gates new-epoch acceptance).

2. **KAT-deterministic Corona-SHA3 profile** — every Sign-path
   primitive takes a `hash.HashSuite` argument. Production deployments
   use cSHAKE256 / KMAC256 / TupleHash256 per FIPS 202 + SP 800-185.
   The legacy BLAKE3 suite remains available for cross-port byte
   checks.

3. **Cross-runtime byte-equality** — Go reference at `sign/` +
   `threshold/`; C++ port at `~/work/luxcpp/crypto/corona/`. KAT
   manifest (`scripts/regen-kats.manifest.sha256`) enforces
   byte-equal round-trip via `scripts/regen-kats.sh --verify`.

4. **Constant-time audit complete** — `CONSTANT-TIME-REVIEW.md`
   shows zero `(c)` (must-fix) entries. Two `(b)` entries are
   documented with mitigations (one closed in `dkg2/`; one in
   lens-specific secp256k1 paths not on the Corona threshold path).

5. **Reproducibility-first** — `scripts/build.sh`, `scripts/test.sh`,
   `scripts/gen_vectors.sh` are deterministic. KAT regeneration is
   byte-equal across runs; CI enforces drift = build bug.

6. **Honest gap disclosure** — Corona does NOT ship a mechanized
   refinement proof. See `PROOF-CLAIMS.md` for the narrow claim and
   the roadmap. The honest framing: production-hardened
   implementation of a published academic construction, not
   machine-checked refinement of a NIST standard.

## Trust footprint (one-screen summary)

After Corona v0.4.1:

| Category | Count / Status |
|---|---|
| EasyCrypt files | **0** (no mechanized refinement — see `PROOF-CLAIMS.md`) |
| Lean ↔ EC bridge files | **0** |
| Jasmin source files | **0** (libjade does not target Corona parameter set) |
| Go reference test coverage | sign + threshold + dkg2 + reshare + primitives + hash — 45+ tests in `reshare/`, 10+ in `dkg2/`, comprehensive sign roundtrip + threshold tests |
| Fuzz harnesses | `reshare/fuzz_*_test.go`, `dkg2/fuzz_round_test.go`, `threshold/fuzz_round_test.go` |
| KAT cross-runtime byte-equality | enforced by `scripts/regen-kats.sh` + `regen-kats.manifest.sha256` |
| Constant-time audit | `CONSTANT-TIME-REVIEW.md` — 0 `(c)`, 2 `(b)` mitigated |

The trust base for Corona at submission time reduces to:

- The Boschini et al. ePrint 2024/1113 construction analysis
  (academic prior art).
- The Go reference implementation correctness (reviewed by code +
  KATs + fuzz).
- The `luxfi/lattice/v7` (lattigo fork) NTT / Montgomery / Gaussian
  sampler primitives — documented constant-time per upstream.
- The `crypto/subtle` standard library constant-time helpers.
- The Go toolchain.

## What this submission does NOT claim

| Out-of-scope claim | Why |
|---|---|
| Byte-equality with FIPS 204 ML-DSA | That is Pulsar's claim. Corona is R-LWE; ML-DSA is M-LWE. |
| Mechanized refinement proof | Multi-month research project. No FIPS standard target exists for R-LWE threshold. See `PROOF-CLAIMS.md`. |
| Post-quantum hardness of R-LWE | Assumed from Lyubashevsky-Peikert-Regev (2010) and follow-up analysis. |
| ACVP/CAVP algorithm validation certificate | Not applicable — NIST has no ACVP test vector set for R-LWE threshold. |
| FIPS 140-3 module validation | Downstream — applies to packaged modules. |
| Asynchronous identifiable abort | Synchronous only. |
| 1-round signing | Construction is 2-round by design (Boschini et al.). |
| DKG without external randomness beacon | Honest-majority unbiased; production binds a beacon at the consensus layer. |

## Reproducibility commitment

```bash
git clone --branch submission-2026-11-16 https://github.com/luxfi/corona
cd corona
scripts/build.sh                # builds reference impl
scripts/test.sh                 # runs unit + KAT + integration tests
scripts/bench.sh                # performance (expect within 5% of REPORT.md)
scripts/gen_vectors.sh          # regenerate KAT vectors deterministically
```

Drift between submission tarball and reproduced output is a build
bug — please file at the GitHub issues link above. NIST reviewers
should obtain byte-identical artifacts on reproduction.

## Patent / IP posture (TL;DR)

- **Code**: Apache-2.0.
- **Patents**: Royalty-free grant to any implementation of the
  Corona construction released under Apache-2.0 or compatible OSI
  license, OR any NIST MPTC/PQC/ACVP submission/validation/interoperability test.
- **Defensive termination**: license terminates against any party
  asserting patents against Corona, the underlying Boschini et al.
  construction, FIPS 204 ML-DSA, or any other NIST-standardized PQ
  signature scheme.
- **Full text**: `PATENTS.md` §3.

## Contact

| Purpose | Contact |
|---|---|
| Submission coordination | `mptc@lux.network` |
| Patent / IP inquiries | `legal@lux.network` |
| Security disclosure | See `SECURITY.md` |
| Public discussion | <https://github.com/luxfi/corona/discussions> |
| Primary maintainer | `z@lux.network` (Lux Industries, Inc.) |

## Roadmap (v0.5 and beyond)

| Milestone | Target |
|---|---|
| Submission package scaffolding (this revision) | v0.5.0 |
| Single-document `spec/corona.tex` consolidating `SPEC.md` + paper sections | v0.6.0 |
| EasyCrypt theory shell for the construction-level interchangeability claim | v0.7.0 (research) |
| Lean 4 / Mathlib mechanization of the Lagrange-aggregation identity over `R_q` | v0.7.0 (research) |
| External cryptographic audit (engaged lab) | v0.8.0 |
| `dudect`-style statistical CT validation harness | v0.8.0 |
| Production deployment runbook hardening | continuous |

The roadmap is published at `SUBMISSION.md` "What this submission
does NOT claim" + tracked at the GitHub issues link above.

---

**Document metadata**

- Name: `NIST-SUBMISSION.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
- Submission package version: Corona v0.2 (tagged `submission-2026-11-16` on cut date)
