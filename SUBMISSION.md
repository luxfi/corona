# NIST MPTC Submission — Corona

This document is the cover sheet for the **Corona** submission to the
NIST Multi-Party Threshold Cryptography (MPTC) project. It is written
for NIST reviewers and points at every artifact a reviewer needs.

The `corona` repository is the **single canonical home** for the
submission: it carries the Go reference implementation under
`sign/` + `threshold/` + `dkg2/` + `reshare/` + `primitives/` + `hash/`,
the cover sheet, the design spec, the KAT vector format, the
constant-time evidence, and the tarball-cut tooling. There is exactly
one canonical implementation. A NIST reviewer gets a self-contained
checkout that does not require network access.

The repository is **active** (not frozen). The submission tarball is
cut from a tag on `main` at NIST's deadline via
`scripts/cut-submission.sh`; reviewer feedback and post-submission
patches land in this same repository so the artifact chain stays
auditable.

**Date stamp (this revision): 2026-05-18.**

**Maturity stamp**: v0.2 ready. This submission is **not**
NIST-ratified, **not** FIPS 140-3 validated, **not** ACVP-validated,
and explicitly **not anchored to a FIPS standard** (R-LWE threshold
signing has no NIST standard — the academic Boschini et al. paper is
the construction spec). It is the algorithm-level reference plus
production lifecycle additions plus reproducibility tooling.

## At a glance

| Field | Value |
|---|---|
| Submission name | **Corona** |
| Submitting organisation | Lux Industries, Inc. |
| Algorithm | Threshold Ring-LWE 2-round signing + DKG + proactive resharing |
| Target NIST MPTC classes | **N1** (threshold signing, single-party-output-compatible against the construction's own verifier) + **N4** (multi-party key generation with public-key preservation across resharing) |
| Underlying construction | Boschini, Kaviani, Lai, Malavolta, Takahashi, Tibouchi. *Practical two-round threshold signatures from learning with errors.* IACR ePrint **2024/1113**, IEEE S&P 2025 |
| Lattice family | Ring-LWE over `R_q = Z_q[X]/(X^N + 1)`, `N = 256`, `q = 0x1000000004A01` (48-bit NTT-friendly prime) |
| Round count | 2 rounds per signature |
| Signature output | Byte-compatible with the construction's own verifier (`sign.Verify`); **NOT byte-equal to FIPS 204 ML-DSA** — that property belongs to the M-LWE sibling [`luxfi/pulsar`](https://github.com/luxfi/pulsar) |
| Hash suite | Corona-SHA3 (cSHAKE256 / KMAC256 / TupleHash256 per FIPS 202 + SP 800-185); legacy Corona-BLAKE3 retained for cross-port byte checks |
| Repository | <https://github.com/luxfi/corona> (single canonical home: code, spec pointers, KAT, cut tool) |
| Algorithm source | This repository, `sign/` + `threshold/` + `dkg2/` + `reshare/` + `primitives/` + `hash/`. Latest tagged release at this revision: `v0.4.1` (next: `v0.5.0` accompanying the submission package). |
| Tarball cut tool | `scripts/cut-submission.sh` (tags from `main`, regenerates KATs, snapshots vendor tree, tars) |
| Submission tag | `submission-YYYY-MM-DD` (cut from `main` at deadline) |
| Spec | `SPEC.md` + `papers/lp-073-pulsar/` LaTeX sections + `DESIGN.md`. The formal MPTC LaTeX spec (`spec/corona.tex`) is consolidated from existing material; full single-document spec.tex is in progress. |
| License | Apache-2.0 (code) — see `LICENSE` |
| Patent posture | **Royalty-free grant** — see `PATENTS.md` (public-facing grant text) and `docs/patent-claims.md` (attorney-prep claim drafts). Lux Industries grants a worldwide, royalty-free, irrevocable patent license to any implementation conformant to the Corona construction released under Apache-2.0 or compatible OSI license, OR any NIST MPTC / PQC / ACVP submission, validation, or interoperability test. Defensive termination mirrors Apache-2.0 §3. |
| Sibling submission | **Pulsar** ([`luxfi/pulsar`](https://github.com/luxfi/pulsar)) — M-LWE threshold ML-DSA with FIPS 204 byte-equality. Independent submission; reviewable separately. |

## Headline claim

> Every signature produced by a Corona threshold ceremony (DKG →
> Round-1 → Round-2 → Combine) verifies under the Corona verifier
> (`sign.Verify`) on the same message and group public key `(A, bTilde)`
> as a single-party Corona signature would, AND the underlying group
> public key is preserved bit-identically across proactive resharing
> events within a key era (Class N4 invariant).

This is a **construction-level interchangeability** claim, NOT a FIPS
204 byte-equality claim. Corona uses Ring-LWE arithmetic that has no
NIST standard analogue at the time of submission; the Boschini et al.
construction IS the spec.

**Verifier-side story (load-bearing for N1 framing).** Because there
is no NIST standard R-LWE threshold signature, the Class N1
"output-interchangeability" axis is reduced to: any verifier that
accepts a single-party run of the underlying Boschini et al.
construction MUST accept a Corona threshold-aggregated signature on
the same `(pk, m)`. The Corona reference verifier at
`sign/sign.go:Verify` plays both roles (threshold-output verifier and
single-party-output verifier) because the construction is symmetric
in that respect. A reviewer evaluating the N1 claim should compare
Corona's threshold-emitted bytes to the bytes a single-party run of
the same parameter set would produce on the reconstructed secret —
the comparison is via the same `Verify` routine, not via a third
party FIPS-validated verifier (which does not exist for R-LWE
threshold).

## Algorithm scope

The algorithm being submitted is the Corona implementation at
`luxfi/corona` v0.4.1. The construction is the 2-round protocol of
Boschini, Kaviani, Lai, Malavolta, Takahashi, Tibouchi
(IACR ePrint 2024/1113, IEEE S&P 2025) — **unchanged in its math** —
plus the following production lifecycle layers that the original
paper does not specify (these are Corona's contribution to the
submission package):

1. **Proper Pedersen DKG over `R_q`** with hiding blinds — `dkg2/`.
   Replaces the original construction's trusted-dealer assumption
   with a publicly-verifiable distributed key generation. The legacy
   `dkg/` package (Feldman VSS without blinding) is retained for
   historical reference only and is documented as broken for public
   broadcast (see `RED-DKG-REVIEW.md` in the production lineage).

2. **Proactive resharing across committee rotation** — `reshare/`.
   Preserves the group public key `(A, bTilde)` across validator-set
   changes within a key era; only the share distribution rotates.
   Two distinct primitives are exposed: `Refresh` (same set, fresh
   shares — HJKY97 lineage) and `ReshareToNewSet` (set rotation,
   new shares — Desmedt-Jajodia 1997 / Wong-Wang-Wing 2002 lineage).

3. **Identifiable abort with attributable evidence** — `dkg2/complaint.go`
   + `reshare/complaint.go`. Per-pair Pedersen-style verification with
   constant-time slot equality on the recipient side; failure produces
   signed evidence pointing to a malicious sender.

4. **Activation certificate** (the circuit-breaker) — `reshare/activation.go`.
   After a resharing finishes the math, the new committee
   threshold-signs an activation message under the unchanged group
   public key; only on successful verification does the chain mark
   the new epoch live.

5. **Hash-suite injection through every Sign-path primitive** —
   `hash/sp800_185.go` + `primitives/hash.go`. Production deployments
   use Corona-SHA3 (cSHAKE256 / KMAC256 / TupleHash256 per FIPS 202 +
   SP 800-185). The legacy Corona-BLAKE3 suite remains available for
   cross-port byte checks but is NOT the normative submission profile.

## What to read first

A reviewer with limited time should read in this order:

1. **`SUBMISSION.md`** (this file) — submission metadata and headline
2. **`NIST-SUBMISSION.md`** — one-page executive summary
3. **`SPEC.md`** — standalone construction specification
4. **`DESIGN.md`** — Pulsar/Corona lifecycle design (the "what is preserved across resharing" invariants)
5. **`PROOF-CLAIMS.md`** — what is claimed vs not (HONEST framing — no machine-checked refinement proof at this submission, unlike Pulsar)
6. **`TRUSTED-COMPUTING-BASE.md`** — implementation TCB (Go + lattigo + crypto/subtle)
7. **`docs/evaluation.md`** — performance + correctness + KAT cross-validation evidence
8. **`PATENTS.md`** — royalty-free patent grant text
9. **`README.md`** — repository layout and how to reproduce
10. **`CONSTANT-TIME-REVIEW.md`** — per-path constant-time audit (0 critical findings)
11. **`DEPLOYMENT-RUNBOOK.md`** — operator-facing trust-model disclosure

## What to run

The reproducibility gate is `scripts/build.sh` against the tarball
extract — the entire submission is self-contained, so no network
access is required:

```bash
tar xzf submission-YYYY-MM-DD.tar.gz
cd corona
scripts/build.sh          # builds Go ref
scripts/test.sh           # runs unit + KAT replay tests
scripts/bench.sh          # produces signing/verification benchmarks
scripts/gen_vectors.sh    # regenerates KAT vectors (deterministic)
```

`scripts/build.sh` exits non-zero on any failure. CI runs the same
script on every commit; the reproducibility property is the load-
bearing one for the submission.

To cut a fresh tarball (maintainer-side):

```bash
scripts/cut-submission.sh                       # dry-run, no tarball
scripts/cut-submission.sh submission-2026-11-16 # production cut + tag
```

The cut script verifies a clean tree, regenerates the KATs from the
in-tree canonical implementation, re-runs the round-trip replay
tests, tars the entire submission checkout, and prints the SHA-256.

## Class N1 — Construction-level output interchangeability

The N1 claim is asserted at **three** levels of evidence (one fewer
than Pulsar; the missing level is the machine-checked refinement
chain, because R-LWE has no FIPS standard to refine against):

| Evidence | Where |
|---|---|
| Algorithmic argument | `SPEC.md` §§7–8 + Boschini et al. ePrint 2024/1113 §§3–4 |
| Test harness | KAT replay tests; `cmd/cross_runtime_verify/` cross-runtime verification |
| Cross-implementation KATs | `cmd/cross_runtime_oracle/` + `scripts/regen-kats.sh` (Go ↔ C++ luxcpp port) |

**What Corona DOES NOT provide vs Pulsar**:

- No EasyCrypt refinement chain (Corona has no FIPS-standard target).
- No Lean ↔ EC algebraic bridge files.
- No Jasmin high-assurance implementation (libjade does not cover Corona's R-LWE parameter set).
- No machine-checked `Class N1 byte-equality` theorem.

The honest framing for Corona is: **production-hardened
implementation of a published academic construction**, not
**machine-checked refinement of a NIST standard**. The mechanized
proof tier remains a roadmap item; see `PROOF-CLAIMS.md` for the
narrow stated claim and the (admittedly long) closure path.

## Class N4 — Public-key preservation across resharing

Multi-party proactive resharing preserves the group public key
`(A, bTilde)` across committee rotations (epoch boundaries), so a
single long-lived public identity persists while the secret-share
custodians rotate.

| Evidence | Where |
|---|---|
| Algorithmic argument | `DESIGN.md` §"Three layers, one shipping path" + §"Two distinct primitives in pulsar/reshare/" |
| Test harness | `reshare/reshare_test.go`, `reshare/refresh_test.go`, `reshare/full_integration_test.go` (45 tests; activation under unchanged GroupKey is the load-bearing assertion) |
| KAT cross-validation | `cmd/reshare_oracle/` emits JSON consumed by the C++ port; `scripts/regen-kats.sh` enforces byte-equal round-trip |

## High-assurance track — HONEST DELTA vs Pulsar

Pulsar ships an EasyCrypt + Lean + Jasmin high-assurance track that
mechanically refines its Class N1 byte-equality claim against a
formal model of FIPS 204. **Corona does NOT ship that.** The honest
delta:

| Pulsar artifact | Corona equivalent | Status |
|---|---|---|
| 13/13 EasyCrypt files compile, 0/0 admits | none | NOT PRESENT — multi-month research project, see `PROOF-CLAIMS.md` |
| 5/5 Lean ↔ EC algebraic-bridge files | none | NOT PRESENT |
| 3/3 jasmin-ct blocking on threshold layer | none | NOT PRESENT — libjade does not target this parameter set |
| Class N1 byte-equality theorem (mechanized) | construction-level claim only | NOT MECHANIZED — Boschini et al. paper is the spec, no FIPS target |
| `pq-crystals` / BoringSSL / OpenSSL cross-validation | none possible | NOT APPLICABLE — no third-party R-LWE threshold verifier exists |

What Corona DOES offer at submission-time:

1. **Production-hardened reference implementation** in Go
   (`sign/`, `threshold/`, `dkg2/`, `reshare/`, `primitives/`, `hash/`).
2. **Per-path constant-time audit** (`CONSTANT-TIME-REVIEW.md`) — zero
   `(c)` (must-fix) entries, two documented `(b)` entries with
   mitigations.
3. **KAT-deterministic outputs** under Corona-SHA3 (and legacy
   Corona-BLAKE3 for cross-port byte checks).
4. **Cross-runtime byte-equality** (Go ↔ C++ port at
   `~/work/luxcpp/crypto/corona/`) enforced by
   `scripts/regen-kats.sh` manifest.
5. **Fuzz coverage** — `reshare/fuzz_*_test.go`, `dkg2/fuzz_round_test.go`,
   `threshold/fuzz_round_test.go`. Per-push smoke runs are
   informational; submission-grade fuzz budgets are operational.
6. **Identifiable-abort evidence pipeline** at the dkg2 / reshare layer.

## What this submission does NOT claim

- **No byte-equality with FIPS 204 ML-DSA** — that is Pulsar's claim.
  Corona is an independent R-LWE construction with no NIST standard
  to verify against.
- **No mechanized refinement proof** — no EasyCrypt, no Lean, no
  Jasmin. The construction is the published academic paper; the Go
  implementation matches it by reading, code review, and KAT
  cross-validation. Machine-checked refinement is a multi-month
  research roadmap item (see `PROOF-CLAIMS.md`).
- **No FIPS 140-3 module validation** — applies to packaged
  cryptographic modules, not this reference implementation. Downstream
  of this submission.
- **No ACVP / CAVP algorithm validation certificate** — no NIST ACVP
  test vector set exists for R-LWE threshold signatures.
- **No identifiable abort under network partition** — synchronous
  network assumption only; asynchronous identifiable abort is a
  separate problem.
- **No 1-round signing** — the construction is 2-round by design,
  inherited from Boschini et al. ePrint 2024/1113.
- **No bias-resistant DKG under collusion** — Pedersen DKG over `R_q`
  in `dkg2/` provides hiding and binding under standard assumptions;
  bias resistance under fully-colluding majority requires an external
  randomness beacon at the consensus layer (out of scope).
- **No cross-key-era preservation** — Reanchor (rare governance
  event) starts a new key era with a fresh `(A', s', bTilde')`;
  resharing only preserves `(A, bTilde)` **within** a key era.

## Comparison to sibling and related submissions

| Submission | Lattice | Round count | Output story | NIST class |
|---|---|---|---|---|
| **Corona** (this) | Ring-LWE (R-LWE) | 2 | Construction-level interchangeable with single-party Corona verifier; no NIST standard target | N1 + N4 |
| **Pulsar** ([`luxfi/pulsar`](https://github.com/luxfi/pulsar)) | Module-LWE (M-LWE) | 2 | Byte-equal to FIPS 204 ML-DSA-65 | N1 + N4 |
| Raccoon (NIST PQC) | Module-LWE | 3 | Compatible verification | not MPTC |
| Boschini et al. (academic upstream) | R-LWE | 2 | Construction-level; trusted-dealer Gen only | not submitted as MPTC |

The R-LWE / M-LWE pair is intentional. Lux's primary-network
QuasarCert MAY combine Corona (R-LWE) and Pulsar (M-LWE) as a
**Double Lattice** layered defence so a break in one lattice family
does not break finality. That layered combination is the consumer's
design choice and is not part of this submission. Corona stands
alone as an MPTC Class N1 + N4 candidate.

## Contact

- Primary: <z@lux.network> (Lux Industries, Inc.)
- Submission coordination: <mptc@lux.network>
- Security disclosure: see `SECURITY.md`
- Public discussion: <https://github.com/luxfi/corona/discussions>

## Reproducibility commitment

The build, test, vector-generation, and benchmark scripts are
deterministic from fixed seeds. A reviewer reproducing the
submission tarball from `submission-` should obtain
byte-identical artifacts. Drift is a build bug; please open an issue.

---

**Document metadata**

- Name: `SUBMISSION.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
- Submission package version: Corona v0.2 (tagged `submission-2026-11-16` on cut date)
- Underlying library version at this revision: `luxfi/corona v0.4.1`
