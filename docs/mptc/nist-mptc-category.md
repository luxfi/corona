# NIST MPTC category targeting — Corona

> Reference: NIST IR 8214C, *First Call for Multi-Party Threshold Schemes*
> (January 2026). Package deadline expected 2026-Nov-16. Preview deadline
> 2026-Jul-20.

## Corona target: **Class N1 + N4 (construction-level)**

NIST MPTC subdivides threshold schemes into:

- **Class S** (Special) — threshold-friendly primitives that *are not*
  output-interchangeable with a NIST-specified primitive. Submission
  evaluated for "novel threshold-friendly design."
- **Class N** (Normal-mode) — threshold implementations *of* a
  NIST-specified primitive whose outputs are interchangeable with the
  corresponding non-threshold primitive's outputs.
  - **N1**: signing
  - **N2**: encryption / decryption
  - **N3**: KEM
  - **N4**: ML keygen / DKG (Module-Lattice key generation, distributed)

Corona aims for **N1 (construction-level threshold signing) + N4
(distributed Ring-LWE keygen + reshare preservation)**.

### N1 framing for Corona — HONEST distinction from Pulsar

NIST's Class N is defined relative to a "NIST-specified primitive."
**R-LWE threshold signing has no NIST standard at submission time.**
This makes Corona's N1 framing structurally different from Pulsar's
(which targets FIPS 204 ML-DSA byte-equality):

| Aspect | Pulsar (M-LWE) | Corona (R-LWE) |
|---|---|---|
| NIST standard target | FIPS 204 ML-DSA-65 | **none** |
| Verifier-side interchange | byte-equal with BoringSSL FIPS / AWS-LC / OpenSSL 3.0 PQ | construction-level only (Corona's own `sign.Verify`) |
| Third-party FIPS-validated verifier exists | YES | NO |
| Mechanized refinement against the spec | EasyCrypt 13/13, 0/0 admits | NONE (no FIPS spec to refine against) |
| Class N1 evidence stack | Algorithmic + EC mechanized + Lean bridge + Jasmin-CT + 3-way KAT | Algorithmic + Go-vs-C++ cross-runtime KAT |

The honest framing for Corona's N1 claim: **construction-level output
interchangeability** — every threshold-emitted signature verifies
under the Corona reference verifier as a single-party Corona signature
would. This is necessary for N1 but is **NOT** the byte-equal-against-
FIPS framing that Pulsar provides.

A reviewer who weighs Class N strictly by NIST-standard-target presence
should classify Corona as Class S1 + S4 instead (special threshold-
friendly, no NIST standard). The N1 + N4 framing is appropriate IF the
reviewer accepts construction-level interchangeability as sufficient
for Class N status when no NIST standard exists for the underlying
primitive. This decision is for NIST MPTC reviewers, not for Lux to
preempt.

Corona's submission package is structured to support **either reading**:
- If N1 + N4: cite the construction-level interchange + reshare
  preservation as the relevant evidence.
- If S1 + S4: cite the same evidence + the production lifecycle
  additions (Pedersen DKG, reshare, activation cert, hash-suite
  injection) as the "novel threshold-friendly design" novelty.

The downstream consumer story is identical either way: Quasar
consensus uses Corona as the R-LWE finality kernel; threshold-emitted
signatures verify under `sign.Verify` regardless of whether NIST
ultimately classifies the submission N or S.

## Output interchangeability — what has to hold

Corona signatures `σ = (c, z, Δ)` are produced by:
- `c ∈ R_q` (ternary challenge)
- `z ∈ R_q^M` (Lagrange-aggregated response with low L2 norm)
- `Δ` (auxiliary; see `sign/sign.go`)

For Corona to claim Class N1 (construction-level), the threshold-
aggregated signature MUST:
1. Verify under unmodified `sign.Verify(group_pk, m, σ)`.
2. Be byte-stream-equivalent to what a single-party run of the same
   parameter set would emit on the Lagrange-reconstructed secret
   `s = Σ_{i ∈ Q} λ_i^Q · s_i`.

These conditions are inherited from Boschini et al. ePrint 2024/1113
§3 (the construction's correctness theorem). Corona's reference
implementation in `threshold/threshold.go` + `sign/sign.go` realizes
both conditions; KAT cross-runtime byte-equality (Go ↔ C++) provides
the test evidence.

## Required package deliverables

Per NIST IR 8214C §5:

| element | format | location |
|---|---|---|
| Technical Specification | LaTeX (paper sections) + Markdown (`SPEC.md` consolidated entry) | `papers/lp-073-pulsar/` + `SPEC.md`; single-doc `spec/corona.tex` is roadmap v0.6.0 |
| Reference Implementation | open-source code (Go) | `sign/`, `threshold/`, `dkg2/`, `reshare/`, `primitives/`, `hash/` |
| Report on Experimental Evaluation | Markdown + reproducible scripts | `docs/mptc/evaluation.md` + `scripts/bench.sh` |
| Notes on Patent Claims | Markdown (RF grant + attorney-prep drafts) | `PATENTS.md` + `docs/mptc/patent-claims.md` |
| Concrete parameter set | section in spec | `SPEC.md` §3 + `papers/lp-073-pulsar/` |
| Security analysis (proofs) | inherited from cited paper + Markdown framing | Boschini et al. ePrint 2024/1113 §3 + `PROOF-CLAIMS.md` |
| Public repository | GitHub | <https://github.com/luxfi/corona> |
| Build/test/benchmark scripts | shell | `scripts/*.sh` |
| Open-source license | text | `LICENSE` (Apache-2.0) |
| I/O test vectors | JSON (cross-runtime) | `cmd/*_oracle*/` + manifest at `scripts/regen-kats.manifest.sha256` |

Optional but strongly recommended (provided):
- Executive summary (1-2 pages) at front of spec — `NIST-SUBMISSION.md`.
- Threat-model document (`docs/mptc/threat-model.md`).
- Design-decisions document (`docs/mptc/design-decisions.md`).
- Trust-base document (`TRUSTED-COMPUTING-BASE.md`).
- Constant-time audit (`CONSTANT-TIME-REVIEW.md`).
- Honest non-claims (`PROOF-CLAIMS.md`).

## Required security strengths

NIST MPTC §4.5 gives the required and suggested security-strength
targets:

| target | classical | post-quantum (NIST PQ category) | statistical |
|---|---|---|---|
| **required** (≥1 parameterization) | ≥ 128 bits | ≥ Category 1 | ≥ 40 bits |
| **suggested** (additional, optional) | ≥ 192 bits | ≥ Category 3 | ≥ 64 bits |

Corona v0.4.1 ships a single parameter set tuned to provide ≥ 128
bits of post-quantum security per lattice-estimator methodology.
A second parameter set targeting NIST PQ Category 3 is roadmap
v0.6.0. Concrete lattice-estimator output for the current parameter
set is roadmap v0.6.0 — at submission scaffolding the security claim
is qualitative (per Lux engineering's design choice against the R-LWE
literature) rather than quantitative.

## Class N vs Class S decision (deferred to NIST)

Corona is N if and only if:
1. A working reference implementation produces signatures that verify
   under `sign.Verify` for any valid threshold ceremony. ✓ ATTESTED
2. The threshold key generation produces a `(A, bTilde)` that is a
   valid Corona group public key. ✓ ATTESTED
3. The verification relation is the Corona reference verifier
   (`sign.Verify`) verbatim, with no threshold-specific changes. ✓ ATTESTED

If NIST's interpretation of Class N requires the underlying primitive
to be a NIST standard (not just a published academic construction),
Corona falls back to Class S1 + S4. The evidence supports either
reading; the class decision is for NIST.

## Pulsar (M-LWE) for comparison

Pulsar targets **Class N1 + N4** unambiguously: FIPS 204 ML-DSA-65 is
a NIST standard, and Pulsar's threshold signature output is
byte-equal to FIPS 204 ML-DSA-65 verified by unmodified BoringSSL
FIPS / AWS-LC / OpenSSL 3.0 PQ. Pulsar's submission is at
<https://github.com/luxfi/pulsar>.

The R-LWE / M-LWE pair is intentional: Lux's primary-network
QuasarCert may combine Corona + Pulsar as a **Double Lattice**
layered defence (separate consumer-side design choice; not part of
this submission).

## Status

- [x] Class candidacy declared (N1 + N4 construction-level, with
      explicit honesty disclosure about lack of NIST standard target;
      S1 + S4 fallback acceptable if NIST prefers)
- [ ] Preview writeup drafted
- [ ] Preview submitted (target 2026-Jul-20)
- [ ] Single-document `spec/corona.tex` (roadmap v0.6.0)
- [x] Reference impl shipping (v0.4.1)
- [x] KAT cross-runtime byte-equality (Go ↔ C++)
- [x] Experimental-evaluation framing (`docs/mptc/evaluation.md`; specific numbers regenerated via `scripts/bench.sh`)
- [x] Patent-claims drafts (`docs/mptc/patent-claims.md`)
- [ ] Package submitted (target 2026-Nov-16)
- [ ] EasyCrypt theory shell (roadmap v0.7.0)
- [ ] dudect statistical CT harness (roadmap v0.8.0)
- [ ] External cryptographic audit (roadmap v0.8.0)

---

**Document metadata**

- Name: `docs/mptc/nist-mptc-category.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
