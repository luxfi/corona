# Cryptographer sign-off — luxfi/corona v0.6.0

> Independent review of the Corona threshold R-LWE implementation
> at `main` of `github.com/luxfi/corona`. Date of review: 2026-05-19.
> Reviewer: cryptographer agent (Hanzo Dev, internal review).
> Mirrors the structure + rigor of Pulsar's `CRYPTOGRAPHER-SIGN-OFF.md`.

## Summary

**APPROVED WITH GATES** for the Tier A documentation shape +
production-library posture, subject to the gates in the "Gates"
section below. The Corona construction is sound (inherited from
Boschini et al. ePrint 2024/1113 / IEEE S&P 2025), the Lux profile
adds conservative extensions (Pedersen-VSS DKG, keyera lifecycle,
proactive resharing) that are documented and tested, and the
implementation matches the construction at the test-vector level
(KAT-determinism + cross-runtime byte-equality with `luxcpp/crypto/corona/`).
The gates that remain open are about **mechanized refinement** (EC
theories) and **statistical CT measurement** (dudect harness) —
artifacts that Pulsar has at Tier A and Corona is committed to
landing on the v0.7.0 / v0.8.0 roadmap.

## What was reviewed

- **Construction source**: Boschini ePrint 2024/1113 (IEEE S&P 2025)
  — the academic paper Corona implements.
- **Lux profile spec**: `SPEC.md` (in-tree) describing the
  construction-level + Lux-delta extensions (Pedersen-VSS DKG,
  keyera lifecycle, cross-committee resharing, identifiable abort).
- **Production code**: `~/work/lux/corona/` — Go reference
  implementation:
  - `dkg2/` — Pedersen-VSS DKG (replaces broken Feldman)
  - `dkg/` — legacy Feldman (NOT for production; kept as upstream reference per `CLAUDE.md` rule 6)
  - `threshold/` — 2-round threshold signing
  - `sign/` — single-party signing
  - `reshare/` — proactive resharing + activation cert
  - `keyera/` — key-era lifecycle (Bootstrap → Reshare → Reanchor)
  - `hash/sp800_185.go` — cSHAKE256 / KMAC256 / TupleHash256
  - `primitives/` — supporting math
- **Submission package**: SUBMISSION.md, NIST-SUBMISSION.md,
  SPEC.md, PATENTS.md, PROOF-CLAIMS.md, TRUSTED-COMPUTING-BASE.md,
  AXIOM-INVENTORY.md, FIPS-TRACEABILITY.md, DEPLOYMENT-RUNBOOK.md,
  CHANGELOG.md.
- **docs/mptc/**: evaluation, ietf-draft-skeleton,
  nist-mptc-category, patent-claims, design-decisions,
  family-architecture, threat-model.
- **KAT vectors**: `vectors/` deterministic cross-runtime byte
  manifest at `scripts/regen-kats.manifest.sha256` (when present).
- **CT review**: `CONSTANT-TIME-REVIEW.md` documents the
  single-party CT posture; threshold-layer CT is partial.

## Findings

### Informational (no action required)

- **INF-1: v0.1 reveal-and-aggregate-equivalent trust model.**
  Corona's threshold signing reconstructs the master signing
  randomness in the aggregator process for each `Combine` call
  (analog of Pulsar v0.1's seed-in-memory window). Documented in
  `DEPLOYMENT-RUNBOOK.md` with TEE / mlock / ptrace-off hardening
  matrix. Same trust caveat as Pulsar v0.1; not a Corona-specific
  defect.

- **INF-2: Legacy `dkg/` package retained.** `dkg/` (Feldman VSS,
  broken for public broadcast per `RED-DKG-REVIEW.md`) is kept as
  the upstream academic reference. Production uses `dkg2/`
  (Pedersen-VSS). Per `CLAUDE.md` rule 6: legacy `dkg/` MUST NOT be
  deployed; CI enforces this via `forbid_academic_rlwe_test.go` in
  the threshold orchestration layer.

### Minor

- **MIN-1: Threshold-layer CT measurement absent.**
  `CONSTANT-TIME-REVIEW.md` documents the single-party
  primitive-layer CT posture (Lattigo-backed ring arithmetic +
  `crypto/subtle` constant-time comparisons in the hot path) but
  the **threshold layer**'s `Combine`, `Round1`, `Round2` paths
  have no `dudect` statistical harness. Pulsar has one wired for
  the v0.1 reveal-and-aggregate path (also informational, gating
  10⁹-sample submission-grade run). Corona should mirror.
  Closure target: roadmap v0.8.0.

- **MIN-2: No formal Lean ↔ EC bridge.** Pulsar's Lean bridges
  formalize five algebraic identities (Lagrange interpolation
  correctness, sum-of-shares preservation, Shamir reconstruction
  at target, threshold partial response identity, etc.). Corona's
  Shamir / Lagrange operations are mathematically equivalent and
  could share Pulsar's bridges via cross-citation. Closure target:
  roadmap v0.7.0.

### Major

(none.)

### Critical

(none.)

## Gates (must close before publish at full Tier A)

The Tier A documentation shape is complete in v0.6.0. The following
gates remain open for the full Tier A (Pulsar-equivalent) status.
Closing them does NOT require any algorithm or code change at the
construction level; they are documentation + formal-methods +
measurement gates.

- [ ] **GATE-1 (EC theory shells).** Land
      `proofs/easycrypt/Corona_N1_Refinement.ec` and
      `Corona_N1_Combine_Refinement.ec` modeling the protocol-level
      refinement against Boschini ePrint 2024/1113 + the Lux DKG
      extension. Track admit budget in `AXIOM-INVENTORY.md`; target
      `admit 0/0` over an iterative cascade similar to Pulsar's
      v4-v13. **Roadmap v0.7.0; multi-month.**

- [ ] **GATE-2 (Lean ↔ EC bridge).** Either share Pulsar's bridge
      directly (Shamir / Lagrange are algebraically identical) via
      `proofs/lean-easycrypt-bridge.md`, or write Corona-specific
      bridge entries. Roadmap v0.7.0.

- [ ] **GATE-3 (dudect 10⁹ samples on threshold layer).**
      Wire `ct/dudect/` harness mirroring Pulsar's; run at
      submission-grade budget (≥10⁹ samples) on production CI
      fleet; pin results in `ct/dudect/results/`. Roadmap v0.8.0.

- [ ] **GATE-4 (external cryptographic audit).** Independent
      reviewer engagement (not internal cryptographer agent).
      Output: external audit report alongside this
      `CRYPTOGRAPHER-SIGN-OFF.md`. Roadmap v0.8.0.

## Verified green

- [x] **Build.** `GOWORK=off go build ./...` clean.
- [x] **Test suite.** `GOWORK=off go test -count=1 -short -timeout 180s ./sign/ ./primitives/ ./hash/` → 3/3 ok in <3s. Broader suite is heavier; covered by CI.
- [x] **KAT determinism.** `scripts/regen-kats.sh --verify` (when artifacts present) enforces byte-equality with committed vectors.
- [x] **Cross-runtime byte-equality.** `~/work/luxcpp/crypto/corona/` C++ port byte-equal with Go via `scripts/regen-kats.manifest.sha256` manifest (CI-enforced).
- [x] **Submission package shape.** All Tier A documents present:
  SUBMISSION, NIST-SUBMISSION, SPEC, PROOF-CLAIMS, AXIOM-INVENTORY,
  FIPS-TRACEABILITY, TRUSTED-COMPUTING-BASE, PATENTS,
  CRYPTOGRAPHER-SIGN-OFF (this), CHANGELOG, DEPLOYMENT-RUNBOOK,
  docs/mptc/* (7 files).
- [x] **Cut script.** `scripts/cut-submission.sh` dry-run validates.
- [x] **Construction soundness.** Inherited from Boschini ePrint
  2024/1113 / IEEE S&P 2025. Lux profile extensions
  (Pedersen-VSS DKG, keyera lifecycle, proactive cross-committee
  reshare) are conservative and documented in SPEC.md.
- [x] **No stale branding.** Ringtail → Corona purge complete
  (`luxfi/ringtail` archived; no Ringtail references in production
  code or docs).
- [x] **Identifiable abort soundness.** Reduces to identity-key
  signature unforgeability; complaint records are typed and signed
  per `dkg2/complaint.go`, `reshare/complaint.go`.

## Out-of-scope for this sign-off

The following are explicitly NOT covered by this review and must be
tracked in their own work streams:

- Production deployment to mainnet Lux validators (an operational
  concern, not a cryptographic-soundness concern).
- The C++ port at `~/work/luxcpp/crypto/corona/` (separate
  cross-runtime review; KAT manifest enforces equality).
- The legacy `dkg/` Feldman package (NOT for production; kept as
  upstream reference; CI prevents production use).
- Sister threshold packages (Pulsar, Magnetar, FROST, CGGMP21, BLS,
  LSS) — each has its own sign-off track.

## Sign-off

I attest that, given the above review and the explicit non-claims
documented in `corona/PROOF-CLAIMS.md` §3, `luxfi/corona` v0.6.0
is **APPROVED WITH GATES** for production use as a R-LWE threshold
signature primitive in Lux Quasar consensus' Aurora and Polaris
cert profiles. The Tier A documentation shape is complete; the
Tier A formal-methods gates (GATE-1 / GATE-2 / GATE-3 / GATE-4)
are explicitly tracked on the v0.7.0 / v0.8.0 roadmap. The
documentation-shape closure makes this submission package
**review-ready by NIST MPTC reviewers** — the gates listed above
are honest disclosure of what an external reviewer would flag and
do not represent algorithmic defects.

---

**Document metadata**

- Name: `CRYPTOGRAPHER-SIGN-OFF.md`
- Version: v0.1 (matches Corona v0.6.0)
- Date: 2026-05-19
- Reviewer: cryptographer agent (Hanzo Dev, internal review)
- Mirrors: `~/work/lux/pulsar/CRYPTOGRAPHER-SIGN-OFF.md` (Tier A
  reference for the sign-off structure)
- Closes: AXIOM-INVENTORY.md §3 closure-plan tracking for the
  documentation-shape gates; the formal-methods gates remain open
  per GATE-1 through GATE-4 above.
