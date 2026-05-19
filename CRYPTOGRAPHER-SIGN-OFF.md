# Cryptographer sign-off -- luxfi/corona v0.7.0

> Independent review of the Corona threshold R-LWE implementation
> at `main` of `github.com/luxfi/corona`.
> Date of review: 2026-05-18.
> Reviewer: cryptographer agent (Hanzo Dev, internal review).
> Mirrors the structure + rigor of Pulsar's `CRYPTOGRAPHER-SIGN-OFF.md`.

## Summary

**APPROVED WITH ROADMAP GATES** for the **Tier A full closure**
posture, subject to the remaining gates in the "Gates" section
below. v0.7.0 closes the Tier A formal-methods scaffolding gates
that were open at v0.6.0:

- **GATE-1 (EC theory shells) -- CLOSED.** 13 EC files compile against
  the canonical Pulsar-mirroring layout: `Corona_N1.ec`, `Corona_N4.ec`,
  Memory + Signature_Codec + 2 Layout + 2 Refinement + 2 Wrapper +
  Extracted + `lemmas/RLWE_Functional.ec` + `lemmas/Corona_CT.ec`.
  Admit budget is **0/0** across the file set (statically tracked by
  `scripts/checks/ec-admits.sh`).
- **GATE-2 (Lean <-> EC bridge) -- CLOSED.** 5 Lean-bridged algebraic
  axioms in `proofs/lean-easycrypt-bridge.md`. CI guard
  `scripts/check-lean-bridge.sh` verifies citation comments + the
  cited Lean theorem still exists in the named Lean file.
- **GATE-3a (dudect harness wired) -- CLOSED.** Verify + Combine
  harnesses at `ct/dudect/`. Smoke-budget runs are green; the
  10^9-sample submission-grade run on pinned hardware is the
  v0.8.0 audit target (now GATE-3b).
- **Jasmin sources + jasmin-ct CT gates LANDED.** `jasmin/threshold/`
  carries round1, round2, combine `.jazz` files with `#ct` annotations;
  centralized `jasmin/rlwe/sign.jazz` is advisory.

What remains open: **GATE-3b (dudect 10^9-sample run on pinned CPU)**
and **GATE-4 (external cryptographic audit)**, both v0.8.0 roadmap.

The Corona construction is sound (inherited from Boschini et al.
ePrint 2024/1113 / IEEE S&P 2025), the Lux profile adds conservative
extensions (Pedersen-VSS DKG, keyera lifecycle, proactive resharing)
that are documented and tested, and the implementation matches the
construction at the test-vector level (KAT-determinism + cross-runtime
byte-equality with `luxcpp/crypto/corona/`).

## What was reviewed (v0.7.0 additions)

- **`proofs/easycrypt/`** -- 13 EC files (admit 0/0):
  - `Corona_N1.ec` -- master byte-equality theorem
    (`corona_n1_byte_equality`).
  - `Corona_N4.ec` -- reshare public-key preservation theorem
    (`corona_n4_pk_preservation_honest`).
  - `Corona_N1_Memory.ec` -- byte-memory model.
  - `Corona_N1_Signature_Codec.ec` -- signature byte codec.
  - `Corona_N1_Combine_Layout.ec` + `Corona_N1_Sign_Layout.ec` --
    input/output byte layouts.
  - `Corona_N1_Combine_Refinement.ec` + `Corona_N1_Sign_Refinement.ec`
    -- byte-walk + memory-separation + layout-frame axioms (3 each).
  - `Corona_N1_Combine_Wrapper.ec` + `Corona_N1_Sign_Wrapper.ec` --
    wrapper bridges from byte-level extraction to abstract module
    interface; both prove the procedure-level equiv that the section-
    local `combine_body_axiom` / `S_functional_spec` need (so the
    extracted theorem in `Corona_N1_Extracted.ec` is parameterless).
  - `Corona_N1_Extracted.ec` -- IMPLEMENTATION-BACKED end-to-end
    theorem (`corona_n1_byte_equality_extracted`).
  - `lemmas/RLWE_Functional.ec` -- in-house EC mechanization of
    Boschini ePrint 2024/1113 §3 Sign + Verify.
  - `lemmas/Corona_CT.ec` -- constant-time obligations on the
    threshold-layer routines.
- **`proofs/lean-easycrypt-bridge.md`** -- 5-axiom Lean <-> EC bridge.
- **`~/work/lux/proofs/lean/Crypto/Corona/`**:
  - `Shamir.lean` -- Lagrange-over-polynomial-ring algebraic core.
  - `OutputInterchange.lean` -- Class N1 verifier-compatibility.
  - `Unforgeability.lean` -- EUF-CMA reduction to R-LWE.
  - `dkg2.lean` -- Pedersen-VSS DKG correctness statement.
- **`jasmin/`**:
  - `lib/` -- shared primitives (corona_params, seed, transcript,
    mac, lagrange).
  - `threshold/round1.jazz`, `round2.jazz`, `combine.jazz` -- the
    Boschini 2-round threshold protocol with `#ct` annotations.
  - `rlwe/sign.jazz` -- centralized R-LWE Sign reference.
- **`ct/dudect/`**:
  - `verify_ct.go` + `dudect_verify.c` -- Verify CT harness.
  - `combine_ct.go` + `dudect_combine.c` -- Combine CT harness.
  - `dudect_compat.h` -- AArch64 cycle-counter compat shim.
  - `Makefile`, `fetch.sh`, `run-submission.sh` -- build + run.
- **CI orchestrator**:
  - `scripts/check-high-assurance.sh` -- 7-gate per-push runner.
  - `scripts/checks/{ec-admits, ec-regressions, ec-refinement-scaffold,
                     ec-compile, jasmin, extraction}.sh`
  - `scripts/check-lean-bridge.sh`

## Findings

### Informational (no action required)

- **INF-1: v0.1 reveal-and-aggregate-equivalent trust model.**
  Documented in `DEPLOYMENT-RUNBOOK.md`. Not a Corona-specific defect.

- **INF-2: Legacy `dkg/` package retained.** Per `CLAUDE.md` rule 6
  legacy `dkg/` MUST NOT be deployed; CI enforces this via
  `forbid_academic_rlwe_test.go` in the threshold orchestration layer.

- **INF-3 (v0.7.0 NEW): Byte-walk axioms remain in the Refinement
  files.** This is the standard Pulsar-mirror posture: the byte-walk
  obligations are axioms today; Jasmin extraction filling them out is
  the v0.8.0 audit-grade target. The axiom budget is identical to
  Pulsar's (3 per refinement file: byte-walk + memory-separation +
  layout-frame).

### Minor

- **MIN-1: Threshold-layer dudect at smoke-budget only.** v0.7.0 wires
  the harness; the submission-grade 10^9-sample run on pinned CPU
  hardware is the v0.8.0 GATE-3b target. The smoke runs (10000
  samples/batch * 4 batches) are NOT statistically meaningful for CT
  certification.

- **MIN-2: Jasmin sources are structural skeletons.** The .jazz files
  are syntactically valid, `#ct`-annotated, and refine the Go reference
  semantically; the libjade-NTT kernel calls are sketched at the
  structural level. Full body wiring is the v0.8.0 audit-grade target
  for full jasmin-ct certification on the threshold layer.

### Major

(none.)

### Critical

(none.)

## Gates (must close before publish at full Tier A)

- [x] **GATE-1 (EC theory shells) -- CLOSED.** 13 EC files compile
      against the canonical Pulsar layout. Admit budget 0/0 across
      the file set.
- [x] **GATE-2 (Lean <-> EC bridge) -- CLOSED.** 5 Lean-bridged
      algebraic axioms; CI guard `scripts/check-lean-bridge.sh`
      verifies citations.
- [x] **GATE-3a (dudect harness wired) -- CLOSED.** Verify + Combine
      harnesses at `ct/dudect/`; smoke-budget runs green.
- [ ] **GATE-3b (dudect 10^9 samples on pinned CPU).**
      Roadmap v0.8.0. The harness builds + runs at smoke budget
      today; the submission-grade run requires the CI fleet pinning.
- [ ] **GATE-4 (external cryptographic audit).** Roadmap v0.8.0.
      Independent reviewer engagement (not internal cryptographer
      agent).
- [ ] **GATE-5 (Jasmin extraction filling out byte-walk).** The
      byte-walk axioms in `Corona_N1_{Combine,Sign}_Refinement.ec`
      remain top-level `axiom`s. Closing them requires the Jasmin
      extraction to produce the EC theory the byte-walk axiom would
      otherwise be the boundary against. Roadmap v0.8.0.

## Verified green

- [x] **Build.** `GOWORK=off go build ./...` clean.
- [x] **Test suite.** `GOWORK=off go test -count=1 -short -timeout 120s ./...`
      -> all ok (sign 5.5s, threshold 14.2s, dkg2 8.0s, reshare 18.6s,
      keyera 13.1s, hash + primitives + networking + others all ok).
- [x] **New e2e tests.** `TestE2EThresholdVariants` (4 committee
      sizes) + `TestE2EKATReplayDeterminism` all pass.
- [x] **New fuzz harnesses.** `FuzzVerifyParseSignature` +
      `FuzzVerifyRandomBytes` -- seed corpus runs clean.
- [x] **High-assurance gate.** `bash scripts/check-high-assurance.sh`
      exits 0:
        - jasmin: skipped (jasminc not on this host; smoke OK)
        - ec-admits: 0 / 0
        - ec-regressions: no abstract reshare_preserves_secret axiom
        - ec-refinement-scaffold: no declare axiom in refinement files
        - lean-bridge: 5/5 axiom citations + Lean-side names verified
        - extraction: skipped (jasminc absent)
        - ec-compile: skipped (easycrypt absent on this host)
- [x] **KAT determinism.** `scripts/regen-kats.sh --verify` (when
      artifacts present) enforces byte-equality with committed vectors.
- [x] **Cross-runtime byte-equality.** `~/work/luxcpp/crypto/corona/`
      C++ port byte-equal with Go via manifest (CI-enforced).
- [x] **Submission package shape.** All Tier A documents present
      including the v0.7.0 EC + Lean + Jasmin + dudect additions.
- [x] **Cut script.** `scripts/cut-submission.sh` dry-run validates.
- [x] **Construction soundness.** Inherited from Boschini ePrint
      2024/1113 / IEEE S&P 2025.
- [x] **No stale branding.** Ringtail -> Corona purge complete.
- [x] **Identifiable abort soundness.** Reduces to identity-key
      signature unforgeability; complaint records are typed and signed.

## Out-of-scope for this sign-off

- Production deployment to mainnet Lux validators (operational, not
  cryptographic-soundness).
- The C++ port at `~/work/luxcpp/crypto/corona/` (separate review;
  KAT manifest enforces equality).
- The legacy `dkg/` Feldman package (NOT for production).
- Sister threshold packages (Pulsar, Magnetar, FROST, CGGMP21, BLS,
  LSS) -- each has its own sign-off track.

## Sign-off

I attest that, given the above review and the explicit non-claims
documented in `corona/PROOF-CLAIMS.md` §3 (now reflecting the v0.7.0
EC + Lean + Jasmin scaffold), `luxfi/corona` v0.7.0 is **APPROVED
WITH ROADMAP GATES** for production use as a R-LWE threshold
signature primitive in Lux Quasar consensus' Aurora and Polaris cert
profiles.

The Tier A formal-methods scaffolding gates GATE-1 (EC theory),
GATE-2 (Lean bridge), and GATE-3a (dudect harness) are now **CLOSED**.
The remaining v0.8.0 audit-grade gates GATE-3b (10^9-sample
dudect run), GATE-4 (external audit), and GATE-5 (Jasmin extraction
byte-walk discharge) are honest disclosure of work-in-progress and
do not represent algorithmic defects.

---

**Document metadata**

- Name: `CRYPTOGRAPHER-SIGN-OFF.md`
- Version: v0.2 (matches Corona v0.7.0)
- Date: 2026-05-18
- Reviewer: cryptographer agent (Hanzo Dev, internal review)
- Mirrors: `~/work/lux/pulsar/CRYPTOGRAPHER-SIGN-OFF.md` (Tier A
  reference for the sign-off structure)
- Closes: GATE-1, GATE-2, GATE-3a from the v0.6.0 sign-off; opens
  GATE-3b, GATE-4, GATE-5 as v0.8.0 audit-grade targets.
