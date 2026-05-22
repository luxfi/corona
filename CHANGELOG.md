# corona CHANGELOG

Notable changes to the `corona` module. Pre-release; semantic versioning
applied per PHILOSOPHY.md (patch only -- never minor/major without explicit
approval).

## v0.7.3 (public-BFT Bootstrap via dkg2 Pedersen-DKG + Path (a) noise flooding)

Closes the last trusted-dealer caveat in `keyera.Bootstrap` for any
deployment that cannot vouch for a single dealer's host platform. The
trusted-dealer path is retained (under a renamed alias) for genesis
ceremonies where a non-distributed trust root is acceptable by policy.

### New public surface (`keyera/bootstrap_pedersen.go`)

- `keyera.BootstrapPedersen(suite, t, validators, groupID, eraID, entropy)
  (*KeyEra, *BootstrapTranscript, error)` -- public-BFT-safe bootstrap.
  Routes the keygen ceremony through `dkg2/` (Pedersen-DKG over `R_q`) +
  Path (a) noise flooding so no single party ever holds the master
  secret `s` at any point in the ceremony.

- `keyera.FinishBootstrapPedersen(suite, t, validators, ..., dkgParams,
  sessions, round1) (*KeyEra, *BootstrapTranscript, error)` -- kernel
  entrypoint that drives Rounds 1.5 + 2 + Path (a) on a pre-computed
  set of Round 1 outputs. Tests use this to inject deliberately
  dishonest contributions and exercise the identifiable-abort path.

- `keyera.BootstrapTrustedDealer` / `keyera.BootstrapTrustedDealerWithSuite`
  -- renamed aliases for the legacy single-dealer path. Retained for
  genesis ceremonies where the foundation explicitly chooses a
  non-distributed trust root (see `DEPLOYMENT-RUNBOOK.md
  §Bootstrap-Trust` decision matrix).

- `keyera.BootstrapTranscript` -- public, byte-stable record produced
  by every Pedersen bootstrap run. Honest validators that observe the
  same cohort messages compute identical transcript bytes; the chain
  commits to `TranscriptHash` to ratify the era.

- `keyera.AbortEvidence` + `keyera.ExtractAbortEvidence(err)` -- public
  surface for identifiable-abort consumption. A non-nil `AbortEvidence`
  carries the disqualified set and signed `dkg2.Complaint`s ready for
  the slashing pipeline.

### Tests (`keyera/bootstrap_pedersen_test.go`)

All green via `GOWORK=off go test -count=1 -short ./keyera/`:

- `TestBootstrapPedersen_RoundTrip` -- 5-party Pedersen-DKG with `t=3`;
  transcript determinism across replays; bTilde / digest stability.
- `TestBootstrapPedersen_DishonestDealer` -- tampered share-to-recipient-0
  triggers `ErrBootstrapPedersenAbort` naming sender 2; `AbortEvidence`
  carries a re-checkable `ComplaintBadDelivery`.
- `TestBootstrapPedersen_FollowedBySign` -- Pedersen bootstrap → standard
  2-round threshold sign → `threshold.Verify` PASS. The noise-flooded
  GroupKey is structurally identical to a trusted-dealer Corona setup.
- `TestBootstrapPedersen_NoMasterSecretInMemory` -- structural assertion
  that `dkg2.DKGSession` exposes no master-secret field, and that no two
  parties' SkShares / Lambdas collide.
- `TestBootstrapPedersen_ParameterValidation` -- bounds checking.
- `TestBootstrapPedersen_DefaultSuite` -- `nil` resolves to Corona-SHA3.
- `TestBootstrapTrustedDealer_LegacyAlias` -- legacy alias is byte-
  equivalent to historical `Bootstrap`.

### Documentation

- `AUDIT-2026-05.md` -- read-only SOTA refresh covering threshold lattice
  DKG / signing literature 2024-2026. Verdict: Boschini-Takahashi-Tibouchi
  2024/1113 remains canonical; 2025 follow-ups (del Pino, Doerner-Kondi,
  Hofheinz, Beimel-Eitan) are complementary or non-blocking; no SOTA
  refresh blocks this revision.
- `DEPLOYMENT-RUNBOOK.md` -- new `§Bootstrap-Trust` decision matrix
  documenting Option A (`BootstrapPedersen`, recommended) vs Option B
  (`BootstrapTrustedDealer`, ceremony-only) trade-off.
- `keyera/keyera.go` -- inline trust-model documentation pointing at
  `BootstrapPedersen` as the public-BFT-safe alternative.

### Cross-runtime byte equality

- KAT manifest preserved (`scripts/regen-kats.manifest.sha256`); existing
  trusted-dealer KATs continue to byte-match `~/work/luxcpp/crypto/corona/`.
- `BootstrapPedersen` adds new ceremony bytes (deterministic given
  entropy); a future cross-runtime port can pin them via the public
  `BootstrapTranscript.TranscriptHash`.

## v0.7.0 (Tier A full closure -- EC + Lean + Jasmin + dudect scaffolding)

This revision lands the Tier A formal-methods scaffolding for Corona,
mirroring Pulsar's structure exactly. Closes GATE-1 / GATE-2 / GATE-3a
from the v0.6.0 sign-off.

### EasyCrypt theories (13 files; admit budget 0/0)

- `proofs/easycrypt/Corona_N1.ec` -- master byte-equality theorem
  (`corona_n1_byte_equality`).
- `proofs/easycrypt/Corona_N4.ec` -- reshare public-key preservation
  (`corona_n4_pk_preservation_honest`).
- `proofs/easycrypt/Corona_N1_Memory.ec` -- byte-memory model + frame laws.
- `proofs/easycrypt/Corona_N1_Signature_Codec.ec` -- signature codec.
- `proofs/easycrypt/Corona_N1_Combine_Layout.ec` -- Combine byte layout.
- `proofs/easycrypt/Corona_N1_Sign_Layout.ec` -- Sign byte layout.
- `proofs/easycrypt/Corona_N1_Combine_Refinement.ec` -- 3 byte-walk +
  memory-separation + layout-frame axioms.
- `proofs/easycrypt/Corona_N1_Sign_Refinement.ec` -- 3 byte-walk axioms.
- `proofs/easycrypt/Corona_N1_Combine_Wrapper.ec` -- wrapper bridge.
- `proofs/easycrypt/Corona_N1_Sign_Wrapper.ec` -- wrapper bridge.
- `proofs/easycrypt/Corona_N1_Extracted.ec` -- IMPLEMENTATION-BACKED
  end-to-end theorem.
- `proofs/easycrypt/lemmas/RLWE_Functional.ec` -- in-house EC
  mechanization of Boschini ePrint 2024/1113 §3 Sign + Verify.
- `proofs/easycrypt/lemmas/Corona_CT.ec` -- constant-time obligations.
- `proofs/easycrypt/README.md` -- file map + admit budget.

### Lean <-> EC bridge (5 axioms)

- `proofs/lean-easycrypt-bridge.md` -- 5-axiom Lean <-> EC bridge:
  `lagrange_inverse_eval`, `threshold_partial_response_identity`,
  `add_share_zeroR`, `reconstruct_linear`, `shamir_correct`.
- `~/work/lux/proofs/lean/Crypto/Corona/Shamir.lean` -- Lagrange-over-
  polynomial-ring algebraic core.
- `~/work/lux/proofs/lean/Crypto/Corona/OutputInterchange.lean` --
  Class N1 verifier-compatibility.
- `~/work/lux/proofs/lean/Crypto/Corona/Unforgeability.lean` --
  EUF-CMA reduction to Ring-LWE.
- `~/work/lux/proofs/lean/Crypto/Corona/dkg2.lean` -- Pedersen-VSS DKG.

### Jasmin sources

- `jasmin/lib/corona_params.jinc` -- parameter set.
- `jasmin/lib/seed.jinc` -- per-round PRNG seed derivation.
- `jasmin/lib/transcript.jinc` -- transcript-hash binder.
- `jasmin/lib/mac.jinc` -- per-peer MAC primitive.
- `jasmin/lib/lagrange.jinc` -- Lagrange-coefficient computation.
- `jasmin/threshold/round1.jazz` -- per-party Round-1 commit (#ct).
- `jasmin/threshold/round2.jazz` -- per-party Round-2 response (#ct).
- `jasmin/threshold/combine.jazz` -- Combine aggregation (#ct).
- `jasmin/rlwe/sign.jazz` -- centralized Boschini Sign reference.
- `jasmin/README.md` -- layout + refinement-target table.

### dudect harness

- `ct/dudect/verify_ct.go` + `dudect_verify.c` -- Verify harness.
- `ct/dudect/combine_ct.go` + `dudect_combine.c` -- Combine harness.
- `ct/dudect/dudect_compat.h` -- AArch64 cycle-counter compat shim.
- `ct/dudect/Makefile` + `fetch.sh` + `run-submission.sh`.

### CI orchestrator (7 gates)

- `scripts/check-high-assurance.sh` -- mirrors Pulsar's structure
  exactly. Sequences jasmin + ec-admits + ec-regressions +
  ec-refinement-scaffold + lean-bridge + extraction + ec-compile.
- `scripts/checks/ec-admits.sh` -- admit-budget 0/0 static guard.
- `scripts/checks/ec-regressions.sh` -- retired-axiom regression guard.
- `scripts/checks/ec-refinement-scaffold.sh` -- declare-axiom hygiene.
- `scripts/checks/ec-compile.sh` -- EC compile gate.
- `scripts/checks/jasmin.sh` -- jasmin type-check + jasmin-ct gate.
- `scripts/checks/extraction.sh` -- Jasmin -> EC extraction sanity.
- `scripts/check-lean-bridge.sh` -- 5-axiom Lean <-> EC bridge guard.

### Tests

- `threshold/e2e_threshold_variants_test.go` -- (3,2), (5,3), (7,4),
  (10,7) committee-size e2e variants + KAT replay determinism.
- `threshold/fuzz_verify_test.go` -- `FuzzVerifyParseSignature` +
  `FuzzVerifyRandomBytes`.

### Documentation updates

- `AXIOM-INVENTORY.md` -- v0.7.0 EC residual axiom inventory (admit
  budget 0/0; 5 Lean-bridged + N codec + construction-level axioms).
- `PROOF-CLAIMS.md` -- §3.1 and §3.7 updated to reflect the EC + Lean
  + Jasmin scaffold landing.
- `CRYPTOGRAPHER-SIGN-OFF.md` -- v0.2; closes GATE-1, GATE-2, GATE-3a;
  opens GATE-3b, GATE-4, GATE-5 as v0.8.0 audit-grade targets.

## v0.5.0 (NIST MPTC submission package scaffolding)

### Submission documentation added (no code changes)

This revision adds the NIST MPTC Class N1 + N4 submission package
scaffolding. Pattern mirrors `luxfi/pulsar` (the M-LWE byte-equal
FIPS 204 sibling), adapted honestly to Corona's lighter proof tier.

- `SUBMISSION.md` — NIST MPTC cover sheet. Cites Boschini et al. ePrint
  2024/1113 (IEEE S&P 2025) as the underlying construction. Declares
  construction-level N1 (no FIPS standard target available for R-LWE
  threshold) + N4 (`(A, bTilde)` preserved across reshare within key era).
  Two-variant honesty disclosure: Pedersen DKG (`dkg2/`) is the production
  path; legacy `dkg/` is retained for historical reference only.
- `NIST-SUBMISSION.md` — one-page executive summary.
- `SPEC.md` — standalone construction specification. Pointer to
  `papers/lp-073-pulsar/` LaTeX sections + `DESIGN.md` invariants.
  Full single-document `spec/corona.tex` is roadmap (v0.6.0).
- `PATENTS.md` — royalty-free patent grant + defensive termination.
  Claim scope explicitly EXCLUDES the Boschini et al. published
  construction (academic prior art); claims are limited to Corona's
  production lifecycle additions.
- `PROOF-CLAIMS.md` — HONEST framing. Corona ships NO mechanized
  refinement (no EasyCrypt, no Lean, no Jasmin). Construction-level
  claim only; correctness reduces to code review + KAT + Boschini et
  al. analysis. Mechanized refinement is roadmap (v0.7.0).
- `TRUSTED-COMPUTING-BASE.md` — implementation TCB. Structurally
  simpler than Pulsar's (no EC/Lean/Jasmin tools); higher per-component
  trust on Go reference review + KAT cross-runtime byte-equality.
- `DEPLOYMENT-RUNBOOK.md` — operator-facing trust-model disclosure.
- `LICENSING.md` — pointer to LICENSE + Lux three-tier IP strategy.
- `CONTRIBUTING.md`, `SECURITY.md` — standard NIST-MPTC artifacts.
- `docs/evaluation.md` — performance + correctness + KAT + CT evidence.
- `docs/ietf-draft-skeleton.md` — IETF draft skeleton (HONEST: draft).
- `docs/nist-mptc-category.md` — Class N1 + N4 mapping for Corona.
- `docs/patent-claims.md` — attorney-prep claim drafts (FEWER than
  Pulsar — only Corona-novel lifecycle additions, not the published
  Boschini et al. construction).
- `docs/design-decisions.md`, `docs/family-architecture.md`,
  `docs/threat-model.md` — adapted from Pulsar's pattern to Corona's
  R-LWE / `R_q` setting.

### Honest gaps documented

This submission EXPLICITLY does NOT include (per `PROOF-CLAIMS.md` §3):
- EasyCrypt theories (`Corona_N1.ec` does not exist).
- Lean ↔ EC algebraic-bridge files.
- Jasmin sources (libjade does not target Corona's parameter set).
- Mechanized refinement proof of any kind.
- dudect-style statistical CT validation harness.
- Full LaTeX `spec/corona.tex` single-document spec (paper sections at
  `papers/lp-073-pulsar/` are the current canonical material).
- Parameter-set worksheet with concrete lattice-estimator bounds.
- ACVP/CAVP algorithm validation certificate (no NIST ACVP test vector
  set exists for R-LWE threshold).
- FIPS 140-3 module validation (downstream).
- External cryptographic audit (engaged lab) — roadmap v0.8.0.

### CI gates maintained

- `scripts/build.sh` exits 0 on a fresh clone.
- `scripts/test.sh` exits 0 (Go unit + integration + KAT).
- `scripts/regen-kats.sh --verify` exits 0 (cross-runtime byte-equality
  with `~/work/luxcpp/crypto/corona/` C++ port).
- `scripts/check-high-assurance.sh` — stub at this revision; runs the
  available checks (no EC/Lean/Jasmin to run).

### Tarball cut tooling

- `scripts/cut-submission.sh` — adapted from Pulsar's; produces
  `submission-YYYY-MM-DD.tar.gz` from a clean tag on `main`.

## v0.4.1 (current)

Latest production tag at this revision. See git log for the full v0.4.x
history (Ringtail purge, domain-separation rename PULSAR-* → CORONA-*,
Go 1.26.3 toolchain bump, parallel `VerifyBatch` for N-signature
consensus throughput).

## Unreleased

### Breaking — F22 hash-suite injection into Sign

`corona/primitives/hash.go` no longer hardcodes `blake3.New()`. Every
Sign-path primitive now takes a `hash.HashSuite` as its first argument:

```
PRNGKey(suite, skShare)                       // was PRNGKey(skShare)
PRNGKeyForRound(suite, skShare, sid)          // was PRNGKeyForRound(skShare, sid)
GenerateMAC(suite, TildeD, MACKey, ...)       // was GenerateMAC(TildeD, MACKey, ...)
GaussianHash(suite, r, hash, mu, sigma, ...)  // was GaussianHash(r, hash, mu, sigma, ...)
PRF(suite, r, sd_ij, key, mu, hash, n)        // was PRF(r, sd_ij, key, mu, hash, n)
Hash(suite, A, b, D, sid, T)                  // was Hash(A, b, D, sid, T)
LowNormHash(suite, r, A, b, h, mu, kappa)     // was LowNormHash(r, A, b, h, mu, kappa)
```

`suite == nil` resolves to the production default, `Corona-SHA3`
(cSHAKE256 / KMAC256 / TupleHash256 per FIPS 202 + NIST SP 800-185).
The legacy `Corona-BLAKE3` suite remains available via
`hash.NewCoronaBLAKE3()` for cross-port byte checks.

`sign.Party` gains a `Suite hash.HashSuite` field, defaulted by
`NewParty` to `hash.Default()`. Operators can construct with an explicit
suite via `NewPartyWithSuite(id, r, rXi, rNu, sampler, suite)`. The free
function `sign.Verify(...)` keeps its previous signature and now resolves
to the production default internally; the suite-explicit form is
`sign.VerifyWithSuite(suite, ...)`.

This closes the gap where the HIP-0077 claim that Corona uses SHA-3
cSHAKE256/KMAC256/TupleHash256 in production was structurally false at
the Sign layer (only `corona/reshare/`, `corona/dkg2/`, `corona/keyera/`
were consuming `corona/hash/HashSuite` previously).

### Follow-up — KAT regeneration

The historical BLAKE3 KAT transcripts emitted by
`cmd/corona_oracle_v2` were computed against the previous raw
`blake3.New()` framing in `primitives/hash.go`. After this refactor, the
oracle still emits under `coronahash.NewCoronaBLAKE3()`, but the framing
now includes the suite's customization tags (`CORONA-HC-v1`,
`CORONA-HU-v1`, `CORONA-PRF-v1`, etc.) and length-prefixing, so the
emitted bytes no longer byte-match pre-refactor JSON.

The Corona-SHA3 production KATs are not yet emitted. Both lie outside
the scope of this PR:

- Regenerate the legacy BLAKE3 oracle JSON
  (`go run ./cmd/corona_oracle_v2 emit --out ./test/kats/blake3`)
  and cross-validate with the C++ port.
- Land a parallel `cmd/corona_oracle_v3` (or `--suite` flag) that
  emits Corona-SHA3 KATs under `./test/kats/sha3/` and pin them as the
  normative reference for downstream ports.

The skipped test `TestKATsRegenerated` in
`primitives/hash_test.go` is the placeholder guard.
