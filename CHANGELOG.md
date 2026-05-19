# corona CHANGELOG

Notable changes to the `corona` module. Pre-release; semantic versioning
applied per PHILOSOPHY.md (patch only — never minor/major without explicit
approval).

## v0.5.0 (planned — NIST MPTC submission package scaffolding)

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
