# Corona -- Agent Knowledge Base

**Repository**: github.com/luxfi/corona
**Latest Tag**: v0.10.0 (Corona certified a STRICT trustless lane: dealerless Pedersen DKG keygen + no-reconstruct signing — the no-reconstruct signing property is now PINNED by a code-level structural+behavioural gate, `threshold/no_reconstruct_sign_test.go`)
**Status**: Production (consensus path); NIST MPTC submission package included. Sibling submission `luxfi/pulsar` is the M-LWE byte-equal FIPS 204 path.

## Purpose (one-liner)

Module-LWE threshold signature library used as the post-quantum threshold
layer in Quasar consensus. Corona provides O(1) per-cert proofs after
DKG, paired with BLS12-381 + ML-DSA-65 in the QuasarCert.

Keygen is **natively dealerless**: the Pedersen DKG (`dkg2/`, entered via
`keyera.Bootstrap` → `BootstrapPedersen`) is the production default since
v0.7.5 — no single party ever holds the secret. Signing never reconstructs
the key: `SignFinalize` sums the per-party partial responses
(`z_sum = Σ z_j`, then `A·z_sum`); `ReconstructSecret` was dropped (`f08e2b5`),
and the trusted-dealer helpers (`GenerateKeysTrustedDealer`,
`BootstrapTrustedDealer*`) are tests / KAT / CLI footguns, never the chain
keygen path. This is why **Corona — not Pulsar — carries the permissionless /
no-trusted-dealer guarantee** in the Quasar AND-mode dual-PQ cert: Pulsar's
byte-FIPS-204 keygen is provably stuck at a trusted dealer (a dealerless sum
of FIPS-204 secrets breaks ML-DSA's small-norm `S_η` bound), so the
dealerless property must come from Corona's Module-LWE leg.

This repository is BOTH the production library AND the active NIST MPTC
submission package (Class N1 + N4). The submission tarball is cut from a
tag on `main` via `scripts/cut-submission.sh`; reviewer feedback lands here.

## NIST MPTC submission package (this revision)

| Doc | Purpose |
|-----|---------|
| `SUBMISSION.md` | Cover sheet — cites Boschini et al. 2024/1113, declares construction-level N1 + N4, honest delta vs Pulsar |
| `NIST-SUBMISSION.md` | One-page executive summary |
| `SPEC.md` | Standalone construction specification (companion to `papers/lp-073-pulsar/`) |
| `PROOF-CLAIMS.md` | HONEST framing — NO mechanized refinement; KAT + code review + academic construction analysis |
| `PATENTS.md` | Royalty-free grant + defensive termination |
| `TRUSTED-COMPUTING-BASE.md` | Implementation TCB (Go + lattigo + crypto/subtle); structurally simpler than Pulsar's |
| `DEPLOYMENT-RUNBOOK.md` | Operator-facing trust-model disclosure |
| `LICENSING.md`, `CONTRIBUTING.md`, `SECURITY.md` | Standard NIST-MPTC artifacts |
| `docs/evaluation.md` | Performance + correctness + KAT cross-validation |
| `docs/ietf-draft-skeleton.md` | IETF draft skeleton (HONEST: draft form) |
| `docs/nist-mptc-category.md` | Class N1 + N4 mapping for Corona |
| `docs/patent-claims.md` | Attorney-prep claim drafts (FEWER than Pulsar — only Corona-novel lifecycle additions) |

**HONESTY GUARD**: do not claim Corona has EC / Lean / Jasmin proofs. It does not.
Pulsar does; Corona's Module-LWE construction has no FIPS standard target to refine against. See
`PROOF-CLAIMS.md` §3 for the explicit non-claims list.

## Recent significant commits

| SHA | Tag | Impact |
|-----|-----|--------|
| `500d319` | v0.10.0 | threshold: pin Corona NO-RECONSTRUCT signing (gate 5, trustless-by-default law). `threshold/no_reconstruct_sign_test.go` — GATE A go/ast scan (no signing function recombines shares into s nor invokes the trusted-dealer keygen; per-party `party.Lambda` allowed; negative-control verified), GATE B reflect (Round1Data/Round2Data/Signature carry no share), GATE C independent-verifier ceremony. Complements the Lean-4 `secret_aggregate_no_reconstruct` proof at the code level. Audit verdict: Corona is a STRICT trustless lane for STRICT_DUAL_PQ / POLARIS_MAX |
| `7996ad7` | v0.9.0 | merge Phase-3a: corona keyera DKG cutover onto `luxfi/dkg` v0.2.0 (shared dealerless no-reconstruct VSS); `dkg2` package deleted |
| `f08e2b5` | v0.8.0 | threshold: trusted-dealer keygen made explicit/footgun-only; dead `ReconstructSecret` dropped; sub-quorum soundness pinned — signing sums partials, master secret never formed |
| `7c102d2` | v0.7.9 | threshold: reject duplicate PartyID in Round2/Finalize combine (kernel-boundary uniq guard) |
| `6b4d5d5` | v0.7.8 | docs: correct stale 'no EC toolchain' claims; combine bridge discharged to lemma + jasminc available |
| `baf2ba8` | v0.7.7 | ec: machine-check all 14 theories; discharge combine bridge C11 → lemma via `no_leak_z_aggregate` keystone, residual shrunk to public w-agreement |
| `ee2c5b8` | v0.7.6 | threshold: canonical wire codec for Signature / GroupKey / VerifyBytes |
| `1d44430` | v0.7.5 | keyera: public-BFT `Bootstrap` default → `BootstrapPedersen`; trusted-dealer impl moved to unexported helper; loud-name invariant across Bootstrap + Reanchor |
| `607d71c` | v0.7.4 | keyera: ReanchorPedersen — closes Reanchor trusted-dealer regression; `mathSqrt` → stdlib `math.Sqrt` |
| `e412c7e` | v0.7.3 | keyera: BootstrapPedersen — Pedersen-DKG over R_q + Path (a) noise flooding; closes trusted-dealer caveat |
| `920195e` | v0.7.2 | gpu: opt corona threshold signing into lattice/ring GPU NTT dispatch |
| `4f54c28` | v0.7.1 | remove detailed patent-claims docs (relocated to lux-private/patents) |
| `6f905a0` | v0.7.0 | Tier A full closure: EC theories admit 0/0 + Lean bridges + Jasmin CT + dudect harness + e2e/fuzz |
| `1726e36` | v0.4.1 | threshold: add parallel VerifyBatch — N-signature throughput for consensus |
| `2d910dc` | v0.4.x | corona: don't mix — QUASAR-PULSAR-* prefixes -> QUASAR-CORONA-* in Corona's table |
| `13e1cd8` | v0.4.x | corona: doc drift cleanup — CHANGELOG references match renamed Go code |
| `a7c3919` | v0.4.x | corona: symmetric domain separation — PULSAR-* tags -> CORONA-* |
| `2b262ef` | v0.4.x | go.mod: bump go directive to 1.26.3 (security advisory) |
| `4d02472` | v0.4.x | corona: final Corona purge — code, docs, KAT-side PRF tag |
| `43e7d88` | v0.4.x | corona/papers: Corona2025 cite → boschini2024corona; coronaThreshold → coronaThreshold in TeX |

### Active versions
- Repo: `v0.8.0`. The default `keyera.Bootstrap` / `keyera.BootstrapWithSuite` route through `BootstrapPedersen` (dealerless Pedersen DKG over R_q); the legacy trusted-dealer impl is the unexported `bootstrapTrustedDealerImpl`, reachable only via the explicit `BootstrapTrustedDealer*` / `ReanchorTrustedDealer*` names.
- Pinned by: `luxfi/consensus v1.23.6+` (Module-LWE path is consensus-only).

### Canonical params
- Ring degree: 256 (LogN=8).
- M=8, N=7, Dbar=48, Kappa=23.
- Q=0x1000000004A01 (48-bit NTT-friendly prime).
- Hash suite: Corona-SHA3 (KMAC over cSHAKE256), `hash/sp800_185.go`.

### Cross-repo dependencies
- `luxfi/math/codec` → wire codec (LP-107 Phase 4).
- `luxfi/lattice/v7` → lattigo-backed polynomial ops.
- `golang.org/x/crypto/sha3` → cSHAKE256 / KMAC256 / TupleHash256.
- `zeebo/blake3` → LEGACY only (cross-port byte-check).
- Consumed by:
  - `luxfi/consensus/protocol/quasar` (Module-LWE threshold for QuasarCert).
- Cross-runtime byte-equal port: `~/work/luxcpp/crypto/corona/` (KAT manifest at `scripts/regen-kats.manifest.sha256`).

### Where to look for X
- Threshold kernel: `threshold/` (includes `verify_batch.go`)
- 2-round signing: `sign/`
- Pedersen DKG (lifecycle, replaces broken `dkg/`): `dkg2/`
- Legacy Feldman DKG (broken for public broadcast; reference only): `dkg/`
- Proactive resharing (Refresh + ReshareToNewSet): `reshare/`
- Activation cert circuit-breaker: `reshare/activation.go`
- Corona-SHA3 / KMAC: `hash/sp800_185.go`
- Key-era management: `keyera/`
- KAT oracles: `cmd/{reshare,dkg2,activation,cross_runtime,sign,corona_oracle_v2}*/`
- Submission scripts: `scripts/{cut-submission,build,test,bench,gen_vectors,check-high-assurance,regen-kats}.sh`

### Open follow-ups (tracked in BLOCKERS.md)
- Constant-time: `jasminc -checkCT` on the extracted threshold layer + dudect submission-grade 10⁹-sample run (CORONA-CT-PENDING).
- `no_leak_reduction` discharged to a full Module-LWE/M-SIS simulation proof, OR accepted by external review as a standard reduction; plus the C11′ public-`w` commitment-aggregate bridge (CORONA-EC-RECON-MODEL).
- Independent Module-LWE interop verifier, OR external review accepting the same-construction Go↔C++ KAT posture (CORONA-NO-INDEP-VERIFIER).
- External cryptographic review — shared gate across the three open findings above.
- Variable-size Corona (Module-LWE, Raccoon-line) certs remain a wire-size cost vs Pulsar's fixed-size ML-DSA certs; consensus uses Corona for finality-throughput and Pulsar for the identity rollup.

## Rules

1. Patch-bump only (`v0.7.x → v0.7.y`). Minor bumps require explicit approval.
2. HashSuite is the only acceptable hash plumbing (F22 closure); never
   hardcode SHAKE / KMAC outside `hash/sp800_185.go`.
3. Param changes require a new key-era boundary; never edit in place.
4. NEVER claim mechanized refinement Corona does not have. See `PROOF-CLAIMS.md` §3.
5. NEVER mix Pulsar (ML-DSA) types into Corona (threshold-Raccoon) — both Module-LWE, but independent libraries with no shared types.
6. NEVER push the legacy `dkg/` package onto a deployment surface — it has known
   leakage (Feldman VSS without blinding). Production uses `dkg2/`.
7. Cross-runtime byte-equality with the C++ port (`~/work/luxcpp/crypto/corona/`)
   is a CI-enforced invariant via `scripts/regen-kats.sh --verify`.
