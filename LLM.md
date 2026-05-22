# Corona -- Agent Knowledge Base

**Repository**: github.com/luxfi/corona
**Latest Tag**: v0.7.4 (next: v0.7.5 — public-BFT Bootstrap default closes the last unqualified trusted-dealer dispatch)
**Status**: Production (consensus path); NIST MPTC submission package included. Sibling submission `luxfi/pulsar` is the M-LWE byte-equal FIPS 204 path.

## Purpose (one-liner)

Ring-LWE threshold signature library used as the post-quantum threshold
layer in Quasar consensus. Corona provides O(1) per-cert proofs after
DKG, paired with BLS12-381 + ML-DSA-65 in the QuasarCert.

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
Pulsar does; Corona's R-LWE has no FIPS standard target to refine against. See
`PROOF-CLAIMS.md` §3 for the explicit non-claims list.

## Recent significant commits

| SHA | Tag | Impact |
|-----|-----|--------|
| (pending) | v0.7.5 | keyera: Bootstrap default → BootstrapPedersen; trusted-dealer impl moved to unexported helper; loud-name invariant restored across both Bootstrap and Reanchor |
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
| `4d02472` | v0.4.x | corona: final Ringtail purge — code, docs, KAT-side PRF tag |
| `43e7d88` | v0.4.x | corona/papers: ringtail2025 cite → boschini2024corona; ringtailThreshold → coronaThreshold in TeX |

### Active versions
- Repo: `v0.7.4` (next: `v0.7.5` flips the default `keyera.Bootstrap` / `keyera.BootstrapWithSuite` to route through `BootstrapPedersen`, matching the v0.7.4 Reanchor flip; the legacy trusted-dealer impl is now in the unexported `bootstrapTrustedDealerImpl` and only reachable via the explicit `BootstrapTrustedDealer*` / `ReanchorTrustedDealer*` names).
- Pinned by: `luxfi/consensus v1.23.6+` (R-LWE path is consensus-only).

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
  - `luxfi/consensus/protocol/quasar` (R-LWE threshold for QuasarCert).
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

### Open follow-ups (roadmap)
- v0.6.0: single-document `spec/corona.tex` + parameter-set worksheet
- v0.7.0: EasyCrypt theory shell + Lean Lagrange-aggregation mechanization (RESEARCH; multi-month)
- v0.8.0: dudect-style statistical CT harness + external cryptographic audit
- Variable-size R-LWE certs remain a wire-size cost vs Pulsar M-LWE; consensus uses Corona for finality-throughput and Pulsar for the identity rollup.

## Rules

1. Patch-bump only (`v0.7.x → v0.7.y`). Minor bumps require explicit approval.
2. HashSuite is the only acceptable hash plumbing (F22 closure); never
   hardcode SHAKE / KMAC outside `hash/sp800_185.go`.
3. Param changes require a new key-era boundary; never edit in place.
4. NEVER claim mechanized refinement Corona does not have. See `PROOF-CLAIMS.md` §3.
5. NEVER mix Pulsar (M-LWE) types into Corona (R-LWE) — independent libraries with no shared types.
6. NEVER push the legacy `dkg/` package onto a deployment surface — it has known
   leakage (Feldman VSS without blinding). Production uses `dkg2/`.
7. Cross-runtime byte-equality with the C++ port (`~/work/luxcpp/crypto/corona/`)
   is a CI-enforced invariant via `scripts/regen-kats.sh --verify`.
