# SPEC — Corona Threshold Ring-LWE Signature (v0.2)

> **Standalone protocol specification** for **Corona** — a 2-round
> threshold Ring-LWE signature scheme with Pedersen DKG over `R_q`
> and proactive resharing.
>
> Companion to:
> - `papers/lp-073-pulsar/lp-073-pulsar-pedersen-dkg.tex` — DKG section
> - `papers/lp-073-pulsar/lp-073-pulsar-resharing.tex` — resharing section
> - `DESIGN.md` — Pulsar / Corona lifecycle design (the "what is preserved" invariants)
> - `docs/ietf-draft-skeleton.md` — IETF Internet-Draft version
>
> A single-document `spec/corona.tex` consolidating this material into
> the formal MPTC LaTeX spec format is in progress; the present
> document is the canonical reviewer entry point at submission scaffolding
> time.

## §1 Scope

This document specifies **Corona**, the Ring-LWE 2-round threshold
signature construction shipped at `github.com/luxfi/corona`. Corona
implements the published construction of Boschini, Kaviani, Lai,
Malavolta, Takahashi, and Tibouchi (IACR ePrint 2024/1113, IEEE S&P
2025) on a fixed parameter set, plus the production lifecycle layers
that the academic paper does not specify (Pedersen DKG over `R_q`,
proactive resharing, identifiable abort, activation certificates,
KAT-deterministic Corona-SHA3 hash suite).

This spec does NOT cover:
- The single-party FIPS 204 ML-DSA algorithm (different lattice
  family — see Pulsar at `~/work/lux/pulsar/`).
- Verifier implementations beyond the Corona reference verifier
  (`sign/sign.go:Verify`). No third-party R-LWE threshold verifier
  exists at submission time.
- Pulsar (Module-LWE sibling) — see `https://github.com/luxfi/pulsar`.
- Magnetar (Tier 3 SLH-DSA research profile) — see
  `https://github.com/luxfi/magnetar`.

## §2 Terminology

| Term | Meaning |
|---|---|
| **Party** | A computing entity participating in DKG / signing. |
| **Quorum** `Q` | Subset of parties of size ≥ `t`. |
| **Sharing polynomial** `f` | Degree `t − 1` polynomial whose constant term is the master secret `s ∈ R_q`. |
| **Group public key** `(A, bTilde)` | Pair of public matrix `A ∈ R_q^{k×ℓ}` (expanded from `sid`) and rounded LWE image `bTilde ≈ Round(A·s + e)`. |
| **Session identifier** `sid` | Fresh randomness binding a session. |
| **Key era** | Lineage of a group public key. Preserved across resharing; bumps only at Reanchor. |
| **Generation** | LSS resharing version within a key era. Bumps on every Refresh / Reshare. |
| **Activation cert** | Threshold signature under unchanged `(A, bTilde)` proving new committee's signing capability after a Reshare. |

## §3 Parameter set (single set in v0.2)

| Identifier | Value | Source |
|---|---|---|
| Ring degree `N` | 256 (`LogN = 8`) | `threshold/threshold.go` |
| Polynomial ring | `R_q = Z_q[X]/(X^N + 1)` | construction |
| Prime modulus `q` | `0x1000000004A01` (48-bit NTT-friendly) | `threshold/threshold.go` |
| Module width `M` | 8 | `sign.M` |
| Module height `N_M` | 7 | `sign.N` |
| Challenge weight `Kappa` | 23 | `threshold/threshold.go` |
| Decomposition `Dbar` | 48 | `threshold/threshold.go` |

The single-set submission is intentional: Corona ships a fixed
parameter set tuned to provide ≥ 128 bits of post-quantum security
against the best known R-LWE attacks (per the lattice-estimator
methodology of Albrecht-Player-Scott). A second parameter set
targeting NIST PQ Category 3 is on the roadmap but is NOT in this
submission package.

## §4 Threat model

Per `DESIGN.md` §"Three layers, one shipping path". Summary:

- Static corruption of at most `t − 1` parties.
- Rushing Byzantine adversary.
- Synchronous network with known upper bound `Δ` on message delivery.
- Pedersen DKG (`dkg2/`) provides hiding and binding; legacy `dkg/`
  (Feldman VSS without blinding) is documented as broken for public
  broadcast and is retained for historical reference only.
- R-LWE hardness over the fixed parameter set (Lyubashevsky-Peikert-
  Regev 2010 + follow-up analysis).
- cSHAKE256 / KMAC256 / TupleHash256 collision/preimage resistance
  per FIPS 202 + SP 800-185.

## §5 Security goals

1. **EUF-CMA-Threshold**: no forgery under honest-quorum. Inherited
   from Boschini et al. ePrint 2024/1113 Theorem 4.1 (with the caveat
   that the original paper assumes trusted-dealer Gen; Corona's
   `dkg2/` strengthens this to publicly-verifiable DKG).
2. **Construction-level output interchangeability** (Class N1 / MPTC):
   threshold-emitted bytes verify under the construction's own
   verifier (`sign.Verify`); no FIPS standard target.
3. **Public-key preservation across resharing** (Class N4 / MPTC):
   `(A, bTilde)` byte-identical across Refresh / ReshareToNewSet
   within a key era.
4. **Identifiable abort** with attributable evidence under
   synchronous network assumptions.
5. **Robustness**: ≥ t honest parties → valid signature with
   overwhelming probability.

Detailed proofs / reductions: see `PROOF-CLAIMS.md` for the honest
framing (Corona ships no mechanized refinement at this submission).
The academic proofs in Boschini et al. ePrint 2024/1113 §3 cover the
EUF-CMA reduction for the construction; Corona inherits that
analysis as paper-cited prior art.

## §6 Pedersen DKG over `R_q`

Per `papers/lp-073-pulsar/lp-073-pulsar-pedersen-dkg.tex` (LP-073).
Highlights:

- Each party `i` samples a sharing polynomial `f_i(X)` of degree
  `t − 1` over `R_q^M`.
- Coefficient commitments `C_i^(k) = A·NTT(f_i^(k)) + B·NTT(r_i^(k))`
  where `A, B` are public R_q^M generators derived from `sid_dkg`
  via cSHAKE256, and `r_i^(k)` is a per-coefficient hiding blind.
- Per-pair encrypted-share exchange under authenticated KEX.
- Complaint round produces signed public evidence of malformed
  shares.
- Qualified set `QSET` determined by complaint resolution; if
  `|QSET| < t`, DKG ABORTS.
- Final group public key `bTilde = Round(Σ_{i ∈ QSET} f_i^(0) · A + e)`.
- Implementation: `dkg2/dkg2.go` (commit-share-verify),
  `dkg2/complaint.go` (complaint handling).

Constant-time guarantee: `dkg2/dkg2.go:VerifyShareAgainstCommits`
calls `constTimePolyEqual` over the little-endian byte view of
every `Coeffs[level]` — no early return; the loop runs to completion
before the final `if eq != 1` branch. See `CONSTANT-TIME-REVIEW.md`
§2 for the per-line audit.

## §7 Threshold signing (2 rounds)

Per Boschini et al. ePrint 2024/1113 §3, retargeted to Corona's
parameter set:

**Round 1 (commit).** Each party `i ∈ Q`:
- Samples `y_i ← R_q^M` from a discrete Gaussian (lattigo
  `KeyedPRNG`-backed sampler).
- Computes `w_i = A · y_i`.
- Broadcasts a commitment to `w_i` (cSHAKE256 hash with domain
  separation tag `QUASAR-CORONA-SIGN1-v1`).

**Aggregator.** Collects all commitments from `Q`, computes
the canonical Lagrange aggregation, derives the challenge
`c ← H_c(transcript)` where `H_c` is the ternary-challenge hash
(TupleHash256 with prefix `QUASAR-CORONA-COMBINE-v1`).

**Round 2 (respond).** Each party `i ∈ Q`:
- Computes its partial response `z_i = y_i + c · s_i` over `R_q^M`.
- Broadcasts `z_i` to the aggregator. Authenticated with a per-pair
  KMAC256 MAC derived from the DKG-established pairwise material.

**Combine.** Aggregator:
- Verifies each `z_i` MAC.
- Computes aggregated `z = Σ_{i ∈ Q} λ_i^Q · z_i` where `λ_i^Q` are
  the Lagrange coefficients evaluated at zero for the quorum's
  party indices.
- Checks low-norm conditions on `z` (Boschini et al. ePrint 2024/1113
  Figure 2).
- If accept, packages signature `σ = (c, z, Δ)` per
  `sign/sign.go:Sign`.

Total bandwidth per signing session: 2 broadcast rounds + 1
aggregator-to-all round; `O(n · |w| + n · |z|)` per session.

## §8 Verification

Corona reference verifier at `sign/sign.go:Verify`:

```
sign.Verify(groupKey, message, signature) ∈ {OK, FAIL}
```

The verifier:
1. Reconstructs `w = A · z - c · bTilde` (from the signature's `z`
   and the public `(A, bTilde)`).
2. Recomputes `c' = H_c(transcript_with_w)`.
3. Verifies `c' == c` via constant-time `r.Equal` (lattigo).
4. Checks low-norm bound on `z` (`primitives.CheckL2Norm`).

No third-party FIPS-validated verifier exists for R-LWE threshold
signatures at submission time. Corona's verifier is the spec.

## §9 Proactive resharing

Per `papers/lp-073-pulsar/lp-073-pulsar-resharing.tex` (LP-073).
Preserves `(A, bTilde)` across committee rotation. Two distinct
primitives:

### §9.1 Refresh (same committee, fresh shares)

Each party samples a degree-`t-1` polynomial `z_i(x)` with `z_i(0) = 0`,
distributes `z_i(α_j)` to each peer, and each party updates
`s'_j = s_j + Σ_i z_i(α_j)`. Master secret `s` unchanged. Defends
against mobile-adversary share accumulation. Implementation:
`reshare/refresh_test.go` exercises the round-based protocol.

### §9.2 ReshareToNewSet (set rotation, new shares)

Old qualified subset `Q ⊆ O_old` with `|Q| ≥ t_old` cooperates.
Each `i ∈ Q` samples a fresh polynomial `g_i(x)` of degree
`t_new − 1` with `g_i(0) = s_i` (own old share as constant term).
Delivers `g_i(β_j)` to each new party `j`. New party `j` computes
`s'_j = Σ_{i ∈ Q} λ^Q_i · g_i(β_j)`. The new polynomial
`g(x) = Σ λ^Q_i · g_i(x)` satisfies `g(0) = Σ λ^Q_i · s_i = s` —
recovers the same master secret structurally. Implementation:
`reshare/reshare.go` + `reshare/keyshare.go`.

## §10 Identifiable abort

Per `DESIGN.md` §"Two distinct primitives in pulsar/reshare/" +
§"VSR maturity ladder". TLV-encoded per-kind abort evidence:
- Missing message (timeout + signed absence)
- Equivocation (two signed conflicting messages from same sender)
- Malformed ciphertext (decryption-oracle evidence with care
  taken not to leak threshold-reconstructing data)
- Invalid share contribution (Pedersen commit mismatch with
  constant-time slot-equality check from `dkg2/`)

Implementation: `dkg2/complaint.go` + `reshare/complaint.go`.

## §11 Transcript and domain separation

`DOMAIN_PREFIX` values are defined in `DESIGN.md` §"Domain-separated
message prefixes":

| Prefix | Used for |
|---|---|
| `QUASAR-CORONA-BUNDLE-v1` | Corona pulse over a Quasar bundle |
| `QUASAR-CORONA-SIGN1-v1` | Corona signing Round 1 commit |
| `QUASAR-CORONA-SIGN2-v1` | Corona signing Round 2 response |
| `QUASAR-CORONA-COMBINE-v1` | Corona finalize transcript |
| `QUASAR-CORONA-REFRESH-v1` | Refresh activation cert (same set) |
| `QUASAR-CORONA-RESHARE-v1` | Reshare activation cert (set rotation) |
| `QUASAR-CORONA-ACTIVATE-v1` | Generic activation cert |
| `QUASAR-CORONA-REANCHOR-v1` | Reanchor authorization (governance) |

Replay binding includes `sid + chain_id + epoch + (n, t) + QSET-hash +
M-hash + ctx-hash + key_era_id + group_id + reshare_transcript_hash +
implementation_version`.

## §12 Wire formats

Polynomial vectors and matrices serialize through `luxfi/math/codec`
(LP-107 Phase 4). The `Vector[Poly]` frame is validated before
lattigo `ReadFrom` per `corona/wire/`. Wire formats are pinned by
the KAT manifest at `scripts/regen-kats.manifest.sha256` — any
serialization drift breaks the cross-runtime Go ↔ C++ byte-equality
gate.

## §13 Hash suite

Production: **Corona-SHA3** (cSHAKE256 / KMAC256 / TupleHash256 per
FIPS 202 + SP 800-185). Implementation: `hash/sp800_185.go`.

Customization strings for cSHAKE256:
- `CORONA-HC-v1` — challenge hash (`H_c`)
- `CORONA-HU-v1` — uniform hash (`H_u`)
- `CORONA-PRF-v1` — per-pair PRF seed derivation
- `CORONA-MAC-v1` — per-pair KMAC key derivation
- `CORONA-DKG-v1` — DKG commitment derivation
- `CORONA-RESHARE-v1` — resharing transcript hash

Legacy: **Corona-BLAKE3** — retained for cross-port byte checks via
`hash.NewCoronaBLAKE3()`. NOT the normative submission profile.

## §14 Test vectors

KAT regeneration via `scripts/regen-kats.sh` → emits JSON to
`~/work/luxcpp/crypto/corona/test/kat/` for Go ↔ C++ byte-equality
verification. Manifest at `scripts/regen-kats.manifest.sha256`
pins SHA-256 of every regenerated file.

Five oracle generators in `cmd/`:
- `cmd/corona_oracle_v2/` — sign / verify KAT entries (Corona-BLAKE3)
- `cmd/cross_runtime_oracle/` — cross-language byte-equality vectors
- `cmd/dkg2_oracle/` — DKG transcripts
- `cmd/reshare_oracle/` — Refresh + ReshareToNewSet transcripts
- `cmd/activation_oracle/` — activation cert vectors

## §15 Security considerations

Inherited from Boschini et al. ePrint 2024/1113 §3 (EUF-CMA proof
sketch). Corona-specific additions:

- **Trusted-dealer assumption removed**: Pedersen DKG over `R_q`
  (`dkg2/`) replaces the original construction's trusted-dealer
  Gen.
- **Hiding via blinding**: dkg2 commits are `A·NTT(s) + B·NTT(r)` with
  per-coefficient hiding blind `r`, replacing the broken
  Feldman-style `C = A·NTT(s)` in legacy `dkg/`.
- **Constant-time verification**: see `CONSTANT-TIME-REVIEW.md` for
  the per-path audit. Zero `(c)` (must-fix) findings.
- **Forward security**: share material is zeroed in place after
  activation via `reshare/keyshare.go:EraseShare`. Zeroization is
  best-effort under Go's memory model; production deployments
  pin pages via `mlock` (see `DEPLOYMENT-RUNBOOK.md`).

## §16 Implementation considerations

- Go 1.26.3 minimum (per `go.mod`).
- `luxfi/lattice/v7` provides constant-time NTT / Montgomery
  reduction / discrete-Gaussian sampling.
- `crypto/subtle` for byte-blob constant-time compare.
- `golang.org/x/crypto/sha3` for cSHAKE256 / KMAC256 / TupleHash256.
- No assembly, no SIMD intrinsics. Performance over correctness is a
  non-goal for the reference implementation.

## §17 Known limitations

Per `SUBMISSION.md` §"Does NOT claim":
- No FIPS 204 byte-equality (use Pulsar for that).
- No mechanized refinement proof.
- No identifiable abort under network partition (synchronous only).
- No 1-round signing.
- DKG bias resistance requires external randomness beacon.
- No cross-key-era preservation (Reanchor opens a new key era).

## §18 Proof and audit status

- **Machine-checked refinement proof**: NONE at this submission. See
  `PROOF-CLAIMS.md` for the narrow stated claim and the roadmap
  (multi-month research project).
- **Constant-time audit**: `CONSTANT-TIME-REVIEW.md` — zero `(c)`,
  two `(b)` mitigated (one closed in `dkg2/`; one in lens-specific
  paths off the Corona threshold path).
- **Side-channel statistical (dudect)**: harness not yet wired
  (roadmap v0.8.0). Currently the constant-time evidence is the
  static per-path audit above; statistical validation is future work.
- **External audit**: TBD — engagement post-submission.
- **Fuzz coverage**: `reshare/fuzz_*_test.go` (3 harnesses),
  `dkg2/fuzz_round_test.go`, `threshold/fuzz_round_test.go`. Per-push
  smoke runs are informational; submission-grade fuzz budgets are
  operational.

## §19 Patent / IP declaration

Royalty-free patent grant per `PATENTS.md`. Claim drafts in
`docs/patent-claims.md` (fewer claims than Pulsar — Corona claims
only the production lifecycle additions beyond the published
Boschini et al. construction). Defensive termination extends to all
NIST-standardized PQ signature schemes.

---

**Document metadata**

- Name: `SPEC.md`
- Version: v0.2 (initial submission-package scaffolding)
- Date: 2026-05-18
- Companion docs: `DESIGN.md`, `papers/lp-073-pulsar/`, `docs/ietf-draft-skeleton.md`
- Full LaTeX `spec/corona.tex` is in progress.
