# IETF Internet-Draft Skeleton — Corona Threshold Ring-LWE Signature

> **HONEST FRAMING**: this document is a **draft skeleton**, not a
> submitted Internet-Draft. The CFRG submission timing is contingent
> on the v0.7.0 mechanized refinement work and the v0.8.0 external
> audit landing. At submission scaffolding this revision, the
> skeleton enumerates the sections an eventual `draft-luxfi-cfrg-
> corona-threshold-rlwe-XX.txt` would carry; it does NOT claim CFRG
> adoption, working-group status, or any timeline.
>
> The canonical algorithmic spec at this submission revision is
> `SPEC.md` + `papers/lp-073-pulsar/` LaTeX sections + `DESIGN.md`.
> This IETF skeleton consolidates them into IETF-style section
> headers for eventual CFRG presentation.

## Cover page (draft)

```
Internet Engineering Task Force                              [maintainer]
Internet-Draft                                       Lux Industries, Inc.
Intended status: Informational                                 [draft-XX]
Expires: [TBD]                                                 [date-XX]

       Corona: a 2-round threshold Ring-LWE signature scheme
                 with proactive resharing
              draft-luxfi-cfrg-corona-threshold-rlwe-XX

Abstract

   This document specifies Corona, a 2-round threshold signature
   scheme over Ring-LWE for use in post-quantum threshold signing
   deployments. Corona implements the construction of Boschini,
   Kaviani, Lai, Malavolta, Takahashi, and Tibouchi (IACR ePrint
   2024/1113, IEEE S&P 2025) on a fixed parameter set, plus
   production lifecycle layers: Pedersen distributed key generation
   over R_q, proactive resharing with public-key preservation, and
   identifiable abort with attributable evidence.
```

## §1 Introduction

- §1.1 Motivation — threshold PQ signatures for blockchain finality
  (Quasar consensus reference).
- §1.2 Relationship to FIPS 204 ML-DSA — Corona is R-LWE; ML-DSA is
  M-LWE; the two are independent. The M-LWE sibling is Pulsar
  (`luxfi/pulsar`).
- §1.3 Document scope — algorithm specification + reference
  parameter set; deployment specifics (HSM, validator orchestration)
  are out of scope.

## §2 Conventions

- §2.1 IETF normative terminology (RFC 2119 / RFC 8174).
- §2.2 Notation — see `SPEC.md` §2 for the full glossary. Key terms:
  Party, Quorum `Q`, Sharing polynomial `f`, Group public key
  `(A, bTilde)`, Session identifier `sid`, Key era, Generation,
  Activation cert.
- §2.3 Byte ordering — little-endian throughout, per lattigo wire
  convention.

## §3 Parameter set

- §3.1 Single set, v0.2 — `N = 256`, `q = 0x1000000004A01`, `M = 8`,
  `N_M = 7`, `Kappa = 23`. See `SPEC.md` §3.
- §3.2 Future parameter sets — roadmap (v0.6.0) for a second set
  targeting NIST PQ Category 3.

## §4 Threat model

- §4.1 Static corruption of `t − 1` parties.
- §4.2 Rushing Byzantine adversary.
- §4.3 Synchronous network with known upper bound `Δ`.
- §4.4 Pedersen DKG (`dkg2/`) provides hiding and binding under
  standard assumptions.

See `SPEC.md` §4 + `DESIGN.md` §"Three layers, one shipping path".

## §5 Pedersen DKG over `R_q`

- §5.1 Setup — `(A, B)` generator derivation from `sid_dkg` via
  cSHAKE256.
- §5.2 Per-party polynomial sampling + per-coefficient hiding blinds.
- §5.3 Coefficient commits `C^(k) = A·NTT(s^(k)) + B·NTT(r^(k))`.
- §5.4 Per-pair encrypted-share exchange (authenticated KEX).
- §5.5 Complaint round + qualified-set selection.
- §5.6 Group public key derivation.

See `SPEC.md` §6 + `papers/lp-073-pulsar/lp-073-pulsar-pedersen-dkg.tex`.

## §6 Threshold signing (2 rounds)

- §6.1 Round 1 commit: each party samples `y_i`, computes
  `w_i = A · y_i`, broadcasts commitment.
- §6.2 Aggregator: collect commits, derive challenge `c`.
- §6.3 Round 2 response: each party computes `z_i = y_i + c · s_i`.
- §6.4 Combine: Lagrange-aggregate responses, check low-norm
  bounds, package `σ = (c, z, Δ)`.

See `SPEC.md` §7 + Boschini et al. ePrint 2024/1113 §3 +
`sign/sign.go`.

## §7 Verification

```
Verify(group_pk = (A, bTilde), m, σ = (c, z, Δ)):
  w' ← A · z − c · bTilde
  c' ← H_c(transcript_with_w')
  if c' ≠ c: return FAIL
  if not CheckL2Norm(z, bound): return FAIL
  return OK
```

See `SPEC.md` §8 + `sign/sign.go:Verify`.

## §8 Proactive resharing

- §8.1 Refresh (same set, fresh shares) — HJKY97 lineage.
- §8.2 ReshareToNewSet (set rotation) — Desmedt-Jajodia 1997 /
  Wong-Wang-Wing 2002 lineage.
- §8.3 Activation cert circuit-breaker.

See `SPEC.md` §9 + `papers/lp-073-pulsar/lp-073-pulsar-resharing.tex`
+ `reshare/`.

## §9 Identifiable abort

- §9.1 Failure classes — missing message, equivocation, malformed
  ciphertext, invalid share contribution.
- §9.2 Evidence shape — signed slashing data with care taken not to
  leak threshold-reconstructing data publicly.

See `SPEC.md` §10 + `dkg2/complaint.go` + `reshare/complaint.go`.

## §10 Transcript and domain separation

- §10.1 `QUASAR-CORONA-*` prefix family.
- §10.2 Replay binding (chain_id, epoch, key_era_id, sid, etc.).

See `SPEC.md` §11 + `DESIGN.md` §"Domain-separated message prefixes".

## §11 Wire formats

- §11.1 Polynomial serialization via `luxfi/math/codec`.
- §11.2 `Vector[Poly]` frame validation before lattigo `ReadFrom`.
- §11.3 KAT cross-runtime byte-equality enforcement.

See `SPEC.md` §12.

## §12 Hash suite

- §12.1 Corona-SHA3 (cSHAKE256 / KMAC256 / TupleHash256 per FIPS 202
  + SP 800-185).
- §12.2 Customization-string registry.
- §12.3 Legacy Corona-BLAKE3 (cross-port byte-check only).

See `SPEC.md` §13 + `hash/sp800_185.go`.

## §13 Security considerations

- §13.1 R-LWE hardness assumption.
- §13.2 EUF-CMA reduction — inherited from Boschini et al. ePrint
  2024/1113 §3.
- §13.3 Constant-time guarantees on threshold + dkg2 paths.
- §13.4 Forward security via share zeroization.

See `SPEC.md` §15 + `CONSTANT-TIME-REVIEW.md` + `PROOF-CLAIMS.md`.

## §14 Implementation considerations

- §14.1 Go reference at `github.com/luxfi/corona`.
- §14.2 C++ port at `~/work/luxcpp/crypto/corona/` (cross-runtime
  byte-equal).
- §14.3 No assembly, no SIMD intrinsics in the reference.

See `SPEC.md` §16.

## §15 IANA considerations

This document has no IANA actions at this draft revision. Future
revisions may request:

- Hash suite identifier registration (`corona-sha3`, `corona-blake3`).
- Domain-separation prefix registration in the threshold-signature
  prefix registry (if such a registry is established).

## §16 References

### §16.1 Normative

- [FIPS202] NIST. *SHA-3 Standard: Permutation-Based Hash and
  Extendable-Output Functions.* August 2015.
- [SP800-185] NIST. *SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash,
  and ParallelHash.* December 2016.

### §16.2 Informative

- [BoschiniEtAl24] Boschini, Kaviani, Lai, Malavolta, Takahashi,
  Tibouchi. *Practical two-round threshold signatures from learning
  with errors.* IACR ePrint 2024/1113, IEEE S&P 2025.
- [LPR10] Lyubashevsky, Peikert, Regev. *On ideal lattices and
  learning with errors over rings.* EUROCRYPT 2010.
- [HJKY97] Herzberg, Jakobsson, Jarecki, Krawczyk, Yung. *Proactive
  secret sharing or: How to cope with perpetual leakage.* CRYPTO
  1995/1997.
- [DJ97] Desmedt, Jajodia. *Redistributing secret shares to new
  access structures.* 1997.
- [WWW02] Wong, Wang, Wing. *Verifiable secret redistribution for
  archive systems.* 2002.
- [Pedersen91] Pedersen. *Non-interactive and information-theoretic
  secure verifiable secret sharing.* CRYPTO 1991.
- [Seesahai25] Seesahai. *LSS MPC ECDSA: A Pragmatic Framework for
  Dynamic and Resilient Threshold Signatures.* August 2025.
- [FIPS204] NIST. *Module-Lattice-Based Digital Signature Standard
  (ML-DSA).* August 2024. (For context — Pulsar (M-LWE) targets
  byte-equality with FIPS 204; Corona (R-LWE) does NOT.)

## Appendix A — Test vectors

KAT-deterministic regeneration via `scripts/regen-kats.sh`. See
`SPEC.md` §14 for the oracle inventory and cross-runtime byte-
equality manifest at `scripts/regen-kats.manifest.sha256`.

## Appendix B — Known limitations

Per `SUBMISSION.md` §"What this submission does NOT claim":

- No FIPS 204 byte-equality (use Pulsar for that).
- No mechanized refinement proof at submission scaffolding (roadmap
  v0.7.0).
- No identifiable abort under network partition (synchronous only).
- No 1-round signing (construction is 2-round by design).
- DKG bias resistance requires external randomness beacon.

## Appendix C — Author's address

```
[primary maintainer]
Lux Industries, Inc.
Email: z@lux.network

Submission coordination: mptc@lux.network
Security disclosure: security@lux.network
Public discussion: https://github.com/luxfi/corona/discussions
```

---

**Document metadata**

- Name: `docs/mptc/ietf-draft-skeleton.md`
- Version: v0.1 — DRAFT SKELETON (not a submitted Internet-Draft)
- Date: 2026-05-18
- Status: skeleton consolidating `SPEC.md` + `DESIGN.md` + paper
  sections into IETF-style section headers. CFRG submission timing
  is contingent on v0.7.0 + v0.8.0 milestones.
