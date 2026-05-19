# Corona — Patent Claim Drafts (Attorney Review)

> **Internal working document.** This file is the technical substrate
> for a patent attorney to draft formal claims from. It is **not** a
> filed patent application or a legal opinion. It enumerates the
> Corona contributions that we consider patentable, with claim
> language, prior-art mapping, and implementation citations.
>
> Public-facing IP terms are in `../../PATENTS.md`. The royalty-free
> grant in PATENTS.md §3 covers all claims listed below, present
> and future.

## §0 Drafting notes for the attorney

- **Inventors**: Lux Industries cryptography team. Specific named
  inventors to be assigned per claim group based on contribution
  records (commit history in `git log`).
- **Priority date**: file as a US provisional within 12 months of
  the NIST MPTC submission's public date (currently anticipated:
  2026-Nov-16). File BEFORE the NIST submission becomes public to
  preserve foreign-filing rights.
- **Prior art search scope**: NIST PQC / MPTC submissions
  (Dilithium, Kyber, Falcon, SPHINCS+, FROST, GG18, CGGMP21,
  Pulsar), IACR ePrint archive 2018-2026, the Boschini et al.
  ePrint 2024/1113 paper, IEEE S&P 2025 proceedings, HJKY97 +
  Desmedt-Jajodia 1997 + Wong-Wang-Wing 2002 proactive-secret-
  sharing literature, Pedersen 1991 VSS, lattigo + libjade
  implementations, OpenSSL + BoringSSL FIPS PQ providers.
- **Patent family**: file as one provisional with multiple claim
  groups; split into independent applications at PCT entry if claim
  diversity warrants.
- **Co-pending work**: the Boschini et al. published construction is
  academic prior art. Corona claims **exclude** the published
  construction's math itself; claim scope is the production
  lifecycle additions Lux contributes.

**HONESTY guardrail**: this claim set is intentionally **smaller**
than Pulsar's 21-claim portfolio because Pulsar can claim novelty in
its specific FROST-style Lagrange-aggregation technique combined with
FIPS 204's rejection-sampling loop (a non-obvious composition),
whereas Corona implements a published academic construction
(Boschini et al. 2024/1113) unchanged in its math. Corona's claims
are limited to the production lifecycle Lux added atop the published
construction.

## §1 Claim group A — Pedersen DKG over `R_q` with hiding blinds

### §1.1 Independent claim (Claim 1, draft)

> **Claim 1.** A method for distributed generation of a Ring-LWE
> threshold signing key share over a polynomial ring
> `R_q = Z_q[X]/(X^N + 1)`, the method comprising:
>
> (a) at each dealer party `i` in a committee of `n` parties:
>
>     (a1) sampling a sharing polynomial `f_i(X)` of degree `t − 1`
>          over `R_q^M`, where `M` is the module width;
>
>     (a2) sampling, for each coefficient `f_i^(k)` of `f_i(X)`, a
>          hiding-blind polynomial `r_i^(k)` of the same shape;
>
>     (a3) computing a Pedersen-style coefficient commitment
>          `C_i^(k) = A · NTT(f_i^(k)) + B · NTT(r_i^(k))` for each
>          `k ∈ [0, t)`, where `A, B` are public R_q^M generators
>          derived deterministically from a session identifier
>          `sid_dkg` via cSHAKE256 with customization string
>          `"CORONA-DKG-v1"`;
>
>     (a4) broadcasting `{C_i^(k)}_{k=0}^{t-1}` to all parties in the
>          committee;
>
>     (a5) distributing, by per-pair encrypted-share exchange under
>          authenticated key exchange, the share-pair
>          `(f_i(α_j), r_i(α_j))` to each recipient party `j`;
>
> (b) at each recipient party `j`:
>
>     (b1) decrypting the share-pair from each dealer;
>
>     (b2) verifying the Pedersen identity
>          `A · NTT(share_ij) + B · NTT(blind_ij) ?= Σ_{k=0}^{t-1}
>           C_i^(k) · α_j^k` by accumulating
>          `eq &= ConstantTimeCompare(lhs_bytes[k], rhs_bytes[k])`
>          across all slots `k ∈ [0, M)` with NO per-slot early
>          return;
>
>     (b3) emitting a complaint message if and only if `eq != 1`
>          after the loop terminates;
>
> (c) determining a qualified set `QSET` from the complaint round
>     such that `|QSET| ≥ t`; and
>
> (d) computing the group public key as `bTilde = Round(Σ_{i ∈ QSET}
>     f_i^(0) · A + e)` where `e` is the LWE noise term inherited
>     from the underlying R-LWE construction,
>
> wherein the constant-time accumulation in (b2) prevents the
> recipient's response-time variation from leaking which slot first
> diverged when an invalid share-pair is received.

### §1.2 Reference to spec and implementation

- Spec section: `SPEC.md` §6 + `papers/lp-073-pulsar/lp-073-pulsar-pedersen-dkg.tex`
- Implementation: `dkg2/dkg2.go` (commit-share-verify), `dkg2/dkg2.go:560` (`constTimePolyEqual` helper), `dkg2/complaint.go` (complaint handling)
- Constant-time evidence: `CONSTANT-TIME-REVIEW.md` §2

### §1.3 Dependent claims

**Claim 2.** The method of claim 1, wherein the per-pair encrypted-
share exchange in (a5) uses ML-KEM-768 hybrid recipient wrapping
combined with AEAD encryption.

**Claim 3.** The method of claim 1, wherein the complaint round in
(b3) further comprises:

- a per-complaint timeout configured at the consensus layer;
- a deterministic disqualification algorithm that filters the
  qualified set based on the complaint quorum;
- a publicly-verifiable evidence record sufficient for third-party
  slashing decisions.

**Claim 4.** The method of claim 1, wherein the public generators
`A, B` in (a3) are derived via cSHAKE256 with customization string
`"CORONA-DKG-v1"` AND session-bound by `sid_dkg` to prevent cross-
session generator reuse.

**Claim 5.** A computer-readable storage medium containing
instructions that, when executed by a plurality of computing devices
in a committee, cause the devices to perform the method of any of
claims 1-4.

### §1.4 Prior-art mapping

| Prior-art reference | Distinguishing feature |
|---|---|
| Pedersen 1991 VSS | Original Pedersen VSS is over a multiplicative group (elliptic curve or `Z_p^*`); Corona's adaptation to the `R_q^M` polynomial-vector setting with per-coefficient hiding blinds and the specific cSHAKE256 generator derivation is the novelty. |
| Feldman 1987 VSS | Feldman VSS has no hiding blinds; Corona's legacy `dkg/` package uses Feldman and is documented as broken for public broadcast. Pedersen `dkg2/` provides hiding. |
| Gennaro-Jarecki-Krawczyk-Rabin 1999 DKG | GJKR DKG is over a discrete-log group; the lattice adaptation pattern is novel. |
| FROST DKG (Komlo-Goldberg 2020) | FROST DKG is for Schnorr/Ed25519; does not apply to lattice-based signatures. |
| Boschini et al. ePrint 2024/1113 | The base construction assumes a trusted-dealer Gen; Corona's `dkg2/` removes that assumption by introducing a publicly-verifiable Pedersen DKG. The DKG construction is Corona's contribution, not the cited paper's. |

## §2 Claim group B — Proactive resharing with `(A, bTilde)` preservation

### §2.1 Independent claim (Claim 6, draft)

> **Claim 6.** A method for proactive secret-sharing rotation in a
> Ring-LWE threshold signing system, the method comprising:
>
> (a) at an old qualified subset `Q ⊆ O_old` of an old committee
>     with `|Q| ≥ t_old`, where each party `i ∈ Q` holds an old
>     share `s_i^old` of a sharing polynomial `f^old` over `R_q^M`
>     such that `f^old(0) = s`:
>
>     (a1) sampling, at each party `i ∈ Q`, a fresh polynomial
>          `g_i(X)` of degree `t_new − 1` over `R_q^M` with constant
>          term `g_i(0) = s_i^old`;
>
>     (a2) computing, at each party `i ∈ Q`, Pedersen-style
>          coefficient commitments to `g_i(X)` under the protocol's
>          deterministic generator derivation;
>
>     (a3) distributing, by per-pair encrypted-share exchange, the
>          share `g_i(β_j)` to each new party `j` in the new
>          committee `O_new`;
>
> (b) at each new party `j ∈ O_new`:
>
>     (b1) verifying received shares against the broadcast Pedersen
>          commits using constant-time per-slot accumulation;
>
>     (b2) computing the new share `s_j^new = Σ_{i ∈ Q} λ_i^Q · g_i(β_j)`
>          where `λ_i^Q` are the Lagrange interpolation coefficients
>          evaluated at zero for the old qualified subset's party
>          indices;
>
> (c) verifying, at all parties, that the new committee's threshold
>     signature on a domain-separated activation message
>     `m_act = "QUASAR-CORONA-ACTIVATE-v1" || transcript_hash ||
>     reshare_transcript_hash` verifies under the **byte-identical
>     unchanged** group public key `(A, bTilde)` of the old committee;
>
> wherein, if the activation verification in (c) succeeds, the chain
> accepts the new committee as live and the old committee's signing
> capability is retired; if the activation verification fails, the
> chain rolls back to the old committee and signing continues under
> the old shares.

### §2.2 Reference to spec and implementation

- Spec section: `SPEC.md` §9 + `papers/lp-073-pulsar/lp-073-pulsar-resharing.tex`
- Implementation: `reshare/reshare.go`, `reshare/keyshare.go`, `reshare/activation.go` (activation cert circuit-breaker)
- Tests: `reshare/full_integration_test.go`, `reshare/refresh_test.go`, `reshare/reshare_test.go`

### §2.3 Dependent claims

**Claim 7.** The method of claim 6, wherein the activation message
in (c) further binds:
- chain identifier;
- network identifier;
- key era identifier;
- group identifier;
- old epoch and new epoch counters;
- old validator set hash and new validator set hash;
- old threshold and new threshold;
- group public key hash;
- pairwise material commitment hash;
- implementation version (for cross-port byte-equality
  determinism).

**Claim 8.** The method of claim 6, wherein the resharing operation
is parameterized as either:
- a Refresh variant where `O_new = O_old` and the master secret
  distribution is refreshed under the same committee for defense
  against mobile-adversary share accumulation; OR
- a ReshareToNewSet variant where `O_new ≠ O_old` and the share
  distribution rotates to a new validator set with potentially
  different threshold `t_new`.

**Claim 9.** The method of claim 6, wherein failure to verify the
activation cert in (c) triggers an LSS-style Rollback operation to
the previous generation's snapshot, without identifying a malicious
actor and without invoking slashing.

### §2.4 Prior-art mapping

| Prior-art reference | Distinguishing feature |
|---|---|
| HJKY97 (Herzberg et al. CRYPTO 1995/1997) | HJKY97 is the classical Refresh primitive over discrete-log groups; Corona's lattice adaptation to `R_q^M` and the activation-cert circuit-breaker are the novelty. |
| Desmedt-Jajodia 1997 | DJ97 specifies redistribution to new access structures; Corona's lattice adaptation + Lagrange-aggregation-over-old-Q + activation-cert composition are novel. |
| Wong-Wang-Wing 2002 (VSR for archive systems) | WWW02 introduces verifiable secret redistribution; Corona's lattice adaptation + the specific activation-cert circuit-breaker pattern that gates new-epoch acceptance ARE novel. |
| LSS framework (Seesahai 2025) | LSS specifies Generation, RollbackFrom, and the Bootstrap Dealer / Signature Coordinator role separation. Corona adapts these to the lattice setting via the `lss_pulsar.go` adapter pattern. |
| Boschini et al. ePrint 2024/1113 | The base construction does NOT specify proactive resharing. Corona's resharing layer is entirely Lux's contribution atop the published construction. |

## §3 Claim group C — Activation cert circuit-breaker

### §3.1 Independent claim (Claim 10, draft)

> **Claim 10.** A method for safely transitioning a Ring-LWE
> threshold signing system from an old validator committee to a new
> validator committee after a proactive secret-resharing operation,
> the method comprising:
>
> (a) completing a resharing operation that transfers a sharing
>     polynomial from the old committee to the new committee while
>     preserving a group public key `(A, bTilde)`;
>
> (b) constructing, by the new committee, a domain-separated
>     activation message `m_act` that binds the old and new epochs,
>     the old and new validator-set hashes, the old and new
>     thresholds, the group-public-key hash, the resharing transcript
>     hash, and an implementation-version field;
>
> (c) producing, by the new committee using their freshly-derived
>     shares, a threshold signature `σ_act` on `m_act` via the
>     2-round threshold signing protocol;
>
> (d) verifying `σ_act` under the **byte-identical unchanged**
>     `(A, bTilde)` of the old committee;
>
> (e) gating acceptance of the new epoch on the verification in (d):
>     if accept, the new committee becomes the active signing
>     committee and the old committee's signing authority is retired;
>     if reject, the chain rolls back to the old committee and
>     signing continues under the old shares.

### §3.2 Reference to spec and implementation

- Spec section: `SPEC.md` §9 + `DESIGN.md` §"Activation cert (the circuit-breaker)"
- Implementation: `reshare/activation.go`
- Test: `reshare/activation_test.go`

### §3.3 Dependent claims

**Claim 11.** The method of claim 10, wherein the activation
verification in (d) is performed by every validator independently,
not by a single coordinator, so that no single party can unilaterally
accept or reject a new committee.

**Claim 12.** The method of claim 10, wherein multiple consecutive
activation failures (a configurable threshold) trigger a Reanchor
governance event that opens a new key era with a fresh group public
key `(A', bTilde')`.

## §4 Claim group D — Constant-time slot-equality `eq &=` accumulation

### §4.1 Independent claim (Claim 13, draft)

> **Claim 13.** A method for constant-time verification of a Pedersen
> commitment over a polynomial-vector ring `R_q^M`, the method
> comprising:
>
> (a) computing, at the recipient, the left-hand side
>     `LHS^(k) = A · NTT(share^(k)) + B · NTT(blind^(k))` for each
>     slot `k ∈ [0, M)`;
>
> (b) computing the right-hand side `RHS^(k) = Σ_{l=0}^{t-1}
>     C^(l) · α_recipient^l` for each slot `k`;
>
> (c) initializing an accumulator `eq = 1`;
>
> (d) for each slot `k ∈ [0, M)`, updating
>     `eq &= ConstantTimeCompare(LHS^(k).bytes, RHS^(k).bytes)`
>     using a fixed-time byte-blob compare routine, with NO per-slot
>     early return;
>
> (e) emitting a complaint message if and only if `eq != 1` after
>     the loop in (d) terminates,
>
> wherein the recipient's response-time variation does not reveal
> which slot first diverged when an invalid commitment is received.

### §4.2 Reference to spec and implementation

- Implementation: `dkg2/dkg2.go:560` (`constTimePolyEqual` helper) +
  `dkg2/dkg2.go:539` (Round 2 share verification loop)
- Constant-time evidence: `CONSTANT-TIME-REVIEW.md` §2

### §4.3 Distinguishing feature

The novelty is the SPECIFIC application of the `eq &=
ConstantTimeCompare` accumulation pattern to Pedersen commitments
over `R_q^M` polynomial-vector slots, in a context where naive
implementation would leak the first-diverging slot index via
response-time variation (the gap Findings 5/6 of upstream
RED-DKG-REVIEW.md called out for the broken legacy `dkg/` Feldman
path). The pattern itself (`eq &=` accumulation with no early
return) is a known constant-time idiom; the specific application to
the R-LWE Pedersen verification is the contribution.

## §5 Claim group E — Hash-suite injection through every Sign-path primitive

### §5.1 Independent claim (Claim 14, draft)

> **Claim 14.** A computer-implemented system for distributed
> signing on a Ring-LWE threshold signature scheme, the system
> comprising a software architecture wherein every cryptographic
> primitive on the Sign code path accepts, as its first argument, a
> hash-suite handle `HashSuite` that selects between at least:
>
> (a) a production hash suite using cSHAKE256, KMAC256, and
>     TupleHash256 per FIPS 202 and NIST SP 800-185, with a registry
>     of domain-separation customization strings of the form
>     `"CORONA-<purpose>-v1"`; AND
>
> (b) a legacy hash suite using BLAKE3 with the same domain-
>     separation customization tags wrapped in BLAKE3-specific
>     framing,
>
> such that any single deployment can switch its entire Sign code
> path between suite (a) and suite (b) without modifying any
> primitive's source code, by passing a different `HashSuite` handle
> at construction time.

### §5.2 Reference to spec and implementation

- Spec section: `SPEC.md` §13 + `CHANGELOG.md` "F22 hash-suite injection"
- Implementation: `hash/sp800_185.go` (Corona-SHA3),
  `hash/blake3.go` (legacy), `primitives/hash.go` (per-primitive
  suite injection)

### §5.3 Distinguishing feature

The novelty is the architectural pattern where the suite is a
first-argument parameter on every primitive (not a package-level
global, not a build flag) so that the same compiled binary can run
multiple parallel deployments under different suites without
recompilation. This enables cross-port byte-equality validation
(Corona-BLAKE3 KAT) without disturbing the production Corona-SHA3
path.

## §6 What Corona does NOT claim

Explicitly disclaimed:

- The base 2-round R-LWE threshold construction (Boschini et al.
  ePrint 2024/1113) — academic prior art.
- Ring-LWE primitive (Lyubashevsky-Peikert-Regev 2010) — academic.
- Shamir secret sharing (1979) — public domain.
- Lagrange interpolation — classical mathematics.
- Generic Pedersen VSS construction (Pedersen 1991) — academic.
- Generic HJKY97 / Desmedt-Jajodia / Wong-Wang-Wing proactive
  secret sharing — academic.
- SHAKE / cSHAKE / KMAC / TupleHash (FIPS 202 + SP 800-185) — NIST
  standards, public domain.
- LSS framework (Seesahai 2025) — academic.

## §7 Comparison to Pulsar's patent claims

Pulsar's `docs/patent-claims.md` enumerates 21 claims across 5 claim
groups, centered on the FIPS 204 byte-identical output
interchangeability technique (Lagrange aggregation + kappa
rejection-sampling integration + FIPS 204 §5.4.1 ExternalMu binding).

Corona's claim set is **smaller** (~14 claims across 5 groups,
shown above) because Corona's underlying construction is published
academic prior art that Corona does not modify. Corona's novelty is
exclusively in the production lifecycle additions: Pedersen DKG
over `R_q`, proactive resharing preserving `(A, bTilde)`,
activation cert circuit-breaker, constant-time Pedersen slot
equality, hash-suite injection architecture.

A reviewer evaluating overlap between the two portfolios should
note: Corona Claim 6 (resharing) and Pulsar Claim 11 (reshare) are
**conceptually parallel** but apply to different lattice families
(R-LWE vs M-LWE) and rely on different underlying Pedersen-commit
shapes; they are independently patentable but the underlying
algorithmic ideas overlap.

---

**Document metadata**

- Name: `docs/mptc/patent-claims.md`
- Version: v0.1 (initial submission-package scaffolding)
- Date: 2026-05-18
- Construction version: Corona v0.4.1 (production library) /
  v0.5.0 (submission package)
- Construction repository: <https://github.com/luxfi/corona>
