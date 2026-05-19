# PATENTS — Corona Threshold Ring-LWE Signature

> **Statement of Intellectual Property and Royalty-Free Patent Grant**
> for the Corona threshold-signing construction submitted to the NIST
> Multi-Party Threshold Cryptography (MPTC) project.

## TL;DR

Lux Industries, Inc. ("Lux") grants a **worldwide, royalty-free,
non-exclusive, irrevocable patent license** for any implementation of
the Corona threshold signature construction that is either (a)
licensed under Apache-2.0 or a compatible OSI-approved license, OR
(b) is part of a NIST MPTC / PQC / ACVP submission, validation, or
interoperability test.

The grant terminates automatically and prospectively against any
party that asserts a patent claim against Corona, the underlying
Boschini et al. R-LWE construction, FIPS 204 ML-DSA, or any other
NIST-standardized post-quantum signature scheme. Defensive
termination mirrors Apache-2.0 §3.

The full text of the grant is in **§3 Patent Grant** below.

## §1 Scope of the IP statement

This document covers patent rights and patent posture for:

- The **Corona threshold-signing construction** as implemented at
  `github.com/luxfi/corona` (DKG → Round-1 → Round-2 → Combine →
  Reshare).
- The **reference implementation** in `sign/`, `threshold/`,
  `dkg2/`, `reshare/`, `primitives/`, and `hash/`.
- The **test-vector format** in `cmd/*_oracle*/` and the
  cross-runtime byte-equality manifest at
  `scripts/regen-kats.manifest.sha256`.

It does NOT cover, and explicitly DISCLAIMS, the following prior art:

| Component | Status |
|---|---|
| The base 2-round Ring-LWE threshold construction (Boschini, Kaviani, Lai, Malavolta, Takahashi, Tibouchi. *Practical two-round threshold signatures from learning with errors.* IACR ePrint 2024/1113, IEEE S&P 2025) | Academic prior art. Corona implements this construction unchanged in its math. Lux asserts no patents on the published Boschini et al. algorithm itself. |
| Ring-LWE (R-LWE) primitive (Lyubashevsky, Peikert, Regev. *On ideal lattices and learning with errors over rings.* EUROCRYPT 2010) | Academic / public domain. |
| Shamir secret sharing (1979) | Public domain. |
| Lagrange polynomial interpolation | Classical mathematics. |
| Pedersen verifiable secret sharing (Pedersen 1991) | Academic prior art. Corona's `dkg2/` adapts the Pedersen VSS construction to `R_q^M` lattice commits; the adaptation pattern is generic. |
| HJKY97 proactive secret sharing (Herzberg, Jakobsson, Jarecki, Krawczyk, Yung. CRYPTO 1995/1997) | Academic prior art. Corona's `Refresh` primitive follows the HJKY97 same-set refresh shape. |
| Desmedt-Jajodia 1997 / Wong-Wang-Wing 2002 redistribution to new access structures | Academic prior art. Corona's `ReshareToNewSet` follows this VSR composition. |
| SHAKE128 / SHAKE256 / Keccak / cSHAKE / KMAC / TupleHash (FIPS 202 + SP 800-185) | Public domain — NIST standards. |
| FROST threshold-signing baseline (academic literature) | Published in IACR ePrint; no novelty asserted here against the published construction. |
| LSS (Linear Secret Sharing) framework (Seesahai 2025) | Academic prior art. Corona's lifecycle interfaces (Generation, RollbackFrom, Bootstrap Dealer / Signature Coordinator role separation) follow the LSS pattern. |

## §2 What Lux considers patentable (high level)

Subject to attorney review (see `docs/patent-claims.md` for the
detailed numbered claim drafts), Lux considers the following Corona
contributions to be candidates for patent protection. Note: this
list is intentionally narrower than Pulsar's because the underlying
2-round R-LWE construction is published academic prior art (Boschini
et al. 2024/1113). Corona's novel contributions are the production
lifecycle layers atop the published construction.

### §2.1 Pedersen DKG over `R_q` with hiding blinds

The specific adaptation of Pedersen verifiable secret sharing to the
`R_q^M` polynomial-vector setting, where coefficient commitments
take the form `C^(k) = A·NTT(s^(k)) + B·NTT(r^(k))` for per-
coefficient hiding blind `r^(k)`. The adaptation includes:

- Domain-separated generator derivation from `sid_dkg` via cSHAKE256
  (`CORONA-DKG-v1` customization string).
- Per-pair authenticated KEX (ML-KEM-768 hybrid recommended).
- Complaint round with publicly-verifiable evidence.
- Qualified-set selection with deterministic ordering.

Detailed in `papers/lp-073-pulsar/lp-073-pulsar-pedersen-dkg.tex`;
implementation in `dkg2/`.

### §2.2 Class N4 reshare with public-key preservation over `R_q`

Proactive secret-sharing protocol that rotates shares across
committee changes while preserving the group public key `(A, bTilde)`
in the R-LWE setting. Permits long-lived public identity with
rotating custodians. Two distinct primitives:

- `Refresh` — same committee, fresh shares (HJKY97 lineage adapted
  to R-LWE).
- `ReshareToNewSet` — set rotation with `t_old → t_new` threshold
  changes (Desmedt-Jajodia / Wong-Wang-Wing lineage adapted to
  R-LWE).

Detailed in `papers/lp-073-pulsar/lp-073-pulsar-resharing.tex`;
implementation in `reshare/`.

### §2.3 Activation certificate as circuit-breaker

The specific protocol step where, after a Reshare math completes,
the new committee threshold-signs an activation message under the
**unchanged** group public key using their freshly-derived shares;
only on successful verification does the chain mark the new epoch
live. The activation message canonical bytes include
`key_era_id || old_epoch || new_epoch || old_validator_set_hash ||
new_validator_set_hash || reshare_transcript_hash` with
domain-separated prefix `QUASAR-CORONA-ACTIVATE-v1`. Detailed in
`DESIGN.md` §"Activation cert (the circuit-breaker)"; implementation
in `reshare/activation.go`.

### §2.4 Constant-time Pedersen slot equality with `eq &=` accumulation

The specific implementation pattern in `dkg2/dkg2.go:VerifyShareAgainstCommits`
where Pedersen identity verification iterates over all `M` slots,
accumulating `eq &= subtle.ConstantTimeCompare(lhs_bytes, rhs_bytes)`
with NO early return on per-slot mismatch — preventing the recipient's
response-time variation from leaking which slot first diverged.
Specifically addresses Findings 5/6 of the upstream
RED-DKG-REVIEW.md; the same idiom can apply to any `(A, B)`-based
Pedersen commit scheme over a polynomial ring.

### §2.5 Hash-suite injection through every Sign-path primitive

The specific architectural pattern where every Sign-path primitive
(`PRNGKey`, `PRNGKeyForRound`, `GenerateMAC`, `GaussianHash`, `PRF`,
`Hash`, `LowNormHash`) takes a `hash.HashSuite` as its first argument
with `nil` resolving to the production default (`Corona-SHA3` via
KMAC over cSHAKE256), enabling per-deployment hash-profile selection
without code changes. Detailed in `CHANGELOG.md` "F22 hash-suite
injection into Sign"; implementation in `primitives/hash.go` +
`hash/sp800_185.go`.

## §3 Patent grant (the load-bearing text)

> **CORONA PATENT GRANT — v1.0**
>
> Lux Industries, Inc. ("Lux"), a Delaware corporation, hereby grants
> to any person or entity ("You") a **worldwide, royalty-free,
> non-exclusive, no-charge, fully-paid-up, irrevocable** (except as
> stated in §3.2 below) patent license to make, have made, use, offer
> to sell, sell, import, and otherwise transfer any implementation of
> the Corona threshold-signing construction described in `SPEC.md`
> and `DESIGN.md` (the "Construction"), provided that such
> implementation:
>
> (a) Implements the Construction (signing, DKG, or proactive
>     resharing) in a manner consistent with the algorithmic
>     specification (the "Construction-Conformance Condition"); AND
>
> (b) Is licensed to the public under (i) the Apache License, Version
>     2.0, or (ii) any other Open-Source-Initiative-approved license
>     compatible with Apache-2.0, OR (c) is part of a submission to,
>     validation under, or interoperability test for the NIST
>     Multi-Party Threshold Cryptography (MPTC) project, the NIST
>     Post-Quantum Cryptography (PQC) standardization process, or any
>     successor program administered by NIST.
>
> The license granted in this §3 covers all "Necessary Claims" owned
> or controllable by Lux that would, in absence of this license,
> necessarily be infringed by an implementation meeting (a) and (b).
> "Necessary Claims" means claims of any patent or patent
> application that are essential for compliance with the Corona
> specification, that Lux has the right at the time of execution to
> grant a license under.
>
> ### §3.1 Documentation and reference-implementation grant
>
> The Corona specification (`SPEC.md`, `DESIGN.md`,
> `papers/lp-073-pulsar/`), the reference implementation (`sign/`,
> `threshold/`, `dkg2/`, `reshare/`, `primitives/`, `hash/`), and the
> test vectors (under `cmd/*_oracle*/` and the cross-runtime manifest)
> are released under the Apache License, Version 2.0. The patent
> grant in this document operates in addition to (not in lieu of) the
> patent provisions in the Apache-2.0 license.
>
> ### §3.2 Defensive termination
>
> The patent license granted in this §3 terminates automatically and
> prospectively, without notice, with respect to any party (the
> "Asserting Party") if the Asserting Party initiates patent
> litigation (including a cross-claim or counter-claim in a lawsuit)
> alleging that:
>
> (i) The Corona construction; or
> (ii) The underlying Boschini-Kaviani-Lai-Malavolta-Takahashi-Tibouchi
>      2-round R-LWE threshold signature construction (IACR ePrint
>      2024/1113); or
> (iii) FIPS 204 ML-DSA, or any other NIST-standardized post-quantum
>       signature scheme; or
> (iv) Any implementation of (i), (ii), or (iii) — including without
>      limitation the reference implementation in this repository,
>      independent third-party implementations, NIST ACVP/CAVP
>      reference vectors, or any FIPS 140-3 validated module
>      containing such an implementation,
>
> infringes any patent owned or controllable by the Asserting Party.
> Termination is prospective only; it does not undo the validity of
> any implementation distributed prior to the date the Asserting
> Party initiated the litigation.
>
> Defensive termination mirrors the patent-termination clause of the
> Apache License, Version 2.0, §3, generalized to also cover the
> underlying Boschini et al. construction, FIPS 204 ML-DSA, and
> successor NIST-standardized post-quantum signature schemes. The
> purpose is to deter patent assertion against the broader post-
> quantum signature ecosystem, not only against Corona itself.
>
> ### §3.3 No trademark license
>
> This grant does not authorize the use of Lux's trademarks
> (including "Corona", "Pulsar", "Quasar", "Lux", "Lux Industries",
> and their respective logos) except as required for reasonable and
> customary use in describing the origin of the Construction and
> reproducing the content of any NOTICE file.
>
> ### §3.4 Disclaimer
>
> THE CONSTRUCTION AND ALL ASSOCIATED MATERIALS ARE PROVIDED ON AN
> "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER
> EXPRESS OR IMPLIED. Lux shall not be liable for any damages
> resulting from the use of the patent license granted in this §3.

## §4 Filing strategy (informational)

This section is for transparency; it does not modify the grant
in §3.

Lux intends to pursue patent protection on the Corona production-
lifecycle additions as follows:

1. **US provisional application** within 12 months of public
   disclosure (the NIST MPTC submission counts as public disclosure
   for §102 purposes; filing before submission preserves priority).

2. **PCT international application** within 12 months of the
   provisional, designating jurisdictions where R-LWE deployment is
   anticipated (EU, JP, CN, KR, IN, AU, CA, UK, BR).

3. **EPO and major-jurisdiction national-phase entries** at the PCT
   30-month deadline, prioritized by anticipated deployment markets.

4. **Continuation / divisional applications** to cover incremental
   refinements (e.g., the constant-time `eq &=` Pedersen slot-equality
   pattern, the activation-cert circuit-breaker, future hash-suite
   profile additions).

The royalty-free grant in §3 applies to ALL such filings, present
and future, that are owned or controllable by Lux.

## §5 Why the grant is structured this way

A few notes for reviewers who might ask "why this language and not
plain public-domain dedication":

### §5.1 Defensive patent ownership protects the ecosystem

Without Lux holding the patents on the Corona production-lifecycle
additions, a third party could observe the public NIST submission,
file blocking patents on (e.g.) the activation-cert circuit-breaker
shape, and assert them against open-source implementations. Lux
holding the patents (with a royalty-free grant) removes that attack
surface.

This is the same logic that protects FRAND ecosystems and that
underlies Apache-2.0's patent grant + retaliation clause.

### §5.2 Compatibility with NIST MPTC submission terms

The NIST Multi-Party Threshold Cryptography project's submission
guidelines require submitters to provide a patent statement
specifying the IP terms under which the submitted construction may
be used. The grant in §3 satisfies that requirement and goes beyond
NIST's baseline by extending defensive termination to the underlying
Boschini et al. construction (not just Corona's production
lifecycle additions) and to all NIST-standardized post-quantum
signature schemes.

### §5.3 Compatibility with the published Boschini et al. construction

The underlying 2-round R-LWE threshold protocol is published in the
academic literature (IACR ePrint 2024/1113, IEEE S&P 2025). Lux
asserts no patents on the published academic construction itself;
Corona's claims are limited to the production-lifecycle additions.
Any third-party implementation of the Boschini et al. construction
is free of Corona patent assertions whether or not it adopts
Corona's lifecycle layers.

### §5.4 Defensive termination for the broader PQ ecosystem

Extending defensive termination to the underlying Boschini et al.
construction AND to FIPS 204 ML-DSA (and successors) — not just
Corona itself — converts Lux's patent portfolio into a small
deterrent against PQ-signature patent trolls. It costs Lux nothing
(Lux does not intend to assert offensively) and benefits the
ecosystem.

## §6 What this document does NOT do

- It does not assign any Lux patent rights to NIST, IETF, or any
  third party. Lux retains ownership; the grant in §3 is a license.
- It does not commit Lux to maintain or prosecute any specific
  patent application. Lux may abandon applications for business
  reasons; the grant in §3 covers issued patents in proportion to
  what is actually granted.
- It does not waive Lux's right to update the grant text (subject
  to §6.1 below).
- It does not modify the Apache-2.0 license covering the
  reference implementation, specification, and vectors.
- It does not claim patent rights on the Boschini et al. published
  construction (academic prior art).

### §6.1 Modifications to this grant

Lux may issue future versions of this PATENTS document with
clarifications or extensions of the grant. Future versions will
apply to implementations published under the future version's
identifier. **The grant in §3 of this v1.0 document is
irrevocable for implementations relying on it**, subject only to
the defensive-termination clause in §3.2.

## §7 Contact

| Purpose | Contact |
|---|---|
| Patent / IP inquiries | `legal@lux.network` |
| Licensing for non-conforming implementations | `legal@lux.network` |
| NIST submission coordination | `mptc@lux.network` |
| Security disclosure | See `SECURITY.md` |

For patent-claim drafting (the document an attorney would work
from), see `docs/patent-claims.md`.

---

**Document metadata**

- Document name: `PATENTS.md`
- Document version: v1.0
- Document date: 2026-05-18
- Construction version: Corona v0.2 (NIST MPTC submission package scaffolding)
- Construction repository: <https://github.com/luxfi/corona>
- License of this document: Creative Commons CC-BY-4.0 (so it
  can be freely reproduced in NIST submission packages and audit
  reports without modification).
