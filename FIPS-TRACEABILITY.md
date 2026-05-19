# FIPS-TRACEABILITY — Corona

> Construction-paper → code traceability map. R-LWE has no FIPS
> standard, so this document maps **Boschini ePrint 2024/1113 (IEEE
> S&P 2025)** sections to `~/work/lux/corona/` implementation paths.
> Equivalent role to Pulsar's `FIPS-TRACEABILITY.md` (which maps
> FIPS 204 § → code).

## §1 Reference

- **Boschini, C., Kaviani, A., Lai, R. W. F., Malavolta, G.,
  Takahashi, A., Tibouchi, M.** *Practical two-round threshold
  signatures from learning with errors.* IACR ePrint 2024/1113 →
  IEEE S&P 2025.

This is the construction-level normative reference for Corona. The
Lux production fork extends the construction with a public-DKG
lifecycle (`dkg2/`) and proactive resharing (`reshare/`); these
extensions are documented in `SPEC.md`.

## §2 Section → code mapping

### §2.1 Notation + ring construction (paper §2-3)

| Paper § | Topic | Code |
|---|---|---|
| §2.1 | Cyclotomic ring `R_q = Z_q[X]/(X^256+1)` | `sign/config.go:19` (`Q = 0x1000000004A01`); `threshold/threshold.go:46` (`ring.NewRing(256, []uint64{Q})`) |
| §2.2 | Module-LWE parameters | `sign/config.go:25` (M, N, K, Dbar, Kappa) |
| §2.3 | Montgomery + Barrett constants | `luxfi/lattice/v7/ring/modular_reduction.go` (via dependency) |
| §2.4 | NTT roots + cyclotomic factorization | `luxfi/lattice/v7/ring/ntt.go` (via dependency) |

### §2.2 Distributed key generation (paper §4)

| Paper § | Topic | Code |
|---|---|---|
| §4.1 | Pedersen-VSS over `R_q` | `dkg2/dkg2.go`, `dkg2/round1.go`, `dkg2/round2.go` |
| §4.2 | Per-party complaint records | `dkg2/complaint.go` |
| §4.3 | Round-3 share verification | `dkg2/dkg2.go` (Round3 method) |
| §4.4 | Group public key derivation | `keyera/keyera.go` (`EpochShareState.GroupPubkey`) |

Note: the paper's DKG uses Feldman commitments; the Lux profile
replaces this with Pedersen-VSS to close the pseudoinverse-
recoverable attack described in `~/work/luxcpp/crypto/corona/RED-DKG-REVIEW.md`.
The Lux delta is conservative — Pedersen is strictly more hiding
than Feldman. Documented in `SPEC.md` §4.

### §2.3 Threshold signing (paper §5)

| Paper § | Topic | Code |
|---|---|---|
| §5.1 | Round-1: commit-and-MAC | `threshold/round1.go` |
| §5.2 | Round-2: mask reveal | `threshold/round2.go` |
| §5.3 | Combine: Lagrange + ML-DSA aggregation | `threshold/combine.go` |
| §5.4 | Hash domain separation (cSHAKE256 / KMAC256) | `hash/sp800_185.go` (SP 800-185 conformance) |

### §2.4 Reshare protocol (paper §7, Lux extension)

The paper's §7 covers proactive secret sharing under fixed
committees. The Lux profile adds **cross-committee resharing** via
the keyera-lifecycle pattern:

| Topic | Code |
|---|---|
| Reshare protocol (Desmedt-Jajodia over `R_q`) | `reshare/reshare.go` |
| Activation cert circuit-breaker | `reshare/activation.go` |
| Per-party complaints | `reshare/complaint.go` |
| Key-era management (Bootstrap → Reshare → Reanchor) | `keyera/keyera.go` |

The Lux Reshare extension preserves the group public key across an
arbitrary number of epochs within a key era. Reanchor opens a new
key era. Documented in `SPEC.md` §5 + `DEPLOYMENT-RUNBOOK.md`.

### §2.5 Identifiable abort (paper §6)

The Lux profile implements identifiable abort across both DKG and
signing phases:

| Phase | Code |
|---|---|
| DKG complaint records | `dkg2/complaint.go` |
| Threshold-sign complaint records | `threshold/complaint.go` (if present; otherwise via per-round share verification) |
| Reshare complaint records | `reshare/complaint.go` |

Each complaint carries a signed evidence blob attributable to a
specific signer. Soundness reduces to identity-key signature
unforgeability — see `AXIOM-INVENTORY.md` §2.

## §3 What this document is NOT

- NOT a security proof. The Boschini construction's security is
  proved in the cited paper.
- NOT a NIST FIPS standard reference (R-LWE has no FIPS standard).
- NOT a mechanized refinement against the cited paper. EC theories
  that formalize this mapping are roadmap v0.7.0 (see
  `AXIOM-INVENTORY.md` §2 + `PROOF-CLAIMS.md` §3).

This document is the **citation discipline**: every operation in
the shipped code traces to a specific paper section, with Lux
deltas (Pedersen-VSS, keyera lifecycle, proactive cross-committee
reshare) called out explicitly.

## §4 Cross-references

- `SUBMISSION.md` — submission cover sheet
- `SPEC.md` — protocol specification (includes Lux-delta detail)
- `AXIOM-INVENTORY.md` — residual axiom inventory
- `PROOF-CLAIMS.md` — narrow claim + non-claims
- `TRUSTED-COMPUTING-BASE.md` — TCB
- Boschini ePrint 2024/1113 — construction-level normative reference
