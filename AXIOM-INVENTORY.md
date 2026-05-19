# AXIOM-INVENTORY — Corona

> Honest enumeration of every cryptographic assumption + residual
> axiom Corona depends on. This document is load-bearing for the
> Tier A submission gate: per the project rubric, AXIOM-INVENTORY
> MUST be reviewable by an external cryptographer and MUST close
> every residual axiom with either a closure plan or an explicit
> non-closure rationale.
>
> Status at v0.6.0: **EC theory artifacts are roadmap**; this document
> enumerates the construction-level + implementation-level axioms
> against which the eventual proofs will be discharged.

## §1 Construction-level axioms (cryptographic assumptions)

These are the underlying hardness + soundness assumptions of the
R-LWE threshold construction. They are NOT closing in any Lux work
— they are the substrate of the security argument and are inherited
from the academic literature.

| Axiom | Reference | Rationale for non-closure |
|---|---|---|
| **Module-LWE / Ring-LWE hardness** | Lyubashevsky-Peikert-Regev (TOC 2013) for R-LWE; Langlois-Stehlé (Designs, Codes 2015) for module variants | Standard PQ lattice hardness assumption; same substrate as ML-DSA / ML-KEM. Not a Corona-specific assumption. |
| **Short Integer Solution (SIS) hardness over `R_q`** | Ajtai (1996); Micciancio-Regev (SIAM 2007) for ring variant | Unforgeability of Corona's underlying signature reduces to R-SIS at the parameters in `~/work/lux/corona/sign/config.go`. Not closing. |
| **Boschini-Kaviani-Lai-Malavolta-Takahashi-Tibouchi construction soundness** | IACR ePrint 2024/1113; IEEE S&P 2025 | The 2-round threshold-signing protocol's UC-soundness is proved in the cited paper. Lux's production fork inherits this proof; the Lux modifications (Pedersen-VSS DKG, keyera lifecycle, proactive reshare) are conservative additions analyzed below. |
| **Pedersen-VSS soundness** | Pedersen (CRYPTO 1991) | Lux's DKG (`dkg2/`) uses Pedersen-VSS to replace the upstream broken Feldman commit. Soundness reduces to discrete-log hardness in the underlying group; assumed. |
| **cSHAKE256 / KMAC256 collision + preimage resistance** | NIST SP 800-185 | Used in `hash/sp800_185.go` for domain-separated hashing across DKG, signing, reshare. Hash function security is standard assumption. |

## §2 Implementation-level axioms (TCB)

These are residual gaps between the verified construction and the
shipped Go implementation. Each has a closure plan.

| Axiom | Location | Closure plan |
|---|---|---|
| `cloudflare/circl` lattice primitives correctness | indirect via `luxfi/lattice/v7` | Trust the library; upstream is community-audited. Not closing in Lux. |
| `luxfi/lattice/v7` ring arithmetic correctness | `threshold/`, `sign/` | Cross-runtime byte-equality with C++ port at `luxcpp/crypto/corona/`; KAT manifest pins it. CI-enforced via `scripts/regen-kats.sh --verify`. |
| Implementation matches Boschini construction at the protocol level | `dkg2/`, `threshold/`, `sign/`, `reshare/` | **OPEN — gated by EC theory shell.** Roadmap v0.7.0: implement EC theories `Corona_N1_Refinement.ec`, `Corona_N1_Combine_Refinement.ec`, `Corona_N4_Reshare.ec`. Pulsar got to admit 0/0 over 13 EC iterations; Corona will follow the same closure path. |
| Constant-time execution of the threshold layer | `threshold/`, `sign/` | **OPEN.** No `dudect` harness yet for the threshold layer. Roadmap v0.8.0. Single-party Corona signing CT is partial; see `CONSTANT-TIME-REVIEW.md`. |
| Identifiable abort attribution under partition | `reshare/complaint.go`, `dkg2/complaint.go` | Lux profile adds typed complaint records; soundness reduces to identity-key signature unforgeability. Documented in `SPEC.md` and tested in `complaint_test.go`. Formal proof: roadmap v0.7.0. |
| Cross-era key preservation via Reanchor | `reshare/activation.go`, `keyera/` | Lux profile adds activation cert circuit-breaker. Soundness inherited from R-LWE + KMAC collision resistance. Formal proof: roadmap v0.7.0. |

## §3 Comparison to Pulsar's AXIOM-INVENTORY

Pulsar's `~/work/lux/pulsar/AXIOM-INVENTORY.md` enumerates 14 residual
EC axioms remaining after the v4-v13 decomposition cascade. Corona
v0.6.0 has zero EC artifacts; the comparable axiom inventory for
Corona is the **roadmap target** of v0.7.0+.

Corona is structurally easier than Pulsar in one respect: there is
no FIPS 204 byte-equal claim, so no `accept_signing_attempt`
predicate or κ-rejection-sampling-loop reasoning. The Corona N1
analog is "implementation matches Boschini construction" which is a
narrower refinement than Pulsar's FIPS 204 byte-equality.

## §4 Honest non-claim

This document is the **inventory** of axioms Corona's proofs WILL
discharge. It is NOT a claim that Corona's proofs are CLOSED.
EC theories for Corona are explicitly roadmap (see `PROOF-CLAIMS.md`
§3 non-claims + this file's §2 closure plans).

At v0.6.0, Corona's proof basis is:
1. Construction soundness inherited from Boschini ePrint 2024/1113
2. KAT-determinism (`scripts/regen-kats.sh --verify`) on every commit
3. Cross-runtime byte-equality with `luxcpp/crypto/corona/` C++ port
4. Test-suite coverage (`go test -count=1 -race ./...`)
5. Constant-time review documented at `CONSTANT-TIME-REVIEW.md`

EC mechanization is the load-bearing gap between Tier A documentation
shape (achieved v0.6.0) and the full Tier A cut-readiness Pulsar
v1.0.9 holds (admit 0/0 across 13 EC files).

## §5 Cross-references

- `SUBMISSION.md` — submission cover sheet
- `PROOF-CLAIMS.md` — narrow claim + explicit non-claims
- `TRUSTED-COMPUTING-BASE.md` — TCB inventory
- `FIPS-TRACEABILITY.md` — Boschini paper → code traceability
- `DEPLOYMENT-RUNBOOK.md` — operator trust-model disclosure
- `CRYPTOGRAPHER-SIGN-OFF.md` — independent review verdict
- Roadmap target for EC theory shells: v0.7.0 (`CHANGELOG.md`)
