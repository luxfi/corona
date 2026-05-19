# AXIOM-INVENTORY -- Corona

> Honest enumeration of every cryptographic assumption + residual
> axiom Corona depends on. This document is load-bearing for the
> Tier A submission gate: per the project rubric, AXIOM-INVENTORY
> MUST be reviewable by an external cryptographer and MUST close
> every residual axiom with either a closure plan or an explicit
> non-closure rationale.
>
> Status at **v0.7.0**: EC theory artifacts have landed. 13 EC files
> mirror the Pulsar Tier A layout. The admit budget is **0/0**
> across the EC file set (statically tracked by
> `scripts/checks/ec-admits.sh`). Section §2 enumerates the residual
> axioms (top-level `axiom` declarations and `declare axiom`s inside
> sections), each cited with its closure pathway.

## §1 Construction-level axioms (cryptographic assumptions)

These are the underlying hardness + soundness assumptions of the
R-LWE threshold construction. They are NOT closed in any Lux work --
they are the substrate of the security argument and are inherited
from the academic literature.

| Axiom | Reference | Rationale for non-closure |
|---|---|---|
| **Module-LWE / Ring-LWE hardness** | Lyubashevsky-Peikert-Regev (TOC 2013) for R-LWE; Langlois-Stehle (Designs, Codes 2015) for module variants | Standard PQ lattice hardness assumption; same substrate as ML-DSA / ML-KEM. Not a Corona-specific assumption. |
| **Short Integer Solution (SIS) hardness over `R_q`** | Ajtai (1996); Micciancio-Regev (SIAM 2007) for ring variant | Unforgeability of Corona's underlying signature reduces to R-SIS at the parameters in `sign/config.go`. Not closing. |
| **Boschini-Kaviani-Lai-Malavolta-Takahashi-Tibouchi construction soundness** | IACR ePrint 2024/1113; IEEE S&P 2025 | The 2-round threshold-signing protocol's UC-soundness is proved in the cited paper. Lux's production fork inherits this proof; the Lux modifications (Pedersen-VSS DKG, keyera lifecycle, proactive reshare) are conservative additions analyzed below. |
| **Pedersen-VSS soundness** | Pedersen (CRYPTO 1991) | Lux's DKG (`dkg2/`) uses Pedersen-VSS to replace the upstream broken Feldman commit. Soundness reduces to discrete-log hardness in the underlying group; assumed. |
| **cSHAKE256 / KMAC256 collision + preimage resistance** | NIST SP 800-185 | Used in `hash/sp800_185.go` for domain-separated hashing across DKG, signing, reshare. Hash function security is standard assumption. |

## §2 EC residual axioms (v0.7.0 inventory)

The 13 EC files compile against the `axiom` and `declare axiom`
declarations enumerated below. Each is one of: (a) an algebraic
identity discharged in Lean (5 Lean-bridged axioms), (b) a structural
type/codec property closed at the wrapper layer, or (c) a Boschini
ePrint 2024/1113 construction-level identity cited at its inline
comment.

| Axiom | File | Status | Closure pathway |
|---|---|---|---|
| `lagrange_inverse_eval` | `Corona_N1.ec` | Lean-bridged | `Crypto.Corona.Shamir.shamir_correct_at_target` (Lean) |
| `threshold_partial_response_identity` | `Corona_N1.ec` | Lean-bridged | `Crypto.Threshold.Lagrange.threshold_partial_response_identity` (Lean) |
| `reconstruct_linear` | `Corona_N4.ec` | Lean-bridged | `Crypto.Threshold.Lagrange.combine_distributes_over_sum` (Lean) |
| `shamir_correct` | `Corona_N4.ec` | Lean-bridged | `Crypto.Corona.Shamir.shamir_correct_at_target` (Lean) |
| `add_share_zeroR` | `Corona_N4.ec` | Lean-bridged | Mathlib `AddCommMonoid` instance |
| `share_dim_correct`, `poly_share_roundtrip` et al. | `Corona_N1.ec` | Structural | Type-level invariant; concretization closes |
| `reconstruct_polys_view`, `share_polys_injective`, `poly_share_of_injective`, `poly_share_of_share_polys` | `Corona_N1.ec` | Structural | Pinning the abstract share_t to its polynomial-vector view |
| `poly_degree_nonneg`, `context_bytes_len_bound` | `Corona_N1.ec` | Definitional | Trivially provable once share_t is concretized |
| `accept_signing_attempt_iff_components` | `Corona_N1.ec` | Construction | Boschini §3 accept-event decomposition |
| `compute_mu_injective`, `pack_unpack_sk_roundtrip` | `Corona_N1.ec` | Construction | Corona transcript_hash binder; sk-codec |
| `pack_unpack_n1_signature_roundtrip` | `Corona_N1.ec` | Construction | Corona signature codec round-trip |
| `committee_quorum_uniq`, `committee_quorum_nonempty`, `fresh_sharing_size` | `Corona_N4.ec` | Definitional | Committee-quorum well-formedness |
| `sig_len_pos`, `sig_len_within_cap`, `encode_signature_wf` | `Corona_N1_Signature_Codec.ec` | Codec | Producer-side byte-length invariant |
| `q_pos`, `q_xi_pos`, `q_nu_pos`, `n_poly_pos`, `dbar_pos`, `kappa_pos` | `lemmas/RLWE_Functional.ec` | Concrete arithmetic | Closed via `decide` |
| `l2_norm_sq_*_nonneg`, `inf_norm_R_nonneg` | `lemmas/RLWE_Functional.ec` | Definitional | Definition of norm |
| `rlwe_sign_size`, `rlwe_correctness` | `lemmas/RLWE_Functional.ec` | Construction | Boschini ePrint 2024/1113 §3 correctness theorem |
| `share_to_bits_id`, `msg_to_bits_id`, `ctx_to_bits_id`, `rnd_to_bits_id`, `bits_to_sig_id` | `lemmas/RLWE_Functional.ec` | Type identification | Pass-through codec |
| `*_width_pos` (per-section widths) | `Corona_N1_Combine_Layout.ec`, `Corona_N1_Sign_Layout.ec` | Definitional | Non-negative widths |
| `combine_body_spec`, `combine_body_writes_signature`, `layout_combine_frame` | `Corona_N1_Combine_Refinement.ec` | Byte-walk + frame | Jasmin-side via `combine.jazz` extraction |
| `sign_body_spec`, `sign_body_writes_signature`, `layout_sign_frame` | `Corona_N1_Sign_Refinement.ec` | Byte-walk + frame | Jasmin-side via `rlwe/sign.jazz` extraction |
| `share_encode_decode_roundtrip`, `combine_abs_op_lifted_bridge` | `Corona_N1_Combine_Wrapper.ec` | Codec bridge | Wire encoding |
| `sign_abs_op_lifted_bridge`, `sign_abs_op_lifted_eq_rlwe` | `Corona_N1_Sign_Wrapper.ec` | RLWE conformance | Bridge to `rlwe_sign_op` |
| `combine_body_axiom` (section-local `declare axiom`) | `Corona_N1.ec` § ClassN1 | Module contract | Discharged in `Corona_N1_Combine_Wrapper.wrapper_combine_refines_abs` |
| `S_functional_spec` (section-local `declare axiom`) | `Corona_N1.ec` § ClassN1 | Module contract | Discharged in `Corona_N1_Sign_Wrapper.wrapper_sign_refines_central` |
| `round1_commit_constant_time`, `round2_response_constant_time` (section-local) | `lemmas/Corona_CT.ec` | CT contract | Discharged Jasmin-side via `jasminc -checkCT` |

**Admit budget: 0/0** across all 13 EC files
(`scripts/checks/ec-admits.sh` is the static guard).

## §3 Implementation-level axioms (TCB)

These are residual gaps between the verified construction and the
shipped Go implementation. Each has a closure plan.

| Axiom | Location | Closure plan |
|---|---|---|
| `cloudflare/circl` lattice primitives correctness | indirect via `luxfi/lattice/v7` | Trust the library; upstream is community-audited. Not closing in Lux. |
| `luxfi/lattice/v7` ring arithmetic correctness | `threshold/`, `sign/` | Cross-runtime byte-equality with C++ port at `luxcpp/crypto/corona/`; KAT manifest pins it. CI-enforced via `scripts/regen-kats.sh --verify`. |
| Implementation matches Boschini construction at the protocol level | `dkg2/`, `threshold/`, `sign/`, `reshare/` | **v0.7.0**: EC scaffold lands (13 files, admit 0/0). Closure pathway from byte-walk axioms in `Corona_N1_{Combine,Sign}_Refinement.ec` requires the Jasmin extraction to fill out (production target at v0.8.0). |
| Constant-time execution of the threshold layer | `threshold/`, `sign/` | **v0.7.0**: dudect harness lands at `ct/dudect/` (Verify + Combine). Smoke-budget runs are wired; the submission-grade 10^9-sample run on pinned hardware is the v0.8.0 audit target. |
| Identifiable abort attribution under partition | `reshare/complaint.go`, `dkg2/complaint.go` | Lux profile adds typed complaint records; soundness reduces to identity-key signature unforgeability. Documented in `SPEC.md` and tested in `complaint_test.go`. EC formal proof remains roadmap v0.8.0. |
| Cross-era key preservation via Reanchor | `reshare/activation.go`, `keyera/` | Lux profile adds activation cert circuit-breaker. Soundness inherited from R-LWE + KMAC collision resistance. `Corona_N4.ec` proves the public-key preservation property on the honest reshare module. |

## §4 Comparison to Pulsar's AXIOM-INVENTORY

Pulsar's `~/work/lux/pulsar/AXIOM-INVENTORY.md` enumerates the residual
EC axioms after the v4-v13 decomposition cascade. Corona v0.7.0
achieves the same structural shape:

- 13 EC files (Pulsar parity)
- Admit budget 0/0 (Pulsar parity)
- 5 Lean-bridged algebraic axioms (Pulsar parity: `lagrange_inverse_eval`,
  `threshold_partial_response_identity`, `add_share_zeroR`,
  `reconstruct_linear`, `shamir_correct`)
- Byte-walk + memory-separation + layout-frame axioms in the two
  Refinement files (Pulsar parity)
- Wrapper-side discharge of section-local module-contract axioms
  (Pulsar parity)

Corona is structurally easier than Pulsar in one respect: there is
no FIPS 204 byte-equal claim, so no `accept_signing_attempt`
kappa-rejection-sampling-loop reasoning. The Corona N1 analog is
"implementation matches Boschini construction" which is a narrower
refinement than Pulsar's FIPS 204 byte-equality.

## §5 Honest framing

This document is the **inventory** of axioms Corona's EC proofs
depend on at v0.7.0. The EC files compile against these named axioms
+ the Lean-bridged ones; the **admit budget is 0/0** across the 13-file
set. Five algebraic axioms are bridged to Lean theorems with explicit
inline citations (CI-enforced via `scripts/check-lean-bridge.sh`).

What remains operational:
- Jasmin extraction filling out the byte-walk refinement (production
  target v0.8.0).
- dudect submission-grade 10^9-sample runs on pinned hardware
  (production target v0.8.0).
- External cryptographic audit engagement (production target v0.8.0).

## §6 Cross-references

- `SUBMISSION.md` -- submission cover sheet
- `PROOF-CLAIMS.md` -- narrow claim + explicit non-claims
- `TRUSTED-COMPUTING-BASE.md` -- TCB inventory
- `FIPS-TRACEABILITY.md` -- Boschini paper -> code traceability
- `DEPLOYMENT-RUNBOOK.md` -- operator trust-model disclosure
- `CRYPTOGRAPHER-SIGN-OFF.md` -- independent review verdict
- `proofs/lean-easycrypt-bridge.md` -- Lean-bridged axiom correspondence
- `proofs/easycrypt/Corona_N1_Extracted.ec` -- implementation-backed N1 theorem
- `CHANGELOG.md` -- v0.7.0 roadmap closure
