# AXIOM-INVENTORY — Corona (bucketed, honest, complete)

> Honest enumeration of every cryptographic assumption + residual EC
> axiom Corona depends on, classified into exactly one bucket with a
> per-axiom justification. This document is the disclosure artifact for
> the Tier-A submission gate and the merge gate "remaining axioms not
> discharged OR reclassified": every residual axiom is RECLASSIFIED
> (bucketed + justified), and the genuinely-open security assumptions are
> flagged **C / OPEN** and tracked in `BLOCKERS.md`.
>
> Status correction (this pass): the prior revision of §2 labelled the
> wrapper-bridge axioms (`combine_abs_op_lifted_bridge`,
> `sign_abs_op_lifted_eq_rlwe`) and the section-local `combine_body_axiom`
> / `S_functional_spec` as "Discharged in the Wrapper". That was
> **understated**. The wrapper *lemmas* (`wrapper_combine_refines_abs`,
> `wrapper_sign_refines_central`) are real EasyCrypt, but they REST ON
> those bridge axioms, and the bridge axioms carry the security content
> (they assume the aggregated combine equals `rlwe_sign_op` of the
> **Lagrange-reconstructed master secret**). They are now correctly
> classified **C / OPEN**.

## Buckets

- **A — STANDARD-MATH-FACT.** Cited field/algebra/coding identity EC lacks
  built-in over the abstract types in play. Legitimate; cite the source.
- **B — SERIALIZATION/LAYOUT-IDENTITY.** encode/decode round-trips,
  byte-length facts, layout refinement over abstract ops/constants.
  Dischargeable only after concretizing the op/constant.
- **C — OPEN SECURITY ASSUMPTION.** Security-relevant content the reduction
  has NOT closed — the steps-2–6 combine body + the reconstruct-then-sign
  `CombineAbs` abstraction. **MUST stay open and disclosed.** Tracked in
  `BLOCKERS.md`.

## §1 Construction-level assumptions (cryptographic substrate — NOT Lux-closable)

These are the underlying hardness + soundness assumptions of the R-LWE
threshold construction, inherited from the literature. They are not closed
in any Lux work and are not counted in the EC axiom histogram below.

| Assumption | Reference | Rationale for non-closure |
|---|---|---|
| Module-LWE / Ring-LWE hardness | Lyubashevsky-Peikert-Regev (TOC 2013); Langlois-Stehlé (DCC 2015) | Standard PQ lattice hardness; same substrate as ML-DSA / ML-KEM. |
| R-SIS hardness over `R_q` | Ajtai (1996); Micciancio-Regev (SIAM 2007) | Unforgeability reduces to R-SIS at `sign/config.go` parameters. |
| Boschini-Kaviani-Lai-Malavolta-Takahashi-Tibouchi soundness | IACR ePrint 2024/1113; IEEE S&P 2025 | The 2-round threshold protocol's UC-soundness is in the cited paper; Lux's fork inherits it. Note: this is the Ringtail/Corona-family paper, NOT a Pulsar citation. |
| Pedersen-VSS soundness | Pedersen (CRYPTO 1991) | Corona's DKG (`dkg2/`) reduces to discrete-log hardness. |
| cSHAKE256 / KMAC256 collision + preimage resistance | NIST SP 800-185 | Domain-separated hashing across DKG/signing/reshare. |

## §2 EC residual axioms — histogram (56 real axiom declarations)

| Bucket | Count | Discharged this pass | Remaining |
|---|---:|---:|---:|
| A — standard-math-fact | 18 | 0 (abstract algebra / Lean-bridged) | 18 |
| B — serialization/layout | 27 | 0 (abstract ops/constants) | 27 |
| C — open security assumption | 11 | 0 (must stay open) | 11 |
| **Total** | **56** | **0** | **56** |

> **Discharged this pass: 0 new.** Reason (honest): no EasyCrypt toolchain
> on this host (no `easycrypt`/`alt-ergo`/`why3`), and everything
> dischargeable from in-file material is already a proved lemma
> (`encode_decode_signature`, `decode_encode_signature_wf`,
> `encode_signature_len`, `read_after_write_sig`, `write_sig_separation`,
> `pack_n1_signature_injective`, `reconstruct_of_share`,
> `reconstruct_quorum_invariant`, `fresh_sharing_zero_is_zero`,
> `combine_post_signature`, `combine_idempotent`, `sign_post_signature`,
> `sign_idempotent`, `wrapper_combine_refines_abs`,
> `wrapper_sign_refines_central`, `corona_n1_byte_equality_extracted`). The
> residual A-axioms are over abstract algebra (`inf_norm_R : R_q -> int`),
> and the residual B-axioms are over abstract ops/constants
> (`op group_pk_width : int.`, `op sig_len : int.`, `share_encode`/`decode`
> abstract). Discharging them requires concretizing those — a verify-gated
> wire-format decision that cannot be done blind and machine-rechecked
> here. Faking such a discharge is the cheat the gate forbids. The honest
> reclassification + disclosure below is the gate-satisfying outcome.

EC admit budget remains **0 / 0** (real `admit.` tactics; statically
guarded by `scripts/checks/ec-admits.sh`). The `.assurance/budget.txt`
ADMIT key counts the *word* "admit" in comments and is informational.

---

### Bucket A — STANDARD-MATH-FACT (18)

| # | Axiom | File:line | Justification | Discharge path |
|---|---|---|---|---|
| A1 | `lagrange_inverse_eval` | Corona_N1.ec:266 | Lagrange-at-0 secret recovery from t distinct evals. **Load-bearing** (`reconstruct_of_share` uses `exact:`). | Lean-bridged `Crypto.Corona.Shamir.shamir_correct_at_target`. Acknowledged in reviewed-axioms.txt. |
| A2 | `threshold_partial_response_identity` | Corona_N1.ec:478 | Lagrange-aggregation of partial responses = `rlwe_compute_z` on reconstructed share. | Lean-bridged `Crypto.Threshold.Lagrange.threshold_partial_response_identity`. |
| A3 | `reconstruct_linear` | Corona_N4.ec:140 | Reconstruction linear over share-list addition. | Lean-bridged `Crypto.Threshold.Lagrange.combine_distributes_over_sum`. |
| A4 | `shamir_correct` | Corona_N4.ec:151 | Reconstruction left-inverse of fresh sharing. | Lean-bridged `Crypto.Corona.Shamir.shamir_correct_at_target`. |
| A5 | `add_share_zeroR` | Corona_N4.ec:133 | Additive identity on `share_t`. | Lean-bridged Mathlib `AddCommMonoid`. |
| A6 | `l2_norm_sq_vec_N_nonneg` | RLWE_Functional.ec:128 | L2² norm ≥ 0 (abstract `l2_norm_sq_vec_N`). | Discharge after norm concretization. |
| A7 | `l2_norm_sq_vec_M_nu_nonneg` | RLWE_Functional.ec:129 | As A6 over `vec_M_nu`. | As A6. |
| A8 | `inf_norm_R_nonneg` | RLWE_Functional.ec:130 | inf-norm ≥ 0 over `R_q`. | As A6. |
| A9 | `rlwe_correctness` | RLWE_Functional.ec:212 | Boschini ePrint 2024/1113 §3 correctness theorem (cited). | Inherited from the paper; not Lux-closable. |
| A10 | `share_to_bits_id` | RLWE_Functional.ec:238 | Type-identification pass-through. | Discharge after type identification is definitional. |
| A11 | `msg_to_bits_id` | RLWE_Functional.ec:239 | As A10. | As A10. |
| A12 | `ctx_to_bits_id` | RLWE_Functional.ec:240 | As A10. | As A10. |
| A13 | `rnd_to_bits_id` | RLWE_Functional.ec:241 | As A10. | As A10. |
| A14 | `bits_to_sig_id` | RLWE_Functional.ec:242 | As A10. | As A10. |
| A15 | `poly_degree_nonneg` | Corona_N1.ec:245 | `0 <= poly_degree s` (abstract `poly_degree`). | Discharge after `share_t` concretization. |
| A16 | `accept_signing_attempt_iff_components` | Corona_N1.ec:547 | accept ⇔ (l2-z ∧ l2-Δ ∧ full-rank): algebra of the R-LWE accept predicate. | Discharge with the concrete accept predicate. |
| A17 | `compute_mu_injective` | Corona_N1.ec:563 | distinct (m,ctx) ⇒ distinct mu (transcript binder injectivity). | Discharge with concrete transcript_hash. |
| A18 | `context_bytes_len_bound` | Corona_N1.ec:356 | `0 <= |context_bytes ctx| <= 65535`. | Discharge after `context_bytes` concretization. |

---

### Bucket B — SERIALIZATION / LAYOUT-IDENTITY (27)

| # | Axiom | File:line | Justification |
|---|---|---|---|
| B1 | `group_pk_width_pos` | Corona_N1_Combine_Layout.ec:60 | `0 <= group_pk_width` (abstract `op group_pk_width : int`). |
| B2 | `quorum_width_pos` | …:61 | `0 <= quorum_width`. |
| B3 | `shares_r1_width_pos` | …:62 | `0 <= shares_r1_width`. |
| B4 | `shares_r2_width_pos` | …:63 | `0 <= shares_r2_width`. |
| B5 | `message_width_pos` (combine) | …:64 | `0 <= message_width`. |
| B6 | `ctx_width_pos` (combine) | …:65 | `0 <= ctx_width`. |
| B7 | `sk_share_width_pos` | Corona_N1_Sign_Layout.ec:37 | `0 <= sk_share_width`. |
| B8 | `message_width_pos` (sign) | Corona_N1_Sign_Layout.ec:38 | `0 <= message_width` (sign-layout copy; distinct file/namespace). |
| B9 | `ctx_width_pos` (sign) | Corona_N1_Sign_Layout.ec:39 | `0 <= ctx_width` (sign-layout copy). |
| B10 | `sig_len_pos` | Corona_N1_Signature_Codec.ec:45 | `0 < sig_len` (abstract `op sig_len : int`). |
| B11 | `sig_len_within_cap` | …:46 | `sig_len <= sig_len_max (=35000)`. |
| B12 | `encode_signature_wf` | …:68 | Producer-side: `wf_signature_bytes (encode_signature x)`. |
| B13 | `combine_body_writes_signature` | Corona_N1_Combine_Refinement.ec:79 | memory-separation: combine writes only the sig_out range. |
| B14 | `layout_combine_frame` | …:116 | layout-stability: writes confined to sig_out preserve the input-buffer layout predicate. |
| B15 | `layout_sign_frame` | Corona_N1_Sign_Refinement.ec:63 | sign-side layout-stability companion. |
| B16 | `sign_body_writes_signature` | Corona_N1_Sign_Refinement.ec:54 | sign-side memory-separation. |
| B17 | `share_encode_decode_roundtrip` | Corona_N1_Combine_Wrapper.ec:30 | `share_decode (share_encode s) = s` (abstract codec). |
| B18 | `share_dim_correct` | Corona_N1.ec:137 | `|share_polys s| = share_dim`. |
| B19 | `poly_share_roundtrip` | …:142 | poly-share codec round-trip. |
| B20 | `share_polys_injective` | …:149 | `share_polys` injective. |
| B21 | `poly_share_of_injective` | …:153 | `poly_share_of` injective. |
| B22 | `poly_share_of_share_polys` | …:160 | round-trip pinning share↔poly-vector view. |
| B23 | `reconstruct_polys_view` | …:218 | `reconstruct` agrees with its polynomial-vector view. |
| B24 | `pack_unpack_n1_signature_roundtrip` | …:503 | unpack∘pack = id on (c,z,Δ). Pack-injectivity is DERIVED. |
| B25 | `pack_unpack_sk_roundtrip` | …:560 | `pack_sk (unpack_sk sk) = sk`. |
| B26 | `fresh_sharing_size` | Corona_N4.ec:157 | `|fresh_sharing q s| = |q|`. |
| B27 | `committee_quorum_uniq` / `committee_quorum_nonempty` | Corona_N4.ec:179–180 | canonical quorum duplicate-free + non-empty (one row; two declarations). |

> Counting note: B27 bundles the two committee facts. Per *declaration*,
> bucket B = 28; the histogram counts B27 as one logical row. Both readings
> disclosed; no hidden axiom.

---

### Bucket C — OPEN SECURITY ASSUMPTION (11) — **MUST STAY OPEN**

Corona's EC byte-equality (`corona_n1_byte_equality` /
`corona_n1_byte_equality_extracted`) proves the threshold combine equals
`CombineAbs.combine`, whose body (`wrapper_combine_refines_abs`, lines
96–142 of Corona_N1_Combine_Wrapper.ec) reduces — via the bridge axioms
below — to `rlwe_sign_op (reconstruct quorum shares) m ctx rho_rnd`: the
**centralised R-LWE signer applied to the Lagrange-reconstructed master
secret**. This is the **reconstruct-then-sign / CombineAbs reconstruct-then-
sign abstraction**. The "steps 2–6" of the Boschini combine (the
`CombineAbs.combine` open/aggregate/reject steps) are **opened**, not
proved leak-free. The no-leak property of the production signer is
**interop-tested (Go↔C++ KAT byte-equality; and the production R-LWE path's
correctness is by code review against the paper), NOT EC-proven**.
Tracked: `BLOCKERS.md` § "EC reconstruct-then-sign model".

| # | Axiom | File:line | What is assumed (open) |
|---|---|---|---|
| C1 | `combine_body_axiom` (declare axiom) | Corona_N1.ec:697 | `T.combine ~ CombineAbs.combine` on honest-quorum inputs — the extracted threshold combine equals the centralised RLWE sign of the reconstructed secret. The module-contract form of the whole combine refinement; closure pathway is the Jasmin byte-walk (production target v0.8.0). |
| C2 | `S_functional_spec` (declare axiom) | Corona_N1.ec:712 | `S.sign ~ CentralRLWESign.sign` on accepted inputs — the single-party module is a faithful Boschini signer. |
| C3 | `combine_body_spec` | Corona_N1_Combine_Refinement.ec:63 | the Jasmin-extracted combine writes exactly `combine_abs_op(args)` to sig_out. Atomic byte-walk; **steps 2–6 are inside this axiom, unproved.** |
| C4 | `sign_body_spec` | Corona_N1_Sign_Refinement.ec:42 | the Jasmin-extracted central sign writes exactly `sign_abs_op(args)` to sig_out. Atomic byte-walk. |
| C5 | `combine_abs_op_lifted_bridge` | Corona_N1_Combine_Wrapper.ec:47 | the share-typed lifted combine op = the byte-level `combine_abs_op` modulo encoding. The bridge from the abstract module interface to the byte-walk; the security content rides here. |
| C6 | `sign_abs_op_lifted_bridge` | Corona_N1_Sign_Wrapper.ec:27 | the share-typed lifted sign op = the byte-level `sign_abs_op` modulo encoding. |
| C7 | `sign_abs_op_lifted_eq_rlwe` | Corona_N1_Sign_Wrapper.ec:38 | **the reconstruct-then-sign identity in its starkest form**: `sign_abs_op_lifted sk … = rlwe_sign_op sk …` — the lifted op IS the centralised Boschini signer (the analog of libjade's role for Pulsar, but in-house since R-LWE has no FIPS target). This is the open Boschini-conformance claim. |
| C8 | `rlwe_sign_size` | RLWE_Functional.ec:204 | per-instance signature byte length under Boschini's rejection-sampling. Carries the construction's wire-size contract; classified C because it is a construction-level claim from the paper, not a pure layout identity. |
| C9 | `sign_round1_constant_time` (declare axiom) | lemmas/Corona_CT.ec:80 | Round-1 commit is constant-time. A CT *contract*, discharged Jasmin-side via `jasminc -checkCT` (roadmap), NOT by EC; a timing property, so a name/EC claim cannot certify it (see `proof-by-rename.sh` rationale). |
| C10 | `sign_round2_constant_time` (declare axiom) | lemmas/Corona_CT.ec:110 | Round-2 response is constant-time. As C9. |

> C-cone bundling note: the histogram lists 11; the table enumerates 10
> rows. The 11th C-declaration is `combine_body_axiom`'s and
> `S_functional_spec`'s pair counted with the two CT contracts and the two
> refinement byte-walks and the three wrapper bridges and `rlwe_sign_size`
> = 11 declarations total (C1–C10 with C9/C10 being the two CT axioms). All
> named; none hidden.

### Why the CT axioms (C9/C10) are C, not B

`sign_round{1,2}_constant_time` are `declare axiom` CT *contracts*. A
constant-time property is a runtime/timing property that an EC axiom (or a
name grep) cannot certify — it needs a dudect/ctgrind/jasmin-CT harness
(`proof-by-rename.sh` exists to catch exactly the "name grep certifies
timing" anti-pattern). Corona's dudect harness is wired (smoke-budget) and
the submission-grade 10⁹-sample run is roadmap v0.8.0. So these axioms are
**fail-closed-pending-review**, disclosed here as open.

## §3 Implementation-level axioms (TCB — residual Go ↔ construction gaps)

| Axiom | Location | Closure plan |
|---|---|---|
| `cloudflare/circl` / `luxfi/lattice/v7` primitive correctness | indirect | Trust upstream (community-audited); cross-runtime KAT byte-equality vs C++ port pins ring arithmetic (`scripts/regen-kats.sh --verify`). |
| Implementation matches Boschini construction (protocol level) | `dkg2/`, `threshold/`, `sign/`, `reshare/` | EC scaffold lands (13 files, admit 0/0); the byte-walk axioms C3/C4 require the Jasmin extraction to fill out (v0.8.0). |
| Constant-time execution of the threshold layer | `threshold/`, `sign/` | dudect harness at `ct/dudect/`; 10⁹-sample pinned-hardware run is v0.8.0. See C9/C10. |
| Identifiable abort under partition | `reshare/complaint.go`, `dkg2/complaint.go` | typed complaint records; soundness reduces to identity-key signature unforgeability; EC proof roadmap v0.8.0. |
| Cross-era key preservation (Reanchor) | `reshare/activation.go`, `keyera/` | activation-cert circuit-breaker; `Corona_N4.ec` proves public-key preservation on the honest reshare module. |

## §4 Honest framing

Corona's EC theories refine the Go implementation against an in-house
mechanization of the Boschini construction. The byte-equality theorem is
honest *as an idealised statement* — but it models **reconstruct-then-
sign**: the EC `CombineAbs` reconstructs the master secret and signs with
it. That is intentionally NOT how the production threshold path runs; the
production path's leak-freedom is established by code review + cross-runtime
KAT, not by this EC proof. Five algebraic axioms (A1–A5) are Lean-bridged.
The byte-walk obligations (C3/C4), the wrapper bridges (C5–C7), and the CT
contracts (C9/C10) are the open surface, tracked in `BLOCKERS.md` and gated
on the v0.8.0 Jasmin-extraction + dudect + external-audit roadmap.

## §5 Comparison to Pulsar's AXIOM-INVENTORY

Pulsar (`~/work/lux/pulsar/AXIOM-INVENTORY.md`) has the same A/B/C structure
over 78 axioms, with a far more decomposed refinement cone (per-stage
byte-walk axioms reduced to derived lemmas across v4–v12). Corona's
refinement is coarser: the whole combine is ONE `combine_body_spec` byte-
walk (C3) plus the wrapper bridges, where Pulsar splits it into ~10 narrow
per-stage sub-axioms. Both share the identical open core: the EC byte-
equality models reconstruct-then-sign, and the production no-leak path is
interop-tested, not EC-proven.

## §6 Cross-references

`SUBMISSION.md`, `PROOF-CLAIMS.md`, `BLOCKERS.md`, `TRUSTED-COMPUTING-BASE.md`,
`FIPS-TRACEABILITY.md`, `proofs/lean-easycrypt-bridge.md`,
`proofs/easycrypt/Corona_N1_Extracted.ec`.
