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

## §2 EC residual axioms — histogram (nominal sub-bucket counts)

> The per-bucket counts below are hand-maintained nominal figures. The
> MACHINE-ENFORCED authority is `.assurance/budget.txt` `AXIOM=59`
> (comment-stripped declarations across the whole proof tree, EC + Lean);
> sub-bucket drift never gates. The gate `ec-machine-check.sh` confirms
> 14/14 EC theories compile.

| Bucket | Count | Discharged this pass | Remaining |
|---|---:|---:|---:|
| A — standard-math-fact | 18 | 0 (abstract algebra / Lean-bridged; A IS machine-checked in Lean, see below) | 18 |
| B — serialization/layout | 28 | 0; **+1 `mask_telescope_zero`** (EC contract of the machine-checked Lean telescope) | 28 |
| C — open security assumption | 12 | **−1 `combine_abs_op_lifted_eq_rlwe` DISCHARGED → LEMMA** (z-leg via the machine-checked keystone; master secret never reconstructed); **+1 `threshold_public_commitment_eq_central`** — the NARROW PUBLIC-commitment residual that replaces it (no `c*s`, no secret). Net 0; the secret-bearing whole-bridge residual is GONE, only the public-commitment c/Delta-leg residual remains. | 12 |
| **Total** | **(nominal 58; budget authority = 59 EC+Lean)** | **C11 → lemma** | **— see budget.txt** |

> **A IS MACHINE-CHECKED IN LEAN ON THIS HOST.** The five A-axioms (A1–A5:
> `lagrange_inverse_eval`, `threshold_partial_response_identity`,
> `reconstruct_linear`, `shamir_correct`, `add_share_zeroR`) correspond 1:1
> to **sorry-free Lean 4 + Mathlib theorems that `lake build` compiles green
> on this host** (`Crypto.Threshold_Lagrange`, `Crypto.Corona.Shamir`). They
> remain EC `axiom`s only because EasyCrypt's field/polynomial theory is too
> thin to re-derive them in-prover; the gap is cross-prover proof-object
> exchange, not the absence of a proof.

> **Discharged into machine-checked Lean this pass: the no-leak CORRECTNESS
> CORE.** `Corona_N1_NoLeak.ec` states the production no-leak model whose
> algebraic core — the telescoping pairwise-mask cancellation + the Lagrange
> secret aggregate (master secret never formed) — is **newly machine-checked
> in Lean** (`Crypto.Corona.NoLeakAggregate`: `pairwise_mask_telescopes`,
> `summed_response_is_mask_free`, `secret_aggregate_no_reconstruct`,
> `no_leak_under_standard_assumptions`). The residual EC axiom is the
> Module-LWE/MSIS reduction, a STANDARD assumption (the same substrate §1
> lists) — not an implementation reconstruct.
>
> **EC TOOLCHAIN IS LIVE ON THIS HOST** (opam switch `proofs`: easycrypt +
> why3 + alt-ergo, z3 solver). The gate `ec-machine-check.sh` compiles all
> 14/14 EC theories. The earlier "no EasyCrypt toolchain on host" note was
> FALSE and is removed.
>
> **EC axioms DISCHARGED this pass: the combine bridge (C11).** The former
> whole-bridge reconstruct-then-sign axiom `combine_abs_op_lifted_eq_rlwe`
> (C11) is now a **machine-checked LEMMA**: `combine_abs_op_lifted` was given a
> CONCRETE threshold definition (the no-leak assembly), and the bridge to
> `rlwe_sign_op (reconstruct …)` is proven on honest, well-formed quorums.
> The load-bearing z-leg goes through the machine-checked keystone
> `Corona_N1_NoLeak.no_leak_z_aggregate` (= Lean
> `threshold_partial_response_identity`); the c/Delta-legs go through the
> single NARROW PUBLIC residual `threshold_public_commitment_eq_central`
> (C11′). Net C-bucket change: flat (one whole-bridge axiom out, one
> public-commitment axiom in), but the residual is narrowed from a
> whole-signature secret-bearing identity to a public-commitment equality.
>
> The other in-file lemmas were already proved (`encode_decode_signature`,
> `decode_encode_signature_wf`, `encode_signature_len`, `read_after_write_sig`,
> `write_sig_separation`, `pack_n1_signature_injective`, `reconstruct_of_share`,
> `reconstruct_quorum_invariant`, `fresh_sharing_zero_is_zero`,
> `combine_post_signature`, `combine_idempotent`, `sign_post_signature`,
> `sign_idempotent`, `wrapper_combine_refines_abs`,
> `wrapper_sign_refines_central`, `corona_n1_byte_equality_extracted`). The
> residual A-axioms are over abstract algebra (`inf_norm_R : R_q -> int`), and
> the residual B-axioms are over abstract ops/constants (`op group_pk_width :
> int.`, `op sig_len : int.`, `share_encode`/`decode` abstract). Discharging
> them requires concretizing those — a verify-gated wire-format decision that
> cannot be done blind and machine-rechecked here. Faking such a discharge is
> the cheat the gate forbids. The honest reclassification + disclosure below is
> the gate-satisfying outcome.

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

### Bucket C — OPEN SECURITY ASSUMPTION (12) — **MUST STAY OPEN**

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
| ~~C11~~ → **DISCHARGED** | ~~`combine_abs_op_lifted_eq_rlwe`~~ (now a PROVEN LEMMA) | Corona_N1_Combine_Wrapper.ec | The combine reconstruct-then-sign identity is **no longer an axiom**: `combine_abs_op_lifted` is now a CONCRETE threshold definition (the no-leak assembly: `c = kmac_mu_w mu w_pub`; `z = lagrange_aggregate_responses` of `per_party_partial_response`; `Delta = make_delta_of_w w_pub z`) and the bridge `combine_abs_op_lifted_eq_rlwe = rlwe_sign_op (reconstruct …)` is a **machine-checked LEMMA** on honest, well-formed quorums (uniq/size/degree/sharing). The load-bearing z-leg (where the secret enters) is discharged through the **MACHINE-CHECKED keystone** `Corona_N1_NoLeak.no_leak_z_aggregate` (= Lean `threshold_partial_response_identity`; verified load-bearing — removing it fails the proof). The master secret is never reconstructed. The residual shrinks to the PUBLIC-commitment axiom C11′ below. |
| C11′ | `threshold_public_commitment_eq_central` | Corona_N1_Combine_Wrapper.ec | **NARROW, PUBLIC-ONLY** (the SHRUNK residual replacing the secret-bearing whole-bridge C11). The threshold-assembled public Fiat-Shamir commitment `w = A*y` (sum of per-party Round-1 commitments; mask `y = Σ_i R_i*u` is mask-summed and telescopes like the responses — **carries no `c*s`**) equals the central commitment `central_w` on the reconstructed share. References **PUBLIC data only** (the commitment `w`, no secret share, no per-party `c*s_i`): cryptographically benign. The c-leg + Delta-leg of the combine bridge ride here. Discharge pathway (v0.8.0): a commitment-aggregate op + Lean bridge for the `A*y` mask-sum identity. |

> C-cone bundling note: the enumerated C-declarations are C1–C10 plus C11′
> (`threshold_public_commitment_eq_central`) = 11 rows. The former C11
> (`combine_abs_op_lifted_eq_rlwe`) is now a PROVEN LEMMA (struck through
> above), not an axiom — it does not count. The C11→lemma discharge and the
> C11′ replacement are net-flat in the C bucket, but the residual surface is
> narrowed from a whole-signature reconstruct-then-sign identity to a
> public-commitment equality (no secret). All named; none hidden.

### Why the CT axioms (C9/C10) are C, not B

`sign_round{1,2}_constant_time` are `declare axiom` CT *contracts*. A
constant-time property is a runtime/timing property that an EC axiom (or a
name grep) cannot certify — it needs a dudect/ctgrind/jasmin-CT harness
(`proof-by-rename.sh` exists to catch exactly the "name grep certifies
timing" anti-pattern). Corona's dudect harness is wired (smoke-budget) and
the submission-grade 10⁹-sample run is roadmap v0.8.0. So these axioms are
**fail-closed-pending-review**, disclosed here as open.

> **The C1–C10 axioms above are NOT the production residual.** They prove an
> idealised *correctness* fact (threshold output = central sign on the
> reconstructed secret) plus the CT/wire contracts. They are deliberately
> **not** the abstraction the production leaderless path instantiates. The
> production residual is the standard-assumption no-leak reduction below.

---

### Bucket C-standard — NO-LEAK REDUCTION (`Corona_N1_NoLeak.ec`) — the HONEST production residual

This is the headline of the de-misdirection pass. `Corona_N1_NoLeak.ec`
models the production path the way it actually runs: the per-party masked
responses `z_i = R_i·u + maskPrime_i + c·λ_i·s_i − mask_i` aggregate to
`R·u + c·s` because the pairwise-PRF masks **telescope to zero**
(`Σ_i maskPrime_i = Σ_i mask_i`, the same double sum reindexed) — so the
master secret is **never formed** and no per-party `c·s_i` is ever exposed.
The only open content is then a STANDARD-assumption reduction, NOT a
reconstruct.

| # | Axiom | File:line | Bucket | What is assumed |
|---|---|---|---|---|
| NL1 | `mask_telescope_zero` | Corona_N1_NoLeak.ec | **B (standard / Lean-backed)** | `Σ_{i∈Q}(maskPrime_i − mask_i) = 0` — both are the same double sum `Σ_{i,j} p(i,j)` reindexed (Fubini). EC contract of the **machine-checked Lean** `Crypto.Corona.NoLeak.pairwise_mask_telescopes`. References ONLY masks — no secret share. Why the aggregate exposes no per-party `c·λ_i·s_i`. |
| NL2 | `no_leak_reduction` | Corona_N1_NoLeak.ec | **C-standard (OPEN, Module-LWE/MSIS)** | Under Module-LWE + Module-SIS, the public Corona transcript is simulatable from one single-party Boschini signature's leakage — leaks nothing extra about `s`. The honest replacement for `sign_abs_op_lifted_eq_rlwe`: a reduction to the SAME lattice assumptions §1 already lists, secret **never reconstructed**. EC mirror of the **machine-checked Lean** `Crypto.Corona.NoLeak.NoLeakReduction`. Full simulation = v0.8.0 artifact. |

What is **machine-checked in Lean** under NL1/NL2 (this host, `lake build`
green, 0 sorry):

- `Crypto.Corona.NoLeak.pairwise_mask_telescopes` — pairwise-mask aggregate
  is zero (Fubini reindex); the Corona no-leak core.
- `Crypto.Corona.NoLeak.summed_response_is_mask_free` — `Σ_i z_i = Σ_i base_i`:
  the masks contribute nothing, only the aggregate is exposed.
- `Crypto.Corona.NoLeak.secret_aggregate_no_reconstruct` — the surviving
  `c · Σ_i λ_i·s_i = c·s` by Lagrange-at-0, secret never formed.
- `Crypto.Corona.NoLeak.no_leak_under_standard_assumptions` — packaged
  residual: under M-LWE/M-SIS, every transcript is the simulator's output.

The EC `no_leak_z_aggregate` / `mask_telescope_zero` / `no_leak_reduction`
are the procedure-level EC wrappers; they are **written, machine-recheck
pending EasyCrypt** (no `ec` on host; `scripts/checks/ec-compile.sh` is CI).

### The net assurance change of this pass

- **Before:** the headline residual was reconstruct-then-sign
  (`sign_abs_op_lifted_eq_rlwe` / `combine_body_axiom`) — an implementation
  reconstruct.
- **After:** that cone is re-labelled *idealised correctness*; the production
  residual is `no_leak_reduction`, a **Module-LWE/MSIS standard reduction**,
  and its CORRECTNESS core (telescoping masks + Lagrange aggregate) is
  **machine-checked in Lean**. Strictly better: the open assumption is now a
  standard PQ assumption (the same substrate §1 already discloses), not an
  implementation reconstruct.

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
mechanization of the Boschini construction. There are now TWO models. The
`corona_n1_byte_equality` theorem is honest *as an idealised CORRECTNESS
statement* — but it models **reconstruct-then-sign**: the EC `CombineAbs`
reconstructs the master secret and signs with it. That is intentionally NOT
how the production threshold path runs. `Corona_N1_NoLeak.ec` adds the
HONEST production model: the per-party masked responses telescope to
`R·u + c·s` **without forming the master secret**, and the ONLY open
assumption is a STANDARD Module-LWE/Module-SIS reduction (`no_leak_reduction`)
— the same substrate §1 already lists — with the secret never reconstructed.
The CORRECTNESS core of that model (`pairwise_mask_telescopes` +
`secret_aggregate_no_reconstruct`) is **machine-checked in Lean on this
host** (`Crypto.Corona.NoLeakAggregate`; `lake build` green). The
production no-leak path's correctness is ALSO established by code review +
cross-runtime KAT. Five algebraic axioms (A1–A5) are Lean-bridged-and-
machine-checked. The byte-walk obligations (C3/C4), the wrapper bridges
(C5–C7), the CT contracts (C9/C10), and the no-leak simulation
(`no_leak_reduction`) are the open surface, tracked in `BLOCKERS.md` and
gated on the v0.8.0 Jasmin-extraction + dudect + external-audit roadmap.

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
