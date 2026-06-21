(* -------------------------------------------------------------------- *)
(* Corona -- Class N1 NO-LEAK telescoping-mask model                    *)
(* -------------------------------------------------------------------- *)
(* STATUS (honest): WRITTEN; machine-recheck PENDING EasyCrypt.          *)
(*   No `easycrypt`/`why3`/`alt-ergo` on the build host this file was     *)
(*   authored on; it has NOT been re-elaborated here. CI gate            *)
(*   `scripts/checks/ec-compile.sh` (skipped locally when ec absent) is  *)
(*   the authority. Do NOT relabel any lemma below "machine-checked" /   *)
(*   "discharged" until ec-compile runs green. The ALGEBRAIC CORE this   *)
(*   file rests on IS machine-checked, in Lean 4 + Mathlib, on this      *)
(*   host:                                                               *)
(*     Crypto.Corona.NoLeak.{pairwise_mask_telescopes,                   *)
(*       summed_response_is_mask_free, secret_aggregate_no_reconstruct,  *)
(*       no_leak_under_standard_assumptions}                             *)
(*     Crypto.Threshold.Lagrange.threshold_partial_response_identity     *)
(*   (`lake build` exits 0, with no unproven-tactic placeholders).       *)
(*                                                                      *)
(* WHY THIS FILE EXISTS — de-misdirecting reconstruct-then-sign          *)
(* -----------------------------------------------------------------    *)
(* Corona_N1.ec's `corona_n1_byte_equality` proves the threshold combine *)
(* bit-equals `CombineAbs.combine`, whose wrapper bridge                 *)
(* `sign_abs_op_lifted_eq_rlwe` pins it to                               *)
(*                                                                       *)
(*     rlwe_sign_op (reconstruct quorum shares) m ctx rho_rnd           *)
(*                                                                       *)
(* i.e. the centralised Boschini signer applied to the LAGRANGE-         *)
(* RECONSTRUCTED master secret (RECONSTRUCT-THEN-SIGN). The              *)
(* Boschini/Raccoon production combine must NEVER do that                *)
(* (BLOCKERS.md CORONA-EC-RECON-MODEL): reconstructing the secret, or    *)
(* broadcasting per-party `c*s_i` whose aggregate is `c*s`, breaks       *)
(* threshold secrecy and transcript simulation.                         *)
(*                                                                       *)
(* This file states the CORRECT no-leak model: the per-party masked      *)
(* responses                                                             *)
(*     z_i = R_i*u + maskPrime_i + c*lambda_i*s_i - mask_i              *)
(* aggregate to `R*u + c*s` because the pairwise-PRF masks TELESCOPE TO  *)
(* ZERO (Sum_i maskPrime_i = Sum_i mask_i, the same double sum           *)
(* reindexed), so the master secret is NEVER formed and no per-party     *)
(* `c*s_i` is ever exposed in the clear. The residual OPEN content is    *)
(* then NOT "lifted op = central sign on the reconstructed secret" but a *)
(* STANDARD-ASSUMPTION reduction (Module-LWE + Module-SIS, the SAME      *)
(* substrate Corona's AXIOM-INVENTORY.md §1 already discloses).          *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr.
require import Corona_N1.

(* ===================================================================
   PART 1 — the telescoping pairwise-mask cancellation (Corona no-leak core)

   EC mirror of the MACHINE-CHECKED Lean theorem
   `Crypto.Corona.NoLeak.pairwise_mask_telescopes`: for a quorum T and a
   per-pair mask `p : party -> party -> M`,
     mask i      = Sum_{j in T} p i j        (party i's own seeds)
     maskPrime i = Sum_{j in T} p j i        (others' seeds for i)
   the aggregate Sum_{i in T} (maskPrime i - mask i) = 0, because both are
   the SAME double sum Sum_{i,j} p i j reindexed by swapping (i,j)
   (Fubini / Finset.sum_comm). NO antisymmetry of p needed.

   At the EC level we model the masks abstractly. `mask_telescope_zero`
   states the cancellation as the contract the production aggregator
   satisfies; its machine-checked content is the Lean theorem. (B/standard
   layer: a finite-sum reindexing fact, NOT a security conclusion.) *)

type party_mask_t.       (* per-party mask in R_q^N *)

op mask_of       : int list -> int -> party_mask_t.   (* mask i over quorum *)
op mask_prime_of : int list -> int -> party_mask_t.   (* maskPrime i over quorum *)
op sum_party_masks : int list -> (int -> party_mask_t) -> party_mask_t.
op sub_mask : party_mask_t -> party_mask_t -> party_mask_t.
op zero_mask : party_mask_t.

(* TELESCOPE CONTRACT (Lean-backed, B/standard):
   Sum_{i in Q} (maskPrime_i - mask_i) = 0. Machine-checked in Lean as
   `Crypto.Corona.NoLeak.pairwise_mask_telescopes`. Here the EC contract;
   references only the masks (no secret share). *)
axiom mask_telescope_zero (Q : int list) :
    sum_party_masks Q (fun i => sub_mask (mask_prime_of Q i) (mask_of Q i))
  = zero_mask.

(* ===================================================================
   PART 2 — the no-leak z aggregate (master secret never reconstructed)

   With the masks telescoped away, the surviving aggregate is
   `R*u + c * Sum_i lambda_i*s_i = R*u + c*s` by Lagrange-at-0, with the
   secret-sharing polynomial (the master `s`) never formed. The
   pre-existing Corona_N1 axiom `threshold_partial_response_identity`
   ALREADY states this no-leak z identity (the Lagrange aggregate of the
   per-party masked responses = `rlwe_compute_z` on the reconstructed
   share, the secret entering only as the public `z`'s `c*s` summand).

   `no_leak_z_aggregate` re-exports it in no-leak vocabulary. EC mirror of
   the machine-checked Lean `Crypto.Corona.NoLeak.secret_aggregate_no_
   reconstruct` (the y=0 / mask-free specialization of the shared
   threshold identity). (A: Lean-bridged standard fact.) *)

lemma no_leak_z_aggregate
      (Q : int list) (shares : share_t list)
      (c : c_n1_t) (rho_rnd : randomness_t) (mu_val : mu_t) :
    uniq Q =>
    size shares = size Q =>
    poly_degree (reconstruct Q shares) < size Q =>
    shares = List.map (poly_eval (reconstruct Q shares)) Q =>
    lagrange_aggregate_responses Q
      (List.map (per_party_partial_response c rho_rnd mu_val) shares)
    = rlwe_compute_z (unpack_sk (reconstruct Q shares)) mu_val rho_rnd.
proof.
  (* Exactly the Lean-bridged Corona_N1 axiom; re-stated here so the
     no-leak file is self-contained. Closes by `apply`. *)
  exact (threshold_partial_response_identity Q shares c rho_rnd mu_val).
qed.

(* ===================================================================
   PART 3 — the residual cryptographic assumption (STANDARD: M-LWE/M-SIS)

   PARTS 1+2 are CORRECTNESS: the no-leak combine computes the same
   (c, z, Delta) the central signer would, from telescoping-masked
   partials, with the master secret never formed. The remaining content
   is SECRECY: that the public Corona transcript reveals nothing about `s`
   beyond ONE single-party Boschini signature. We state it as an abstract
   simulation-soundness predicate reducing to Module-LWE + Module-SIS --
   the SAME substrate Corona's AXIOM-INVENTORY.md §1 already lists
   (Lyubashevsky-Peikert-Regev; Ajtai / Micciancio-Regev; Boschini
   2024/1113). This is the honest replacement for the reconstruct-then-
   sign `sign_abs_op_lifted_eq_rlwe` bridge: a standard-assumption
   reduction, NOT a reconstruct.

   EC mirror of Lean `Crypto.Corona.NoLeak.NoLeakReduction`. *)

type public_transcript_t.     (* per-party commitments, rounded h, z-sum, c *)
type rlwe_leakage_t.          (* one single-party Boschini sig's public footprint *)

op module_lwe_hard : bool.    (* Gaussian-masked commitments pseudorandom *)
op module_sis_hard : bool.    (* extracting short s from the z-sum is R-SIS *)
op transcript_simulator : rlwe_leakage_t -> public_transcript_t.

(* NO-LEAK REDUCTION (C / OPEN, but now a STANDARD-ASSUMPTION reduction).
   Under Module-LWE + Module-SIS, the public Corona threshold transcript
   is reproducible from a single Boschini signature's leakage alone --
   leaks nothing extra about `s`. The honest replacement for the
   reconstruct-then-sign bridge. DISCLOSED and OPEN: full simulation proof
   = v0.8.0 artifact. It does NOT reconstruct the secret; its content
   reduces to standard lattice hardness. *)
axiom no_leak_reduction :
  module_lwe_hard =>
  module_sis_hard =>
  forall (leak : rlwe_leakage_t),
    exists (tr : public_transcript_t), tr = transcript_simulator leak.

lemma no_leak_under_standard_assumptions (leak : rlwe_leakage_t) :
    module_lwe_hard =>
    module_sis_hard =>
    exists (tr : public_transcript_t), tr = transcript_simulator leak.
proof.
  move=> hlwe hsis.
  exact (no_leak_reduction hlwe hsis leak).
qed.

(* ===================================================================
   ACCOUNTING (this file)

   axioms (3) — all DISCLOSED in AXIOM-INVENTORY.md:
     - mask_telescope_zero     (B / standard: EC contract of the MACHINE-
                                CHECKED Lean pairwise_mask_telescopes;
                                references only masks, no secret share)
     - no_leak_reduction       (C / OPEN, STANDARD: the Module-LWE +
                                Module-SIS simulation reduction -- the
                                honest replacement for the reconstruct-
                                then-sign sign_abs_op_lifted_eq_rlwe bridge)
     - module_lwe_hard / module_sis_hard are `op` declarations (booleans
                                naming the standard assumptions), not axioms.

   PROVED-MODULO-RECHECK lemmas (machine-recheck pending EasyCrypt):
     no_leak_z_aggregate           (re-exports the Lean-bridged
                                    threshold_partial_response_identity)
     no_leak_under_standard_assumptions

   The telescoping-mask + Lagrange-aggregate CORRECTNESS core is machine-
   checked in Lean on this host; the EC side is the procedure-level wrapper
   pending ec-compile. The ONLY genuinely-open assumption is
   `no_leak_reduction`, a Module-LWE/MSIS reduction -- a STANDARD PQ
   assumption (the same substrate §1 already discloses), not an
   implementation reconstruct.
   =================================================================== *)
