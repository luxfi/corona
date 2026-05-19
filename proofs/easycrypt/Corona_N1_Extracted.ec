(* -------------------------------------------------------------------- *)
(* Corona -- Class N1 EXTRACTED byte-equality theorem                   *)
(* -------------------------------------------------------------------- *)
(* The IMPLEMENTATION-BACKED N1 byte-equality theorem.                  *)
(*                                                                      *)
(* `Corona_N1.corona_n1_byte_equality` is the GENERIC theorem,          *)
(* parametric over abstract `T : Corona_Threshold` and                  *)
(* `S : RLWESign` modules with two section-local module-contract        *)
(* axioms (`combine_body_axiom`, `S_functional_spec`) as hypotheses.    *)
(*                                                                      *)
(* This file instantiates those abstract modules with the extracted     *)
(* wrappers `CombineExtractedWrapper` and `SignExtractedWrapper`,       *)
(* and the section-local module-contract axioms with the lemmas         *)
(* `wrapper_combine_refines_abs` and `wrapper_sign_refines_central`     *)
(* (both proved in their respective Wrapper files).                     *)
(*                                                                      *)
(* The result, `corona_n1_byte_equality_extracted`, is the CONCRETE     *)
(* end-to-end theorem reviewers should cite for Corona's Class N1       *)
(* byte-equality claim.                                                 *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.
require import Corona_N1.
require import Corona_N1_Signature_Codec.
require import Corona_N1_Combine_Wrapper.
require import Corona_N1_Sign_Wrapper.

(* The extracted theorem: instantiate the generic equiv with the
   wrapper modules + the wrapper-side refinement lemmas. *)
lemma corona_n1_byte_equality_extracted :
  equiv [ ThresholdRun(CombineExtractedWrapper).run
        ~ SinglePartyRun(SignExtractedWrapper).run :
            ={group_pk, shares, quorum, m, ctx, rho_rnd}
            /\ uniq quorum{1}
            /\ size shares{1} = size quorum{1}
            /\ group_pk{1} = derive_pk_op (reconstruct quorum{1} shares{1})
            /\ accept_signing_attempt
                 (reconstruct quorum{1} shares{1})
                 m{1} ctx{1} rho_rnd{1}
            /\ poly_degree (reconstruct quorum{1} shares{1}) < size quorum{1}
            /\ shares{1} = List.map
                 (poly_eval (reconstruct quorum{1} shares{1})) quorum{1}
        ==> ={res} ].
proof.
  (* Instantiate the generic Corona_N1.corona_n1_byte_equality with:
       T <- CombineExtractedWrapper
       S <- SignExtractedWrapper
     The section-local axioms become the wrapper-side lemmas
       combine_body_axiom    <- wrapper_combine_refines_abs
       S_functional_spec     <- wrapper_sign_refines_central
     Both are proved in their respective Wrapper files. *)
  apply (corona_n1_byte_equality
           SignExtractedWrapper
           CombineExtractedWrapper
           wrapper_combine_refines_abs
           wrapper_sign_refines_central).
qed.

(* ===================================================================
   ACCOUNTING

   axioms in this file (0):
     none -- this file only INSTANTIATES the generic theorem with
     the wrapper modules + wrapper-side refinement lemmas.

   The full trust footprint of this extracted theorem:
     - Corona_N1.lagrange_inverse_eval                (Lean-bridged)
     - Corona_N1.threshold_partial_response_identity  (Lean-bridged)
     - Corona_N1.poly_degree_nonneg                   (structural)
     - Corona_N1.share_polys_injective, ...           (structural)
     - Corona_N1.reconstruct_polys_view               (structural)
     - Corona_N1.compute_mu_injective                 (mu pipeline)
     - Corona_N1.pack_unpack_n1_signature_roundtrip   (codec)
     - Corona_N1.pack_unpack_sk_roundtrip             (sk codec)
     - Corona_N1.accept_signing_attempt_iff_components (accept algebra)
     - Corona_N1_Signature_Codec.encode_signature_wf  (producer codec)
     - Corona_N1_Signature_Codec.sig_len_pos          (length)
     - Corona_N1_Combine_Refinement.combine_body_spec (byte-walk)
     - Corona_N1_Combine_Refinement.combine_body_writes_signature
                                                      (sep invariant)
     - Corona_N1_Combine_Refinement.layout_combine_frame
                                                      (layout frame)
     - Corona_N1_Sign_Refinement.sign_body_spec       (byte-walk)
     - Corona_N1_Sign_Refinement.sign_body_writes_signature
                                                      (sep invariant)
     - Corona_N1_Sign_Refinement.layout_sign_frame    (layout frame)
     - Corona_N1_Combine_Wrapper.combine_abs_op_lifted_bridge
                                                      (share encode)
     - Corona_N1_Sign_Wrapper.sign_abs_op_lifted_bridge,
       sign_abs_op_lifted_eq_rlwe                     (RLWE bridge)
     - lemmas/RLWE_Functional.rlwe_correctness        (Boschini §3)
     - lemmas/RLWE_Functional.rlwe_sign_size          (per-instance len)
     - + small concrete-arithmetic axioms (q_pos, etc.)
   =================================================================== *)
