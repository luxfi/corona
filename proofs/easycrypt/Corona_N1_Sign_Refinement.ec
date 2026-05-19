(* -------------------------------------------------------------------- *)
(* Corona -- centralized Sign refinement scaffold                       *)
(* -------------------------------------------------------------------- *)
(* The byte-level refinement of the Jasmin-extracted Corona             *)
(* centralized Sign against the abstract `CentralRLWESign` model in     *)
(* Corona_N1.ec.                                                        *)
(*                                                                      *)
(* Status (v0.7.0): SCAFFOLD. Three top-level `axiom`s -- byte-walk +   *)
(* memory-separation + layout frame -- are PROOF OBLIGATIONS to be      *)
(* discharged Jasmin-side once the extracted Sign EC theory lands.      *)
(*                                                                      *)
(* This file MUST NOT contain `declare axiom` shapes. All section-local *)
(* module-contract axioms live in Corona_N1.ec.                         *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.
require import Corona_N1_Memory.
require import Corona_N1_Signature_Codec.
require import Corona_N1_Sign_Layout.

(* The abstract centralized Sign semantics in op form. *)
op sign_abs_op :
     (* sk_share *) int list
  -> (* m *) int list
  -> (* ctx *) int list
  -> (* rho_rnd *) int list
  -> signature_t.

(* The Jasmin-extracted Sign procedure body. *)
op sign_fn : mem_t -> sign_ptrs_t -> mem_t.

(* Layout predicate: input buffers encode the sign args. *)
op layout_sign
    (m : mem_t) (ptrs : sign_ptrs_t)
    (sk : int list) (msg : int list) (ctx : int list)
    (rho_rnd : int list)
  : bool.

(* ===================================================================
   Atomic byte-walk axiom.
   =================================================================== *)
axiom sign_body_spec :
  forall (m : mem_t) (ptrs : sign_ptrs_t)
         (sk : int list) (msg : int list) (ctx : int list)
         (rho_rnd : int list),
    wf_sign_ptrs ptrs =>
    layout_sign m ptrs sk msg ctx rho_rnd =>
    read_sig_at (sign_fn m ptrs) ptrs.`sig_out_ptr
    = sign_abs_op sk msg ctx rho_rnd.

(* ===================================================================
   Memory-separation invariant.
   =================================================================== *)
axiom sign_body_writes_signature :
  forall (m : mem_t) (ptrs : sign_ptrs_t) (q : int),
    wf_sign_ptrs ptrs =>
    q < ptrs.`sig_out_ptr \/ ptrs.`sig_out_ptr + sig_len <= q =>
    load_byte (sign_fn m ptrs) q = load_byte m q.

(* ===================================================================
   Layout frame.
   =================================================================== *)
axiom layout_sign_frame
    (m : mem_t) (ptrs : sign_ptrs_t)
    (sk : int list) (msg : int list) (ctx : int list)
    (rho_rnd : int list) :
  wf_sign_ptrs ptrs =>
  layout_sign m ptrs sk msg ctx rho_rnd =>
  layout_sign (sign_fn m ptrs) ptrs sk msg ctx rho_rnd.

(* ===================================================================
   Derived lemmas (no admits).
   =================================================================== *)

lemma sign_post_signature
      (m : mem_t) (ptrs : sign_ptrs_t)
      (sk : int list) (msg : int list) (ctx : int list)
      (rho_rnd : int list) :
    wf_sign_ptrs ptrs =>
    layout_sign m ptrs sk msg ctx rho_rnd =>
    read_signature_at (sign_fn m ptrs) ptrs
    = sign_abs_op sk msg ctx rho_rnd.
proof.
  move=> Hwf Hlay.
  rewrite /read_signature_at.
  by apply sign_body_spec.
qed.

lemma sign_idempotent
      (m : mem_t) (ptrs : sign_ptrs_t)
      (sk : int list) (msg : int list) (ctx : int list)
      (rho_rnd : int list) :
    wf_sign_ptrs ptrs =>
    layout_sign m ptrs sk msg ctx rho_rnd =>
    read_signature_at (sign_fn (sign_fn m ptrs) ptrs) ptrs
    = read_signature_at (sign_fn m ptrs) ptrs.
proof.
  move=> Hwf Hlay.
  have Hlay2 := layout_sign_frame m ptrs sk msg ctx rho_rnd Hwf Hlay.
  by rewrite (sign_post_signature _ _ _ _ _ _ Hwf Hlay2)
             (sign_post_signature _ _ _ _ _ _ Hwf Hlay).
qed.

(* ===================================================================
   ACCOUNTING

   axioms (3 -- byte-walk + memory-separation + layout frame):
     sign_body_spec
     sign_body_writes_signature
     layout_sign_frame

   PROVED lemmas (0 admits):
     sign_post_signature
     sign_idempotent
   =================================================================== *)
