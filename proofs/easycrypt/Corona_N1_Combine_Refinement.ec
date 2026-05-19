(* -------------------------------------------------------------------- *)
(* Corona -- Combine refinement scaffold                                *)
(* -------------------------------------------------------------------- *)
(* The byte-level refinement of the Jasmin-extracted Corona Combine     *)
(* against the abstract `CombineAbs` model in Corona_N1.ec.             *)
(*                                                                      *)
(* Status (v0.7.0): SCAFFOLD. The two top-level `axiom`s below are the  *)
(* atomic byte-walk + memory-separation invariants. They are PROOF      *)
(* OBLIGATIONS to be discharged Jasmin-side once the extracted Combine  *)
(* EC theory lands; today they are the boundary between EC and the      *)
(* Jasmin extraction.                                                   *)
(*                                                                      *)
(* This file MUST NOT contain `declare axiom` shapes (Pulsar's          *)
(* scripts/checks/ec-refinement-scaffold.sh greps for them and fails    *)
(* CI). All section-local module-contract axioms live in Corona_N1.ec.  *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.
require import Corona_N1_Memory.
require import Corona_N1_Signature_Codec.
require import Corona_N1_Combine_Layout.

(* The abstract Combine semantics in op form: given the protocol-level
   args, returns the signature bytes. This is the operator-form of
   `CombineAbs.combine` in Corona_N1.ec (extracted from byphoare to a
   total function via determinism of CentralRLWESign.sign). *)
op combine_abs_op :
     (* group_pk *) int
  -> (* m *) int list
  -> (* ctx *) int list
  -> (* quorum *) int list
  -> (* shares *) int list list
  -> (* rho_rnd *) int list
  -> signature_t.

(* The Jasmin-extracted Combine procedure body: given a starting memory
   and pointer record, returns the post-call memory. *)
op combine_fn : mem_t -> combine_ptrs_t -> mem_t.

(* ===================================================================
   Atomic byte-walk axiom: the Jasmin-extracted Combine writes exactly
   `combine_abs_op(args)` to the sig_out address. The args are read
   from the input buffers per the layout convention.

   Hypotheses:
     - wf_combine_ptrs ptrs           (input/output addresses well-formed)
     - layout(mem, ptrs, args)        (input buffers encode the args)

   Conclusion:
     - read_sig_at (combine_fn mem ptrs) ptrs.sig_out_ptr
       = combine_abs_op args
   =================================================================== *)

(* The layout predicate: input buffers encode the args. *)
op layout_combine
    (m : mem_t) (ptrs : combine_ptrs_t)
    (gpk : int) (msg : int list) (ctx : int list)
    (quorum : int list) (shares : int list list)
    (rho_rnd : int list)
  : bool.

(* The byte-walk axiom. *)
axiom combine_body_spec :
  forall (m : mem_t) (ptrs : combine_ptrs_t)
         (gpk : int) (msg : int list) (ctx : int list)
         (quorum : int list) (shares : int list list)
         (rho_rnd : int list),
    wf_combine_ptrs ptrs =>
    layout_combine m ptrs gpk msg ctx quorum shares rho_rnd =>
    read_sig_at (combine_fn m ptrs) ptrs.`sig_out_ptr
    = combine_abs_op gpk msg ctx quorum shares rho_rnd.

(* ===================================================================
   Memory-separation invariant: the Jasmin-extracted Combine only
   writes to the sig_out region. Reads at any other address are
   identical pre- and post-call.
   =================================================================== *)

axiom combine_body_writes_signature :
  forall (m : mem_t) (ptrs : combine_ptrs_t) (q : int),
    wf_combine_ptrs ptrs =>
    q < ptrs.`sig_out_ptr \/ ptrs.`sig_out_ptr + sig_len <= q =>
    load_byte (combine_fn m ptrs) q = load_byte m q.

(* ===================================================================
   Derived lemmas (no admits):
   =================================================================== *)

(* The signature in memory after combine equals the abstract Combine
   output on the matching args. *)
lemma combine_post_signature
      (m : mem_t) (ptrs : combine_ptrs_t)
      (gpk : int) (msg : int list) (ctx : int list)
      (quorum : int list) (shares : int list list)
      (rho_rnd : int list) :
    wf_combine_ptrs ptrs =>
    layout_combine m ptrs gpk msg ctx quorum shares rho_rnd =>
    read_signature_at (combine_fn m ptrs) ptrs
    = combine_abs_op gpk msg ctx quorum shares rho_rnd.
proof.
  move=> Hwf Hlay.
  rewrite /read_signature_at.
  by apply combine_body_spec.
qed.

(* Layout frame: writes confined to the sig_out region preserve the
   input-buffer layout predicate. Stated as an axiom because the
   layout predicate is abstract (its concrete body would unfold the
   wire codec and the disjoint-write frame law would discharge it
   directly).

   The CI guard `scripts/checks/ec-refinement-scaffold.sh` reports
   this in the refinement-scaffold axiom count -- it is one of the
   two atomic byte-walk + memory-separation obligations, the
   layout-stability companion. *)
axiom layout_combine_frame
    (m : mem_t) (ptrs : combine_ptrs_t)
    (gpk : int) (msg : int list) (ctx : int list)
    (quorum : int list) (shares : int list list)
    (rho_rnd : int list) :
  wf_combine_ptrs ptrs =>
  layout_combine m ptrs gpk msg ctx quorum shares rho_rnd =>
  layout_combine (combine_fn m ptrs) ptrs gpk msg ctx
                 quorum shares rho_rnd.

(* Idempotence: running combine twice with the same args yields the
   same signature output at sig_out. Follows from determinism of
   combine_fn + layout preservation. PROVED -- no admits. *)
lemma combine_idempotent
      (m : mem_t) (ptrs : combine_ptrs_t)
      (gpk : int) (msg : int list) (ctx : int list)
      (quorum : int list) (shares : int list list)
      (rho_rnd : int list) :
    wf_combine_ptrs ptrs =>
    layout_combine m ptrs gpk msg ctx quorum shares rho_rnd =>
    read_signature_at (combine_fn (combine_fn m ptrs) ptrs) ptrs
    = read_signature_at (combine_fn m ptrs) ptrs.
proof.
  move=> Hwf Hlay.
  have Hlay2 := layout_combine_frame m ptrs gpk msg ctx
                                     quorum shares rho_rnd Hwf Hlay.
  by rewrite (combine_post_signature _ _ _ _ _ _ _ _ Hwf Hlay2)
             (combine_post_signature _ _ _ _ _ _ _ _ Hwf Hlay).
qed.

(* ===================================================================
   ACCOUNTING

   axioms (3 -- byte-walk + memory-separation + layout frame):
     combine_body_spec
     combine_body_writes_signature
     layout_combine_frame

   PROVED lemmas (0 admits):
     combine_post_signature
     combine_idempotent
   =================================================================== *)
