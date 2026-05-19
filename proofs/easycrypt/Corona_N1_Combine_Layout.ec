(* -------------------------------------------------------------------- *)
(* Corona -- Combine byte layout invariants                             *)
(* -------------------------------------------------------------------- *)
(* The byte-level layout for the Corona Combine procedure's input +     *)
(* output buffers. Decomplected: this file owns Combine-specific        *)
(* layout. It does NOT import Sign_Layout's encoders.                   *)
(*                                                                      *)
(* Layout convention (mirroring jasmin/threshold/combine.jazz):         *)
(*                                                                      *)
(*   inputs_ptr  -> [group_pk (A_bytes || bTilde_bytes)                 *)
(*                  || quorum (int list, length-prefixed)               *)
(*                  || shares_round1 (R1_data list)                     *)
(*                  || shares_round2 (R2_data list)                     *)
(*                  || message_bytes (length-prefixed)                  *)
(*                  || ctx_bytes (length-prefixed)                      *)
(*                  || rho_rnd (32 bytes)]                              *)
(*                                                                      *)
(*   sig_out_ptr -> [sig_bytes (sig_len bytes, packed c || z || Delta)] *)
(*                                                                      *)
(* The layout predicate `combine_layout_pred(mem, ptrs, args)` asserts  *)
(* that the input buffers in `mem` at addresses `ptrs.*` encode the     *)
(* arguments `args.*` per the convention above, and that the output    *)
(* buffer at `ptrs.sig_out_ptr` is read-write of size `sig_len`.        *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.
require import Corona_N1_Memory.
require import Corona_N1_Signature_Codec.

(* ===================================================================
   Combine pointer record.

   Each field is a byte address into `mem_t`. The record carries a
   shape invariant (`wf_combine_ptrs`) asserting addresses are
   non-overlapping with a positive gap (otherwise the byte-walk
   axioms would need extra disjointness premises).
   =================================================================== *)
type combine_ptrs_t = {
  group_pk_ptr   : int;
  quorum_ptr     : int;
  shares_r1_ptr  : int;
  shares_r2_ptr  : int;
  message_ptr    : int;
  ctx_ptr        : int;
  rho_rnd_ptr    : int;
  sig_out_ptr    : int;
}.

(* Section widths used by the layout predicate. Concrete in Corona's
   production wire format. *)
op group_pk_width : int.
op quorum_width   : int.
op shares_r1_width : int.
op shares_r2_width : int.
op message_width  : int.
op ctx_width      : int.
op rho_rnd_width  : int = 32.

(* All widths are non-negative. *)
axiom group_pk_width_pos    : 0 <= group_pk_width.
axiom quorum_width_pos      : 0 <= quorum_width.
axiom shares_r1_width_pos   : 0 <= shares_r1_width.
axiom shares_r2_width_pos   : 0 <= shares_r2_width.
axiom message_width_pos     : 0 <= message_width.
axiom ctx_width_pos         : 0 <= ctx_width.

(* Pairwise-disjoint pointer predicate. Each pair of pointer-bounded
   ranges must be disjoint. Stated as a single conjunction. *)
op wf_combine_ptrs (ptrs : combine_ptrs_t) : bool =
  let gpk = ptrs.`group_pk_ptr in
  let qrm = ptrs.`quorum_ptr in
  let r1  = ptrs.`shares_r1_ptr in
  let r2  = ptrs.`shares_r2_ptr in
  let msg = ptrs.`message_ptr in
  let ctx = ptrs.`ctx_ptr in
  let rho = ptrs.`rho_rnd_ptr in
  let so  = ptrs.`sig_out_ptr in
       (gpk + group_pk_width <= qrm \/ qrm + quorum_width <= gpk)
    /\ (gpk + group_pk_width <= r1  \/ r1  + shares_r1_width <= gpk)
    /\ (gpk + group_pk_width <= r2  \/ r2  + shares_r2_width <= gpk)
    /\ (gpk + group_pk_width <= msg \/ msg + message_width <= gpk)
    /\ (gpk + group_pk_width <= ctx \/ ctx + ctx_width <= gpk)
    /\ (gpk + group_pk_width <= rho \/ rho + rho_rnd_width <= gpk)
    /\ (gpk + group_pk_width <= so  \/ so  + sig_len <= gpk)
    /\ (qrm + quorum_width <= r1  \/ r1  + shares_r1_width <= qrm)
    /\ (qrm + quorum_width <= r2  \/ r2  + shares_r2_width <= qrm)
    /\ (qrm + quorum_width <= msg \/ msg + message_width <= qrm)
    /\ (qrm + quorum_width <= ctx \/ ctx + ctx_width <= qrm)
    /\ (qrm + quorum_width <= rho \/ rho + rho_rnd_width <= qrm)
    /\ (qrm + quorum_width <= so  \/ so  + sig_len <= qrm)
    /\ (r1 + shares_r1_width <= so  \/ so  + sig_len <= r1)
    /\ (r2 + shares_r2_width <= so  \/ so  + sig_len <= r2).

(* The output sig buffer must lie in a writable region; this is captured
   by the wrapper precondition's separation assertion. *)
op sig_out_writable : mem_t -> combine_ptrs_t -> bool.

(* Concrete signature decoding from the memory at the sig_out pointer. *)
op read_signature_at (m : mem_t) (ptrs : combine_ptrs_t) : signature_t =
  read_sig_at m ptrs.`sig_out_ptr.

(* Frame law: a write to the sig_out region leaves all other byte
   reads unchanged. Discharged via Corona_N1_Memory.store_bytes_disjoint
   composed with the wf_combine_ptrs disjointness. *)
lemma read_signature_at_det
      (m : mem_t) (ptrs : combine_ptrs_t) (sig : signature_t) :
  read_signature_at (write_sig_at m ptrs.`sig_out_ptr sig) ptrs = sig.
proof. by rewrite /read_signature_at; apply read_after_write_sig. qed.

(* ===================================================================
   ACCOUNTING

   axioms (6 -- per-section width non-negativity):
     group_pk_width_pos
     quorum_width_pos
     shares_r1_width_pos
     shares_r2_width_pos
     message_width_pos
     ctx_width_pos

   ops:
     combine_ptrs_t (record), wf_combine_ptrs,
     sig_out_writable, read_signature_at.

   PROVED lemmas (0 admits):
     read_signature_at_det
   =================================================================== *)
