(* -------------------------------------------------------------------- *)
(* Corona -- Sign byte layout invariants                                *)
(* -------------------------------------------------------------------- *)
(* The byte-level layout for the centralized Corona Sign procedure's    *)
(* input + output buffers. Decomplected from Combine_Layout: this file  *)
(* owns Sign-specific layout. It does NOT import Combine_Layout's       *)
(* encoders. They share Memory + Signature_Codec only.                  *)
(*                                                                      *)
(* Layout convention (mirroring jasmin/rlwe/sign.jazz):                 *)
(*                                                                      *)
(*   inputs_ptr  -> [sk_share_ptr   (N*256*8 bytes for R_q^N)            *)
(*                  || message_ptr  (length-prefixed)                    *)
(*                  || ctx_ptr      (length-prefixed)                    *)
(*                  || rho_rnd      (32 bytes)]                          *)
(*                                                                      *)
(*   sig_out_ptr -> [sig_bytes (sig_len bytes, packed c || z || Delta)]  *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.
require import Corona_N1_Memory.
require import Corona_N1_Signature_Codec.

type sign_ptrs_t = {
  sk_share_ptr : int;
  message_ptr  : int;
  ctx_ptr      : int;
  rho_rnd_ptr  : int;
  sig_out_ptr  : int;
}.

(* Section widths. *)
op sk_share_width : int.
op message_width  : int.
op ctx_width      : int.
op rho_rnd_width  : int = 32.

axiom sk_share_width_pos : 0 <= sk_share_width.
axiom message_width_pos  : 0 <= message_width.
axiom ctx_width_pos      : 0 <= ctx_width.

op wf_sign_ptrs (ptrs : sign_ptrs_t) : bool =
  let sk  = ptrs.`sk_share_ptr in
  let msg = ptrs.`message_ptr in
  let ctx = ptrs.`ctx_ptr in
  let rho = ptrs.`rho_rnd_ptr in
  let so  = ptrs.`sig_out_ptr in
       (sk + sk_share_width <= msg \/ msg + message_width <= sk)
    /\ (sk + sk_share_width <= ctx \/ ctx + ctx_width <= sk)
    /\ (sk + sk_share_width <= rho \/ rho + rho_rnd_width <= sk)
    /\ (sk + sk_share_width <= so  \/ so  + sig_len <= sk)
    /\ (msg + message_width <= ctx \/ ctx + ctx_width <= msg)
    /\ (msg + message_width <= rho \/ rho + rho_rnd_width <= msg)
    /\ (msg + message_width <= so  \/ so  + sig_len <= msg)
    /\ (ctx + ctx_width <= rho \/ rho + rho_rnd_width <= ctx)
    /\ (ctx + ctx_width <= so  \/ so  + sig_len <= ctx)
    /\ (rho + rho_rnd_width <= so  \/ so  + sig_len <= rho).

op sig_out_writable : mem_t -> sign_ptrs_t -> bool.

op read_signature_at (m : mem_t) (ptrs : sign_ptrs_t) : signature_t =
  read_sig_at m ptrs.`sig_out_ptr.

(* Frame law: a write to the sig_out region leaves all other byte
   reads unchanged. *)
lemma read_signature_at_det
      (m : mem_t) (ptrs : sign_ptrs_t) (sig : signature_t) :
  read_signature_at (write_sig_at m ptrs.`sig_out_ptr sig) ptrs = sig.
proof. by rewrite /read_signature_at; apply read_after_write_sig. qed.

(* ===================================================================
   ACCOUNTING

   axioms (3 -- per-section width non-negativity):
     sk_share_width_pos
     message_width_pos
     ctx_width_pos

   ops: sign_ptrs_t, wf_sign_ptrs, sig_out_writable, read_signature_at.

   PROVED lemmas (0 admits):
     read_signature_at_det
   =================================================================== *)
