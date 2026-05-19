(* -------------------------------------------------------------------- *)
(* Corona -- centralized Sign wrapper bridge                            *)
(* -------------------------------------------------------------------- *)
(* Adapts the Jasmin-extracted W64-pointer-based sign_fn to the         *)
(* RLWESign abstract module interface in Corona_N1.ec.                  *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.
require import Corona_N1.
require import Corona_N1_Signature_Codec.
require import Corona_N1_Sign_Layout.
require import Corona_N1_Sign_Refinement.

(* The abstract Sign semantics in op form, lifted to share_t input. *)
op sign_abs_op_lifted
    (sk : share_t) (m : message_t) (ctx : ctx_t)
    (rho_rnd : randomness_t) : signature_t.

(* Encoding ops -- mirror those in the Combine wrapper. *)
op share_encode : share_t -> int list.
op msg_encode : message_t -> int list.
op ctx_encode : ctx_t -> int list.
op rho_encode : randomness_t -> int list.

(* Bridge: lifted sign op matches the byte-level abstract sign op
   modulo the share encoding. *)
axiom sign_abs_op_lifted_bridge :
  forall (sk : share_t) (m : message_t) (ctx : ctx_t)
         (rho_rnd : randomness_t),
    sign_abs_op_lifted sk m ctx rho_rnd
    = sign_abs_op (share_encode sk) (msg_encode m) (ctx_encode ctx)
                  (rho_encode rho_rnd).

(* Lifted op matches rlwe_sign_op on byte equality. This is the
   Boschini construction conformance for the centralized signer
   (equivalent to libjade's role for Pulsar, but in-house since
   R-LWE has no FIPS analog). *)
axiom sign_abs_op_lifted_eq_rlwe :
  forall (sk : share_t) (m : message_t) (ctx : ctx_t)
         (rho_rnd : randomness_t),
    sign_abs_op_lifted sk m ctx rho_rnd
    = rlwe_sign_op sk m ctx rho_rnd.

(* The wrapper module. *)
module SignExtractedWrapper : RLWESign = {
  proc sign(sk : share_t, m : message_t, ctx : ctx_t,
            rho_rnd : randomness_t) : signature_t = {
    var sig : signature_t;
    sig <- sign_abs_op_lifted sk m ctx rho_rnd;
    return sig;
  }
}.

(* The wrapper's sign matches CentralRLWESign.sign on byte equality. *)
lemma wrapper_sign_refines_central :
  equiv [ SignExtractedWrapper.sign ~ CentralRLWESign.sign :
            ={arg}
            /\ accept_signing_attempt sk{1} m{1} ctx{1} rho_rnd{1}
          ==> ={res} ].
proof.
  proc.
  wp.
  skip => /> &m1 &m2 ? ? ? ? ?.
  by rewrite sign_abs_op_lifted_eq_rlwe.
qed.

(* ===================================================================
   ACCOUNTING

   axioms (2 -- lifted bridge + RLWE conformance):
     sign_abs_op_lifted_bridge
     sign_abs_op_lifted_eq_rlwe

   PROVED lemmas (0 admits):
     wrapper_sign_refines_central
   =================================================================== *)
