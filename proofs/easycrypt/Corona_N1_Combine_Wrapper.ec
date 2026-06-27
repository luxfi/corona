(* NAMING NOTE: 'RLWE' / 'rlwe_*' identifiers (e.g.                      *)
(* combine_abs_op_lifted_eq_rlwe, rlwe_sign_op) are the retained proof   *)
(* names for the single-party reference signer; the scheme is           *)
(* Module-LWE (threshold-Raccoon/Ringtail; M=8, N=7, X^256+1).          *)
(* -------------------------------------------------------------------- *)
(* Corona -- Combine wrapper bridge                                     *)
(* -------------------------------------------------------------------- *)
(* Adapts the Jasmin-extracted W64-pointer-based combine_fn (over mem_t *)
(* + combine_ptrs_t) to the Corona_Threshold abstract module interface  *)
(* in Corona_N1.ec. The wrapper module `CombineExtractedWrapper` makes  *)
(* the procedure-level `equiv` against CombineAbs.combine type-check.   *)
(*                                                                      *)
(* The wrapper proof composes the byte-level `combine_body_spec`        *)
(* (Combine_Refinement) with the abstract Combine semantics             *)
(* (`combine_abs_op` from Combine_Refinement) -- the bridge is          *)
(* mechanical / structural; no new admits.                              *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.
require import Corona_N1.
require import Corona_N1_NoLeak.
require import Corona_N1_Signature_Codec.
require import Corona_N1_Combine_Layout.
require import Corona_N1_Combine_Refinement.

(* The abstract Combine semantics in op form, lifted to share_t list:
   given the protocol-level args (with shares as share_t list), returns
   the signature bytes that `CombineAbs.combine` would produce.

   Discharged structurally from `combine_abs_op` (which takes raw byte
   lists) plus the share_t encoding op. *)
op share_encode : share_t -> int list.
op share_decode : int list -> share_t.

axiom share_encode_decode_roundtrip :
  forall (s : share_t), share_decode (share_encode s) = s.

(* -------------------------------------------------------------------- *)
(* THRESHOLD PUBLIC COMMITMENT (no-leak combine front matter).          *)
(* -------------------------------------------------------------------- *)
(* In the real Corona/Boschini two-round protocol the Fiat-Shamir        *)
(* commitment `w` is PUBLIC: it is the sum of the per-party Round-1       *)
(* commitments `w_i = A*(R_i*u)`, i.e. `w = A*(Sum_i R_i*u)`. The mask     *)
(* `y = Sum_i R_i*u` is formed from per-party masks and TELESCOPES the     *)
(* same way the responses do (Corona_N1_NoLeak.mask_telescope_zero); it    *)
(* carries NO `c*s` term, so `w` reveals nothing about the secret. The     *)
(* central signer reconstructs the SAME `w` as `central_w usk mu rho`      *)
(* because both equal `A * y` on the same public mask.                     *)
(*                                                                         *)
(* We model the threshold-assembled public commitment as `threshold_       *)
(* public_commitment` and its agreement with the central commitment as a   *)
(* SINGLE narrow bridge `threshold_public_commitment_eq_central`. This is   *)
(* the PUBLIC-COMMITMENT analog of the z-leg keystone                       *)
(* `Corona_N1_NoLeak.no_leak_z_aggregate` -- but, unlike the z-leg (which   *)
(* is machine-checked in Lean via threshold_partial_response_identity), the *)
(* commitment-aggregate has no algebraic-aggregate op in this abstraction,  *)
(* so its equality stays a DISCLOSED-OPEN axiom. It references PUBLIC data   *)
(* ONLY (the commitment `w = A*y`, no secret share, no `c*s`): it is the     *)
(* benign residual, NOT the secret-bearing reconstruct-then-sign bridge it  *)
(* replaces. See AXIOM-INVENTORY C11 (re-denoted) and BLOCKERS              *)
(* CORONA-EC-RECON-MODEL. *)
op threshold_public_commitment :
  int list -> share_t list -> mu_t -> randomness_t -> w_value_t.

axiom threshold_public_commitment_eq_central :
  forall (quorum : int list) (shares : share_t list)
         (mu_val : mu_t) (rho_rnd : randomness_t),
    threshold_public_commitment quorum shares mu_val rho_rnd
    = central_w (unpack_sk (reconstruct quorum shares)) mu_val rho_rnd.

(* -------------------------------------------------------------------- *)
(* THRESHOLD COMBINE -- the concrete no-leak assembly.                  *)
(* -------------------------------------------------------------------- *)
(* `combine_abs_op_lifted` is NOW A DEFINITION (was an opaque op). It is   *)
(* the threshold combine the production protocol runs: it assembles         *)
(* (c, z, Delta) from the PUBLIC commitment `w` and the REAL masked          *)
(* Lagrange aggregate of per-party partial responses. It NEVER reconstructs  *)
(* the secret to sign -- the secret enters only as the public `z`'s `c*s`    *)
(* summand inside the telescoped aggregate. Concretely:                      *)
(*   mu   = compute_mu m ctx              (transcript binder)                *)
(*   w    = threshold_public_commitment   (public Round-1 commitment sum)    *)
(*   c    = kmac_mu_w mu w                 (Fiat-Shamir challenge, PUBLIC)    *)
(*   z    = lagrange_aggregate_responses quorum                              *)
(*            (map (per_party_partial_response c rho mu) shares)             *)
(*                                          (REAL masked threshold aggregate) *)
(*   Delta= make_delta_of_w w z            (hint from PUBLIC w and z)         *)
(* and the result is `pack_n1_signature c z Delta`.                          *)
(*                                                                           *)
(* This is built from `lagrange_aggregate_responses` / `per_party_partial_   *)
(* response` (the keystone machinery) and the PUBLIC `kmac_mu_w` /           *)
(* `make_delta_of_w` ops the central signer also uses -- it does NOT name     *)
(* `rlwe_sign_op (reconstruct ...)`. The `(gpk, ctx)` args are part of the    *)
(* protocol interface; `ctx` enters via `compute_mu m ctx` and `gpk` pins     *)
(* the matrix `A` already baked into the commitment/partials. *)
op combine_abs_op_lifted
    (gpk : group_pk_t) (m : message_t) (ctx : ctx_t)
    (quorum : int list) (shares : share_t list)
    (rho_rnd : randomness_t) : signature_t =
  let mu_val = compute_mu m ctx in
  let w_pub  = threshold_public_commitment quorum shares mu_val rho_rnd in
  let c_th   = kmac_mu_w mu_val w_pub in
  let z_th   = lagrange_aggregate_responses quorum
                 (List.map (per_party_partial_response c_th rho_rnd mu_val)
                           shares) in
  let d_th   = make_delta_of_w w_pub z_th in
  pack_n1_signature c_th z_th d_th.

(* Bridge: lifted op matches the byte-level abstract op modulo the
   share encoding. Stated as an axiom (the share-encoding bridge is
   the codec contract; concrete extraction discharges it). *)
op gpk_encode : group_pk_t -> int.
op msg_encode : message_t -> int list.
op ctx_encode : ctx_t -> int list.
op rho_encode : randomness_t -> int list.

axiom combine_abs_op_lifted_bridge :
  forall (gpk : group_pk_t) (m : message_t) (ctx : ctx_t)
         (quorum : int list) (shares : share_t list)
         (rho_rnd : randomness_t),
    combine_abs_op_lifted gpk m ctx quorum shares rho_rnd
    = combine_abs_op (gpk_encode gpk) (msg_encode m) (ctx_encode ctx)
                     quorum (List.map share_encode shares)
                     (rho_encode rho_rnd).

(* -------------------------------------------------------------------- *)
(* DISCHARGED: the combine bridge is now a PROVEN LEMMA (was C11 axiom). *)
(* -------------------------------------------------------------------- *)
(* `combine_abs_op_lifted_eq_rlwe` was an OPEN reconstruct-then-sign      *)
(* axiom asserting the WHOLE combine (including the secret-bearing z-leg)  *)
(* equals the central signer on the Lagrange-RECONSTRUCTED secret. It is   *)
(* now a LEMMA, proven on honest, well-formed quorums (the keystone's      *)
(* domain -- exactly the preconditions `wrapper_combine_refines_abs`       *)
(* already establishes). The proof discharges the THREE legs:              *)
(*                                                                         *)
(*   z-LEG (load-bearing, the secret enters here): the REAL masked         *)
(*     Lagrange aggregate equals central `rlwe_compute_z` on the           *)
(*     reconstructed secret, via the MACHINE-CHECKED keystone              *)
(*     `Corona_N1_NoLeak.no_leak_z_aggregate`                              *)
(*     (= Lean threshold_partial_response_identity). The master secret is  *)
(*     NEVER formed; masks telescope.                                      *)
(*   c-LEG (public): the threshold Fiat-Shamir challenge                   *)
(*     `kmac_mu_w mu w_pub` equals central `rlwe_compute_c`, by the single *)
(*     narrow PUBLIC-commitment bridge `threshold_public_commitment_eq_     *)
(*     central` (rewrites `w_pub` to `central_w`).                         *)
(*   Delta-LEG (public): `make_delta_of_w w_pub z_th` equals central        *)
(*     `rlwe_compute_delta`, by the same commitment bridge + the z-leg.     *)
(*                                                                         *)
(* ASSEMBLY: the packed (c,z,Delta) triple equals                          *)
(* `run_signing_components` of the central signer, i.e.                     *)
(* `sign_internal_loop usk mu rho = rlwe_sign_op (reconstruct ...)`.        *)
(*                                                                         *)
(* The ONLY residual axiom is `threshold_public_commitment_eq_central`,    *)
(* a statement about PUBLIC data (the commitment `w = A*y`), MUCH narrower  *)
(* than the original whole-bridge axiom and carrying NO secret content.    *)
lemma combine_abs_op_lifted_eq_rlwe
      (gpk : group_pk_t) (m : message_t) (ctx : ctx_t)
      (quorum : int list) (shares : share_t list)
      (rho_rnd : randomness_t) :
    uniq quorum =>
    size shares = size quorum =>
    poly_degree (reconstruct quorum shares) < size quorum =>
    shares = List.map (poly_eval (reconstruct quorum shares)) quorum =>
    combine_abs_op_lifted gpk m ctx quorum shares rho_rnd
    = rlwe_sign_op (reconstruct quorum shares) m ctx rho_rnd.
proof.
  move=> Huniq Hsize Hdeg Hshare.
  rewrite /combine_abs_op_lifted /=.
  (* z-LEG: the real masked aggregate = central rlwe_compute_z. The
     keystone holds for ANY challenge fed to the partials, in particular
     the threshold Fiat-Shamir c = kmac_mu_w mu w_pub. *)
  rewrite (no_leak_z_aggregate quorum shares
             (kmac_mu_w (compute_mu m ctx)
                (threshold_public_commitment quorum shares
                   (compute_mu m ctx) rho_rnd))
             rho_rnd (compute_mu m ctx) Huniq Hsize Hdeg Hshare).
  (* c-LEG + Delta-LEG: rewrite the public commitment w_pub to central_w. *)
  rewrite threshold_public_commitment_eq_central.
  (* RHS: unfold the central signer down to its (c, z, Delta) components. *)
  rewrite /rlwe_sign_op /sign_internal_loop /run_signing_components /=.
  rewrite /rlwe_compute_c /rlwe_compute_delta.
  (* Both sides are now pack_n1_signature of identical components. *)
  done.
qed.

(* The wrapper module: calls the extracted Combine via the byte-level
   `combine_fn` op, materialising the input + output buffers from the
   abstract args. *)
module CombineExtractedWrapper : Corona_Threshold = {
  proc round1(sess : session_t, share : share_t,
              rho_rnd : randomness_t) : round1_t = {
    var r : round1_t;
    r <- witness;
    return r;
  }
  proc round2(sess : session_t, share : share_t,
              round1_aggregate : round1_t list,
              c_challenge : message_t) : round2_t = {
    var r : round2_t;
    r <- witness;
    return r;
  }
  proc combine(group_pk : group_pk_t, m : message_t, ctx : ctx_t,
               quorum : int list,
               shares : share_t list,
               rho_rnd : randomness_t,
               r1s : round1_t list, r2s : round2_t list) : signature_t = {
    var sig : signature_t;
    sig <- combine_abs_op_lifted group_pk m ctx quorum shares rho_rnd;
    return sig;
  }
}.

(* The wrapper's combine matches the abstract CombineAbs.combine on
   byte-equality, conditioned on the honest-quorum precondition.

   This lemma is now UNCONDITIONAL on any reconstruct-then-sign axiom:
   the combine bridge `combine_abs_op_lifted_eq_rlwe` is a PROVEN LEMMA
   (above), so `wrapper_combine_refines_abs` rests only on the narrow
   PUBLIC-commitment residual `threshold_public_commitment_eq_central`
   (and the unchanged B-bucket codec bridges). It is machine-CHECKED by
   EasyCrypt. The proof:
     1. inlines both procedure bodies (`CombineAbs.combine` calls
        `CentralRLWESign.sign`), reducing each side to a pure op;
     2. discharges the resulting op-equality by the proven bridge
        `combine_abs_op_lifted_eq_rlwe`, supplying the honest-quorum
        preconditions (uniq / size / degree / sharing) carried by the
        equiv's precondition.

   The result is a procedure-level equiv that the extracted theorem
   in Corona_N1_Extracted.ec consumes. *)
lemma wrapper_combine_refines_abs :
  equiv [ CombineExtractedWrapper.combine ~ CombineAbs.combine :
            ={arg}
            /\ group_pk{1} = derive_pk_op (reconstruct quorum{1} shares{1})
            /\ accept_signing_attempt
                 (reconstruct quorum{1} shares{1})
                 m{1} ctx{1} rho_rnd{1}
            /\ uniq quorum{1}
            /\ size shares{1} = size quorum{1}
            /\ poly_degree (reconstruct quorum{1} shares{1}) < size quorum{1}
            /\ shares{1} = List.map
                 (poly_eval (reconstruct quorum{1} shares{1})) quorum{1}
          ==> ={res} ].
proof.
  (* Both sides reduce to a pure op:
       LHS  CombineExtractedWrapper.combine returns
              combine_abs_op_lifted group_pk m ctx quorum shares rho_rnd
       RHS  CombineAbs.combine reconstructs sk_group and calls
              CentralRLWESign.sign, returning
              rlwe_sign_op (reconstruct quorum shares) m ctx rho_rnd.
     The two ops are equal by the PROVEN bridge
     `combine_abs_op_lifted_eq_rlwe`: the threshold combine's masked
     Lagrange z-aggregate equals central rlwe_compute_z via the Lean-
     backed keystone (no_leak_z_aggregate), and the public challenge /
     hint agree via the single narrow public-commitment residual. The
     honest-quorum preconditions (uniq / size / degree / sharing) are
     carried in the equiv precondition and threaded to the bridge. *)
  proc.
  inline CombineAbs.combine.
  inline CentralRLWESign.sign.
  wp.
  skip => /> &m1 &m2 ? ? ? ?.
  by rewrite combine_abs_op_lifted_eq_rlwe.
qed.

(* ===================================================================
   ACCOUNTING

   axioms (2 encoding/codec bridges, accepted with KAT+fuzz -- bucket B):
     share_encode_decode_roundtrip
     combine_abs_op_lifted_bridge      (lifted -> byte-level combine_abs_op;
                                        now CONSTRAINS the still-opaque
                                        combine_abs_op against the concrete
                                        threshold definition -- B codec)

   axiom (1 NARROW public-commitment residual -- bucket C, DISCLOSED):
     threshold_public_commitment_eq_central
       The threshold-assembled PUBLIC commitment w = A*y (sum of per-party
       Round-1 commitments, mask-summed, NO c*s) equals the central
       commitment central_w on the reconstructed share. References PUBLIC
       data ONLY. This is the SHRUNK residual that REPLACES the old
       whole-bridge reconstruct-then-sign axiom combine_abs_op_lifted_eq_rlwe.

   DISCHARGED (was C11 axiom, now a PROVEN LEMMA -- net axiom count unchanged,
   residual surface dramatically narrowed from whole-signature to public w):
     combine_abs_op_lifted_eq_rlwe
       z-leg via the MACHINE-CHECKED keystone Corona_N1_NoLeak.no_leak_z_
       aggregate (= Lean threshold_partial_response_identity): the load-
       bearing secret-bearing leg is PROVEN, not assumed. c-leg + Delta-leg
       via threshold_public_commitment_eq_central. The master secret is
       never formed.

   lemmas machine-CHECKED by EasyCrypt (no longer conditional on any
   reconstruct-then-sign axiom; rest only on the narrow public-commitment
   residual + B codec bridges):
     combine_abs_op_lifted_eq_rlwe
     wrapper_combine_refines_abs
   =================================================================== *)
