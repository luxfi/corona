(* -------------------------------------------------------------------- *)
(* Corona -- Class N4 public-key preservation across reshare            *)
(* -------------------------------------------------------------------- *)
(* STATUS: CLOSED. 0 admits across the file (mirroring Pulsar_N4.ec).   *)
(*                                                                      *)
(* This file proves `corona_n4_pk_preservation_honest` against the      *)
(* concrete honest reshare module `ReshareHonest`. The headline         *)
(* algebraic identity                                                   *)
(*                                                                      *)
(*   reconstruct q (zip_add (fresh_sharing q s)                         *)
(*                          (fresh_sharing q zero_share)) = s           *)
(*                                                                      *)
(* (Shamir-zero re-randomisation over R_q) is the cryptographic-        *)
(* reduction core. It reduces to three Lagrange-algebraic axioms over   *)
(* `share_t` viewed as an additive group over R_q^N (mechanized in the  *)
(* Lean theory `Crypto.Corona.Shamir`, stated EC-side as forward-facing *)
(* lemmas about `add_share` / `reconstruct` / `fresh_sharing`).         *)
(*                                                                      *)
(* What this file does NOT contain (and the rationale):                 *)
(*   - There is NO abstract section with a `declare axiom               *)
(*     reshare_preserves_secret` over an arbitrary Corona_Reshare R.   *)
(*     That shape is a *behavioural* hypothesis (a malicious R can      *)
(*     emit garbage shares) and is replaced by the concrete             *)
(*     `ReshareHonest` proof here. CI guard:                            *)
(*     `scripts/check-high-assurance.sh` greps for the old axiom shape  *)
(*     and fails if it is reintroduced.                                 *)
(*                                                                      *)
(*   - There is NO vacuous placeholder lemma. The real committee-root   *)
(*     binding-invariant statement is part of the Pedersen DKG (dkg2)   *)
(*     transcript module.                                               *)
(* -------------------------------------------------------------------- *)
(* Claim:                                                                *)
(*   The Corona proactive-resharing protocol (Refresh +                 *)
(*   ReshareToNewSet in luxfi/corona/reshare/) preserves the group      *)
(*   public key across committee rotations. Specifically: for every     *)
(*   starting share set `shares_old` over committee `C_old` with        *)
(*   public key `derive_pk(reconstruct(shares_old))`, after running     *)
(*   Reshare into a new committee `C_new`, the resulting share set      *)
(*   `shares_new` satisfies                                              *)
(*                                                                       *)
(*       derive_pk(reconstruct(shares_new))  =  derive_pk(reconstruct(  *)
(*                                                shares_old))           *)
(*                                                                       *)
(*   provided >= threshold honest parties in both committees.            *)
(*                                                                       *)
(* Reduction strategy:                                                   *)
(*   1. Shamir-zero re-randomisation: Reshare produces a fresh sharing   *)
(*      of the SAME secret over R_q by sampling shares of zero and       *)
(*      adding them to fresh shares of the original secret.              *)
(*   2. R_q-linearity: derive_pk is the linear map bTilde =              *)
(*      round_xi(A*s + e) mod q, so the public key depends only on s    *)
(*      (the secret), not on the sharing.                                *)
(*   3. => public key is invariant across reshare.                       *)
(*                                                                       *)
(* Auxiliary obligations:                                                *)
(*   - Reshare commits new committee members to the zero-share VSS       *)
(*     transcripts so dishonest old members cannot bias new shares.      *)
(*   - The reshare ceremony's activation cert commits to the OLD        *)
(*     committee roster so reviewers can detect post-hoc roster         *)
(*     substitution (luxfi/corona/reshare/activation.go).                *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

type group_pk_t.
type share_t.
type committee_t.
type reshare_transcript_t.

op derive_pk : share_t -> group_pk_t.
op reconstruct : int list -> share_t list -> share_t.

(* ===================================================================
   Lagrange-algebraic structure on share_t.

   share_t is the abstract type for a per-party Shamir share. For
   Corona it is R_q^N (a vector over the polynomial ring with N=7
   coordinates), which is an additive group under componentwise
   addition. The operators below pin that structure: a zero element,
   a binary +, and the dealer's polynomial-evaluation primitive
   `poly_eval`.

   The bridge to the Lean theory `Crypto.Corona.Shamir` is
   one-to-one: `add_share` <-> R_q^N `+`, `zero_share` <-> 0,
   `poly_eval` <-> the dealer's polynomial-eval operator
   `Polynomial.eval`. `fresh_sharing` is a *concrete* definition
   in terms of `poly_eval`, not an abstract operator.
   =================================================================== *)
op zero_share : share_t.
op add_share  : share_t -> share_t -> share_t.

(* Lift componentwise: zip two share lists with `add_share`. *)
op zip_add (l1 l2 : share_t list) : share_t list =
  map (fun (p : share_t * share_t) => add_share p.`1 p.`2) (zip l1 l2).

(* The dealer's polynomial-evaluation primitive. `poly_eval s i`
   returns the share for party index `i` produced by the dealer
   whose Shamir polynomial has constant term `s`.

   IMPORTANT: A real Shamir sharing is RANDOMISED (many polynomials
   share the same constant term). The operator here is a DETERMINISTIC
   REPRESENTATIVE of the distributional sharing family. This file
   proves functional secret preservation across reshare -- it does NOT
   prove distributional freshness / hiding of the new sharing. The
   latter is a separate hop-game argument; see `Corona_N1.ec` and
   the Lean theory `Crypto.Corona.Shamir` for the distributional
   hiding side. *)
op poly_eval : share_t -> int -> share_t.

(* CONCRETE definition: `fresh_sharing q s` returns the list of shares
       [ poly_eval s i_0; poly_eval s i_1; ...; poly_eval s i_{|q|-1} ]
   where the dealer's polynomial has constant term `s`. With this
   definition, malicious instantiations that emit garbage shares are
   RULED OUT BY TYPE: `fresh_sharing` is uniquely determined by
   `poly_eval`, and any `poly_eval` that satisfies the Lagrange-
   inverse identity below (`shamir_correct`) automatically makes
   `fresh_sharing` the unique correct sharing. *)
op fresh_sharing (q : int list) (s : share_t) : share_t list =
  List.map (poly_eval s) q.

(* ===================================================================
   Shamir layer -- algebraic axioms.

   These are field identities about R_q^N, NOT behavioral hypotheses
   about any module. They are mechanized in the Lean theory
   `Crypto.Corona.Shamir` (file `Shamir.lean`); we state them EC-side
   as the algebraic kernel the Reshare proof reduces to.
   =================================================================== *)

(* Adding zero is identity.
   BRIDGE: instance fact for any AddCommMonoid (Mathlib auto-derives
   for Polynomial F); see bridge doc § "Axiom 4". *)
axiom add_share_zeroR : forall (s : share_t), add_share s zero_share = s.

(* Reconstruction is linear over share-list addition.
   BRIDGE: Crypto.Threshold.Lagrange.combine_distributes_over_sum
   (`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean:81`).
   Proved as `(Lagrange.interpolate s v).map_add a b` -- direct
   instance of `LinearMap.map_add`. *)
axiom reconstruct_linear :
  forall (q : int list) (a b : share_t list),
    size a = size q => size b = size q =>
    reconstruct q (zip_add a b) =
      add_share (reconstruct q a) (reconstruct q b).

(* Reconstruction is a left inverse of fresh sharing at any quorum.
   BRIDGE: Crypto.Corona.Shamir.shamir_correct_at_target
   (`~/work/lux/proofs/lean/Crypto/Corona/Shamir.lean`) +
   Crypto.Threshold.Lagrange.secret_recovery_at_zero
   (`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean:62`). *)
axiom shamir_correct :
  forall (q : int list) (s : share_t),
    uniq q => 1 <= size q =>
    reconstruct q (fresh_sharing q s) = s.

(* fresh_sharing produces |q| shares. *)
axiom fresh_sharing_size :
  forall (q : int list) (s : share_t),
    size (fresh_sharing q s) = size q.

(* A fresh sharing of zero, reconstructed at any quorum, is zero.
   DERIVED here as a lemma, not stated as a separate axiom. *)
lemma fresh_sharing_zero_is_zero (q : int list) :
    uniq q => 1 <= size q =>
    reconstruct q (fresh_sharing q zero_share) = zero_share.
proof.
  move=> uq szq.
  by rewrite (shamir_correct q zero_share).
qed.

(* ===================================================================
   Committee -> quorum projection.

   Each committee_t value picks a canonical t-quorum (a list of party
   indices used by the dealer at sharing time).
   =================================================================== *)
op committee_quorum : committee_t -> int list.

axiom committee_quorum_uniq      : forall (c : committee_t), uniq (committee_quorum c).
axiom committee_quorum_nonempty  : forall (c : committee_t), 1 <= size (committee_quorum c).

module type Corona_Reshare = {
  proc reshare(c_old : committee_t, shares_old : share_t list,
               c_new : committee_t) : share_t list * reshare_transcript_t
}.

(* ===================================================================
   Concrete honest reshare module.

   The canonical Shamir-zero re-randomisation: each new-committee
   party receives the SUM of (a fresh re-share of the old secret)
   and (a fresh sharing of zero). Both summands are dealt by the
   `fresh_sharing` op at the new committee's canonical quorum
   (`committee_quorum c_new`). The old secret is recovered by
   reconstructing the old shares at the old committee's quorum
   (`committee_quorum c_old`).

   Refines (by code review): luxfi/corona/reshare/reshare.go's
   ReshareToNewSet flow + Refresh's zero-share + add path.
   =================================================================== *)
module ReshareHonest : Corona_Reshare = {
  proc reshare(c_old : committee_t, shares_old : share_t list,
               c_new : committee_t) : share_t list * reshare_transcript_t = {
    var q_old : int list;
    var q_new : int list;
    var old_secret : share_t;
    var refresh : share_t list;
    var zero_pad : share_t list;
    var new_shares : share_t list;
    var tr : reshare_transcript_t;
    q_old      <- committee_quorum c_old;
    q_new      <- committee_quorum c_new;
    old_secret <- reconstruct q_old shares_old;
    refresh    <- fresh_sharing q_new old_secret;
    zero_pad   <- fresh_sharing q_new zero_share;
    new_shares <- zip_add refresh zero_pad;
    tr <- witness;
    return (new_shares, tr);
  }
}.

(* ===================================================================
   N4 -- concrete proof against ReshareHonest.

   The `scripts/check-high-assurance.sh` guard greps for the old
   abstract `declare axiom reshare_preserves_secret` shape and fails
   CI if it ever reappears.
   =================================================================== *)

(* Algebraic core lemma: for any quorum q and any secret s,
     reconstruct q (zip_add (fresh_sharing q s) (fresh_sharing q 0)) = s.
   This is the headline Shamir-zero re-randomisation identity. *)
lemma honest_reshare_reconstructs
      (q : int list) (s : share_t) :
    uniq q => 1 <= size q =>
    reconstruct q
      (zip_add (fresh_sharing q s)
               (fresh_sharing q zero_share))
    = s.
proof.
  move=> uq szq.
  rewrite reconstruct_linear; first 2 by rewrite fresh_sharing_size.
  rewrite shamir_correct //.
  rewrite fresh_sharing_zero_is_zero //.
  by rewrite add_share_zeroR.
qed.

(* The headline concrete discharge: for the honest reshare module,
   the new-committee reconstruct equals the old-committee reconstruct. *)
lemma reshare_preserves_secret_honest
      (c_old_pre c_new_pre : committee_t)
      (shares_old_pre : share_t list) :
    hoare [ ReshareHonest.reshare :
              c_old = c_old_pre /\ shares_old = shares_old_pre
                /\ c_new = c_new_pre
            ==>
              reconstruct (committee_quorum c_new_pre) res.`1
              = reconstruct (committee_quorum c_old_pre) shares_old_pre ].
proof.
  proc; auto => &m [#] -> -> ->.
  have Huniq     : uniq (committee_quorum c_new_pre).
  - by apply committee_quorum_uniq.
  have Hnonempty : 1 <= size (committee_quorum c_new_pre).
  - by apply committee_quorum_nonempty.
  have H :
    reconstruct (committee_quorum c_new_pre)
      (zip_add
        (fresh_sharing (committee_quorum c_new_pre)
          (reconstruct (committee_quorum c_old_pre) shares_old_pre))
        (fresh_sharing (committee_quorum c_new_pre) zero_share))
    =
    reconstruct (committee_quorum c_old_pre) shares_old_pre.
  - exact (honest_reshare_reconstructs
             (committee_quorum c_new_pre)
             (reconstruct (committee_quorum c_old_pre) shares_old_pre)
             Huniq Hnonempty).
  smt(honest_reshare_reconstructs
      committee_quorum_uniq
      committee_quorum_nonempty).
qed.

(* Corollary at the public-key level: derive_pk congruence + the
   reconstruct equality. *)
lemma corona_n4_pk_preservation_honest
      (c_old_pre c_new_pre : committee_t)
      (shares_old_pre : share_t list) :
    hoare [ ReshareHonest.reshare :
              c_old = c_old_pre /\ shares_old = shares_old_pre
                /\ c_new = c_new_pre
            ==>
              derive_pk (reconstruct (committee_quorum c_new_pre) res.`1)
              = derive_pk (reconstruct (committee_quorum c_old_pre)
                                       shares_old_pre) ].
proof.
  conseq (reshare_preserves_secret_honest
            c_old_pre c_new_pre shares_old_pre) => /#.
qed.
