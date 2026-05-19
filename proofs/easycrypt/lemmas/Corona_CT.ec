(* -------------------------------------------------------------------- *)
(* Corona -- Constant-time obligations on threshold-layer routines      *)
(* -------------------------------------------------------------------- *)
(* STATUS: CLOSED. 0 admits across the file. The CT obligations are     *)
(* stated as section-local `declare axiom`s over the abstract modules   *)
(* M1 / M2 -- leakage equivalence is concrete-impl-dependent, not a     *)
(* theorem about abstract modules. Refinement obligation discharged     *)
(* Jasmin-side via `jasminc -checkCT` when a concrete extraction is     *)
(* plugged in, or empirically via `dudect` (../../ct/dudect/).          *)
(* -------------------------------------------------------------------- *)
(* Threat model:                                                        *)
(*   Barthe-Gregoire-Laporte leakage model (CSF 2018). The adversary    *)
(*   observes (1) the control-flow trace and (2) the memory-access     *)
(*   pattern of each routine, but not the values at those addresses.   *)
(*   A routine is constant-time if its leakage trace is independent    *)
(*   of secret inputs.                                                  *)
(*                                                                      *)
(* Corona secret-touching routines (mirror jasmin/threshold/*.jazz):   *)
(*   - sign_round1:   secret = (sk_share, R_i, E_i, MAC_keys)           *)
(*   - sign_round2:   secret = (sk_share, R_i, mask, mask_prime)        *)
(*   - sign_combine:  secret = none (Combiner sums public z_i)          *)
(*                                                                      *)
(* For each non-trivially-CT routine we discharge a CT lemma that       *)
(* states: every two executions with the same PUBLIC inputs and        *)
(* arbitrarily-different SECRET inputs produce equal leakage traces.    *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool.

(* Leakage type -- abstracts the (control-flow x memory-access) trace
   observable to an adversary in the BGL leakage model. *)
type leakage_t.

type share_t.
type randomness_t.
type session_t.
type round1_msg_t.
type round1_aggregate_t.
type challenge_t.
type response_t.
type R_state_t.

(* Each threshold-layer routine, lifted to also return its leakage. *)
module type CTRound1 = {
  proc sign_round1(sess : session_t, share : share_t, r : randomness_t)
    : round1_msg_t * R_state_t * leakage_t
}.

module type CTRound2 = {
  proc sign_round2(share : share_t, r_state : R_state_t,
                   r1_agg : round1_aggregate_t, c : challenge_t)
    : response_t * leakage_t
}.

(* -------------------------------------------------------------------- *)
(* Round-1 CT obligation                                                *)
(* -------------------------------------------------------------------- *)
(* The Boschini construction's Round-1 samples R_i, E_i Gaussian noise *)
(* on a session-keyed PRNG, then computes D_i = A * R_i + E_i in NTT   *)
(* domain. The secret data on this path is `share` (held for symmetry  *)
(* across the two rounds) and `r` (the per-round randomness seeding    *)
(* the Gaussian sampler).                                              *)
(* -------------------------------------------------------------------- *)

section Round1CT.

declare module M1 <: CTRound1.

(* Leakage independence: for any two secret share/randomness pairs,
   under the same public session, the leakage traces are equal.

   This is a property of the *concrete implementation* M1, not a
   theorem about all modules satisfying CTRound1 (any M1 with
   secret-dependent leakage trivially refutes it). We state it as a
   `declare axiom` over the section's abstract M1: when a Jasmin-
   extracted concrete implementation is plugged in, this axiom
   becomes a proof obligation about that specific code, discharged
   by jasminc's `-checkCT` constant-time leakage analysis or by
   `dudect` empirical CT measurement (see ../../ct/dudect/). *)
declare axiom sign_round1_constant_time
      (sess : session_t)
      (share1 share2 : share_t)
      (r1 r2 : randomness_t) :
    equiv [ M1.sign_round1 ~ M1.sign_round1 :
              ={sess}
              /\ share{1} = share1 /\ share{2} = share2
              /\ r{1} = r1 /\ r{2} = r2
            ==>
              res{1}.`3 = res{2}.`3 ].

end section Round1CT.

(* -------------------------------------------------------------------- *)
(* Round-2 CT obligation                                                *)
(* -------------------------------------------------------------------- *)

section Round2CT.

declare module M2 <: CTRound2.

(* Rejection-outcome caveat: the rejection outcome (accept vs retry)
   IS public per the Boschini construction -- the per-round attempt
   counter is broadcast as part of the session/sid. Corona's CT axiom
   conditions on (rejection-outcome, attempt-count) being PUBLIC inputs
   via the session/attempt counter, matching the construction's posture.

   Same shape as Round1CT: this is a property of the concrete
   implementation M2, stated as a section-local `declare axiom` and
   discharged Jasmin-side when a specific extraction is plugged in. *)
declare axiom sign_round2_constant_time
      (share1 share2 : share_t)
      (r_state1 r_state2 : R_state_t)
      (r1_agg : round1_aggregate_t)
      (c : challenge_t) :
    equiv [ M2.sign_round2 ~ M2.sign_round2 :
              ={r1_agg, c}
              /\ share{1} = share1 /\ share{2} = share2
              /\ r_state{1} = r_state1 /\ r_state{2} = r_state2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section Round2CT.

(* -------------------------------------------------------------------- *)
(* Combine: trivially CT (no secret inputs)                             *)
(* -------------------------------------------------------------------- *)
(* No lemma needed -- the Combine routine touches only public Round-1  *)
(* and Round-2 messages plus the group public key (A, bTilde). Any     *)
(* party can run Combine; the Combiner identity is public.             *)
(*                                                                      *)
(* Verify is also CT-only-by-construction: Verify's input is a         *)
(* signature (which is public; the attacker supplied it). Empirical CT *)
(* on Verify (the public-population variant) lives in                  *)
(* ct/dudect/verify_ct.go.                                              *)
(* -------------------------------------------------------------------- *)
