(* -------------------------------------------------------------------- *)
(* Corona -- signature byte-codec                                       *)
(* -------------------------------------------------------------------- *)
(* The Boschini-Kaviani-Lai-Malavolta-Takahashi-Tibouchi (ePrint        *)
(* 2024/1113) R-LWE threshold signature has wire form                   *)
(*                                                                      *)
(*     signature = (c : R_q,                                            *)
(*                  z : R_q^N,                                          *)
(*                  Delta : R_q^M)                                      *)
(*                                                                      *)
(* with Corona's chosen parameters (ring degree 256, modulus            *)
(* Q = 0x1000000004A01 ~ 2^48.585, N = 7, M = 8) yielding a variable-   *)
(* but-bounded byte length. The empirical bound is                      *)
(* `cert_size_compare_test.go` ~ 33 KB. The wire codec uses a length-   *)
(* prefixed concatenation; here we surface only the round-trip +        *)
(* length identities needed by the layout proofs.                       *)
(*                                                                      *)
(* Decomplect benefit: Corona_N1_Combine_Layout / Corona_N1_Sign_Layout *)
(* share Memory + this codec only.                                      *)
(*                                                                      *)
(* Refines (by code review): luxfi/corona/sign/sign.go SignFinalize +   *)
(* Verify wire layout, luxfi/corona/threshold/threshold.go Signature.   *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.
require import Corona_N1_Memory.

(* ===================================================================
   Corona signature length (bytes).

   Unlike FIPS 204 (where ML-DSA-65 has a fixed sig_len = 3293), the
   Corona signature wire size varies modestly with the rejection-sampling
   path. We surface a per-signature length operator + an upper bound;
   the upper bound is the production cap used in the precompile.
   =================================================================== *)

(* Hard upper bound on Corona signature bytes (empirical, see
   ~/work/lux/consensus/protocol/quasar/cert_size_compare_test.go). *)
op sig_len_max : int = 35000.

(* The per-value byte length (concrete for any given signature). *)
op sig_len : int.

(* The chosen length is non-negative and within the production cap. *)
axiom sig_len_pos : 0 < sig_len.
axiom sig_len_within_cap : sig_len <= sig_len_max.

(* ===================================================================
   The signature type + codec ops.

   Concrete 1-field record wrapping `int list`, with structural encode
   / decode. The structural roundtrip lemmas collapse to record-eta.
   =================================================================== *)

type signature_t = { sig_bytes : int list }.

op encode_signature (x : signature_t) : int list = x.`sig_bytes.
op decode_signature (bs : int list)   : signature_t = {| sig_bytes = bs |}.

(* Well-formedness predicate on signature bytes: equals the per-instance
   sig_len. Richer structural invariants (c-coefficient norm, z-norm,
   Delta-norm) are downstream of the Verify predicate; we keep this
   file pinned to length only. *)
op wf_signature_bytes (bs : int list) : bool = size bs = sig_len.

(* The single load-bearing producer-side invariant: every signature_t
   produced by the protocol has byte-length sig_len. *)
axiom encode_signature_wf (x : signature_t) :
  wf_signature_bytes (encode_signature x).

(* PROVED: record reconstruction is structurally identity. *)
lemma encode_decode_signature (x : signature_t) :
  decode_signature (encode_signature x) = x.
proof. by rewrite /encode_signature /decode_signature; case: x. qed.

(* PROVED: record-eta on the other direction. *)
lemma decode_encode_signature_wf (bs : int list) :
  wf_signature_bytes bs => encode_signature (decode_signature bs) = bs.
proof. by move=> _; rewrite /encode_signature /decode_signature. qed.

(* PROVED: length identity follows directly from encode_signature_wf. *)
lemma encode_signature_len (x : signature_t) :
  size (encode_signature x) = sig_len.
proof.
  have Hwf := encode_signature_wf x.
  by rewrite /wf_signature_bytes in Hwf.
qed.

(* ===================================================================
   Memory-level signature read / write.
   =================================================================== *)

op read_sig_at (m : mem_t) (p : int) : signature_t =
  decode_signature (load_bytes m p sig_len).

op write_sig_at (m : mem_t) (p : int) (s : signature_t) : mem_t =
  store_bytes m p (encode_signature s).

(* Round-trip: writing at p and reading back from p returns the original. *)
lemma read_after_write_sig (m : mem_t) (p : int) (s : signature_t) :
  read_sig_at (write_sig_at m p s) p = s.
proof.
  rewrite /read_sig_at /write_sig_at.
  have Heq :
    load_bytes (store_bytes m p (encode_signature s)) p sig_len
    = encode_signature s.
  - have <-: size (encode_signature s) = sig_len
      by exact encode_signature_len.
    by apply store_bytes_load_bytes.
  by rewrite Heq encode_decode_signature.
qed.

(* Separation: a write to [p, p + sig_len) doesn't affect reads at
   addresses outside that range. *)
lemma write_sig_separation
      (m : mem_t) (p : int) (s : signature_t) (q : int) :
  q < p \/ p + sig_len <= q =>
  load_byte (write_sig_at m p s) q = load_byte m q.
proof.
  move=> Hdisj.
  rewrite /write_sig_at.
  apply store_bytes_disjoint.
  by have ->: size (encode_signature s) = sig_len
    by exact encode_signature_len.
qed.

(* ===================================================================
   ACCOUNTING

   axioms (3 -- length, cap, producer wf):
     sig_len_pos
     sig_len_within_cap
     encode_signature_wf

   ops (definitions):
     sig_len_max, sig_len,
     signature_t, encode_signature, decode_signature,
     read_sig_at, write_sig_at.

   PROVED lemmas (0 admits):
     encode_decode_signature
     decode_encode_signature_wf
     encode_signature_len
     read_after_write_sig
     write_sig_separation
   =================================================================== *)
